use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use arcgis_sharing_rs::{
    auth::{
        exchange_oauth_authorization_code, exchange_oauth_refresh_token,
        exchange_oauth_refresh_token_credential,
    },
    error::{Error as ArcGISClientError, OAuthError},
};
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use tokio::sync::{Mutex, RwLock};
use tracing::Instrument;
use uuid::Uuid;

use crate::config::{ArcgisPortalConfig, AuthSettings, PortalRegistry};

// Fixed TTLs/caps; upgrade path is env-config or per-IP rate limiting at the proxy.
const PENDING_OAUTH_SESSION_TTL_SECS: i64 = 600;
const PENDING_AUTH_CODE_TTL_SECS: i64 = 600;
const PENDING_CONSENT_TTL_SECS: i64 = 600;
const MAX_PENDING_OAUTH_SESSIONS: usize = 1000;
const MAX_PENDING_AUTH_CODES: usize = 1000;
const MAX_PENDING_CONSENTS: usize = 1000;
const ARCGIS_TOKEN_SAFETY_MARGIN_SECONDS: i64 = 30;
const FORCED_REFRESH_RATE_LIMIT_SECONDS: i64 = 5;

pub type ArcGISTokenResponse = arcgis_sharing_rs::models::OAuthAuthorizationCodeResponse;
pub type ArcGISAccessTokenResponse = arcgis_sharing_rs::models::OAuthAccessTokenResponse;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingStoreError {
    CapacityExceeded,
}

fn is_expired(created_at: i64, ttl_secs: i64) -> bool {
    chrono::Utc::now().timestamp() > created_at + ttl_secs
}

/// Portal context bound to an MCP access token for runtime API calls.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PortalContext {
    pub key: String,
    pub portal_url: String,
    pub api_root: String,
    pub portal_apps: String,
    pub stories_root: String,
}

impl From<&ArcgisPortalConfig> for PortalContext {
    fn from(portal: &ArcgisPortalConfig) -> Self {
        Self {
            key: portal.key.clone(),
            portal_url: portal.portal_url.clone(),
            api_root: portal.api_root.clone(),
            portal_apps: portal.portal_apps.clone(),
            stories_root: portal.stories_root.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct McpTokenRecord {
    pub arcgis_token: ArcGISAccessTokenResponse,
    pub portal: PortalContext,
    pub expires_at: i64,
    pub resource: String,
    pub scopes: Vec<String>,
}

pub enum SessionResolution {
    Active(Box<McpTokenRecord>),
    Inactive,
    TemporarilyUnavailable,
    RateLimited,
}

impl SessionResolution {
    #[cfg(test)]
    pub(crate) fn into_active(self) -> Option<McpTokenRecord> {
        match self {
            Self::Active(record) => Some(*record),
            Self::Inactive | Self::TemporarilyUnavailable | Self::RateLimited => None,
        }
    }
}

struct StoredSession {
    session_id: String,
    resource: String,
    scopes: Vec<String>,
    portal: PortalContext,
    arcgis_access_token: String,
    arcgis_access_expires_at: i64,
    arcgis_refresh_token: String,
    arcgis_refresh_expires_at: i64,
    arcgis_username: Option<String>,
    arcgis_ssl: Option<bool>,
    arcgis_credential_generation: i64,
}

/// Stored when /oauth/authorize/continue is received; consumed by /arcgis/callback.
#[derive(Clone, Debug)]
pub struct PendingOAuthSession {
    pub client_id: String,
    pub mcp_client_state: Option<String>,
    pub mcp_redirect_uri: String,
    pub mcp_code_challenge: Option<String>,
    pub resource: String,
    pub scopes: Vec<String>,
    pub arcgis_pkce_verifier: Vec<u8>,
    pub portal: ArcgisPortalConfig,
    pub created_at: i64,
}

/// Stored when /arcgis/callback completes; consumed by /oauth/token.
#[derive(Clone, Debug)]
pub struct PendingAuthCode {
    pub arcgis_token: ArcGISTokenResponse,
    pub client_id: String,
    pub mcp_code_challenge: Option<String>,
    pub mcp_redirect_uri: String,
    pub resource: String,
    pub scopes: Vec<String>,
    pub portal: PortalContext,
    pub created_at: i64,
}

/// Validated authorization parameters awaiting an explicit user decision.
#[derive(Clone, Debug)]
pub struct PendingConsent {
    pub client_id: String,
    pub mcp_client_state: Option<String>,
    pub mcp_redirect_uri: String,
    pub mcp_code_challenge: String,
    pub resource: String,
    pub scopes: Vec<String>,
    csrf_token: String,
    created_at: i64,
}

#[derive(Clone, Debug)]
pub struct ArcGISAuthStore {
    pub base_url: String,
    pub portal_registry: Arc<PortalRegistry>,
    pending_consents: Arc<RwLock<HashMap<String, PendingConsent>>>,
    pending_oauth_sessions: Arc<RwLock<HashMap<String, PendingOAuthSession>>>,
    pending_auth_codes: Arc<RwLock<HashMap<String, PendingAuthCode>>>,
    refresh_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    pool: SqlitePool,
    auth_settings: AuthSettings,
}

impl ArcGISAuthStore {
    #[cfg(test)]
    pub fn new(pool: SqlitePool, base_url: String, portal_registry: PortalRegistry) -> Self {
        Self::with_auth_settings(pool, base_url, portal_registry, AuthSettings::default())
    }

    pub fn with_auth_settings(
        pool: SqlitePool,
        base_url: String,
        portal_registry: PortalRegistry,
        auth_settings: AuthSettings,
    ) -> Self {
        Self {
            base_url,
            portal_registry: Arc::new(portal_registry),
            pending_consents: Arc::new(RwLock::new(HashMap::new())),
            pending_oauth_sessions: Arc::new(RwLock::new(HashMap::new())),
            pending_auth_codes: Arc::new(RwLock::new(HashMap::new())),
            refresh_locks: Arc::new(Mutex::new(HashMap::new())),
            pool,
            auth_settings,
        }
    }

    pub fn portal_registry(&self) -> &PortalRegistry {
        &self.portal_registry
    }

    pub async fn create_pending_consent(
        &self,
        client_id: String,
        mcp_client_state: Option<String>,
        mcp_redirect_uri: String,
        mcp_code_challenge: String,
        resource: String,
        scopes: Vec<String>,
    ) -> Result<(String, String), PendingStoreError> {
        let request_id = Uuid::new_v4().to_string();
        let csrf_token = Uuid::new_v4().to_string();
        let mut consents = self.pending_consents.write().await;
        consents.retain(|_, consent| !is_expired(consent.created_at, PENDING_CONSENT_TTL_SECS));
        if consents.len() >= MAX_PENDING_CONSENTS {
            return Err(PendingStoreError::CapacityExceeded);
        }
        consents.insert(
            request_id.clone(),
            PendingConsent {
                client_id,
                mcp_client_state,
                mcp_redirect_uri,
                mcp_code_challenge,
                resource,
                scopes,
                csrf_token: csrf_token.clone(),
                created_at: chrono::Utc::now().timestamp(),
            },
        );
        Ok((request_id, csrf_token))
    }

    /// Consume only when both opaque values match, keeping authorization data server-side.
    pub async fn consume_pending_consent(
        &self,
        request_id: &str,
        csrf_token: &str,
    ) -> Option<PendingConsent> {
        let mut consents = self.pending_consents.write().await;
        let consent = consents.get(request_id)?;
        if consent.csrf_token != csrf_token {
            return None;
        }
        let consent = consents.remove(request_id)?;
        if is_expired(consent.created_at, PENDING_CONSENT_TTL_SECS) {
            return None;
        }
        Some(consent)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_pending_oauth_session(
        &self,
        client_id: String,
        mcp_client_state: Option<String>,
        mcp_redirect_uri: String,
        mcp_code_challenge: Option<String>,
        resource: String,
        scopes: Vec<String>,
        portal: ArcgisPortalConfig,
    ) -> Result<(String, String), PendingStoreError> {
        let arcgis_pkce_verifier = generate_pkce_verifier();
        let arcgis_pkce_challenge = pkce_code_challenge(&arcgis_pkce_verifier);
        let state_id = Uuid::new_v4().to_string();
        let created_at = chrono::Utc::now().timestamp();
        let mut sessions = self.pending_oauth_sessions.write().await;
        if sessions.len() >= MAX_PENDING_OAUTH_SESSIONS {
            return Err(PendingStoreError::CapacityExceeded);
        }
        sessions.insert(
            state_id.clone(),
            PendingOAuthSession {
                client_id,
                mcp_client_state,
                mcp_redirect_uri,
                mcp_code_challenge,
                resource,
                scopes,
                arcgis_pkce_verifier,
                portal,
                created_at,
            },
        );
        Ok((state_id, arcgis_pkce_challenge))
    }

    pub async fn consume_pending_oauth_session(
        &self,
        state_id: &str,
    ) -> Option<PendingOAuthSession> {
        let session = self.pending_oauth_sessions.write().await.remove(state_id)?;
        if is_expired(session.created_at, PENDING_OAUTH_SESSION_TTL_SECS) {
            return None;
        }
        Some(session)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn store_pending_auth_code(
        &self,
        arcgis_token: ArcGISTokenResponse,
        client_id: String,
        mcp_code_challenge: Option<String>,
        mcp_redirect_uri: String,
        resource: String,
        scopes: Vec<String>,
        portal: PortalContext,
    ) -> Result<String, PendingStoreError> {
        let code = format!("mcp-code-{}", Uuid::new_v4());
        let created_at = chrono::Utc::now().timestamp();
        let mut codes = self.pending_auth_codes.write().await;
        if codes.len() >= MAX_PENDING_AUTH_CODES {
            return Err(PendingStoreError::CapacityExceeded);
        }
        codes.insert(
            code.clone(),
            PendingAuthCode {
                arcgis_token,
                client_id,
                mcp_code_challenge,
                mcp_redirect_uri,
                resource,
                scopes,
                portal,
                created_at,
            },
        );
        Ok(code)
    }

    pub async fn consume_pending_auth_code(&self, code: &str) -> Option<PendingAuthCode> {
        let pending = self.pending_auth_codes.write().await.remove(code)?;
        if is_expired(pending.created_at, PENDING_AUTH_CODE_TTL_SECS) {
            return None;
        }
        Some(pending)
    }

    pub async fn sweep_expired(&self) {
        let before_consents = {
            let mut consents = self.pending_consents.write().await;
            let before = consents.len();
            consents.retain(|_, consent| !is_expired(consent.created_at, PENDING_CONSENT_TTL_SECS));
            before - consents.len()
        };
        let before_sessions = {
            let mut sessions = self.pending_oauth_sessions.write().await;
            let before = sessions.len();
            sessions.retain(|_, s| !is_expired(s.created_at, PENDING_OAUTH_SESSION_TTL_SECS));
            before - sessions.len()
        };
        let before_codes = {
            let mut codes = self.pending_auth_codes.write().await;
            let before = codes.len();
            codes.retain(|_, c| !is_expired(c.created_at, PENDING_AUTH_CODE_TTL_SECS));
            before - codes.len()
        };
        if before_consents > 0 || before_sessions > 0 || before_codes > 0 {
            tracing::debug!(
                expired_consents = before_consents,
                expired_sessions = before_sessions,
                expired_codes = before_codes,
                "swept expired pending OAuth state"
            );
        }

        if let Err(error) =
            sqlx::query("DELETE FROM mcp_access_tokens WHERE expires_at <= unixepoch()")
                .execute(&self.pool)
                .await
        {
            tracing::warn!(%error, "failed to sweep expired MCP access credentials");
        }
        if let Err(error) = sqlx::query(
            "UPDATE mcp_refresh_tokens SET successor_access_token = NULL, successor_refresh_token = NULL \
             WHERE state = 'consumed' AND consumed_at + ? < unixepoch()",
        )
        .bind(self.auth_settings.mcp_refresh_replay_window_seconds)
        .execute(&self.pool)
        .await
        {
            tracing::warn!(%error, "failed to clear expired refresh replay responses");
        }
        if let Err(error) = sqlx::query(
            "DELETE FROM sessions WHERE absolute_expires_at <= unixepoch() OR last_activity_at + ? <= unixepoch()",
        )
        .bind(self.auth_settings.session_inactivity_timeout_seconds)
        .execute(&self.pool)
        .await
        {
            tracing::warn!(%error, "failed to sweep expired MCP sessions");
        }
        if let Ok(rows) = sqlx::query("SELECT session_id FROM sessions")
            .fetch_all(&self.pool)
            .await
        {
            let session_ids: HashSet<String> =
                rows.into_iter().map(|row| row.get("session_id")).collect();
            self.refresh_locks.lock().await.retain(|session_id, lock| {
                session_ids.contains(session_id) && Arc::strong_count(lock) > 1
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn store_issued_tokens(
        &self,
        mcp_access_token: String,
        mcp_refresh_token: String,
        arcgis_token: ArcGISTokenResponse,
        client_id: String,
        portal: PortalContext,
        resource: String,
        scopes: Vec<String>,
    ) -> Result<u64, String> {
        let now = chrono::Utc::now().timestamp();
        let arcgis_access_lifetime = i64::try_from(arcgis_token.expires_in)
            .map_err(|_| "ArcGIS access credential lifetime is too large")?;
        let arcgis_refresh_lifetime = i64::try_from(arcgis_token.refresh_token_expires_in)
            .map_err(|_| "ArcGIS refresh credential lifetime is too large")?;
        if arcgis_access_lifetime
            <= self
                .auth_settings
                .arcgis_access_refresh_buffer_seconds
                .max(ARCGIS_TOKEN_SAFETY_MARGIN_SECONDS)
        {
            return Err("ArcGIS access refresh buffer consumes the credential lifetime".into());
        }
        if arcgis_refresh_lifetime <= self.auth_settings.arcgis_refresh_renewal_buffer_seconds {
            return Err("ArcGIS refresh renewal buffer consumes the credential lifetime".into());
        }
        let session_id = Uuid::new_v4().to_string();
        let arcgis_access_expires_at = now
            .checked_add(arcgis_access_lifetime)
            .ok_or("ArcGIS access credential expiration is too large")?;
        let arcgis_refresh_expires_at = now
            .checked_add(arcgis_refresh_lifetime)
            .ok_or("ArcGIS refresh credential expiration is too large")?;
        let absolute_expires_at = now
            .checked_add(self.auth_settings.session_max_age_seconds)
            .ok_or("MCP session maximum age is too large")?;
        let configured_access_expires_at = now
            .checked_add(self.auth_settings.mcp_access_token_lifetime_seconds)
            .ok_or("MCP access credential lifetime is too large")?;
        let inactivity_expires_at = now
            .checked_add(self.auth_settings.session_inactivity_timeout_seconds)
            .ok_or("MCP session inactivity timeout is too large")?;
        let mcp_access_expires_at = configured_access_expires_at
            .min(absolute_expires_at)
            .min(inactivity_expires_at);
        let mcp_access_expires_in = u64::try_from(mcp_access_expires_at.saturating_sub(now))
            .map_err(|_| "invalid MCP access credential lifetime")?;

        let mut tx = self.pool.begin().await.map_err(|e| e.to_string())?;

        sqlx::query(
            "INSERT INTO sessions \
             (session_id, client_id, resource_uri, scope, portal_key, portal_url, portal_api_root, portal_apps, portal_stories_root, arcgis_access_token, arcgis_access_expires_at, arcgis_refresh_token, arcgis_refresh_expires_at, arcgis_username, arcgis_ssl, created_at, last_activity_at, absolute_expires_at, status) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')",
        )
        .bind(&session_id)
        .bind(&client_id)
        .bind(&resource)
        .bind(crate::oauth::store::scope_string(&scopes))
        .bind(&portal.key)
        .bind(&portal.portal_url)
        .bind(&portal.api_root)
        .bind(&portal.portal_apps)
        .bind(&portal.stories_root)
        .bind(&arcgis_token.access_token)
        .bind(arcgis_access_expires_at)
        .bind(&arcgis_token.refresh_token)
        .bind(arcgis_refresh_expires_at)
        .bind(&arcgis_token.username)
        .bind(arcgis_token.ssl)
        .bind(now)
        .bind(now)
        .bind(absolute_expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        sqlx::query(
            "INSERT INTO mcp_access_tokens (mcp_access_token, session_id, expires_at) VALUES (?, ?, ?)",
        )
        .bind(&mcp_access_token)
        .bind(&session_id)
        .bind(mcp_access_expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        sqlx::query(
            "INSERT INTO mcp_refresh_tokens (mcp_refresh_token, session_id, state) VALUES (?, ?, 'active')",
        )
        .bind(&mcp_refresh_token)
        .bind(&session_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(mcp_access_expires_in)
    }

    pub async fn resolve_session(
        &self,
        mcp_access_token: &str,
        resource: &str,
    ) -> SessionResolution {
        self.resolve_session_inner(mcp_access_token, resource, false, true)
            .await
    }

    pub async fn force_refresh_session(
        &self,
        mcp_access_token: &str,
        resource: &str,
    ) -> SessionResolution {
        self.resolve_session_inner(mcp_access_token, resource, true, false)
            .await
    }

    async fn resolve_session_inner(
        &self,
        mcp_access_token: &str,
        resource: &str,
        force_refresh: bool,
        update_activity: bool,
    ) -> SessionResolution {
        let session = match self.load_session(mcp_access_token, resource).await {
            Ok(Some(session)) => session,
            Ok(None) => return SessionResolution::Inactive,
            Err(error) => {
                tracing::error!(%error, "failed to load MCP session");
                return SessionResolution::TemporarilyUnavailable;
            }
        };
        let now = chrono::Utc::now().timestamp();
        let observed_generation = session.arcgis_credential_generation;
        if !force_refresh
            && session.arcgis_access_expires_at - now
                > self
                    .auth_settings
                    .arcgis_access_refresh_buffer_seconds
                    .max(ARCGIS_TOKEN_SAFETY_MARGIN_SECONDS)
        {
            return self.activate_session(session, now, update_activity).await;
        }

        let lock = self.refresh_lock(&session.session_id).await;
        let _guard = lock.lock().await;
        let session = match self.load_session(mcp_access_token, resource).await {
            Ok(Some(session)) => session,
            Ok(None) => return SessionResolution::Inactive,
            Err(error) => {
                tracing::error!(%error, "failed to reload MCP session");
                return SessionResolution::TemporarilyUnavailable;
            }
        };
        let now = chrono::Utc::now().timestamp();
        if (!force_refresh || session.arcgis_credential_generation != observed_generation)
            && session.arcgis_access_expires_at - now
                > self
                    .auth_settings
                    .arcgis_access_refresh_buffer_seconds
                    .max(ARCGIS_TOKEN_SAFETY_MARGIN_SECONDS)
        {
            return self.activate_session(session, now, update_activity).await;
        }
        if force_refresh {
            let allowed = sqlx::query(
                "UPDATE sessions SET last_forced_refresh_at = ? WHERE session_id = ? \
                 AND (last_forced_refresh_at IS NULL OR last_forced_refresh_at + ? <= ?)",
            )
            .bind(now)
            .bind(&session.session_id)
            .bind(FORCED_REFRESH_RATE_LIMIT_SECONDS)
            .bind(now)
            .execute(&self.pool)
            .await;
            match allowed {
                Ok(result) if result.rows_affected() == 1 => {}
                Ok(_) => return SessionResolution::RateLimited,
                Err(error) => {
                    tracing::error!(%error, "failed to rate-limit forced refresh");
                    return SessionResolution::TemporarilyUnavailable;
                }
            }
        }

        let Some(portal) = self.portal_registry.get(&session.portal.key) else {
            tracing::error!(portal = %session.portal.key, "session portal is no longer configured");
            return SessionResolution::TemporarilyUnavailable;
        };
        let token_url = format!(
            "{}/sharing/rest/oauth2/token",
            session.portal.portal_url.trim_end_matches('/')
        );
        let renew_refresh = session.arcgis_refresh_expires_at - now
            <= self.auth_settings.arcgis_refresh_renewal_buffer_seconds;

        let refreshed = if renew_refresh {
            let redirect_uri = format!("{}/arcgis/callback", self.base_url);
            exchange_oauth_refresh_token_credential(
                &token_url,
                &portal.client_id,
                &redirect_uri,
                &session.arcgis_refresh_token,
            )
            .instrument(tracing::info_span!(
                "arcgis.refresh_credential_exchange",
                "http.request.method" = "POST",
                "url.full" = %token_url,
            ))
            .await
            .map(|response| {
                (
                    response.access_token,
                    response.expires_in,
                    response.refresh_token,
                    response.refresh_token_expires_in,
                    response.username.or(session.arcgis_username.clone()),
                    response.ssl.or(session.arcgis_ssl),
                )
            })
        } else {
            exchange_oauth_refresh_token(
                &token_url,
                &portal.client_id,
                &session.arcgis_refresh_token,
            )
            .instrument(tracing::info_span!(
                "arcgis.access_credential_refresh",
                "http.request.method" = "POST",
                "url.full" = %token_url,
            ))
            .await
            .map(|response| {
                (
                    response.access_token,
                    response.expires_in,
                    session.arcgis_refresh_token.clone(),
                    u64::try_from(session.arcgis_refresh_expires_at.saturating_sub(now))
                        .unwrap_or(0),
                    response.username.or(session.arcgis_username.clone()),
                    response.ssl.or(session.arcgis_ssl),
                )
            })
        };

        let (access_token, access_lifetime, refresh_token, refresh_lifetime, username, ssl) =
            match refreshed {
                Ok(credentials) => credentials,
                Err(error) if Self::is_invalid_refresh_credential(&error) => {
                    if let Err(revoke_error) =
                        sqlx::query("UPDATE sessions SET status = 'revoked' WHERE session_id = ?")
                            .bind(&session.session_id)
                            .execute(&self.pool)
                            .await
                    {
                        tracing::error!(%revoke_error, "failed to revoke rejected MCP session");
                    }
                    return SessionResolution::Inactive;
                }
                Err(error) => {
                    tracing::warn!(%error, session_id = %session.session_id, "ArcGIS credential refresh failed temporarily");
                    if session.arcgis_access_expires_at - now >= ARCGIS_TOKEN_SAFETY_MARGIN_SECONDS
                    {
                        return self.activate_session(session, now, update_activity).await;
                    }
                    return SessionResolution::TemporarilyUnavailable;
                }
            };

        let Ok(access_lifetime) = i64::try_from(access_lifetime) else {
            return SessionResolution::TemporarilyUnavailable;
        };
        let Ok(refresh_lifetime) = i64::try_from(refresh_lifetime) else {
            return SessionResolution::TemporarilyUnavailable;
        };
        if access_lifetime
            <= self
                .auth_settings
                .arcgis_access_refresh_buffer_seconds
                .max(ARCGIS_TOKEN_SAFETY_MARGIN_SECONDS)
            || refresh_lifetime <= self.auth_settings.arcgis_refresh_renewal_buffer_seconds
        {
            tracing::warn!(session_id = %session.session_id, "ArcGIS returned credentials shorter than configured buffers");
            if session.arcgis_access_expires_at - now >= ARCGIS_TOKEN_SAFETY_MARGIN_SECONDS {
                return self.activate_session(session, now, update_activity).await;
            }
            return SessionResolution::TemporarilyUnavailable;
        }
        let Some(access_expires_at) = now.checked_add(access_lifetime) else {
            return SessionResolution::TemporarilyUnavailable;
        };
        let refresh_expires_at = if renew_refresh {
            let Some(expires_at) = now.checked_add(refresh_lifetime) else {
                return SessionResolution::TemporarilyUnavailable;
            };
            expires_at
        } else {
            session.arcgis_refresh_expires_at
        };
        let updated = sqlx::query(
            "UPDATE sessions SET arcgis_access_token = ?, arcgis_access_expires_at = ?, \
                    arcgis_refresh_token = ?, arcgis_refresh_expires_at = ?, arcgis_username = ?, \
                    arcgis_ssl = ?, arcgis_credential_generation = arcgis_credential_generation + 1, \
                    last_activity_at = CASE WHEN ? THEN ? ELSE last_activity_at END \
             WHERE session_id = ? AND status = 'active' AND absolute_expires_at > ? \
               AND last_activity_at + ? > ?",
        )
        .bind(&access_token)
        .bind(access_expires_at)
        .bind(&refresh_token)
        .bind(refresh_expires_at)
        .bind(&username)
        .bind(ssl)
        .bind(update_activity)
        .bind(now)
        .bind(&session.session_id)
        .bind(now)
        .bind(self.auth_settings.session_inactivity_timeout_seconds)
        .bind(now)
        .execute(&self.pool)
        .await;
        match updated {
            Ok(result) if result.rows_affected() == 1 => {
                SessionResolution::Active(Box::new(McpTokenRecord {
                    arcgis_token: ArcGISAccessTokenResponse {
                        access_token,
                        expires_in: u64::try_from(access_lifetime).unwrap_or(0),
                        username,
                        ssl,
                    },
                    portal: session.portal,
                    expires_at: access_expires_at,
                    resource: session.resource,
                    scopes: session.scopes,
                }))
            }
            Ok(_) => SessionResolution::Inactive,
            Err(error) => {
                tracing::error!(%error, "failed to persist refreshed ArcGIS credentials");
                SessionResolution::TemporarilyUnavailable
            }
        }
    }

    async fn load_session(
        &self,
        mcp_access_token: &str,
        resource: &str,
    ) -> Result<Option<StoredSession>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT s.session_id, s.scope, s.portal_key, s.portal_url, s.portal_api_root, s.portal_apps, s.portal_stories_root, \
                    s.arcgis_access_token, s.arcgis_access_expires_at, s.arcgis_refresh_token, s.arcgis_refresh_expires_at, \
                    s.arcgis_username, s.arcgis_ssl, s.arcgis_credential_generation, s.resource_uri \
             FROM mcp_access_tokens a JOIN sessions s ON s.session_id = a.session_id \
             WHERE a.mcp_access_token = ? AND s.resource_uri = ? AND s.status = 'active' \
               AND a.expires_at > unixepoch() \
               AND s.absolute_expires_at > unixepoch() \
               AND s.last_activity_at + ? > unixepoch()",
        )
        .bind(mcp_access_token)
        .bind(resource)
        .bind(self.auth_settings.session_inactivity_timeout_seconds)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let scope: String = row.get("scope");
        let Ok(scopes) = crate::oauth::store::normalize_scope(&scope) else {
            return Ok(None);
        };
        Ok(Some(StoredSession {
            session_id: row.get("session_id"),
            resource: row.get("resource_uri"),
            scopes,
            portal: PortalContext {
                key: row.get("portal_key"),
                portal_url: row.get("portal_url"),
                api_root: row.get("portal_api_root"),
                portal_apps: row.get("portal_apps"),
                stories_root: row.get("portal_stories_root"),
            },
            arcgis_access_token: row.get("arcgis_access_token"),
            arcgis_access_expires_at: row.get("arcgis_access_expires_at"),
            arcgis_refresh_token: row.get("arcgis_refresh_token"),
            arcgis_refresh_expires_at: row.get("arcgis_refresh_expires_at"),
            arcgis_username: row.get("arcgis_username"),
            arcgis_ssl: row.get("arcgis_ssl"),
            arcgis_credential_generation: row.get("arcgis_credential_generation"),
        }))
    }

    async fn activate_session(
        &self,
        session: StoredSession,
        now: i64,
        update_activity: bool,
    ) -> SessionResolution {
        let updated = sqlx::query(
            "UPDATE sessions SET last_activity_at = CASE WHEN ? THEN ? ELSE last_activity_at END \
             WHERE session_id = ? AND status = 'active' \
             AND absolute_expires_at > ? AND last_activity_at + ? > ?",
        )
        .bind(update_activity)
        .bind(now)
        .bind(&session.session_id)
        .bind(now)
        .bind(self.auth_settings.session_inactivity_timeout_seconds)
        .bind(now)
        .execute(&self.pool)
        .await;
        match updated {
            Ok(result) if result.rows_affected() == 1 => {
                SessionResolution::Active(Box::new(McpTokenRecord {
                    arcgis_token: ArcGISAccessTokenResponse {
                        access_token: session.arcgis_access_token,
                        expires_in: u64::try_from(
                            session.arcgis_access_expires_at.saturating_sub(now),
                        )
                        .unwrap_or(0),
                        username: session.arcgis_username,
                        ssl: session.arcgis_ssl,
                    },
                    expires_at: session.arcgis_access_expires_at,
                    resource: session.resource,
                    scopes: session.scopes,
                    portal: session.portal,
                }))
            }
            Ok(_) => SessionResolution::Inactive,
            Err(error) => {
                tracing::error!(%error, "failed to update MCP session activity");
                SessionResolution::TemporarilyUnavailable
            }
        }
    }

    fn is_invalid_refresh_credential(error: &ArcGISClientError) -> bool {
        matches!(
            error,
            ArcGISClientError::OAuth { source, .. }
                if matches!(source.as_ref(), OAuthError::InvalidRefreshCredential { .. })
        )
    }

    pub async fn refresh_access_token(
        &self,
        mcp_refresh_token: &str,
        client_id: &str,
        resource: &str,
        requested_scopes: Option<&[String]>,
    ) -> Result<(String, String, u64, Vec<String>), String> {
        let refresh_row =
            sqlx::query("SELECT session_id FROM mcp_refresh_tokens WHERE mcp_refresh_token = ?")
                .bind(mcp_refresh_token)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| e.to_string())?;

        let refresh_row = refresh_row.ok_or("Invalid refresh token")?;
        let session_id: String = refresh_row.get("session_id");
        let lock = self.refresh_lock(&session_id).await;
        let _guard = lock.lock().await;

        let row = sqlx::query(
            "SELECT r.state, r.consumed_at, r.successor_access_token, r.successor_refresh_token, \
                    s.client_id, s.resource_uri, s.scope, s.status, s.last_activity_at, s.absolute_expires_at \
             FROM mcp_refresh_tokens r JOIN sessions s ON s.session_id = r.session_id \
             WHERE r.mcp_refresh_token = ?",
        )
        .bind(mcp_refresh_token)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| e.to_string())?;

        let row = row.ok_or("Invalid refresh token")?;
        if row.get::<String, _>("client_id") != client_id {
            return Err("client does not match refresh token".into());
        }
        if row.get::<String, _>("resource_uri") != resource {
            return Err("resource does not match refresh token".into());
        }
        let granted_scopes = crate::oauth::store::normalize_scope(&row.get::<String, _>("scope"))
            .map_err(|_| "Invalid scope stored for refresh token")?;
        let scopes = match requested_scopes {
            Some(requested) if requested.iter().all(|scope| granted_scopes.contains(scope)) => {
                requested.to_vec()
            }
            Some(_) => return Err("requested scope exceeds original grant".into()),
            None => granted_scopes,
        };
        let now = chrono::Utc::now().timestamp();
        let absolute_expires_at: i64 = row.get("absolute_expires_at");
        let inactivity_expires_at = row
            .get::<i64, _>("last_activity_at")
            .checked_add(self.auth_settings.session_inactivity_timeout_seconds)
            .ok_or("MCP session inactivity deadline is too large")?;
        if row.get::<String, _>("status") != "active"
            || absolute_expires_at <= now
            || inactivity_expires_at <= now
        {
            return Err("MCP session is inactive or expired".into());
        }

        if row.get::<String, _>("state") == "consumed" {
            let consumed_at: Option<i64> = row.get("consumed_at");
            if consumed_at.is_some_and(|consumed_at| {
                now - consumed_at <= self.auth_settings.mcp_refresh_replay_window_seconds
            }) {
                let access: Option<String> = row.get("successor_access_token");
                let refresh: Option<String> = row.get("successor_refresh_token");
                if let (Some(access), Some(refresh)) = (access, refresh) {
                    let expires_at: i64 = sqlx::query_scalar(
                        "SELECT expires_at FROM mcp_access_tokens WHERE mcp_access_token = ?",
                    )
                    .bind(&access)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(|e| e.to_string())?;
                    return Ok((
                        access,
                        refresh,
                        u64::try_from(expires_at.saturating_sub(now)).unwrap_or(0),
                        scopes,
                    ));
                }
            }
            sqlx::query("UPDATE sessions SET status = 'revoked' WHERE session_id = ?")
                .bind(&session_id)
                .execute(&self.pool)
                .await
                .map_err(|e| e.to_string())?;
            return Err("refresh token replay detected; MCP session revoked".into());
        }

        let new_access = format!("mcp-token-{}", Uuid::new_v4());
        let new_refresh = format!("mcp-refresh-{}", Uuid::new_v4());
        let credential_expires_at = now
            .checked_add(self.auth_settings.mcp_access_token_lifetime_seconds)
            .ok_or("MCP access credential lifetime is too large")?;
        let expires_at = credential_expires_at
            .min(absolute_expires_at)
            .min(inactivity_expires_at);
        let expires_in = u64::try_from(expires_at.saturating_sub(now))
            .map_err(|_| "invalid MCP access credential lifetime")?;

        let mut tx = self.pool.begin().await.map_err(|e| e.to_string())?;

        let consumed = sqlx::query(
            "UPDATE mcp_refresh_tokens SET state = 'consumed', consumed_at = ?, successor_access_token = ?, successor_refresh_token = ? \
             WHERE mcp_refresh_token = ? AND state = 'active' \
               AND EXISTS (SELECT 1 FROM sessions s WHERE s.session_id = mcp_refresh_tokens.session_id \
                           AND s.status = 'active' AND s.absolute_expires_at > unixepoch() \
                           AND s.last_activity_at + ? > unixepoch())",
        )
            .bind(now)
            .bind(&new_access)
            .bind(&new_refresh)
            .bind(mcp_refresh_token)
            .bind(self.auth_settings.session_inactivity_timeout_seconds)
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
        if consumed.rows_affected() != 1 {
            return Err("MCP session expired during refresh".into());
        }

        sqlx::query(
            "INSERT INTO mcp_access_tokens (mcp_access_token, session_id, expires_at) VALUES (?, ?, ?)",
        )
        .bind(&new_access)
        .bind(&session_id)
        .bind(expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        sqlx::query(
            "INSERT INTO mcp_refresh_tokens (mcp_refresh_token, session_id, state) VALUES (?, ?, 'active')",
        )
        .bind(&new_refresh)
        .bind(&session_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        if scopes
            != crate::oauth::store::normalize_scope(&row.get::<String, _>("scope"))
                .map_err(|_| "Invalid scope stored for refresh token")?
        {
            sqlx::query("UPDATE sessions SET scope = ? WHERE session_id = ?")
                .bind(crate::oauth::store::scope_string(&scopes))
                .bind(&session_id)
                .execute(&mut *tx)
                .await
                .map_err(|e| e.to_string())?;
        }

        tx.commit().await.map_err(|e| e.to_string())?;

        Ok((new_access, new_refresh, expires_in, scopes))
    }

    async fn refresh_lock(&self, session_id: &str) -> Arc<Mutex<()>> {
        let mut locks = self.refresh_locks.lock().await;
        locks
            .entry(session_id.to_owned())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

pub async fn arcgis_callback(
    Query(params): Query<CallbackQuery>,
    State(store): State<Arc<ArcGISAuthStore>>,
) -> impl IntoResponse {
    tracing::debug!(
        "arcgis_callback: code present={}, error present={}",
        params.code.as_ref().is_some_and(|code| !code.is_empty()),
        params.error.is_some()
    );

    let state_id = match params.state {
        Some(s) if !s.is_empty() => s,
        _ => {
            tracing::warn!("arcgis_callback: missing state param");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "missing state parameter" })),
            )
                .into_response();
        }
    };

    let session = match store.consume_pending_oauth_session(&state_id).await {
        Some(s) => s,
        None => {
            tracing::warn!("arcgis_callback: unknown state={}", state_id);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "unknown or expired state" })),
            )
                .into_response();
        }
    };

    if let Some(error) = params.error.as_deref() {
        let mut response_params = vec![("error", error)];
        if let Some(description) = params.error_description.as_deref() {
            response_params.push(("error_description", description));
        }
        return authorization_response_redirect(
            &session.mcp_redirect_uri,
            &store.base_url,
            &response_params,
            session.mcp_client_state.as_deref(),
        );
    }

    let code = match params.code.as_deref() {
        Some(code) if !code.is_empty() => code,
        _ => {
            tracing::warn!("arcgis_callback: missing code and error params");
            return authorization_error_redirect(&session, &store.base_url, "server_error");
        }
    };

    let verifier_str = match std::str::from_utf8(&session.arcgis_pkce_verifier) {
        Ok(s) => s.to_string(),
        Err(_) => {
            tracing::warn!("arcgis_callback: pkce verifier is not valid UTF-8");
            return authorization_error_redirect(&session, &store.base_url, "server_error");
        }
    };

    let server_callback = format!("{}/arcgis/callback", store.base_url);
    let token_url = format!(
        "{}/sharing/rest/oauth2/token",
        session.portal.portal_url.trim_end_matches('/')
    );

    let arcgis_token: ArcGISTokenResponse = match exchange_oauth_authorization_code(
        &token_url,
        &session.portal.client_id,
        code,
        &server_callback,
        &verifier_str,
    )
    .instrument(tracing::info_span!(
        "arcgis.token_exchange",
        "http.request.method" = "POST",
        "url.full" = %token_url,
    ))
    .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("arcgis_callback: token exchange failed: {}", e);
            return authorization_error_redirect(&session, &store.base_url, "server_error");
        }
    };

    let username = arcgis_token.username.clone().unwrap_or_default();
    let portal_context = PortalContext::from(&session.portal);
    let mcp_auth_code = match store
        .store_pending_auth_code(
            arcgis_token,
            session.client_id.clone(),
            session.mcp_code_challenge.clone(),
            session.mcp_redirect_uri.clone(),
            session.resource.clone(),
            session.scopes.clone(),
            portal_context,
        )
        .await
    {
        Ok(code) => code,
        Err(PendingStoreError::CapacityExceeded) => {
            tracing::warn!("arcgis_callback: pending auth code capacity exceeded");
            return authorization_error_redirect(&session, &store.base_url, "server_error");
        }
    };

    tracing::info!(
        "arcgis_callback: stored pending auth code for user={} portal={}",
        username,
        session.portal.key
    );

    authorization_response_redirect(
        &session.mcp_redirect_uri,
        &store.base_url,
        &[("code", &mcp_auth_code)],
        session.mcp_client_state.as_deref(),
    )
}

fn authorization_error_redirect(
    session: &PendingOAuthSession,
    issuer: &str,
    error: &str,
) -> axum::response::Response {
    authorization_response_redirect(
        &session.mcp_redirect_uri,
        issuer,
        &[("error", error)],
        session.mcp_client_state.as_deref(),
    )
}

pub fn authorization_response_redirect(
    redirect_uri: &str,
    issuer: &str,
    response_params: &[(&str, &str)],
    state: Option<&str>,
) -> axum::response::Response {
    match authorization_response_url(redirect_uri, issuer, response_params, state) {
        Ok(url) => Redirect::to(url.as_str()).into_response(),
        Err(error) => {
            tracing::error!("validated OAuth redirect URI is not a valid URL: {error}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn authorization_response_url(
    redirect_uri: &str,
    issuer: &str,
    response_params: &[(&str, &str)],
    state: Option<&str>,
) -> Result<url::Url, url::ParseError> {
    const RESPONSE_PARAMETER_NAMES: &[&str] = &[
        "code",
        "error",
        "error_description",
        "error_uri",
        "state",
        "iss",
    ];

    let mut url = url::Url::parse(redirect_uri)?;
    let existing_pairs: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(name, _)| !RESPONSE_PARAMETER_NAMES.contains(&name.as_ref()))
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();

    {
        let mut pairs = url.query_pairs_mut();
        pairs.clear().extend_pairs(existing_pairs);
        pairs.extend_pairs(response_params.iter().copied());
        if let Some(state) = state {
            pairs.append_pair("state", state);
        }
        pairs.append_pair("iss", issuer);
    }

    Ok(url)
}

fn generate_pkce_verifier() -> Vec<u8> {
    let mut bytes = [0u8; 96];
    getrandom::fill(&mut bytes).expect("failed to read random bytes for PKCE verifier");
    URL_SAFE_NO_PAD.encode(bytes).into_bytes()
}

fn pkce_code_challenge(verifier: &[u8]) -> String {
    let verifier = std::str::from_utf8(verifier).expect("PKCE verifier must be UTF-8");
    pkce_challenge_from_verifier(verifier)
}

pub fn percent_encode_component(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

pub fn pkce_challenge_from_verifier(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use axum::{
        Json, Router,
        extract::{Query, State},
        http::{StatusCode, header::LOCATION},
        response::IntoResponse,
        routing::post,
    };
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use tokio::net::TcpListener;

    use crate::config::{ArcgisPortalConfig, AuthSettings, PortalRegistry};

    use super::{
        ArcGISAuthStore, ArcGISTokenResponse, CallbackQuery, PortalContext, arcgis_callback,
        authorization_response_url, is_expired, pkce_challenge_from_verifier,
    };

    async fn test_pool() -> sqlx::SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(":memory:")
                    .create_if_missing(true),
            )
            .await
            .expect("connect in-memory sqlite");
        sqlx::migrate!().run(&pool).await.expect("run migrations");
        pool
    }

    fn test_portal(portal_url: &str) -> ArcgisPortalConfig {
        ArcgisPortalConfig {
            key: "test-portal".into(),
            label: "Test Portal".into(),
            portal_url: portal_url.into(),
            api_root: format!("{portal_url}/sharing/rest"),
            portal_apps: format!("{portal_url}/apps"),
            client_id: "test-arcgis-client".into(),
            stories_root: "https://storymaps.example.com/stories".into(),
        }
    }

    async fn test_store(portal_url: &str, issuer: &str) -> Arc<ArcGISAuthStore> {
        let registry =
            PortalRegistry::from_portals(vec![test_portal(portal_url)]).expect("portal registry");
        Arc::new(ArcGISAuthStore::new(
            test_pool().await,
            issuer.into(),
            registry,
        ))
    }

    async fn mock_arcgis_token_server() -> String {
        async fn token_handler() -> impl IntoResponse {
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "access_token": "arcgis-access-token",
                    "expires_in": 3600,
                    "refresh_token": "arcgis-refresh-token",
                    "refresh_token_expires_in": 1209600,
                    "username": "testuser",
                    "ssl": true,
                })),
            )
        }

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock ArcGIS server");
        let address = listener.local_addr().expect("mock server address");
        let app = Router::new().route("/sharing/rest/oauth2/token", post(token_handler));
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve mock ArcGIS server");
        });
        format!("http://{address}")
    }

    fn sample_arcgis_credentials() -> ArcGISTokenResponse {
        ArcGISTokenResponse {
            access_token: "arcgis-access-token".into(),
            expires_in: 3600,
            refresh_token: "arcgis-refresh-token".into(),
            refresh_token_expires_in: 1_209_600,
            username: Some("testuser".into()),
            ssl: Some(true),
        }
    }

    async fn store_credential_family(store: &ArcGISAuthStore) {
        store_credential_family_for_portal(store, "https://portal.example.com").await;
    }

    async fn store_credential_family_for_portal(store: &ArcGISAuthStore, portal_url: &str) {
        store
            .store_issued_tokens(
                "mcp-access".into(),
                "mcp-refresh".into(),
                sample_arcgis_credentials(),
                "client-id".into(),
                PortalContext::from(&test_portal(portal_url)),
                "https://mcp.example.com/mcp".into(),
                vec!["profile".into()],
            )
            .await
            .expect("store credential family");
    }

    #[derive(Clone)]
    struct TokenServerState {
        status: StatusCode,
        body: serde_json::Value,
        requests: Arc<AtomicUsize>,
        delay_millis: u64,
    }

    async fn mock_token_response_server(
        status: StatusCode,
        body: serde_json::Value,
    ) -> (String, Arc<AtomicUsize>) {
        async fn token_handler(State(state): State<TokenServerState>) -> impl IntoResponse {
            state.requests.fetch_add(1, Ordering::SeqCst);
            if state.delay_millis > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(state.delay_millis)).await;
            }
            (state.status, Json(state.body))
        }

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock token server");
        let address = listener.local_addr().expect("mock token server address");
        let requests = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/sharing/rest/oauth2/token", post(token_handler))
            .with_state(TokenServerState {
                status,
                body,
                requests: requests.clone(),
                delay_millis: 0,
            });
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve mock token server");
        });
        (format!("http://{address}"), requests)
    }

    async fn mock_delayed_token_response_server(
        status: StatusCode,
        body: serde_json::Value,
    ) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind delayed token server");
        let address = listener.local_addr().expect("delayed token server address");
        let requests = Arc::new(AtomicUsize::new(0));
        async fn token_handler(State(state): State<TokenServerState>) -> impl IntoResponse {
            state.requests.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(state.delay_millis)).await;
            (state.status, Json(state.body))
        }
        let app = Router::new()
            .route("/sharing/rest/oauth2/token", post(token_handler))
            .with_state(TokenServerState {
                status,
                body,
                requests: requests.clone(),
                delay_millis: 100,
            });
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve delayed token server");
        });
        (format!("http://{address}"), requests)
    }

    #[test]
    fn pkce_challenge_from_verifier_rfc7636_appendix_b() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            pkce_challenge_from_verifier(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn is_expired_false_within_ttl() {
        let created_at = chrono::Utc::now().timestamp() - 300;
        assert!(!is_expired(created_at, 600));
    }

    #[test]
    fn is_expired_true_past_ttl() {
        let created_at = chrono::Utc::now().timestamp() - 601;
        assert!(is_expired(created_at, 600));
    }

    #[test]
    fn authorization_response_url_preserves_query_and_encodes_response() {
        let issuer = "https://auth.example.com/tenant name";
        let url = authorization_response_url(
            "https://client.example.com/callback?tenant=a%2Fb&iss=old&state=old#complete",
            issuer,
            &[("code", "code +&=")],
            Some("state +&="),
        )
        .expect("build authorization response URL");
        let pairs: Vec<_> = url.query_pairs().collect();

        assert_eq!(url.fragment(), Some("complete"));
        assert!(pairs.contains(&("tenant".into(), "a/b".into())));
        assert!(pairs.contains(&("code".into(), "code +&=".into())));
        assert!(pairs.contains(&("state".into(), "state +&=".into())));
        assert!(pairs.contains(&("iss".into(), issuer.into())));
        assert_eq!(pairs.iter().filter(|(name, _)| name == "iss").count(), 1);
        assert_eq!(pairs.iter().filter(|(name, _)| name == "state").count(), 1);
    }

    #[tokio::test]
    async fn callback_success_includes_state_and_issuer() {
        let issuer = "https://auth.example.com";
        let portal_url = mock_arcgis_token_server().await;
        let store = test_store(&portal_url, issuer).await;
        let redirect_uri = "https://client.example.com/callback?tenant=one";
        let (state_id, _) = store
            .create_pending_oauth_session(
                "client-id".into(),
                Some("state +&=".into()),
                redirect_uri.into(),
                Some("mcp-pkce-challenge".into()),
                "https://mcp.example.com/mcp".into(),
                vec!["profile".into()],
                test_portal(&portal_url),
            )
            .await
            .expect("create pending OAuth session");

        let response = arcgis_callback(
            Query(CallbackQuery {
                code: Some("arcgis-code".into()),
                state: Some(state_id),
                error: None,
                error_description: None,
            }),
            State(store),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers()[LOCATION]
            .to_str()
            .expect("location header");
        let url = url::Url::parse(location).expect("parse redirect URL");
        let pairs: Vec<_> = url.query_pairs().collect();
        assert!(pairs.contains(&("tenant".into(), "one".into())));
        assert!(
            pairs
                .iter()
                .any(|(name, value)| { name == "code" && value.starts_with("mcp-code-") })
        );
        assert!(pairs.contains(&("state".into(), "state +&=".into())));
        assert!(pairs.contains(&("iss".into(), issuer.into())));
    }

    #[tokio::test]
    async fn callback_error_redirects_only_after_valid_state() {
        let issuer = "https://auth.example.com";
        let portal_url = "https://portal.example.com";
        let store = test_store(portal_url, issuer).await;
        let (state_id, _) = store
            .create_pending_oauth_session(
                "client-id".into(),
                Some("client-state".into()),
                "https://client.example.com/callback".into(),
                None,
                "https://mcp.example.com/mcp".into(),
                vec!["profile".into()],
                test_portal(portal_url),
            )
            .await
            .expect("create pending OAuth session");

        let response = arcgis_callback(
            Query(CallbackQuery {
                code: None,
                state: Some(state_id),
                error: Some("access_denied".into()),
                error_description: Some("User denied access".into()),
            }),
            State(store.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers()[LOCATION]
            .to_str()
            .expect("location header");
        let pairs: Vec<_> = url::Url::parse(location)
            .expect("parse redirect URL")
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        assert!(pairs.contains(&("error".into(), "access_denied".into())));
        assert!(pairs.contains(&("state".into(), "client-state".into())));
        assert!(pairs.contains(&("iss".into(), issuer.into())));

        let response = arcgis_callback(
            Query(CallbackQuery {
                code: None,
                state: Some("unknown-state".into()),
                error: Some("access_denied".into()),
                error_description: None,
            }),
            State(store),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!response.headers().contains_key(LOCATION));
    }

    #[tokio::test]
    async fn expired_access_credential_does_not_invalidate_refresh_credential() {
        let store = test_store("https://portal.example.com", "https://auth.example.com").await;
        store_credential_family(&store).await;
        sqlx::query("UPDATE mcp_access_tokens SET expires_at = unixepoch() - 1")
            .execute(&store.pool)
            .await
            .expect("expire access credential");

        let refreshed = store
            .refresh_access_token(
                "mcp-refresh",
                "client-id",
                "https://mcp.example.com/mcp",
                None,
            )
            .await
            .expect("refresh MCP credentials");

        assert_ne!(refreshed.0, "mcp-access");
        assert_eq!(refreshed.2, 3600);
    }

    #[tokio::test]
    async fn refresh_enforces_client_resource_and_scope_bindings() {
        let store = test_store("https://portal.example.com", "https://auth.example.com").await;
        store_credential_family(&store).await;

        for (client, resource, scopes, expected) in [
            (
                "other-client",
                "https://mcp.example.com/mcp",
                None,
                "client does not match refresh token",
            ),
            (
                "client-id",
                "https://other.example.com/mcp",
                None,
                "resource does not match refresh token",
            ),
            (
                "client-id",
                "https://mcp.example.com/mcp",
                Some(vec!["admin".into()]),
                "requested scope exceeds original grant",
            ),
        ] {
            let error = store
                .refresh_access_token("mcp-refresh", client, resource, scopes.as_deref())
                .await
                .expect_err("binding mismatch");
            assert_eq!(error, expected);
        }
    }

    #[tokio::test]
    async fn concurrent_refresh_replay_returns_one_successor_pair() {
        let store = test_store("https://portal.example.com", "https://auth.example.com").await;
        store_credential_family(&store).await;
        let first_store = store.clone();
        let second_store = store.clone();

        let first = tokio::spawn(async move {
            first_store
                .refresh_access_token(
                    "mcp-refresh",
                    "client-id",
                    "https://mcp.example.com/mcp",
                    None,
                )
                .await
        });
        let second = tokio::spawn(async move {
            second_store
                .refresh_access_token(
                    "mcp-refresh",
                    "client-id",
                    "https://mcp.example.com/mcp",
                    None,
                )
                .await
        });
        let (first, second) = tokio::join!(first, second);
        let first = first.expect("first task").expect("first refresh");
        let second = second.expect("second task").expect("second refresh");

        assert_eq!((&first.0, &first.1), (&second.0, &second.1));
    }

    #[tokio::test]
    async fn replay_after_window_revokes_credential_family() {
        let settings = AuthSettings {
            mcp_refresh_replay_window_seconds: 1,
            ..AuthSettings::default()
        };
        let pool = test_pool().await;
        let registry =
            PortalRegistry::from_portals(vec![test_portal("https://portal.example.com")])
                .expect("portal registry");
        let store = ArcGISAuthStore::with_auth_settings(
            pool,
            "https://auth.example.com".into(),
            registry,
            settings,
        );
        store_credential_family(&store).await;
        store
            .refresh_access_token(
                "mcp-refresh",
                "client-id",
                "https://mcp.example.com/mcp",
                None,
            )
            .await
            .expect("initial refresh");
        sqlx::query(
            "UPDATE mcp_refresh_tokens SET consumed_at = unixepoch() - 2 WHERE mcp_refresh_token = 'mcp-refresh'",
        )
        .execute(&store.pool)
        .await
        .expect("age consumed credential");

        let error = store
            .refresh_access_token(
                "mcp-refresh",
                "client-id",
                "https://mcp.example.com/mcp",
                None,
            )
            .await
            .expect_err("late replay");
        let status: String = sqlx::query_scalar("SELECT status FROM sessions")
            .fetch_one(&store.pool)
            .await
            .expect("session status");

        assert_eq!(error, "refresh token replay detected; MCP session revoked");
        assert_eq!(status, "revoked");
    }

    #[tokio::test]
    async fn stable_session_migration_invalidates_legacy_credentials() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(":memory:")
                    .create_if_missing(true),
            )
            .await
            .expect("connect legacy database");
        for migration in [
            include_str!("../migrations/0001_init.sql"),
            include_str!("../migrations/0002_token_portal_mapping.sql"),
            include_str!("../migrations/0003_token_resource_binding.sql"),
            include_str!("../migrations/0004_invalidate_legacy_tokens.sql"),
            include_str!("../migrations/0005_token_scopes.sql"),
        ] {
            sqlx::raw_sql(migration)
                .execute(&pool)
                .await
                .expect("apply legacy migration");
        }
        sqlx::query(
            "INSERT INTO tokens (mcp_access_token, arcgis_token, expires_at, portal_key, portal_url, portal_api_root, portal_apps, portal_stories_root, resource_uri, scope) \
             VALUES ('old-access', '{}', 9999999999, 'portal', 'url', 'api', 'apps', 'stories', 'https://mcp.example.com/mcp', 'profile')",
        )
        .execute(&pool)
        .await
        .expect("insert legacy access credential");
        sqlx::query(
            "INSERT INTO refresh_tokens (mcp_refresh_token, mcp_access_token, resource_uri, scope) \
             VALUES ('old-refresh', 'old-access', 'https://mcp.example.com/mcp', 'profile')",
        )
        .execute(&pool)
        .await
        .expect("insert legacy refresh credential");

        sqlx::raw_sql(include_str!("../migrations/0006_stable_sessions.sql"))
            .execute(&pool)
            .await
            .expect("apply stable session migration");

        let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
            .fetch_one(&pool)
            .await
            .expect("count sessions");
        assert_eq!(sessions, 0);
        assert!(
            sqlx::query("SELECT * FROM tokens")
                .fetch_all(&pool)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn repeated_arcgis_access_refreshes_preserve_refresh_credential() {
        let (portal_url, requests) = mock_token_response_server(
            StatusCode::OK,
            serde_json::json!({
                "access_token": "refreshed-arcgis-access",
                "expires_in": 3600,
                "username": "testuser",
                "ssl": true,
            }),
        )
        .await;
        let store = test_store(&portal_url, "https://auth.example.com").await;
        store_credential_family_for_portal(&store, &portal_url).await;

        for _ in 0..2 {
            sqlx::query("UPDATE sessions SET arcgis_access_expires_at = unixepoch() + 1")
                .execute(&store.pool)
                .await
                .expect("expire ArcGIS access credential");
            let resolved = store
                .resolve_session("mcp-access", "https://mcp.example.com/mcp")
                .await
                .into_active()
                .expect("resolve refreshed session");
            assert_eq!(
                resolved.arcgis_token.access_token,
                "refreshed-arcgis-access"
            );
        }

        let refresh_token: String = sqlx::query_scalar("SELECT arcgis_refresh_token FROM sessions")
            .fetch_one(&store.pool)
            .await
            .expect("stored ArcGIS refresh credential");
        assert_eq!(refresh_token, "arcgis-refresh-token");
        assert_eq!(requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn transient_arcgis_failure_uses_only_safe_fallback_credentials() {
        let (portal_url, requests) = mock_token_response_server(
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({"error": {"code": 503, "message": "unavailable"}}),
        )
        .await;
        let store = test_store(&portal_url, "https://auth.example.com").await;
        store_credential_family_for_portal(&store, &portal_url).await;

        sqlx::query("UPDATE sessions SET arcgis_access_expires_at = unixepoch() + 60")
            .execute(&store.pool)
            .await
            .expect("set safe fallback lifetime");
        assert!(
            store
                .resolve_session("mcp-access", "https://mcp.example.com/mcp")
                .await
                .into_active()
                .is_some()
        );

        sqlx::query("UPDATE sessions SET arcgis_access_expires_at = unixepoch() + 20")
            .execute(&store.pool)
            .await
            .expect("set unsafe fallback lifetime");
        assert!(matches!(
            store
                .resolve_session("mcp-access", "https://mcp.example.com/mcp")
                .await,
            super::SessionResolution::TemporarilyUnavailable
        ));
        assert_eq!(requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn definitive_arcgis_refresh_rejection_revokes_session() {
        let (portal_url, requests) = mock_token_response_server(
            StatusCode::BAD_REQUEST,
            serde_json::json!({
                "error": {
                    "code": 400,
                    "error": "invalid_grant",
                    "error_description": "Refresh token expired"
                }
            }),
        )
        .await;
        let store = test_store(&portal_url, "https://auth.example.com").await;
        store_credential_family_for_portal(&store, &portal_url).await;
        sqlx::query("UPDATE sessions SET arcgis_access_expires_at = unixepoch() + 1")
            .execute(&store.pool)
            .await
            .expect("expire ArcGIS access credential");

        assert!(matches!(
            store
                .resolve_session("mcp-access", "https://mcp.example.com/mcp")
                .await,
            super::SessionResolution::Inactive
        ));
        let status: String = sqlx::query_scalar("SELECT status FROM sessions")
            .fetch_one(&store.pool)
            .await
            .expect("session status");
        assert_eq!(status, "revoked");
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn inactivity_and_absolute_deadlines_are_independent() {
        let store = test_store("https://portal.example.com", "https://auth.example.com").await;
        store_credential_family(&store).await;
        sqlx::query(
            "UPDATE sessions SET last_activity_at = unixepoch() - ?, absolute_expires_at = unixepoch() + 3600",
        )
        .bind(store.auth_settings.session_inactivity_timeout_seconds + 1)
        .execute(&store.pool)
        .await
        .expect("expire session by inactivity");
        assert!(matches!(
            store
                .resolve_session("mcp-access", "https://mcp.example.com/mcp")
                .await,
            super::SessionResolution::Inactive
        ));

        sqlx::query(
            "UPDATE sessions SET last_activity_at = unixepoch(), absolute_expires_at = unixepoch() - 1",
        )
        .execute(&store.pool)
        .await
        .expect("expire session absolutely");
        assert!(matches!(
            store
                .resolve_session("mcp-access", "https://mcp.example.com/mcp")
                .await,
            super::SessionResolution::Inactive
        ));
    }

    #[tokio::test]
    async fn forced_refresh_does_not_update_session_activity() {
        let (portal_url, requests) = mock_token_response_server(
            StatusCode::OK,
            serde_json::json!({
                "access_token": "forced-arcgis-access",
                "expires_in": 3600,
                "username": "testuser",
                "ssl": true,
            }),
        )
        .await;
        let store = test_store(&portal_url, "https://auth.example.com").await;
        store_credential_family_for_portal(&store, &portal_url).await;
        sqlx::query("UPDATE sessions SET last_activity_at = unixepoch() - 100")
            .execute(&store.pool)
            .await
            .expect("set activity timestamp");
        let before: i64 = sqlx::query_scalar("SELECT last_activity_at FROM sessions")
            .fetch_one(&store.pool)
            .await
            .expect("activity before refresh");

        let resolved = store
            .force_refresh_session("mcp-access", "https://mcp.example.com/mcp")
            .await
            .into_active()
            .expect("force refresh session");
        let after: i64 = sqlx::query_scalar("SELECT last_activity_at FROM sessions")
            .fetch_one(&store.pool)
            .await
            .expect("activity after refresh");

        assert_eq!(resolved.arcgis_token.access_token, "forced-arcgis-access");
        assert_eq!(before, after);
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn refresh_credential_exchange_does_not_extend_session_deadline() {
        let (portal_url, requests) = mock_token_response_server(
            StatusCode::OK,
            serde_json::json!({
                "access_token": "exchanged-arcgis-access",
                "expires_in": 3600,
                "refresh_token": "replacement-arcgis-refresh",
                "refresh_token_expires_in": 1209600,
                "username": "testuser",
                "ssl": true,
            }),
        )
        .await;
        let store = test_store(&portal_url, "https://auth.example.com").await;
        store_credential_family_for_portal(&store, &portal_url).await;
        sqlx::query(
            "UPDATE sessions SET arcgis_access_expires_at = unixepoch() + 1, \
                    arcgis_refresh_expires_at = unixepoch() + 3600",
        )
        .execute(&store.pool)
        .await
        .expect("age ArcGIS credentials");
        let deadline_before: i64 = sqlx::query_scalar("SELECT absolute_expires_at FROM sessions")
            .fetch_one(&store.pool)
            .await
            .expect("deadline before exchange");

        let resolved = store
            .resolve_session("mcp-access", "https://mcp.example.com/mcp")
            .await
            .into_active()
            .expect("resolve exchanged session");
        let (refresh_token, deadline_after): (String, i64) =
            sqlx::query_as("SELECT arcgis_refresh_token, absolute_expires_at FROM sessions")
                .fetch_one(&store.pool)
                .await
                .expect("credentials after exchange");

        assert_eq!(
            resolved.arcgis_token.access_token,
            "exchanged-arcgis-access"
        );
        assert_eq!(refresh_token, "replacement-arcgis-refresh");
        assert_eq!(deadline_before, deadline_after);
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn concurrent_forced_refreshes_are_single_flight_and_later_calls_are_limited() {
        let (portal_url, requests) = mock_delayed_token_response_server(
            StatusCode::OK,
            serde_json::json!({
                "access_token": "single-flight-access",
                "expires_in": 3600,
                "username": "testuser",
                "ssl": true,
            }),
        )
        .await;
        let store = test_store(&portal_url, "https://auth.example.com").await;
        store_credential_family_for_portal(&store, &portal_url).await;
        let first_store = store.clone();
        let second_store = store.clone();
        let first = tokio::spawn(async move {
            first_store
                .force_refresh_session("mcp-access", "https://mcp.example.com/mcp")
                .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let second = tokio::spawn(async move {
            second_store
                .force_refresh_session("mcp-access", "https://mcp.example.com/mcp")
                .await
        });
        let (first, second) = tokio::join!(first, second);

        assert!(first.expect("first task").into_active().is_some());
        assert!(second.expect("second task").into_active().is_some());
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        assert!(matches!(
            store
                .force_refresh_session("mcp-access", "https://mcp.example.com/mcp")
                .await,
            super::SessionResolution::RateLimited
        ));
    }
}
