use std::{collections::HashMap, sync::Arc};

use arcgis_sharing_rs::auth::{exchange_oauth_authorization_code, exchange_oauth_refresh_token};
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
use tokio::sync::RwLock;
use tracing::Instrument;
use uuid::Uuid;

use crate::config::{ArcgisPortalConfig, PortalRegistry};

// Fixed TTLs/caps; upgrade path is env-config or per-IP rate limiting at the proxy.
const PENDING_OAUTH_SESSION_TTL_SECS: i64 = 600;
const PENDING_AUTH_CODE_TTL_SECS: i64 = 600;
const PENDING_CONSENT_TTL_SECS: i64 = 600;
const MAX_PENDING_OAUTH_SESSIONS: usize = 1000;
const MAX_PENDING_AUTH_CODES: usize = 1000;
const MAX_PENDING_CONSENTS: usize = 1000;

pub type ArcGISTokenResponse = arcgis_sharing_rs::models::OAuthTokenResponse;

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
    pub arcgis_token: ArcGISTokenResponse,
    pub portal: PortalContext,
    pub expires_at: i64,
    pub resource: String,
    pub scopes: Vec<String>,
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
    pool: SqlitePool,
}

impl ArcGISAuthStore {
    pub fn new(pool: SqlitePool, base_url: String, portal_registry: PortalRegistry) -> Self {
        Self {
            base_url,
            portal_registry: Arc::new(portal_registry),
            pending_consents: Arc::new(RwLock::new(HashMap::new())),
            pending_oauth_sessions: Arc::new(RwLock::new(HashMap::new())),
            pending_auth_codes: Arc::new(RwLock::new(HashMap::new())),
            pool,
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
    }

    pub async fn store_issued_tokens(
        &self,
        mcp_access_token: String,
        mcp_refresh_token: String,
        arcgis_token: ArcGISTokenResponse,
        portal: PortalContext,
        resource: String,
        scopes: Vec<String>,
    ) -> Result<(), String> {
        let expires_at = chrono::Utc::now().timestamp() + arcgis_token.expires_in as i64;
        let arcgis_token_json = serde_json::to_string(&arcgis_token).map_err(|e| e.to_string())?;

        let mut tx = self.pool.begin().await.map_err(|e| e.to_string())?;

        sqlx::query(
            "INSERT OR REPLACE INTO tokens \
             (mcp_access_token, arcgis_token, expires_at, portal_key, portal_url, portal_api_root, portal_apps, portal_stories_root, resource_uri, scope) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&mcp_access_token)
        .bind(&arcgis_token_json)
        .bind(expires_at)
        .bind(&portal.key)
        .bind(&portal.portal_url)
        .bind(&portal.api_root)
        .bind(&portal.portal_apps)
        .bind(&portal.stories_root)
        .bind(&resource)
        .bind(crate::oauth::store::scope_string(&scopes))
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        sqlx::query(
            "INSERT OR REPLACE INTO refresh_tokens (mcp_refresh_token, mcp_access_token, resource_uri, scope) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(&mcp_refresh_token)
        .bind(&mcp_access_token)
        .bind(&resource)
        .bind(crate::oauth::store::scope_string(&scopes))
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn get_token(
        &self,
        mcp_access_token: &str,
        resource: &str,
    ) -> Option<McpTokenRecord> {
        if let Ok(result) = sqlx::query(
            "DELETE FROM tokens WHERE mcp_access_token = ? AND expires_at <= unixepoch()",
        )
        .bind(mcp_access_token)
        .execute(&self.pool)
        .await
            && result.rows_affected() > 0
        {
            sqlx::query("DELETE FROM refresh_tokens WHERE mcp_access_token = ?")
                .bind(mcp_access_token)
                .execute(&self.pool)
                .await
                .ok();
        }

        let row = sqlx::query(
            "SELECT arcgis_token, expires_at, portal_key, portal_url, portal_api_root, portal_apps, portal_stories_root, scope \
             FROM tokens WHERE mcp_access_token = ? AND resource_uri = ?",
        )
        .bind(mcp_access_token)
        .bind(resource)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten()?;

        let arcgis_token_json: String = row.get("arcgis_token");
        let arcgis_token: ArcGISTokenResponse = serde_json::from_str(&arcgis_token_json).ok()?;
        let expires_at: i64 = row.get("expires_at");
        let scope: String = row.get("scope");
        let scopes = crate::oauth::store::normalize_scope(&scope).ok()?;

        Some(McpTokenRecord {
            arcgis_token,
            expires_at,
            resource: resource.to_string(),
            scopes,
            portal: PortalContext {
                key: row.get("portal_key"),
                portal_url: row.get("portal_url"),
                api_root: row.get("portal_api_root"),
                portal_apps: row.get("portal_apps"),
                stories_root: row.get("portal_stories_root"),
            },
        })
    }

    pub async fn refresh_access_token(
        &self,
        mcp_refresh_token: &str,
        resource: &str,
        requested_scopes: Option<&[String]>,
    ) -> Result<(String, String, u64, Vec<String>), String> {
        let refresh_row = sqlx::query(
            "SELECT mcp_access_token, resource_uri, scope FROM refresh_tokens WHERE mcp_refresh_token = ?",
        )
        .bind(mcp_refresh_token)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| e.to_string())?;

        let refresh_row = refresh_row.ok_or("Invalid refresh token")?;
        let old_access_token: String = refresh_row.get("mcp_access_token");
        let bound_resource: String = refresh_row.get("resource_uri");
        if bound_resource != resource {
            return Err("resource does not match refresh token".into());
        }
        let refresh_scope: String = refresh_row.get("scope");
        let granted_scopes = crate::oauth::store::normalize_scope(&refresh_scope)
            .map_err(|_| "Invalid scope stored for refresh token")?;
        let scopes = match requested_scopes {
            Some(requested) if requested.iter().all(|scope| granted_scopes.contains(scope)) => {
                requested.to_vec()
            }
            Some(_) => return Err("requested scope exceeds original grant".into()),
            None => granted_scopes.clone(),
        };

        let row = sqlx::query(
            "SELECT arcgis_token, portal_key, portal_url, portal_api_root, portal_apps, portal_stories_root, scope \
             FROM tokens WHERE mcp_access_token = ? AND resource_uri = ?",
        )
        .bind(&old_access_token)
        .bind(resource)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| e.to_string())?;

        let row = row.ok_or("Access token not found for refresh")?;
        let access_scope: String = row.get("scope");
        if crate::oauth::store::normalize_scope(&access_scope)
            .map_err(|_| "Invalid scope stored for access token")?
            != granted_scopes
        {
            return Err("access and refresh token scopes do not match".into());
        }
        let arcgis_token_json: String = row.get("arcgis_token");
        let arcgis_token: ArcGISTokenResponse =
            serde_json::from_str(&arcgis_token_json).map_err(|e| e.to_string())?;
        let portal = PortalContext {
            key: row.get("portal_key"),
            portal_url: row.get("portal_url"),
            api_root: row.get("portal_api_root"),
            portal_apps: row.get("portal_apps"),
            stories_root: row.get("portal_stories_root"),
        };

        let arcgis_refresh_token = match arcgis_token.refresh_token.as_deref() {
            Some(token) if !token.is_empty() => token,
            _ => {
                Self::cleanup_session(&self.pool, &old_access_token, mcp_refresh_token).await?;
                return Err("ArcGIS refresh token missing; re-authenticate".into());
            }
        };

        let portal_config = self
            .portal_registry
            .get(&portal.key)
            .ok_or_else(|| format!("Portal '{}' not found in registry", portal.key))?;

        let token_url = format!(
            "{}/sharing/rest/oauth2/token",
            portal.portal_url.trim_end_matches('/')
        );

        let new_arcgis_token = match exchange_oauth_refresh_token(
            &token_url,
            &portal_config.client_id,
            arcgis_refresh_token,
        )
        .instrument(tracing::info_span!(
            "arcgis.token_refresh",
            "http.request.method" = "POST",
            "url.full" = %token_url,
        ))
        .await
        {
            Ok(token) => token,
            Err(e) => {
                Self::cleanup_session(&self.pool, &old_access_token, mcp_refresh_token).await?;
                return Err(format!("ArcGIS session expired; re-authenticate: {e}"));
            }
        };

        let expires_in = new_arcgis_token.expires_in;
        let new_token_json = serde_json::to_string(&new_arcgis_token).map_err(|e| e.to_string())?;
        let expires_at = chrono::Utc::now().timestamp() + expires_in as i64;

        let new_access = format!("mcp-token-{}", Uuid::new_v4());
        let new_refresh = format!("mcp-refresh-{}", Uuid::new_v4());

        let mut tx = self.pool.begin().await.map_err(|e| e.to_string())?;

        sqlx::query("DELETE FROM tokens WHERE mcp_access_token = ?")
            .bind(&old_access_token)
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;

        sqlx::query("DELETE FROM refresh_tokens WHERE mcp_refresh_token = ?")
            .bind(mcp_refresh_token)
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;

        sqlx::query(
            "INSERT INTO tokens \
              (mcp_access_token, arcgis_token, expires_at, portal_key, portal_url, portal_api_root, portal_apps, portal_stories_root, resource_uri, scope) \
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&new_access)
        .bind(&new_token_json)
        .bind(expires_at)
        .bind(&portal.key)
        .bind(&portal.portal_url)
        .bind(&portal.api_root)
        .bind(&portal.portal_apps)
        .bind(&portal.stories_root)
        .bind(resource)
        .bind(crate::oauth::store::scope_string(&scopes))
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        sqlx::query(
            "INSERT INTO refresh_tokens (mcp_refresh_token, mcp_access_token, resource_uri, scope) VALUES (?, ?, ?, ?)",
        )
        .bind(&new_refresh)
        .bind(&new_access)
        .bind(resource)
        .bind(crate::oauth::store::scope_string(&scopes))
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        tx.commit().await.map_err(|e| e.to_string())?;

        Ok((new_access, new_refresh, expires_in, scopes))
    }

    async fn cleanup_session(
        pool: &SqlitePool,
        mcp_access_token: &str,
        mcp_refresh_token: &str,
    ) -> Result<(), String> {
        let mut tx = pool.begin().await.map_err(|e| e.to_string())?;

        sqlx::query("DELETE FROM tokens WHERE mcp_access_token = ?")
            .bind(mcp_access_token)
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;

        sqlx::query("DELETE FROM refresh_tokens WHERE mcp_refresh_token = ?")
            .bind(mcp_refresh_token)
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;

        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(())
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

    if arcgis_token.refresh_token.is_none() {
        tracing::warn!(
            portal = %session.portal.key,
            "ArcGIS omitted refresh_token; MCP refresh will fail"
        );
    }

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
    use std::sync::Arc;

    use axum::{
        Json, Router,
        extract::{Query, State},
        http::{StatusCode, header::LOCATION},
        response::IntoResponse,
        routing::post,
    };
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use tokio::net::TcpListener;

    use crate::config::{ArcgisPortalConfig, PortalRegistry};

    use super::{
        ArcGISAuthStore, CallbackQuery, arcgis_callback, authorization_response_url, is_expired,
        pkce_challenge_from_verifier,
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
                    "username": "testuser",
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
}
