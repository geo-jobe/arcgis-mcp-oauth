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
const MAX_PENDING_OAUTH_SESSIONS: usize = 1000;
const MAX_PENDING_AUTH_CODES: usize = 1000;

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
}

/// Stored when /oauth/authorize/continue is received; consumed by /arcgis/callback.
#[derive(Clone, Debug)]
pub struct PendingOAuthSession {
    pub client_id: String,
    pub mcp_client_state: Option<String>,
    pub mcp_redirect_uri: String,
    pub mcp_code_challenge: Option<String>,
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
    pub portal: PortalContext,
    pub created_at: i64,
}

#[derive(Clone, Debug)]
pub struct ArcGISAuthStore {
    pub base_url: String,
    pub portal_registry: Arc<PortalRegistry>,
    pending_oauth_sessions: Arc<RwLock<HashMap<String, PendingOAuthSession>>>,
    pending_auth_codes: Arc<RwLock<HashMap<String, PendingAuthCode>>>,
    pool: SqlitePool,
}

impl ArcGISAuthStore {
    pub fn new(pool: SqlitePool, base_url: String, portal_registry: PortalRegistry) -> Self {
        Self {
            base_url,
            portal_registry: Arc::new(portal_registry),
            pending_oauth_sessions: Arc::new(RwLock::new(HashMap::new())),
            pending_auth_codes: Arc::new(RwLock::new(HashMap::new())),
            pool,
        }
    }

    pub fn portal_registry(&self) -> &PortalRegistry {
        &self.portal_registry
    }

    pub async fn create_pending_oauth_session(
        &self,
        client_id: String,
        mcp_client_state: Option<String>,
        mcp_redirect_uri: String,
        mcp_code_challenge: Option<String>,
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

    pub async fn store_pending_auth_code(
        &self,
        arcgis_token: ArcGISTokenResponse,
        client_id: String,
        mcp_code_challenge: Option<String>,
        mcp_redirect_uri: String,
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
        if before_sessions > 0 || before_codes > 0 {
            tracing::debug!(
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
    ) -> Result<(), String> {
        let expires_at = chrono::Utc::now().timestamp() + arcgis_token.expires_in as i64;
        let arcgis_token_json = serde_json::to_string(&arcgis_token).map_err(|e| e.to_string())?;

        let mut tx = self.pool.begin().await.map_err(|e| e.to_string())?;

        sqlx::query(
            "INSERT OR REPLACE INTO tokens \
             (mcp_access_token, arcgis_token, expires_at, portal_key, portal_url, portal_api_root, portal_apps, portal_stories_root) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&mcp_access_token)
        .bind(&arcgis_token_json)
        .bind(expires_at)
        .bind(&portal.key)
        .bind(&portal.portal_url)
        .bind(&portal.api_root)
        .bind(&portal.portal_apps)
        .bind(&portal.stories_root)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        sqlx::query(
            "INSERT OR REPLACE INTO refresh_tokens (mcp_refresh_token, mcp_access_token) \
             VALUES (?, ?)",
        )
        .bind(&mcp_refresh_token)
        .bind(&mcp_access_token)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn get_token(&self, mcp_access_token: &str) -> Option<McpTokenRecord> {
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
            "SELECT arcgis_token, expires_at, portal_key, portal_url, portal_api_root, portal_apps, portal_stories_root \
             FROM tokens WHERE mcp_access_token = ?",
        )
        .bind(mcp_access_token)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten()?;

        let arcgis_token_json: String = row.get("arcgis_token");
        let arcgis_token: ArcGISTokenResponse = serde_json::from_str(&arcgis_token_json).ok()?;
        let expires_at: i64 = row.get("expires_at");

        Some(McpTokenRecord {
            arcgis_token,
            expires_at,
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
    ) -> Result<(String, String, u64), String> {
        let old_access_token: Option<String> = sqlx::query_scalar(
            "SELECT mcp_access_token FROM refresh_tokens WHERE mcp_refresh_token = ?",
        )
        .bind(mcp_refresh_token)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| e.to_string())?;

        let old_access_token = old_access_token.ok_or("Invalid refresh token")?;

        let row = sqlx::query(
            "SELECT arcgis_token, portal_key, portal_url, portal_api_root, portal_apps, portal_stories_root \
             FROM tokens WHERE mcp_access_token = ?",
        )
        .bind(&old_access_token)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| e.to_string())?;

        let row = row.ok_or("Access token not found for refresh")?;
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
             (mcp_access_token, arcgis_token, expires_at, portal_key, portal_url, portal_api_root, portal_apps, portal_stories_root) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&new_access)
        .bind(&new_token_json)
        .bind(expires_at)
        .bind(&portal.key)
        .bind(&portal.portal_url)
        .bind(&portal.api_root)
        .bind(&portal.portal_apps)
        .bind(&portal.stories_root)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        sqlx::query(
            "INSERT INTO refresh_tokens (mcp_refresh_token, mcp_access_token) VALUES (?, ?)",
        )
        .bind(&new_refresh)
        .bind(&new_access)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        tx.commit().await.map_err(|e| e.to_string())?;

        Ok((new_access, new_refresh, expires_in))
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
    pub code: String,
    pub state: Option<String>,
}

pub async fn arcgis_callback(
    Query(params): Query<CallbackQuery>,
    State(store): State<Arc<ArcGISAuthStore>>,
) -> impl IntoResponse {
    tracing::debug!("arcgis_callback: code present={}", !params.code.is_empty());

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

    let verifier_str = match std::str::from_utf8(&session.arcgis_pkce_verifier) {
        Ok(s) => s.to_string(),
        Err(_) => {
            tracing::warn!("arcgis_callback: pkce verifier is not valid UTF-8");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
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
        &params.code,
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
            return StatusCode::BAD_GATEWAY.into_response();
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
            session.client_id,
            session.mcp_code_challenge,
            session.mcp_redirect_uri.clone(),
            portal_context,
        )
        .await
    {
        Ok(code) => code,
        Err(PendingStoreError::CapacityExceeded) => {
            tracing::warn!("arcgis_callback: pending auth code capacity exceeded");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

    tracing::info!(
        "arcgis_callback: stored pending auth code for user={} portal={}",
        username,
        session.portal.key
    );

    let mut redirect_url = format!("{}?code={}", session.mcp_redirect_uri, mcp_auth_code);
    if let Some(state) = session.mcp_client_state {
        redirect_url.push_str(&format!("&state={}", percent_encode_component(&state)));
    }
    Redirect::to(&redirect_url).into_response()
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
    use super::{is_expired, pkce_challenge_from_verifier};

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
}
