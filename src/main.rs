use axum::{
    Router,
    routing::{get, post},
};
use serde::Deserialize;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tower_http::cors::{Any, CorsLayer};

async fn oauth_protected_resource() {}
async fn oauth_token() {}
async fn health_check() {}
async fn oauth_authorize() {}
async fn oauth_authorize_continue() {}
async fn oauth_register() {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortalContext {
    pub key: String,
    pub portal_url: String,
    pub api_root: String,
    pub portal_apps: String,
    pub stories_root: String,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ArcgisPortalConfig {
    pub key: String,
    pub label: String,
    pub portal_url: String,
    pub api_root: String,
    pub portal_apps: String,
    pub client_id: String,
    pub stories_root: String,
}

#[derive(Clone, Debug)]
pub struct PortalRegistry {
    portals: HashMap<String, ArcgisPortalConfig>,
}

#[derive(Clone, Debug)]
pub struct PendingOAuthSession {
    /// The MCP client's registered client_id (from DCR), forwarded to PendingAuthCode.
    pub client_id: String,
    pub mcp_client_state: Option<String>,
    pub mcp_redirect_uri: String,
    /// The MCP client's PKCE code_challenge (S256), so /oauth/token can verify it.
    pub mcp_code_challenge: Option<String>,
    /// The server-side PKCE verifier for the ArcGIS authorization request.
    pub arcgis_pkce_verifier: Vec<u8>,
    /// Selected portal for this authorization flow.
    pub portal: ArcgisPortalConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ArcGISTokenResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub username: Option<String>,
}

/// Stored when /arcgis/callback completes; consumed by /oauth/token.
#[derive(Clone, Debug)]
pub struct PendingAuthCode {
    pub arcgis_token: ArcGISTokenResponse,
    /// The MCP client's registered client_id, forwarded from PendingOAuthSession.
    pub client_id: String,
    /// The MCP client's PKCE code_challenge, forwarded from PendingOAuthSession.
    pub mcp_code_challenge: Option<String>,
    pub mcp_redirect_uri: String,
    pub portal: PortalContext,
}

#[derive(Clone, Debug)]
pub struct ArcGISAuthStore {
    pub base_url: String,
    pub portal_registry: Arc<PortalRegistry>,

    /// arcgis_state_uuid → PendingOAuthSession (in-memory: ephemeral, single auth-flow lifetime)
    pending_oauth_sessions: Arc<RwLock<HashMap<String, PendingOAuthSession>>>,
    /// mcp_auth_code → PendingAuthCode (in-memory: ephemeral, single auth-flow lifetime)
    pending_auth_codes: Arc<RwLock<HashMap<String, PendingAuthCode>>>,
}

impl ArcGISAuthStore {
    pub fn new(base_url: String, portal_registry: PortalRegistry) -> Self {
        Self {
            base_url,
            portal_registry: Arc::new(portal_registry),
            pending_oauth_sessions: Arc::new(RwLock::new(HashMap::new())),
            pending_auth_codes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn portal_registry(&self) -> &PortalRegistry {
        &self.portal_registry
    }

    /// Build a portal-scoped ArcGIS sharing client for the given token context.
    // pub fn sharing_client_for(
    //     &self,
    //     portal: &PortalContext,
    //     access_token: &str,
    // ) -> ArcGISSharingClient {}

    /// Called by /oauth/authorize/continue. Stores MCP client params and ArcGIS PKCE verifier,
    /// returns the arcgis_state UUID to embed in the ArcGIS redirect.
    pub async fn create_pending_oauth_session(
        &self,
        client_id: String,
        mcp_client_state: Option<String>,
        mcp_redirect_uri: String,
        mcp_code_challenge: Option<String>,
        portal: ArcgisPortalConfig,
    ) -> (String, String) {
        todo!()
        // let arcgis_pkce_verifier = generate_pkce_verifier();
        // let arcgis_pkce_challenge = pkce_code_challenge(&arcgis_pkce_verifier);
        // let state_id = Uuid::new_v4().to_string();
        // self.pending_oauth_sessions.write().await.insert(
        //     state_id.clone(),
        //     PendingOAuthSession {
        //         client_id,
        //         mcp_client_state,
        //         mcp_redirect_uri,
        //         mcp_code_challenge,
        //         arcgis_pkce_verifier,
        //         portal,
        //     },
        // );
        // (state_id, arcgis_pkce_challenge)
    }

    /// Called by /arcgis/callback. Consumes the pending session for the given arcgis state id.
    pub async fn consume_pending_oauth_session(
        &self,
        state_id: &str,
    ) -> Option<PendingOAuthSession> {
        //self.pending_oauth_sessions.write().await.remove(state_id)
        todo!()
    }

    /// Called by /arcgis/callback after receiving the ArcGIS token.
    /// Stores the token under a one-time MCP auth code and returns that code.
    pub async fn store_pending_auth_code(
        &self,
        arcgis_token: ArcGISTokenResponse,
        client_id: String,
        mcp_code_challenge: Option<String>,
        mcp_redirect_uri: String,
        portal: PortalContext,
    ) -> String {
        // let code = format!("mcp-code-{}", Uuid::new_v4());
        // self.pending_auth_codes.write().await.insert(
        //     code.clone(),
        //     PendingAuthCode {
        //         arcgis_token,
        //         client_id,
        //         mcp_code_challenge,
        //         mcp_redirect_uri,
        //         portal,
        //     },
        // );
        // code
        todo!()
    }

    /// Called by /oauth/token. Consumes (single-use) the pending auth code.
    pub async fn consume_pending_auth_code(&self, code: &str) -> Option<PendingAuthCode> {
        //self.pending_auth_codes.write().await.remove(code)
        todo!()
    }

    /// Store the ArcGIS token under an MCP access token (the bearer clients will send).
    pub async fn store_token(
        &self,
        mcp_access_token: String,
        arcgis_token: ArcGISTokenResponse,
        portal: PortalContext,
    ) {
        // let expires_at = chrono::Utc::now().timestamp() + arcgis_token.expires_in as i64;
        // let arcgis_token_json =
        //     serde_json::to_string(&arcgis_token).expect("Failed to serialize ArcGIS token");
        //
        // sqlx::query(
        //     "INSERT OR REPLACE INTO tokens \
        //      (mcp_access_token, arcgis_token, expires_at, portal_key, portal_url, portal_api_root, portal_apps, portal_stories_root) \
        //      VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        // )
        // .bind(&mcp_access_token)
        // .bind(&arcgis_token_json)
        // .bind(expires_at)
        // .bind(&portal.key)
        // .bind(&portal.portal_url)
        // .bind(&portal.api_root)
        // .bind(&portal.portal_apps)
        // .bind(&portal.stories_root)
        // .execute(&self.pool)
        // .await
        // .expect("Failed to store token");
        todo!()
    }

    /// Look up the ArcGIS token and portal context for the given MCP access token.
    /// Lazily removes and returns None if expired.
    pub async fn get_token(&self, mcp_access_token: &str) {
        // sqlx::query("DELETE FROM tokens WHERE mcp_access_token = ? AND expires_at <= unixepoch()")
        //     .bind(mcp_access_token)
        //     .execute(&self.pool)
        //     .await
        //     .ok();
        //
        // let row = sqlx::query(
        //     "SELECT arcgis_token, portal_key, portal_url, portal_api_root, portal_apps, portal_stories_root \
        //      FROM tokens WHERE mcp_access_token = ?",
        // )
        // .bind(mcp_access_token)
        // .fetch_optional(&self.pool)
        // .await
        // .ok()
        // .flatten()?;
        //
        // let arcgis_token_json: String = row.get("arcgis_token");
        // let arcgis_token: ArcGISTokenResponse = serde_json::from_str(&arcgis_token_json).ok()?;
        //
        // Some(McpTokenRecord {
        //     arcgis_token,
        //     portal: PortalContext {
        //         key: row.get("portal_key"),
        //         portal_url: row.get("portal_url"),
        //         api_root: row.get("portal_api_root"),
        //         portal_apps: row.get("portal_apps"),
        //         stories_root: row.get("portal_stories_root"),
        //     },
        // })
        todo!()
    }

    /// Validate that an MCP access token is active (used by middleware).
    pub async fn validate_token(&self, mcp_access_token: &str) -> bool {
        //self.get_token(mcp_access_token).await.is_some()
        todo!()
    }

    /// Register a refresh token mapping so /oauth/token can rotate it.
    pub async fn store_refresh_token(&self, mcp_refresh_token: String, mcp_access_token: String) {
        // sqlx::query(
        //     "INSERT OR REPLACE INTO refresh_tokens (mcp_refresh_token, mcp_access_token) \
        //      VALUES (?, ?)",
        // )
        // .bind(&mcp_refresh_token)
        // .bind(&mcp_access_token)
        // .execute(&self.pool)
        // .await
        // .expect("Failed to store refresh token");
        todo!()
    }

    /// Rotate an MCP refresh token: issues a new access+refresh token pair.
    /// Returns (new_mcp_access_token, new_mcp_refresh_token) or an error string.
    pub async fn refresh_access_token(
        &self,
        mcp_refresh_token: &str,
    ) -> Result<(String, String), String> {
        todo!()
    }
}

#[derive(Debug, Clone)]
pub struct RegisteredClient {
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
}

pub struct AuthStore {
    clients: HashMap<String, RegisteredClient>,
}

impl AuthStore {
    pub fn new() -> Self {
        Self {
            clients: HashMap::new(),
        }
    }

    pub async fn register_client(
        &self,
        client_id: String,
        redirect_uris: Vec<String>,
        client_name: Option<String>,
    ) {
        todo!()
    }
    pub async fn get_registered_client(&self, client_id: &str) -> Option<RegisteredClient> {
        todo!()
    }
}

#[derive(Clone)]
pub struct State {
    pub auth_store: Arc<AuthStore>,
}

#[tokio::main]
async fn main() {
    let state = Arc::new(State {
        auth_store: Arc::new(AuthStore::new()),
    });

    let cors_layer = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let router = Router::new()
        .route("/health", get(health_check))
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth_protected_resource).options(oauth_protected_resource),
        )
        .route("/oauth/authorize", get(oauth_authorize))
        .route("/oauth/authorize/continue", get(oauth_authorize_continue))
        .route("/oauth/register", post(oauth_register))
        .route("/oauth/token", post(oauth_token).options(oauth_token))
        .layer(cors_layer.clone())
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3324").await.unwrap();
    axum::serve(listener, router).await.unwrap();
}
