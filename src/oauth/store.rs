use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};

/// Request body for POST /oauth/token.
#[derive(Deserialize, Serialize)]
pub struct TokenRequest {
    pub grant_type: String,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub redirect_uri: String,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub refresh_token: String,
}

impl std::fmt::Debug for TokenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenRequest")
            .field("grant_type", &self.grant_type)
            .field("code", &redact_if_present(&self.code))
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("code_verifier", &self.code_verifier.as_ref().map(|_| "<redacted>"))
            .field("refresh_token", &redact_if_present(&self.refresh_token))
            .finish()
    }
}

fn redact_if_present(value: &str) -> &str {
    if value.is_empty() {
        "<empty>"
    } else {
        "<redacted>"
    }
}

/// Query parameters for GET /oauth/authorize.
#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    #[allow(dead_code)]
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

/// A client registered via POST /oauth/register (RFC 7591).
#[derive(Debug, Clone)]
pub struct RegisteredClient {
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
}

/// Carries the server's public address for discovery metadata and the DCR client registry.
#[derive(Clone, Debug)]
pub struct McpOAuthStore {
    pub app_address: String,
    pool: SqlitePool,
}

impl McpOAuthStore {
    pub fn new(pool: SqlitePool, app_address: &str) -> Self {
        Self {
            app_address: app_address.to_string(),
            pool,
        }
    }

    /// Store a DCR registration.
    pub async fn register_client(
        &self,
        client_id: String,
        redirect_uris: Vec<String>,
        client_name: Option<String>,
    ) {
        let redirect_uris_json =
            serde_json::to_string(&redirect_uris).expect("Failed to serialize redirect_uris");

        sqlx::query(
            "INSERT OR REPLACE INTO registered_clients (client_id, redirect_uris, client_name) \
             VALUES (?, ?, ?)",
        )
        .bind(&client_id)
        .bind(&redirect_uris_json)
        .bind(client_name.as_deref())
        .execute(&self.pool)
        .await
        .expect("Failed to register client");
    }

    /// Look up a previously registered client. Returns `None` if the `client_id` is unknown.
    pub async fn get_registered_client(&self, client_id: &str) -> Option<RegisteredClient> {
        let row = sqlx::query(
            "SELECT redirect_uris, client_name FROM registered_clients WHERE client_id = ?",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten()?;

        let redirect_uris_json: String = row.get("redirect_uris");
        let redirect_uris: Vec<String> = serde_json::from_str(&redirect_uris_json).ok()?;

        Some(RegisteredClient {
            redirect_uris,
            client_name: row.get("client_name"),
        })
    }
}
