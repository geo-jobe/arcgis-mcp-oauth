use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use thiserror::Error;
use tokio::sync::RwLock;

use crate::oauth::client_metadata::{
    ClientMetadataError, ClientMetadataPolicy, ClientMetadataResolver,
};

// Fixed caps; upgrade path is env-config or per-IP limits at the proxy.
const MAX_REGISTERED_CLIENTS: i64 = 1000;
const MAX_REGISTRATIONS_PER_MINUTE: usize = 10;
const REGISTRATION_RATE_WINDOW_SECS: i64 = 60;

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
    #[serde(default)]
    pub resource: String,
    #[serde(default)]
    pub scope: Option<String>,
}

impl std::fmt::Debug for TokenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenRequest")
            .field("grant_type", &self.grant_type)
            .field("code", &redact_if_present(&self.code))
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field(
                "code_verifier",
                &self.code_verifier.as_ref().map(|_| "<redacted>"),
            )
            .field("refresh_token", &redact_if_present(&self.refresh_token))
            .field("resource", &self.resource)
            .field("scope", &self.scope)
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
    #[serde(default)]
    pub resource: String,
}

pub const SUPPORTED_SCOPES: &[&str] = &["profile"];

pub fn normalize_authorization_scope(scope: Option<&str>) -> Result<Vec<String>, &'static str> {
    match scope {
        Some(scope) => normalize_scope(scope),
        None => Ok(SUPPORTED_SCOPES
            .iter()
            .map(|scope| (*scope).into())
            .collect()),
    }
}

pub fn normalize_scope(scope: &str) -> Result<Vec<String>, &'static str> {
    if scope.is_empty() {
        return Err("scope must not be empty");
    }

    let mut scopes = Vec::new();
    for value in scope.split_ascii_whitespace() {
        if !value.bytes().all(|byte| {
            byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte)
        }) {
            return Err("scope contains invalid characters");
        }
        if !SUPPORTED_SCOPES.contains(&value) {
            return Err("requested scope is not supported");
        }
        scopes.push(value.to_string());
    }
    if scopes.is_empty() {
        return Err("scope must not be empty");
    }
    scopes.sort_unstable();
    scopes.dedup();
    Ok(scopes)
}

pub fn scope_string(scopes: &[String]) -> String {
    scopes.join(" ")
}

pub fn canonical_resource_uri(resource: &str) -> Result<String, &'static str> {
    let mut url = url::Url::parse(resource).map_err(|_| "resource must be an absolute URI")?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err("resource must be an absolute HTTP or HTTPS URI");
    }
    if url.fragment().is_some() {
        return Err("resource must not contain a fragment");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("resource must not contain user information");
    }
    url.set_fragment(None);
    Ok(url.into())
}

#[cfg(test)]
mod tests {
    use super::{canonical_resource_uri, normalize_authorization_scope, normalize_scope};

    #[test]
    fn canonicalizes_resource_uri() {
        assert_eq!(
            canonical_resource_uri("HTTPS://MCP.Example.COM:443/mcp").unwrap(),
            "https://mcp.example.com/mcp"
        );
    }

    #[test]
    fn rejects_invalid_resource_uris() {
        for resource in [
            "",
            "/mcp",
            "ftp://example.com/mcp",
            "https://example.com/mcp#part",
        ] {
            assert!(
                canonical_resource_uri(resource).is_err(),
                "accepted {resource}"
            );
        }
    }

    #[test]
    fn normalizes_and_defaults_scopes() {
        assert_eq!(normalize_scope("profile  profile").unwrap(), ["profile"]);
        assert_eq!(normalize_authorization_scope(None).unwrap(), ["profile"]);
    }

    #[test]
    fn rejects_empty_unknown_and_invalid_scopes() {
        assert!(normalize_scope("").is_err());
        assert!(normalize_scope("email").is_err());
        assert!(normalize_scope("profile\u{00a0}").is_err());
    }
}

/// A client registered via POST /oauth/register (RFC 7591).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RegisteredClient {
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
    pub metadata_url: Option<String>,
}

#[derive(Debug, Error)]
pub enum ClientResolveError {
    #[error("client_id is not registered")]
    Unknown,
    #[error(transparent)]
    Metadata(#[from] ClientMetadataError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterError {
    CapacityExceeded,
    RateLimited,
    Internal,
}

/// Carries the server's public address for discovery metadata and the DCR client registry.
#[derive(Clone)]
pub struct McpOAuthStore {
    pub app_address: String,
    pool: SqlitePool,
    registration_timestamps: Arc<RwLock<Vec<i64>>>,
    metadata_resolver: ClientMetadataResolver,
}

impl McpOAuthStore {
    #[cfg(test)]
    pub fn new(pool: SqlitePool, app_address: &str) -> Self {
        Self::with_client_metadata_policy(
            pool,
            app_address,
            ClientMetadataPolicy {
                allow_private_addresses: false,
            },
        )
    }

    pub fn with_client_metadata_policy(
        pool: SqlitePool,
        app_address: &str,
        policy: ClientMetadataPolicy,
    ) -> Self {
        Self {
            app_address: app_address.to_string(),
            pool,
            registration_timestamps: Arc::new(RwLock::new(Vec::new())),
            metadata_resolver: ClientMetadataResolver::new(policy),
        }
    }

    /// Resolve URL-shaped client IDs through CIMD; all other IDs use DCR.
    pub async fn resolve_client(
        &self,
        client_id: &str,
    ) -> Result<RegisteredClient, ClientResolveError> {
        let is_metadata_url = url::Url::parse(client_id).is_ok();
        if is_metadata_url {
            let metadata = self.metadata_resolver.resolve(client_id).await?;
            return Ok(RegisteredClient {
                redirect_uris: metadata.redirect_uris,
                client_name: Some(metadata.client_name),
                metadata_url: Some(client_id.to_string()),
            });
        }

        self.get_registered_client(client_id)
            .await
            .ok_or(ClientResolveError::Unknown)
    }

    /// Store a DCR registration.
    pub async fn register_client(
        &self,
        client_id: String,
        redirect_uris: Vec<String>,
        client_name: Option<String>,
    ) -> Result<(), RegisterError> {
        let now = chrono::Utc::now().timestamp();
        {
            let mut timestamps = self.registration_timestamps.write().await;
            timestamps.retain(|&ts| now - ts < REGISTRATION_RATE_WINDOW_SECS);
            if timestamps.len() >= MAX_REGISTRATIONS_PER_MINUTE {
                return Err(RegisterError::RateLimited);
            }
            timestamps.push(now);
        }

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM registered_clients")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!("Failed to count registered clients: {e}");
                RegisterError::Internal
            })?;
        if count >= MAX_REGISTERED_CLIENTS {
            return Err(RegisterError::CapacityExceeded);
        }

        let redirect_uris_json = serde_json::to_string(&redirect_uris).map_err(|e| {
            tracing::error!("Failed to serialize redirect_uris: {e}");
            RegisterError::Internal
        })?;

        sqlx::query(
            "INSERT OR REPLACE INTO registered_clients (client_id, redirect_uris, client_name) \
             VALUES (?, ?, ?)",
        )
        .bind(&client_id)
        .bind(&redirect_uris_json)
        .bind(client_name.as_deref())
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Failed to register client: {e}");
            RegisterError::Internal
        })?;

        Ok(())
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
            metadata_url: None,
        })
    }
}
