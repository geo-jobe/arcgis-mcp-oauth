use std::collections::HashMap;
use std::sync::Arc;

use askama::Template;
use axum::{
    Json,
    body::Body,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
};
use rmcp::transport::auth::AuthorizationMetadata;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::arcgis_auth::{
    ArcGISAuthStore, PendingStoreError, percent_encode_component, pkce_challenge_from_verifier,
};
use crate::config::ArcgisPortalConfig;
use crate::oauth::store::{AuthorizeQuery, McpOAuthStore, RegisterError, TokenRequest};

/// Max bytes for `/oauth/token` form body (grant_type, code, PKCE, redirect_uri, etc.).
const OAUTH_TOKEN_MAX_BODY: usize = 4096;

#[derive(Template)]
#[template(path = "oauth_authorize.html")]
struct AuthorizeTemplate {
    continue_url: String,
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    portals: Vec<ArcgisPortalConfig>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct AuthorizeContinueQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub portal_key: String,
}

#[derive(Clone)]
pub struct OAuthRouteState {
    pub mcp_store: Arc<McpOAuthStore>,
    pub arcgis_store: Arc<ArcGISAuthStore>,
}

pub async fn oauth_authorization_server(state: State<Arc<OAuthRouteState>>) -> impl IntoResponse {
    let mut additional_fields = HashMap::new();
    additional_fields.insert(
        "response_types_supported".into(),
        Value::Array(vec![Value::String("code".into())]),
    );
    additional_fields.insert(
        "grant_types_supported".into(),
        Value::Array(vec![
            Value::String("authorization_code".into()),
            Value::String("refresh_token".into()),
        ]),
    );
    let address = state.mcp_store.app_address.clone();

    let metadata = AuthorizationMetadata {
        authorization_endpoint: format!("{}/oauth/authorize", address),
        token_endpoint: format!("{}/oauth/token", address),
        scopes_supported: Some(vec!["profile".to_string(), "email".to_string()]),
        registration_endpoint: Some(format!("{}/oauth/register", address)),
        response_types_supported: Some(vec!["code".to_string()]),
        issuer: Some(address.to_string()),
        jwks_uri: None,
        code_challenge_methods_supported: Some(vec!["S256".to_string()]),
        additional_fields,
    };
    tracing::debug!("metadata: {:?}", metadata);
    (StatusCode::OK, Json(metadata))
}

async fn validate_registered_client(
    mcp_store: &McpOAuthStore,
    client_id: &str,
    redirect_uri: &str,
) -> Result<(), (StatusCode, Value)> {
    let registered = match mcp_store.get_registered_client(client_id).await {
        Some(c) => c,
        None => {
            tracing::warn!("oauth authorize: unknown client_id={client_id}");
            return Err((
                StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "error": "invalid_client",
                    "error_description": "client_id is not registered"
                }),
            ));
        }
    };

    if !registered.redirect_uris.contains(&redirect_uri.to_string()) {
        tracing::warn!(
            "oauth authorize: redirect_uri {redirect_uri} not registered for client_id={client_id}"
        );
        return Err((
            StatusCode::BAD_REQUEST,
            serde_json::json!({
                "error": "invalid_request",
                "error_description": "redirect_uri is not registered for this client"
            }),
        ));
    }

    Ok(())
}

pub async fn oauth_authorize(
    Query(params): Query<AuthorizeQuery>,
    State(state): State<Arc<OAuthRouteState>>,
) -> impl IntoResponse {
    tracing::debug!("oauth_authorize, params: {:?}", params);

    if let Err((status, body)) =
        validate_registered_client(&state.mcp_store, &params.client_id, &params.redirect_uri).await
    {
        return (status, Json(body)).into_response();
    }

    let continue_url = format!("{}/oauth/authorize/continue", state.mcp_store.app_address);
    let template = AuthorizeTemplate {
        continue_url,
        response_type: params.response_type,
        client_id: params.client_id,
        redirect_uri: params.redirect_uri,
        scope: params.scope,
        state: params.state,
        code_challenge: params.code_challenge,
        code_challenge_method: params.code_challenge_method,
        portals: state.arcgis_store.portal_registry().list().to_vec(),
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("failed to render authorize template: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn oauth_authorize_continue(
    Query(params): Query<AuthorizeContinueQuery>,
    State(state): State<Arc<OAuthRouteState>>,
) -> impl IntoResponse {
    tracing::debug!("oauth_authorize_continue, params: {:?}", params);

    if let Err((status, body)) =
        validate_registered_client(&state.mcp_store, &params.client_id, &params.redirect_uri).await
    {
        return (status, Json(body)).into_response();
    }

    let portal = match state.arcgis_store.portal_registry().get(&params.portal_key) {
        Some(portal) => portal.clone(),
        None => {
            tracing::warn!(
                "oauth_authorize_continue: unknown portal_key={}",
                params.portal_key
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "portal_key is not configured"
                })),
            )
                .into_response();
        }
    };

    let (arcgis_state_id, arcgis_pkce_challenge) = match state
        .arcgis_store
        .create_pending_oauth_session(
            params.client_id,
            params.state,
            params.redirect_uri,
            params.code_challenge,
            portal.clone(),
        )
        .await
    {
        Ok(ids) => ids,
        Err(PendingStoreError::CapacityExceeded) => {
            tracing::warn!("oauth_authorize_continue: pending session capacity exceeded");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "authorization session limit reached"
                })),
            )
                .into_response();
        }
    };

    let server_callback = format!("{}/arcgis/callback", state.mcp_store.app_address);
    let portal_base = portal.portal_url.trim_end_matches('/');
    let arcgis_auth_url = format!(
        "{portal_base}/sharing/rest/oauth2/authorize?client_id={}&response_type=code&redirect_uri={}&state={}&code_challenge={}&code_challenge_method=S256&expiration=20160",
        portal.client_id,
        percent_encode_component(&server_callback),
        arcgis_state_id,
        arcgis_pkce_challenge,
    );

    tracing::debug!(
        "oauth_authorize_continue: redirecting to ArcGIS portal={}",
        portal.key
    );
    Redirect::to(&arcgis_auth_url).into_response()
}

pub async fn oauth_token(
    State(state): State<Arc<OAuthRouteState>>,
    request: axum::http::Request<Body>,
) -> impl IntoResponse {
    let bytes = match axum::body::to_bytes(request.into_body(), OAUTH_TOKEN_MAX_BODY).await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!("can't read request body: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "can't read request body"
                })),
            )
                .into_response();
        }
    };

    let token_req = match serde_urlencoded::from_bytes::<TokenRequest>(&bytes) {
        Ok(form) => {
            tracing::trace!(request = ?form, "parsed token request");
            form
        }
        Err(e) => {
            tracing::error!("can't parse form data: {}", e);
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": format!("can't parse form data: {}", e)
                })),
            )
                .into_response();
        }
    };

    if token_req.grant_type == "refresh_token" {
        tracing::info!("Processing refresh_token grant");

        if token_req.refresh_token.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "refresh_token is required"
                })),
            )
                .into_response();
        }

        match state
            .arcgis_store
            .refresh_access_token(&token_req.refresh_token)
            .await
        {
            Ok((new_access, new_refresh, expires_in)) => {
                tracing::info!("Successfully refreshed access token");
                return (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "access_token": new_access,
                        "token_type": "Bearer",
                        "expires_in": expires_in,
                        "refresh_token": new_refresh,
                    })),
                )
                    .into_response();
            }
            Err(e) => {
                tracing::error!("Failed to refresh token: {}", e);
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_grant",
                        "error_description": e
                    })),
                )
                    .into_response();
            }
        }
    }

    if token_req.grant_type != "authorization_code" {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "unsupported_grant_type",
                "error_description": "only authorization_code and refresh_token are supported"
            })),
        )
            .into_response();
    }

    if !token_req.code.starts_with("mcp-code-") {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "invalid authorization code"
            })),
        )
            .into_response();
    }

    let pending = match state
        .arcgis_store
        .consume_pending_auth_code(&token_req.code)
        .await
    {
        Some(p) => p,
        None => {
            tracing::error!("Auth code not found or already used");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_grant",
                    "error_description": "authorization code not found or already used"
                })),
            )
                .into_response();
        }
    };

    if token_req.client_id != pending.client_id {
        tracing::warn!(
            "oauth_token: client_id mismatch: got={} expected={}",
            token_req.client_id,
            pending.client_id
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_client",
                "error_description": "client_id does not match the authorization request"
            })),
        )
            .into_response();
    }

    if token_req.redirect_uri.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "redirect_uri is required"
            })),
        )
            .into_response();
    }
    if token_req.redirect_uri != pending.mcp_redirect_uri {
        tracing::warn!(
            "oauth_token: redirect_uri mismatch: got={} expected={}",
            token_req.redirect_uri,
            pending.mcp_redirect_uri
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "redirect_uri does not match the authorization request"
            })),
        )
            .into_response();
    }

    if let Some(challenge) = &pending.mcp_code_challenge {
        match &token_req.code_verifier {
            Some(verifier) => {
                let computed = pkce_challenge_from_verifier(verifier);
                if &computed != challenge {
                    tracing::error!("PKCE validation failed");
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": "invalid_grant",
                            "error_description": "PKCE validation failed"
                        })),
                    )
                        .into_response();
                }
                tracing::info!("PKCE validation successful");
            }
            None => {
                tracing::error!("code_verifier required but not provided");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_request",
                        "error_description": "code_verifier required"
                    })),
                )
                    .into_response();
            }
        }
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "missing_pkce_challenge",
                "error_description": "pkce code verification is required"
            })),
        )
            .into_response();
    }

    let expires_in = pending.arcgis_token.expires_in;
    let mcp_access_token = format!("mcp-token-{}", Uuid::new_v4());
    let mcp_refresh_token = format!("mcp-refresh-{}", Uuid::new_v4());

    if let Err(e) = state
        .arcgis_store
        .store_issued_tokens(
            mcp_access_token.clone(),
            mcp_refresh_token.clone(),
            pending.arcgis_token,
            pending.portal,
        )
        .await
    {
        tracing::error!("Failed to store issued tokens: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
                "error_description": "failed to persist token"
            })),
        )
            .into_response();
    }

    tracing::info!("successfully issued mcp access token");
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "access_token": mcp_access_token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "refresh_token": mcp_refresh_token,
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct RegistrationRequest {
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
}

pub async fn oauth_register(
    State(state): State<Arc<OAuthRouteState>>,
    Json(body): Json<RegistrationRequest>,
) -> impl IntoResponse {
    let client_id = Uuid::new_v4().to_string();
    if let Err(err) = state
        .mcp_store
        .register_client(
            client_id.clone(),
            body.redirect_uris.clone(),
            body.client_name.clone(),
        )
        .await
    {
        return match err {
            RegisterError::CapacityExceeded => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "client registration limit reached"
                })),
            )
                .into_response(),
            RegisterError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error": "slow_down",
                    "error_description": "too many registration requests"
                })),
            )
                .into_response(),
            RegisterError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "failed to register client"
                })),
            )
                .into_response(),
        };
    }
    tracing::info!(
        "Dynamic client registration: client_id={}, redirect_uris={:?}",
        client_id,
        body.redirect_uris
    );
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "client_id": client_id,
            "redirect_uris": body.redirect_uris,
            "client_name": body.client_name,
            "token_endpoint_auth_method": "none",
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        Json, Router,
        body::{Body, to_bytes},
        extract::State,
        http::{Request, StatusCode},
        response::IntoResponse,
        routing::post,
    };
    use serde_urlencoded;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use tokio::net::TcpListener;

    use crate::arcgis_auth::{
        ArcGISAuthStore, ArcGISTokenResponse, PortalContext, pkce_challenge_from_verifier,
    };
    use crate::config::{ArcgisPortalConfig, PortalRegistry};
    use crate::oauth::store::{McpOAuthStore, TokenRequest};

    use super::*;

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

    fn test_portal_context(portal_url: &str) -> PortalContext {
        PortalContext::from(&test_portal(portal_url))
    }

    fn sample_arcgis_token() -> ArcGISTokenResponse {
        ArcGISTokenResponse {
            access_token: "arcgis-access-token".into(),
            expires_in: 3600,
            refresh_token: Some("arcgis-refresh-token".into()),
            username: Some("testuser".into()),
        }
    }

    async fn invoke_oauth_token(
        state: Arc<OAuthRouteState>,
        req: TokenRequest,
    ) -> (StatusCode, serde_json::Value) {
        let body = serde_urlencoded::to_string(&req).expect("encode token request");
        let request = Request::builder()
            .method("POST")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .expect("build request");

        let response = oauth_token(State(state), request).await.into_response();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), OAUTH_TOKEN_MAX_BODY)
            .await
            .expect("read response body");
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::json!({}));
        (status, json)
    }

    async fn mock_arcgis_token_server() -> String {
        async fn token_handler() -> impl IntoResponse {
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "access_token": "new-arcgis-access",
                    "expires_in": 7200,
                    "refresh_token": "new-arcgis-refresh",
                    "username": "testuser",
                })),
            )
        }

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock arcgis server");
        let addr = listener.local_addr().expect("mock server address");
        let app = Router::new().route("/sharing/rest/oauth2/token", post(token_handler));
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve mock arcgis server");
        });
        format!("http://{}", addr)
    }

    #[tokio::test]
    async fn oauth_token_authorization_code_and_refresh_happy_path() {
        let portal_url = mock_arcgis_token_server().await;
        let pool = test_pool().await;
        let portal = test_portal(&portal_url);
        let portal_registry = PortalRegistry::from_portals(vec![portal]).expect("portal registry");
        let arcgis_store = Arc::new(ArcGISAuthStore::new(
            pool.clone(),
            "http://localhost:3324".into(),
            portal_registry,
        ));
        let mcp_store = Arc::new(McpOAuthStore::new(pool, "http://localhost:3324"));
        let state = Arc::new(OAuthRouteState {
            mcp_store,
            arcgis_store: arcgis_store.clone(),
        });

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = pkce_challenge_from_verifier(verifier);
        let redirect_uri = "http://localhost/callback".to_string();
        let client_id = "test-client".to_string();
        let auth_code = arcgis_store
            .store_pending_auth_code(
                sample_arcgis_token(),
                client_id.clone(),
                Some(challenge),
                redirect_uri.clone(),
                test_portal_context(&portal_url),
            )
            .await
            .expect("store pending auth code");

        let (status, body) = invoke_oauth_token(
            state.clone(),
            TokenRequest {
                grant_type: "authorization_code".into(),
                code: auth_code,
                client_id: client_id.clone(),
                redirect_uri: redirect_uri.clone(),
                code_verifier: Some(verifier.into()),
                refresh_token: String::new(),
            },
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let access_token = body["access_token"]
            .as_str()
            .expect("access_token in response")
            .to_string();
        let refresh_token = body["refresh_token"]
            .as_str()
            .expect("refresh_token in response")
            .to_string();
        assert_eq!(body["token_type"], "Bearer");
        assert_eq!(body["expires_in"], 3600);
        assert!(arcgis_store.get_token(&access_token).await.is_some());

        let (status, body) = invoke_oauth_token(
            state,
            TokenRequest {
                grant_type: "refresh_token".into(),
                code: String::new(),
                client_id: String::new(),
                redirect_uri: String::new(),
                code_verifier: None,
                refresh_token,
            },
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let new_access = body["access_token"]
            .as_str()
            .expect("refreshed access_token");
        let _new_refresh = body["refresh_token"]
            .as_str()
            .expect("refreshed refresh_token");
        assert_ne!(new_access, access_token);
        assert_eq!(body["expires_in"], 7200);
        assert!(arcgis_store.get_token(new_access).await.is_some());
        assert!(arcgis_store.get_token(&access_token).await.is_none());
    }
}
