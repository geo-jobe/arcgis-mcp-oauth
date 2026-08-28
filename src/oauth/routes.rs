use std::collections::HashMap;
use std::sync::Arc;

use askama::Template;
use axum::{
    Form, Json,
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect},
};
use rmcp::transport::auth::AuthorizationMetadata;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::arcgis_auth::{
    ArcGISAuthStore, PendingStoreError, authorization_response_redirect, percent_encode_component,
    pkce_challenge_from_verifier,
};
use crate::config::ArcgisPortalConfig;
use crate::oauth::store::{
    AuthorizeQuery, ClientResolveError, McpOAuthStore, RegisterError, RegisteredClient,
    TokenRequest,
};
use crate::oauth::store::{
    SUPPORTED_SCOPES, canonical_resource_uri, normalize_authorization_scope, normalize_scope,
    scope_string,
};

/// Max bytes for `/oauth/token` form body (grant_type, code, PKCE, redirect_uri, etc.).
const OAUTH_TOKEN_MAX_BODY: usize = 4096;

#[derive(Template)]
#[template(path = "oauth_authorize.html")]
struct AuthorizeTemplate {
    continue_url: String,
    request_id: String,
    csrf_token: String,
    client_id: String,
    client_name: Option<String>,
    client_host: Option<String>,
    redirect_host: String,
    resource: String,
    scopes: Vec<String>,
    portals: Vec<ArcgisPortalConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeDecision {
    pub request_id: String,
    pub csrf_token: String,
    pub portal_key: String,
    pub decision: String,
}

#[derive(Clone)]
pub struct OAuthRouteState {
    pub mcp_store: Arc<McpOAuthStore>,
    pub arcgis_store: Arc<ArcGISAuthStore>,
}

pub async fn oauth_authorization_server(state: State<Arc<OAuthRouteState>>) -> impl IntoResponse {
    let mut additional_fields = HashMap::new();
    additional_fields.insert(
        "grant_types_supported".into(),
        Value::Array(vec![
            Value::String("authorization_code".into()),
            Value::String("refresh_token".into()),
        ]),
    );
    additional_fields.insert(
        "client_id_metadata_document_supported".into(),
        Value::Bool(true),
    );
    additional_fields.insert(
        "authorization_response_iss_parameter_supported".into(),
        Value::Bool(true),
    );
    let address = state.mcp_store.app_address.clone();

    let metadata = AuthorizationMetadata {
        authorization_endpoint: format!("{}/oauth/authorize", address),
        token_endpoint: format!("{}/oauth/token", address),
        scopes_supported: Some(
            SUPPORTED_SCOPES
                .iter()
                .map(|scope| (*scope).into())
                .collect(),
        ),
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
) -> Result<RegisteredClient, (StatusCode, Value)> {
    let registered = match mcp_store.resolve_client(client_id).await {
        Ok(client) => client,
        Err(error) => {
            match &error {
                ClientResolveError::Unknown => {
                    tracing::warn!("oauth authorize: unknown client_id={client_id}");
                }
                ClientResolveError::Metadata(source) => {
                    tracing::warn!(
                        "oauth authorize: rejected CIMD client_id={client_id}: {source}"
                    );
                }
            }
            return Err((
                StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "error": "invalid_client",
                    "error_description": "client_id is not registered or its metadata is invalid"
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

    Ok(registered)
}

pub async fn oauth_authorize(
    Query(params): Query<AuthorizeQuery>,
    State(state): State<Arc<OAuthRouteState>>,
) -> impl IntoResponse {
    tracing::debug!("oauth_authorize, params: {:?}", params);

    let registered =
        match validate_registered_client(&state.mcp_store, &params.client_id, &params.redirect_uri)
            .await
        {
            Ok(registered) => registered,
            Err((status, body)) => return (status, Json(body)).into_response(),
        };

    let resource = match canonical_resource_uri(&params.resource) {
        Ok(resource) => resource,
        Err(description) => {
            return authorization_error_redirect(
                &params.redirect_uri,
                params.state.as_deref(),
                &state.mcp_store.app_address,
                "invalid_target",
                description,
            );
        }
    };
    let scopes = match normalize_authorization_scope(params.scope.as_deref()) {
        Ok(scopes) => scopes,
        Err(description) => {
            return authorization_error_redirect(
                &params.redirect_uri,
                params.state.as_deref(),
                &state.mcp_store.app_address,
                "invalid_scope",
                description,
            );
        }
    };

    if params.response_type != "code" {
        return authorization_error_redirect(
            &params.redirect_uri,
            params.state.as_deref(),
            &state.mcp_store.app_address,
            "unsupported_response_type",
            "only response_type=code is supported",
        );
    }
    let code_challenge = match params.code_challenge {
        Some(challenge)
            if params.code_challenge_method.as_deref() == Some("S256")
                && valid_pkce_challenge(&challenge) =>
        {
            challenge
        }
        _ => {
            return authorization_error_redirect(
                &params.redirect_uri,
                params.state.as_deref(),
                &state.mcp_store.app_address,
                "invalid_request",
                "a valid S256 PKCE code challenge is required",
            );
        }
    };

    let (request_id, csrf_token) = match state
        .arcgis_store
        .create_pending_consent(
            params.client_id.clone(),
            params.state.clone(),
            params.redirect_uri.clone(),
            code_challenge,
            resource.clone(),
            scopes.clone(),
        )
        .await
    {
        Ok(values) => values,
        Err(PendingStoreError::CapacityExceeded) => {
            return authorization_error_redirect(
                &params.redirect_uri,
                params.state.as_deref(),
                &state.mcp_store.app_address,
                "server_error",
                "authorization consent limit reached",
            );
        }
    };

    let continue_url = format!("{}/oauth/authorize/continue", state.mcp_store.app_address);
    let template = AuthorizeTemplate {
        continue_url,
        request_id,
        csrf_token,
        client_id: params.client_id,
        client_name: registered.client_name,
        client_host: registered.metadata_url.as_deref().and_then(url_host),
        redirect_host: url_host(&params.redirect_uri).unwrap_or_else(|| "unknown".into()),
        resource,
        scopes,
        portals: state.arcgis_store.portal_registry().list().to_vec(),
    };

    match template.render() {
        Ok(html) => consent_page_response(html, state.arcgis_store.portal_registry().list()),
        Err(e) => {
            tracing::error!("failed to render authorize template: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn url_host(value: &str) -> Option<String> {
    url::Url::parse(value)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
}

pub async fn oauth_authorize_continue(
    State(state): State<Arc<OAuthRouteState>>,
    Form(params): Form<AuthorizeDecision>,
) -> impl IntoResponse {
    let consent = match state
        .arcgis_store
        .consume_pending_consent(&params.request_id, &params.csrf_token)
        .await
    {
        Some(consent) => consent,
        None => {
            tracing::warn!("oauth consent rejected: missing, expired, replayed, or invalid CSRF");
            return (
                StatusCode::BAD_REQUEST,
                "invalid or expired consent request",
            )
                .into_response();
        }
    };

    if params.decision == "deny" {
        return authorization_error_redirect(
            &consent.mcp_redirect_uri,
            consent.mcp_client_state.as_deref(),
            &state.mcp_store.app_address,
            "access_denied",
            "the user denied the authorization request",
        );
    }
    if params.decision != "allow" {
        return authorization_error_redirect(
            &consent.mcp_redirect_uri,
            consent.mcp_client_state.as_deref(),
            &state.mcp_store.app_address,
            "invalid_request",
            "invalid consent decision",
        );
    }

    let portal = match state.arcgis_store.portal_registry().get(&params.portal_key) {
        Some(portal) => portal.clone(),
        None => {
            tracing::warn!(
                "oauth_authorize_continue: unknown portal_key={}",
                params.portal_key
            );
            return authorization_error_redirect(
                &consent.mcp_redirect_uri,
                consent.mcp_client_state.as_deref(),
                &state.mcp_store.app_address,
                "invalid_request",
                "portal_key is not configured",
            );
        }
    };

    let (arcgis_state_id, arcgis_pkce_challenge) = match state
        .arcgis_store
        .create_pending_oauth_session(
            consent.client_id.clone(),
            consent.mcp_client_state.clone(),
            consent.mcp_redirect_uri.clone(),
            Some(consent.mcp_code_challenge.clone()),
            consent.resource.clone(),
            consent.scopes.clone(),
            portal.clone(),
        )
        .await
    {
        Ok(ids) => ids,
        Err(PendingStoreError::CapacityExceeded) => {
            tracing::warn!("oauth_authorize_continue: pending session capacity exceeded");
            return authorization_error_redirect(
                &consent.mcp_redirect_uri,
                consent.mcp_client_state.as_deref(),
                &state.mcp_store.app_address,
                "server_error",
                "authorization session limit reached",
            );
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

fn valid_pkce_challenge(challenge: &str) -> bool {
    (43..=128).contains(&challenge.len())
        && challenge
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn consent_page_response(html: String, portals: &[ArcgisPortalConfig]) -> axum::response::Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    let portal_origins = portals
        .iter()
        .filter_map(|portal| url::Url::parse(&portal.portal_url).ok())
        .filter(|url| matches!(url.scheme(), "http" | "https"))
        .map(|url| url.origin().ascii_serialization())
        .collect::<Vec<_>>()
        .join(" ");
    let content_security_policy = format!(
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' {portal_origins}; frame-ancestors 'none'; base-uri 'none'"
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&content_security_policy)
            .expect("URL origins must produce a valid CSP header"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    (headers, Html(html)).into_response()
}

fn authorization_error_redirect(
    redirect_uri: &str,
    state: Option<&str>,
    issuer: &str,
    error: &str,
    description: &str,
) -> axum::response::Response {
    authorization_response_redirect(
        redirect_uri,
        issuer,
        &[("error", error), ("error_description", description)],
        state,
    )
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

    let resource = match canonical_resource_uri(&token_req.resource) {
        Ok(resource) => resource,
        Err(description) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_target",
                    "error_description": description
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

        let requested_scopes = match token_req.scope.as_deref().map(normalize_scope).transpose() {
            Ok(scopes) => scopes,
            Err(description) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_scope",
                        "error_description": description
                    })),
                )
                    .into_response();
            }
        };

        match state
            .arcgis_store
            .refresh_access_token(
                &token_req.refresh_token,
                &token_req.client_id,
                &resource,
                requested_scopes.as_deref(),
            )
            .await
        {
            Ok((new_access, new_refresh, expires_in, scopes)) => {
                tracing::info!("Successfully refreshed access token");
                return (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "access_token": new_access,
                        "token_type": "Bearer",
                        "expires_in": expires_in,
                        "refresh_token": new_refresh,
                        "scope": scope_string(&scopes),
                    })),
                )
                    .into_response();
            }
            Err(e) => {
                tracing::error!("Failed to refresh token: {}", e);
                let error = if e == "resource does not match refresh token" {
                    "invalid_target"
                } else if e == "requested scope exceeds original grant" {
                    "invalid_scope"
                } else {
                    "invalid_grant"
                };
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": error,
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

    if resource != pending.resource {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_target",
                "error_description": "resource does not match the authorization request"
            })),
        )
            .into_response();
    }

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

    let mcp_access_token = format!("mcp-token-{}", Uuid::new_v4());
    let mcp_refresh_token = format!("mcp-refresh-{}", Uuid::new_v4());

    let expires_in = match state
        .arcgis_store
        .store_issued_tokens(
            mcp_access_token.clone(),
            mcp_refresh_token.clone(),
            pending.arcgis_token,
            pending.client_id,
            pending.portal,
            pending.resource,
            pending.scopes.clone(),
        )
        .await
    {
        Ok(expires_in) => expires_in,
        Err(e) => {
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
    };

    tracing::info!("successfully issued mcp access token");
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "access_token": mcp_access_token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "refresh_token": mcp_refresh_token,
            "scope": scope_string(&pending.scopes),
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
        http::{Request, StatusCode, header::LOCATION},
        response::IntoResponse,
        routing::post,
    };
    use serde_urlencoded;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use tokio::net::TcpListener;
    use tower::ServiceExt;

    use crate::arcgis_auth::{
        ArcGISAuthStore, ArcGISTokenResponse, PortalContext, pkce_challenge_from_verifier,
    };
    use crate::config::{ArcgisPortalConfig, PortalRegistry};
    use crate::oauth::client_metadata::ClientMetadataPolicy;
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
            refresh_token: "arcgis-refresh-token".into(),
            refresh_token_expires_in: 1_209_600,
            username: Some("testuser".into()),
            ssl: Some(true),
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
                    "username": "testuser",
                    "ssl": true,
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

    fn authorize_query(
        redirect_uri: &str,
        state: &str,
        challenge: &str,
    ) -> crate::oauth::store::AuthorizeQuery {
        crate::oauth::store::AuthorizeQuery {
            response_type: "code".into(),
            client_id: "test-client".into(),
            redirect_uri: redirect_uri.into(),
            resource: "https://mcp.example.com/mcp".into(),
            scope: Some("profile".into()),
            state: Some(state.into()),
            code_challenge: Some(challenge.into()),
            code_challenge_method: Some("S256".into()),
        }
    }

    fn form_value(html: &str, name: &str) -> String {
        let marker = format!("name=\"{name}\" value=\"");
        html.split_once(&marker)
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(value, _)| value.to_string())
            .unwrap_or_else(|| panic!("missing form value {name}"))
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
        let resource = "http://localhost:3325/mcp".to_string();
        let client_id = "test-client".to_string();
        let mismatched_code = arcgis_store
            .store_pending_auth_code(
                sample_arcgis_token(),
                client_id.clone(),
                Some(challenge.clone()),
                redirect_uri.clone(),
                resource.clone(),
                vec!["profile".into()],
                test_portal_context(&portal_url),
            )
            .await
            .expect("store mismatched pending auth code");
        let (status, body) = invoke_oauth_token(
            state.clone(),
            TokenRequest {
                grant_type: "authorization_code".into(),
                code: mismatched_code,
                client_id: client_id.clone(),
                redirect_uri: redirect_uri.clone(),
                code_verifier: Some(verifier.into()),
                refresh_token: String::new(),
                resource: "http://localhost:9999/mcp".into(),
                scope: None,
            },
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_target");

        let auth_code = arcgis_store
            .store_pending_auth_code(
                sample_arcgis_token(),
                client_id.clone(),
                Some(challenge),
                redirect_uri.clone(),
                resource.clone(),
                vec!["profile".into()],
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
                resource: resource.clone(),
                scope: None,
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
        assert_eq!(body["scope"], "profile");
        let stored = arcgis_store
            .resolve_session(&access_token, &resource)
            .await
            .into_active()
            .expect("stored access token");
        assert_eq!(stored.scopes, ["profile"]);
        assert!(
            arcgis_store
                .resolve_session(&access_token, "http://localhost:9999/mcp")
                .await
                .into_active()
                .is_none()
        );

        let (status, body) = invoke_oauth_token(
            state.clone(),
            TokenRequest {
                grant_type: "refresh_token".into(),
                code: String::new(),
                client_id: client_id.clone(),
                redirect_uri: String::new(),
                code_verifier: None,
                refresh_token: refresh_token.clone(),
                resource: "http://localhost:9999/mcp".into(),
                scope: None,
            },
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_target");
        assert!(
            arcgis_store
                .resolve_session(&access_token, &resource)
                .await
                .into_active()
                .is_some()
        );

        let (status, body) = invoke_oauth_token(
            state.clone(),
            TokenRequest {
                grant_type: "refresh_token".into(),
                code: String::new(),
                client_id: client_id.clone(),
                redirect_uri: String::new(),
                code_verifier: None,
                refresh_token: refresh_token.clone(),
                resource: resource.clone(),
                scope: Some("profile email".into()),
            },
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_scope");
        assert!(
            arcgis_store
                .resolve_session(&access_token, &resource)
                .await
                .into_active()
                .is_some()
        );

        let (status, body) = invoke_oauth_token(
            state,
            TokenRequest {
                grant_type: "refresh_token".into(),
                code: String::new(),
                client_id,
                redirect_uri: String::new(),
                code_verifier: None,
                refresh_token,
                resource: resource.clone(),
                scope: None,
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
        assert_eq!(body["expires_in"], 3600);
        assert_eq!(body["scope"], "profile");
        assert!(
            arcgis_store
                .resolve_session(new_access, &resource)
                .await
                .into_active()
                .is_some()
        );
        assert!(
            arcgis_store
                .resolve_session(&access_token, &resource)
                .await
                .into_active()
                .is_some()
        );
    }

    #[tokio::test]
    async fn metadata_and_redirect_error_use_the_same_issuer() {
        let issuer = "https://auth.example.com";
        let pool = test_pool().await;
        let portal_registry =
            PortalRegistry::from_portals(vec![test_portal("https://portal.example.com")])
                .expect("portal registry");
        let arcgis_store = Arc::new(ArcGISAuthStore::new(
            pool.clone(),
            issuer.into(),
            portal_registry,
        ));
        let mcp_store = Arc::new(McpOAuthStore::new(pool, issuer));
        let redirect_uri = "https://client.example.com/callback?tenant=one";
        mcp_store
            .register_client("test-client".into(), vec![redirect_uri.into()], None)
            .await
            .expect("register client");
        let state = Arc::new(OAuthRouteState {
            mcp_store,
            arcgis_store,
        });

        let metadata_response = oauth_authorization_server(State(state.clone()))
            .await
            .into_response();
        let metadata_bytes = to_bytes(metadata_response.into_body(), 4096)
            .await
            .expect("read metadata");
        let metadata: serde_json::Value =
            serde_json::from_slice(&metadata_bytes).expect("parse metadata");
        assert_eq!(metadata["issuer"], issuer);
        assert_eq!(metadata["client_id_metadata_document_supported"], true);
        assert_eq!(
            metadata["authorization_response_iss_parameter_supported"],
            true
        );

        let (request_id, csrf_token) = state
            .arcgis_store
            .create_pending_consent(
                "test-client".into(),
                Some("state +&=".into()),
                redirect_uri.into(),
                pkce_challenge_from_verifier("test-verifier"),
                "https://mcp.example.com/mcp".into(),
                vec!["profile".into()],
            )
            .await
            .expect("create pending consent");
        let response = oauth_authorize_continue(
            State(state.clone()),
            Form(AuthorizeDecision {
                request_id,
                csrf_token,
                portal_key: "unknown-portal".into(),
                decision: "allow".into(),
            }),
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
        assert!(pairs.contains(&("tenant".into(), "one".into())));
        assert!(pairs.contains(&("error".into(), "invalid_request".into())));
        assert!(pairs.contains(&("state".into(), "state +&=".into())));
        assert!(pairs.contains(&("iss".into(), issuer.into())));
    }

    #[tokio::test]
    async fn consent_requires_valid_csrf_and_explicit_allow_or_deny() {
        let issuer = "https://auth.example.com";
        let redirect_uri = "https://client.example.com/callback?tenant=one";
        let pool = test_pool().await;
        let portal_registry =
            PortalRegistry::from_portals(vec![test_portal("https://portal.example.com")])
                .expect("portal registry");
        let mcp_store = Arc::new(McpOAuthStore::new(pool.clone(), issuer));
        mcp_store
            .register_client(
                "test-client".into(),
                vec![redirect_uri.into()],
                Some("Example <script>Client</script>".into()),
            )
            .await
            .expect("register client");
        let state = Arc::new(OAuthRouteState {
            mcp_store,
            arcgis_store: Arc::new(ArcGISAuthStore::new(pool, issuer.into(), portal_registry)),
        });
        let challenge = pkce_challenge_from_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

        let page = oauth_authorize(
            Query(authorize_query(redirect_uri, "allow-state", &challenge)),
            State(state.clone()),
        )
        .await
        .into_response();
        assert_eq!(page.status(), StatusCode::OK);
        assert_eq!(page.headers()[header::CACHE_CONTROL], "no-store");
        let content_security_policy = page.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .expect("CSP");
        assert!(content_security_policy.contains("form-action 'self' https://portal.example.com;"));
        let html = String::from_utf8(
            to_bytes(page.into_body(), 32_768)
                .await
                .expect("read consent page")
                .to_vec(),
        )
        .expect("UTF-8 consent page");
        assert!(html.contains("Example"));
        assert!(!html.contains("<script>Client</script>"));
        assert!(html.contains("https://mcp.example.com/mcp"));
        assert!(html.contains("Test Portal"));
        assert!(html.contains("value=\"allow\""));
        assert!(html.contains("value=\"deny\""));
        assert!(!html.contains("name=\"client_id\""));
        assert!(!html.contains("name=\"redirect_uri\""));
        assert!(!html.contains("name=\"resource\""));
        assert!(!html.contains("name=\"scope\""));
        assert!(!html.contains("name=\"state\""));
        assert!(!html.contains("name=\"code_challenge\""));
        let request_id = form_value(&html, "request_id");
        let csrf_token = form_value(&html, "csrf_token");

        let invalid_csrf = oauth_authorize_continue(
            State(state.clone()),
            Form(AuthorizeDecision {
                request_id: request_id.clone(),
                csrf_token: "wrong-token".into(),
                portal_key: "test-portal".into(),
                decision: "allow".into(),
            }),
        )
        .await
        .into_response();
        assert_eq!(invalid_csrf.status(), StatusCode::BAD_REQUEST);
        assert!(!invalid_csrf.headers().contains_key(LOCATION));

        let tampered_body = serde_urlencoded::to_string([
            ("request_id", request_id.as_str()),
            ("csrf_token", csrf_token.as_str()),
            ("portal_key", "test-portal"),
            ("decision", "allow"),
            ("client_id", "attacker-client"),
        ])
        .expect("encode tampered consent");
        let app = Router::new()
            .route("/oauth/authorize/continue", post(oauth_authorize_continue))
            .with_state(state.clone());
        let tampered = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/authorize/continue")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(tampered_body))
                    .expect("build tampered request"),
            )
            .await
            .expect("submit tampered request");
        assert_eq!(tampered.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(!tampered.headers().contains_key(LOCATION));

        let allowed = oauth_authorize_continue(
            State(state.clone()),
            Form(AuthorizeDecision {
                request_id: request_id.clone(),
                csrf_token: csrf_token.clone(),
                portal_key: "test-portal".into(),
                decision: "allow".into(),
            }),
        )
        .await
        .into_response();
        assert_eq!(allowed.status(), StatusCode::SEE_OTHER);
        let location = allowed.headers()[LOCATION].to_str().expect("location");
        let arcgis_url = url::Url::parse(location).expect("parse ArcGIS redirect");
        assert_eq!(arcgis_url.host_str(), Some("portal.example.com"));
        assert_eq!(
            arcgis_url
                .query_pairs()
                .find(|(name, _)| name == "code_challenge_method")
                .map(|(_, value)| value.into_owned()),
            Some("S256".into())
        );
        let arcgis_state = arcgis_url
            .query_pairs()
            .find(|(name, _)| name == "state")
            .map(|(_, value)| value.into_owned())
            .expect("ArcGIS state");
        let pending = state
            .arcgis_store
            .consume_pending_oauth_session(&arcgis_state)
            .await
            .expect("bound ArcGIS session");
        assert_eq!(pending.client_id, "test-client");
        assert_eq!(pending.mcp_client_state.as_deref(), Some("allow-state"));
        assert_eq!(pending.mcp_redirect_uri, redirect_uri);
        assert_eq!(
            pending.mcp_code_challenge.as_deref(),
            Some(challenge.as_str())
        );
        assert_eq!(pending.resource, "https://mcp.example.com/mcp");
        assert_eq!(pending.scopes, ["profile"]);
        assert_eq!(pending.portal.key, "test-portal");

        let replay = oauth_authorize_continue(
            State(state.clone()),
            Form(AuthorizeDecision {
                request_id,
                csrf_token,
                portal_key: "test-portal".into(),
                decision: "allow".into(),
            }),
        )
        .await
        .into_response();
        assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
        assert!(!replay.headers().contains_key(LOCATION));

        let deny_page = oauth_authorize(
            Query(authorize_query(redirect_uri, "deny +&= state", &challenge)),
            State(state.clone()),
        )
        .await
        .into_response();
        let deny_html = String::from_utf8(
            to_bytes(deny_page.into_body(), 32_768)
                .await
                .expect("read deny page")
                .to_vec(),
        )
        .expect("UTF-8 deny page");
        let denied = oauth_authorize_continue(
            State(state),
            Form(AuthorizeDecision {
                request_id: form_value(&deny_html, "request_id"),
                csrf_token: form_value(&deny_html, "csrf_token"),
                portal_key: "test-portal".into(),
                decision: "deny".into(),
            }),
        )
        .await
        .into_response();
        assert_eq!(denied.status(), StatusCode::SEE_OTHER);
        let denied_url = url::Url::parse(
            denied.headers()[LOCATION]
                .to_str()
                .expect("denial location"),
        )
        .expect("parse denial redirect");
        let denied_pairs: HashMap<_, _> = denied_url.query_pairs().into_owned().collect();
        assert_eq!(denied_url.host_str(), Some("client.example.com"));
        assert_eq!(denied_pairs.get("tenant").map(String::as_str), Some("one"));
        assert_eq!(
            denied_pairs.get("error").map(String::as_str),
            Some("access_denied")
        );
        assert_eq!(
            denied_pairs.get("state").map(String::as_str),
            Some("deny +&= state")
        );
        assert_eq!(denied_pairs.get("iss").map(String::as_str), Some(issuer));
    }

    #[tokio::test]
    async fn authorize_does_not_redirect_to_unvalidated_uri() {
        let pool = test_pool().await;
        let portal_registry =
            PortalRegistry::from_portals(vec![test_portal("https://portal.example.com")])
                .expect("portal registry");
        let mcp_store = Arc::new(McpOAuthStore::new(pool.clone(), "https://auth.example.com"));
        mcp_store
            .register_client(
                "test-client".into(),
                vec!["https://client.example.com/callback".into()],
                None,
            )
            .await
            .expect("register client");
        let state = Arc::new(OAuthRouteState {
            mcp_store,
            arcgis_store: Arc::new(ArcGISAuthStore::new(
                pool,
                "https://auth.example.com".into(),
                portal_registry,
            )),
        });

        let response = oauth_authorize(
            Query(crate::oauth::store::AuthorizeQuery {
                response_type: "code".into(),
                client_id: "unknown-client".into(),
                redirect_uri: "https://attacker.example.com/callback".into(),
                resource: "https://mcp.example.com/mcp".into(),
                scope: None,
                state: Some("client-state".into()),
                code_challenge: None,
                code_challenge_method: None,
            }),
            State(state.clone()),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!response.headers().contains_key(LOCATION));

        let response = oauth_authorize(
            Query(crate::oauth::store::AuthorizeQuery {
                response_type: "code".into(),
                client_id: "test-client".into(),
                redirect_uri: "https://client.example.com/callback".into(),
                resource: "https://mcp.example.com/mcp".into(),
                scope: Some("email".into()),
                state: Some("client-state".into()),
                code_challenge: None,
                code_challenge_method: None,
            }),
            State(state.clone()),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers()[LOCATION].to_str().expect("location");
        assert!(location.contains("error=invalid_scope"));

        let response = oauth_authorize(
            Query(crate::oauth::store::AuthorizeQuery {
                response_type: "code".into(),
                client_id: "test-client".into(),
                redirect_uri: "https://attacker.example.com/callback".into(),
                resource: "https://mcp.example.com/mcp".into(),
                scope: None,
                state: Some("client-state".into()),
                code_challenge: None,
                code_challenge_method: None,
            }),
            State(state.clone()),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!response.headers().contains_key(LOCATION));

        let response = oauth_authorize(
            Query(crate::oauth::store::AuthorizeQuery {
                response_type: "code".into(),
                client_id: "test-client".into(),
                redirect_uri: "https://client.example.com/callback".into(),
                resource: String::new(),
                scope: None,
                state: Some("client-state".into()),
                code_challenge: None,
                code_challenge_method: None,
            }),
            State(state),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers()[LOCATION].to_str().expect("location");
        assert!(location.contains("error=invalid_target"));
    }

    #[tokio::test]
    async fn cimd_client_authorizes_without_dcr_and_rejects_redirect_mismatch() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind metadata server");
        let client_id = format!(
            "http://{}/client.json",
            listener.local_addr().expect("metadata server address")
        );
        let redirect_uri = "http://127.0.0.1:3210/callback";
        let document = serde_json::json!({
            "client_id": client_id,
            "client_name": "CIMD Test Client",
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none"
        });
        let app = Router::new().route(
            "/client.json",
            axum::routing::get(move || {
                let document = document.clone();
                async move {
                    (
                        [(header::CONTENT_TYPE, "application/json")],
                        document.to_string(),
                    )
                }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve metadata document");
        });

        let pool = test_pool().await;
        let portal_registry =
            PortalRegistry::from_portals(vec![test_portal("https://portal.example.com")])
                .expect("portal registry");
        let mcp_store = Arc::new(McpOAuthStore::with_client_metadata_policy(
            pool.clone(),
            "https://auth.example.com",
            ClientMetadataPolicy {
                allow_private_addresses: true,
            },
        ));
        let state = Arc::new(OAuthRouteState {
            mcp_store,
            arcgis_store: Arc::new(ArcGISAuthStore::new(
                pool,
                "https://auth.example.com".into(),
                portal_registry,
            )),
        });
        let challenge = pkce_challenge_from_verifier("test-verifier");
        let query = |redirect_uri: &str| AuthorizeQuery {
            response_type: "code".into(),
            client_id: client_id.clone(),
            redirect_uri: redirect_uri.into(),
            resource: "https://mcp.example.com/mcp".into(),
            scope: Some("profile".into()),
            state: Some("client-state".into()),
            code_challenge: Some(challenge.clone()),
            code_challenge_method: Some("S256".into()),
        };

        let valid = oauth_authorize(Query(query(redirect_uri)), State(state.clone()))
            .await
            .into_response();
        assert_eq!(valid.status(), StatusCode::OK);
        let html = String::from_utf8(
            to_bytes(valid.into_body(), 32_768)
                .await
                .expect("read consent page")
                .to_vec(),
        )
        .expect("consent page UTF-8");
        assert!(html.contains("CIMD Test Client"));
        assert!(html.contains("Redirect host:"));
        assert!(!html.contains("Continue only if you started the connection"));

        let mismatch =
            oauth_authorize(Query(query("http://127.0.0.1:3211/callback")), State(state))
                .await
                .into_response();
        assert_eq!(mismatch.status(), StatusCode::BAD_REQUEST);
        assert!(!mismatch.headers().contains_key(LOCATION));
    }
}
