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

use crate::arcgis_auth::{ArcGISAuthStore, percent_encode_component, pkce_challenge_from_verifier};
use crate::config::ArcgisPortalConfig;
use crate::oauth::store::{AuthorizeQuery, McpOAuthStore, TokenRequest};

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

    let (arcgis_state_id, arcgis_pkce_challenge) = state
        .arcgis_store
        .create_pending_oauth_session(
            params.client_id,
            params.state,
            params.redirect_uri,
            params.code_challenge,
            portal.clone(),
        )
        .await;

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
    let bytes = match axum::body::to_bytes(request.into_body(), usize::MAX).await {
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
        Ok(form) => form,
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
            tracing::error!("Auth code not found: {}", token_req.code);
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

    state
        .arcgis_store
        .store_token(
            mcp_access_token.clone(),
            pending.arcgis_token,
            pending.portal,
        )
        .await;
    state
        .arcgis_store
        .store_refresh_token(mcp_refresh_token.clone(), mcp_access_token.clone())
        .await;

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
    state
        .mcp_store
        .register_client(
            client_id.clone(),
            body.redirect_uris.clone(),
            body.client_name.clone(),
        )
        .await;
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
}
