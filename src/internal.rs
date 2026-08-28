use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Serialize;

use crate::arcgis_auth::{
    ArcGISAccessTokenResponse, ArcGISAuthStore, PortalContext, SessionResolution,
};
use crate::oauth::routes::OAuthRouteState;

#[derive(Clone)]
pub struct InternalRouteState {
    pub oauth: Arc<OAuthRouteState>,
    pub internal_api_key: Arc<String>,
}

#[derive(Serialize)]
struct SessionResponse {
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    arcgis_token: Option<ArcGISAccessTokenResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    portal: Option<PortalContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scopes: Option<Vec<String>>,
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn extract_internal_key(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
}

fn extract_mcp_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("X-MCP-Access-Token")
        .and_then(|v| v.to_str().ok())
}

fn extract_resource(headers: &HeaderMap) -> Option<&str> {
    headers.get("X-MCP-Resource").and_then(|v| v.to_str().ok())
}

pub async fn internal_session(
    State(state): State<Arc<InternalRouteState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let provided_key = match extract_internal_key(&headers) {
        Some(key) => key,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(SessionResponse {
                    active: false,
                    expires_at: None,
                    arcgis_token: None,
                    portal: None,
                    resource: None,
                    scopes: None,
                }),
            );
        }
    };

    if !constant_time_eq(provided_key, state.internal_api_key.as_str()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(SessionResponse {
                active: false,
                expires_at: None,
                arcgis_token: None,
                portal: None,
                resource: None,
                scopes: None,
            }),
        );
    }

    let mcp_token = match extract_mcp_token(&headers) {
        Some(token) if !token.is_empty() => token,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SessionResponse {
                    active: false,
                    expires_at: None,
                    arcgis_token: None,
                    portal: None,
                    resource: None,
                    scopes: None,
                }),
            );
        }
    };

    let resource = match extract_resource(&headers)
        .and_then(|value| crate::oauth::store::canonical_resource_uri(value).ok())
    {
        Some(resource) => resource,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SessionResponse {
                    active: false,
                    expires_at: None,
                    arcgis_token: None,
                    portal: None,
                    resource: None,
                    scopes: None,
                }),
            );
        }
    };

    let store: &ArcGISAuthStore = &state.oauth.arcgis_store;
    match store.resolve_session(mcp_token, &resource).await {
        SessionResolution::Active(record) => {
            let record = *record;
            (
                StatusCode::OK,
                Json(SessionResponse {
                    active: true,
                    expires_at: Some(record.expires_at),
                    arcgis_token: Some(record.arcgis_token),
                    portal: Some(record.portal),
                    resource: Some(record.resource),
                    scopes: Some(record.scopes),
                }),
            )
        }
        SessionResolution::Inactive => (
            StatusCode::NOT_FOUND,
            Json(SessionResponse {
                active: false,
                expires_at: None,
                arcgis_token: None,
                portal: None,
                resource: None,
                scopes: None,
            }),
        ),
        SessionResolution::TemporarilyUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(SessionResponse {
                active: false,
                expires_at: None,
                arcgis_token: None,
                portal: None,
                resource: None,
                scopes: None,
            }),
        ),
        SessionResolution::RateLimited => empty_session_response(StatusCode::TOO_MANY_REQUESTS),
    }
}

pub async fn internal_session_refresh(
    State(state): State<Arc<InternalRouteState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let provided_key = match extract_internal_key(&headers) {
        Some(key) => key,
        None => return empty_session_response(StatusCode::UNAUTHORIZED),
    };
    if !constant_time_eq(provided_key, state.internal_api_key.as_str()) {
        return empty_session_response(StatusCode::UNAUTHORIZED);
    }
    let mcp_token = match extract_mcp_token(&headers) {
        Some(token) if !token.is_empty() => token,
        _ => return empty_session_response(StatusCode::BAD_REQUEST),
    };
    let resource = match extract_resource(&headers)
        .and_then(|value| crate::oauth::store::canonical_resource_uri(value).ok())
    {
        Some(resource) => resource,
        None => return empty_session_response(StatusCode::BAD_REQUEST),
    };

    tracing::info_span!("internal.session.force_refresh").in_scope(
        || tracing::info!(resource = %resource, "forcing ArcGIS access credential refresh"),
    );
    session_resolution_response(
        state
            .oauth
            .arcgis_store
            .force_refresh_session(mcp_token, &resource)
            .await,
    )
}

fn session_resolution_response(
    resolution: SessionResolution,
) -> (StatusCode, Json<SessionResponse>) {
    match resolution {
        SessionResolution::Active(record) => {
            let record = *record;
            (
                StatusCode::OK,
                Json(SessionResponse {
                    active: true,
                    expires_at: Some(record.expires_at),
                    arcgis_token: Some(record.arcgis_token),
                    portal: Some(record.portal),
                    resource: Some(record.resource),
                    scopes: Some(record.scopes),
                }),
            )
        }
        SessionResolution::Inactive => empty_session_response(StatusCode::NOT_FOUND),
        SessionResolution::TemporarilyUnavailable => {
            empty_session_response(StatusCode::SERVICE_UNAVAILABLE)
        }
        SessionResolution::RateLimited => empty_session_response(StatusCode::TOO_MANY_REQUESTS),
    }
}

fn empty_session_response(status: StatusCode) -> (StatusCode, Json<SessionResponse>) {
    (
        status,
        Json(SessionResponse {
            active: false,
            expires_at: None,
            arcgis_token: None,
            portal: None,
            resource: None,
            scopes: None,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::{SessionResponse, constant_time_eq};

    #[test]
    fn constant_time_eq_equal_strings() {
        assert!(constant_time_eq("secret-key", "secret-key"));
    }

    #[test]
    fn constant_time_eq_unequal_same_length() {
        assert!(!constant_time_eq("secret-key", "secret-kex"));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq("short", "longer-string"));
    }

    #[test]
    fn constant_time_eq_both_empty() {
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn session_response_exposes_granted_scopes() {
        let value = serde_json::to_value(SessionResponse {
            active: true,
            expires_at: None,
            arcgis_token: None,
            portal: None,
            resource: Some("https://mcp.example.com/mcp".into()),
            scopes: Some(vec!["profile".into()]),
        })
        .expect("serialize session response");

        assert_eq!(value["scopes"], serde_json::json!(["profile"]));
        assert!(value.get("arcgis_token").is_none());
    }
}
