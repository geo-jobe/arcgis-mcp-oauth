use std::any::Any;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::{
    Json, Router,
    http::{
        Method, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
use tower_http::catch_panic::{CatchPanicLayer, ResponseForPanic};
use tower_http::cors::{Any as CorsAny, CorsLayer};

use crate::arcgis_auth::{ArcGISAuthStore, arcgis_callback};
use crate::config::Settings;
use crate::internal::{InternalRouteState, internal_session};
use crate::oauth::routes::{
    OAuthRouteState, oauth_authorization_server, oauth_authorize, oauth_authorize_continue,
    oauth_register, oauth_token,
};
use crate::oauth::store::McpOAuthStore;
use crate::routes::health_check;

#[derive(Clone)]
struct PanicHandler;

fn panic_message(err: Box<dyn Any + Send + 'static>) -> String {
    if let Some(s) = err.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = err.downcast_ref::<&str>() {
        s.to_string()
    } else {
        format!("{err:?}")
    }
}

impl ResponseForPanic for PanicHandler {
    type ResponseBody = Body;

    fn response_for_panic(
        &mut self,
        err: Box<dyn Any + Send + 'static>,
    ) -> Response<Self::ResponseBody> {
        tracing::error!(message = %panic_message(err), "request handler panicked");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
                "error_description": "Internal server error"
            })),
        )
            .into_response()
    }
}

// ponytail: origins stay Any for MCP clients from arbitrary hosts; methods/headers
// are allowlisted; no cookies/credentials (bearer tokens only).
fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(CorsAny)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE])
}

pub async fn run(settings: Settings, internal_api_key: String) {
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://./data/auth.db".to_string());

    if let Some(path) = database_url.strip_prefix("sqlite://")
        && let Some(parent) = std::path::Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).expect("Failed to create database directory");
    }

    let connect_opts = database_url
        .parse::<SqliteConnectOptions>()
        .expect("Invalid DATABASE_URL")
        .journal_mode(SqliteJournalMode::Wal)
        .create_if_missing(true);

    let pool = SqlitePool::connect_with(connect_opts)
        .await
        .expect("Failed to connect to SQLite database");

    sqlx::migrate!()
        .run(&pool)
        .await
        .expect("Failed to run database migrations");

    tracing::info!("Database migrations applied");

    let public_base_url = settings.public_base_url.clone();
    let portal_registry = settings
        .portal_registry()
        .expect("Invalid arcgis_portals configuration");

    let mcp_store = Arc::new(McpOAuthStore::new(pool.clone(), &public_base_url));
    let arcgis_store = Arc::new(ArcGISAuthStore::new(
        pool,
        public_base_url.clone(),
        portal_registry,
    ));

    let sweep_store = arcgis_store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            sweep_store.sweep_expired().await;
        }
    });

    let oauth_route_state = Arc::new(OAuthRouteState {
        mcp_store: mcp_store.clone(),
        arcgis_store: arcgis_store.clone(),
    });

    let internal_state = Arc::new(InternalRouteState {
        oauth: oauth_route_state.clone(),
        internal_api_key: Arc::new(internal_api_key),
    });

    let cors_layer = cors_layer();

    let oauth_server_router = Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth_authorization_server).options(oauth_authorization_server),
        )
        .route("/oauth/token", post(oauth_token).options(oauth_token))
        .layer(cors_layer.clone())
        .with_state(oauth_route_state.clone());

    let arcgis_auth_router = Router::new()
        .route("/arcgis/callback", get(arcgis_callback))
        .with_state(arcgis_store);

    let internal_router = Router::new()
        .route("/internal/session", get(internal_session))
        .with_state(internal_state);

    let router = Router::new()
        .route("/health", get(health_check))
        .route("/oauth/authorize", get(oauth_authorize))
        .route("/oauth/authorize/continue", post(oauth_authorize_continue))
        .route("/oauth/register", post(oauth_register))
        .merge(oauth_server_router)
        .merge(arcgis_auth_router)
        .merge(internal_router)
        .with_state(oauth_route_state)
        .layer(cors_layer)
        .layer(CatchPanicLayer::custom(PanicHandler));

    let address = settings.socket_address().expect("Invalid bind address");
    tracing::info!("Auth server starting on {}", address);

    let listener = tokio::net::TcpListener::bind(address)
        .await
        .expect("Failed to bind to address");
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("Server failed");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Shutdown signal received, draining in-flight requests");
}
