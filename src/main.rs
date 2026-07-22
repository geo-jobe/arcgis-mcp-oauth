mod arcgis_auth;
mod config;
mod internal;
mod oauth;
mod routes;
mod startup;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "arcgis_mcp_oauth=info,tower_http=info".into()),
        )
        .init();

    let (settings, internal_api_key) =
        config::get_config().expect("Failed to load configuration");

    startup::run(settings, internal_api_key).await;
}
