//! Vaultlock API server entry point.

use axum::{Router, serve};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use vaultlock_api::{config::Config, router};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialise logging before anything else.
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::from_env();
    info!("starting vaultlock api on {}", config.addr);

    let state = vaultlock_api::state::AppState::new().await;
    let state = Arc::new(state);

    let app = Router::new()
        .merge(router::router(state))
        .layer(TraceLayer::new_for_http());

    let listener = TcpListener::bind(&config.addr).await?;
    info!("listening on {}", config.addr);

    serve(listener, app).await?;

    Ok(())
}
