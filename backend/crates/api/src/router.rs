//! Top-level API router.

use crate::{auth, health, state::AppState};
use axum::{Router, routing::get};
use std::sync::Arc;
use tower_http::{cors::CorsLayer, trace::TraceLayer};

/// Build the full API router.
pub fn router(state: Arc<AppState>) -> Router {
    Router::<Arc<AppState>>::new()
        .route("/v1/health", get(health::liveness))
        .route("/v1/health/ready", get(health::readiness))
        .nest("/v1/auth", auth::router())
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}
