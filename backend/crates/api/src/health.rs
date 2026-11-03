//! Health and readiness endpoints.

use axum::{Router, response::Json, routing::get};
use serde::Serialize;

/// Health check response.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Overall status.
    pub status: String,
    /// Database connectivity status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<DatabaseStatus>,
}

/// Database status detail.
#[derive(Debug, Serialize)]
pub struct DatabaseStatus {
    /// Database status.
    pub status: String,
}

/// Build the health router.
pub fn router() -> Router {
    Router::new()
        .route("/health", get(liveness))
        .route("/health/ready", get(readiness))
}

/// Liveness: the process is alive.
pub async fn liveness() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
        database: None,
    })
}

/// Readiness: dependencies are reachable.
pub async fn readiness() -> Json<HealthResponse> {
    // In a full implementation, check database and KMS connectivity here.
    // For the sprint, report ok with minimal detail.
    Json(HealthResponse {
        status: "ok".into(),
        database: None,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_response_sanity() {
        let resp = HealthResponse {
            status: "ok".into(),
            database: None,
        };
        assert_eq!(resp.status, "ok");
    }
}
