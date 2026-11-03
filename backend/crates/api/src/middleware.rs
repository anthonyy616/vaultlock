//! HTTP middleware: request ID, tracing, CORS, auth context.

use axum::http::{Method, header};
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;
use vaultlock_common::error::AppError;

/// Generate a new request ID.
pub fn new() -> String {
    Uuid::new_v4().to_string()
}

/// CORS configuration: permissive in development, tighten in production.
pub fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT])
        .max_age(std::time::Duration::from_secs(86400))
}

/// Authentication extractor: bearer token -> user ID.
/// For v0.1, validates the personal access token hash against the sessions table.
pub async fn auth_from_bearer(token: &str, pool: &sqlx::PgPool) -> Result<uuid::Uuid, AppError> {
    use vaultlock_identity::application;
    use vaultlock_identity::ports::SessionRepository;

    let hash = application::hash_token_bytes(token);
    let repo =
        vaultlock_identity::adapters::SqlxSessionRepository::new(std::sync::Arc::new(pool.clone()));
    let session = repo.find_by_token_hash(&hash).await?;

    let session = session.ok_or(AppError::Unauthorised)?;
    if session.token_kind.to_string() != "personal_access" {
        return Err(AppError::Unauthorised);
    }
    if session.expires_at < time::OffsetDateTime::now_utc() {
        return Err(AppError::Unauthorised);
    }
    if session.revoked_at.is_some() {
        return Err(AppError::Unauthorised);
    }
    Ok(session.user_id)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_is_uuid_string() {
        let id = new();
        assert_eq!(id.len(), 36);
        assert!(id.contains('-'));
    }
}
