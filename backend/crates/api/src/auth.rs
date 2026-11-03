//! Authentication endpoints wired to the identity service.

use crate::{error::ErrorEnvelope, state::AppState};
use axum::{
    Router,
    extract::{Json, State},
    http::StatusCode,
    routing::{get, post},
};
use std::sync::Arc;
use vaultlock_common::error::AppError;
use vaultlock_identity::domain::{
    AuthResponse, DeviceAuthPollResponse, DeviceAuthRequest, LoginRequest, RegisterRequest,
    UserView,
};

/// Register a new user.
async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<UserView>), ErrorEnvelope> {
    let service = state.identity.as_ref();
    let user = service.register(req).await.map_err(ErrorEnvelope::from)?;
    Ok((StatusCode::CREATED, Json(user_to_view(&user))))
}

/// Login: email + password -> personal access token.
async fn login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, ErrorEnvelope> {
    let service = state.identity.as_ref();
    let resp = service
        .authenticate(req)
        .await
        .map_err(ErrorEnvelope::from)?;
    Ok(Json(resp))
}

/// Start a device-authorisation flow (CLI login).
async fn start_device_flow(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DeviceAuthRequest>,
) -> Result<Json<DeviceAuthPollResponse>, ErrorEnvelope> {
    let service = state.identity.as_ref();
    let (_auth, poll) = service
        .start_device_flow(req)
        .await
        .map_err(ErrorEnvelope::from)?;
    Ok(Json(poll))
}

/// Get current user profile.
async fn me(State(_state): State<Arc<AppState>>) -> Result<Json<UserView>, ErrorEnvelope> {
    // In a real implementation, extract user_id from the auth token.
    // For the sprint, this is a placeholder.
    Err(ErrorEnvelope::from(AppError::Unauthorised))
}

/// Build the auth router.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/auth/register", post(register))
        .route("/v1/auth/login", post(login))
        .route("/v1/auth/device/start", post(start_device_flow))
        .route("/v1/auth/me", get(me))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn user_to_view(user: &vaultlock_identity::domain::User) -> UserView {
    UserView {
        id: user.id,
        email: user.email.clone(),
        display_name: user.display_name.clone(),
        email_verified: user.email_verified_at.is_some(),
        created_at: user.created_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;
    use uuid::Uuid;
    use vaultlock_identity::domain::{User, UserView};

    #[test]
    fn user_to_view_maps_fields() {
        let user = User {
            id: Uuid::new_v4(),
            email: "a@b.com".into(),
            display_name: Some("A".into()),
            password_hash: None,
            recovery_code_hash: None,
            email_verified_at: Some(OffsetDateTime::now_utc()),
            password_changed_at: Some(OffsetDateTime::now_utc()),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            deleted_at: None,
        };
        let view = user_to_view(&user);
        assert_eq!(view.email, "a@b.com");
        assert!(view.email_verified);
    }
}
