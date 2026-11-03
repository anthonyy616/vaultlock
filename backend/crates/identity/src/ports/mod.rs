//! Repository traits (ports) for identity persistence.

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::{
    Device, DeviceAuthStatus, DeviceAuthorization, EmailToken, EmailTokenKind, Session, User,
};

/// User persistence.
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Insert a new user.
    async fn insert(&self, user: &User) -> vaultlock_common::error::AppResult<()>;
    /// Find by id.
    async fn find_by_id(&self, id: Uuid) -> vaultlock_common::error::AppResult<Option<User>>;
    /// Find by email (case-insensitive, active only).
    async fn find_by_email(&self, email: &str) -> vaultlock_common::error::AppResult<Option<User>>;
    /// Update display name.
    async fn update_display_name(
        &self,
        user_id: Uuid,
        display_name: Option<String>,
    ) -> vaultlock_common::error::AppResult<()>;
    /// Update password hash.
    async fn update_password(
        &self,
        user_id: Uuid,
        password_hash: String,
    ) -> vaultlock_common::error::AppResult<()>;
    /// Mark email verified.
    async fn mark_email_verified(&self, user_id: Uuid) -> vaultlock_common::error::AppResult<()>;
}

/// Session persistence.
#[async_trait]
pub trait SessionRepository: Send + Sync {
    /// Insert a session.
    async fn insert(&self, session: &Session) -> vaultlock_common::error::AppResult<()>;
    /// Find by token hash.
    async fn find_by_token_hash(
        &self,
        token_hash: &[u8],
    ) -> vaultlock_common::error::AppResult<Option<Session>>;
    /// Revoke all sessions for a user except the given one.
    async fn revoke_others(
        &self,
        user_id: &Uuid,
        keep_id: &Uuid,
    ) -> vaultlock_common::error::AppResult<()>;
    /// Revoke all sessions for a user.
    async fn revoke_others_all(&self, user_id: &Uuid) -> vaultlock_common::error::AppResult<()>;
    /// Rotate token hash and expiry for a session.
    async fn rotate_token(
        &self,
        session_id: &Uuid,
        new_token_hash: &[u8],
        expires_at: OffsetDateTime,
    ) -> vaultlock_common::error::AppResult<()>;
    /// Revoke sessions by device.
    async fn revoke_by_device(&self, device_id: Uuid) -> vaultlock_common::error::AppResult<()>;
}

/// Device persistence.
#[async_trait]
pub trait DeviceRepository: Send + Sync {
    /// Insert a device.
    async fn insert(&self, device: &Device) -> vaultlock_common::error::AppResult<()>;
    /// Find by id.
    async fn find_by_id(&self, id: Uuid) -> vaultlock_common::error::AppResult<Option<Device>>;
    /// List devices for a user.
    async fn list_by_user(&self, user_id: Uuid) -> vaultlock_common::error::AppResult<Vec<Device>>;
    /// Revoke a device.
    async fn revoke(&self, device_id: Uuid) -> vaultlock_common::error::AppResult<()>;
}

/// Email token persistence.
#[async_trait]
pub trait EmailTokenRepository: Send + Sync {
    /// Insert a token.
    async fn insert(&self, token: &EmailToken) -> vaultlock_common::error::AppResult<()>;
    /// Find by hash and kind.
    async fn find_by_hash_and_kind(
        &self,
        hash: &[u8],
        kind: EmailTokenKind,
    ) -> vaultlock_common::error::AppResult<Option<EmailToken>>;
    /// Mark a token as used by its raw token value (hashed lookup).
    async fn mark_used(&self, token: String) -> vaultlock_common::error::AppResult<()>;
}

/// Device-authorisation persistence.
#[async_trait]
pub trait DeviceAuthRepository: Send + Sync {
    /// Insert a device authorisation.
    async fn insert(&self, auth: &DeviceAuthorization) -> vaultlock_common::error::AppResult<()>;
    /// Find by id.
    async fn find_by_id(
        &self,
        id: Uuid,
    ) -> vaultlock_common::error::AppResult<Option<DeviceAuthorization>>;
    /// Find by device code hash and user code.
    async fn find_by_codes(
        &self,
        device_code: &str,
        user_code: &str,
    ) -> vaultlock_common::error::AppResult<Option<DeviceAuthorization>>;
    /// Update status and optionally bind a user.
    async fn update_status(
        &self,
        id: Uuid,
        status: DeviceAuthStatus,
        user_id: Option<Uuid>,
    ) -> vaultlock_common::error::AppResult<()>;
}
