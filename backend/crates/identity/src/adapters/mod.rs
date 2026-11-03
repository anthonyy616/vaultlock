//! SQLx adapter implementations for identity repositories.

use async_trait::async_trait;
use sqlx::PgPool;
use std::sync::Arc;

use crate::domain::{
    Device, DeviceAuthStatus, DeviceAuthorization, EmailToken, EmailTokenKind, Session, User,
};
use crate::ports::{
    DeviceAuthRepository, DeviceRepository, EmailTokenRepository, SessionRepository, UserRepository,
};
use uuid::Uuid;
use vaultlock_common::error::AppResult;

/// SQLx-backed user repository.
pub struct SqlxUserRepository {
    pool: Arc<PgPool>,
}

impl SqlxUserRepository {
    /// Create a new SQLx-backed user repository.
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for SqlxUserRepository {
    async fn insert(&self, user: &User) -> AppResult<()> {
        sqlx::query(
            "insert into users (id, email, display_name, password_hash, recovery_code_hash, email_verified_at, password_changed_at, created_at, updated_at, deleted_at)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(user.id)
        .bind(&user.email)
        .bind(&user.display_name)
        .bind(&user.password_hash)
        .bind(&user.recovery_code_hash)
        .bind(user.email_verified_at)
        .bind(user.password_changed_at)
        .bind(user.created_at)
        .bind(user.updated_at)
        .bind(user.deleted_at)
        .execute(&*self.pool)
        .await
        .map_err(vaultlock_common::error::AppError::from)?;
        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> AppResult<Option<User>> {
        let user = sqlx::query_as::<_, User>("select * from users where id = $1")
            .bind(id)
            .fetch_optional(&*self.pool)
            .await
            .map_err(vaultlock_common::error::AppError::from)?;
        Ok(user)
    }

    async fn find_by_email(&self, email: &str) -> AppResult<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            "select * from users where lower(email) = $1 and deleted_at is null",
        )
        .bind(email.to_lowercase())
        .fetch_optional(&*self.pool)
        .await
        .map_err(vaultlock_common::error::AppError::from)?;
        Ok(user)
    }

    async fn update_display_name(
        &self,
        user_id: Uuid,
        display_name: Option<String>,
    ) -> AppResult<()> {
        sqlx::query("update users set display_name = $2, updated_at = now() where id = $1")
            .bind(user_id)
            .bind(&display_name)
            .execute(&*self.pool)
            .await
            .map_err(vaultlock_common::error::AppError::from)?;
        Ok(())
    }

    async fn update_password(&self, user_id: Uuid, password_hash: String) -> AppResult<()> {
        sqlx::query(
            "update users set password_hash = $2, password_changed_at = now(), updated_at = now() where id = $1",
        )
        .bind(user_id)
        .bind(&password_hash)
        .execute(&*self.pool)
        .await
        .map_err(vaultlock_common::error::AppError::from)?;
        Ok(())
    }

    async fn mark_email_verified(&self, user_id: Uuid) -> AppResult<()> {
        sqlx::query("update users set email_verified_at = now(), updated_at = now() where id = $1")
            .bind(user_id)
            .execute(&*self.pool)
            .await
            .map_err(vaultlock_common::error::AppError::from)?;
        Ok(())
    }
}

/// SQLx-backed session repository.
pub struct SqlxSessionRepository {
    pool: Arc<PgPool>,
}

impl SqlxSessionRepository {
    /// Create a new SQLx-backed session repository.
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionRepository for SqlxSessionRepository {
    async fn insert(&self, session: &Session) -> AppResult<()> {
        sqlx::query(
            "insert into sessions (id, token_hash, token_kind, user_id, device_id, expires_at, revoked_at, last_used_at, created_at)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(session.id)
        .bind(&session.token_hash)
        .bind(session.token_kind.to_string())
        .bind(session.user_id)
        .bind(session.device_id)
        .bind(session.expires_at)
        .bind(session.revoked_at)
        .bind(session.last_used_at)
        .bind(session.created_at)            .execute(&*self.pool)
            .await
            .map_err(vaultlock_common::error::AppError::from)?;
        Ok(())
    }

    async fn find_by_token_hash(&self, token_hash: &[u8]) -> AppResult<Option<Session>> {
        let session = sqlx::query_as::<_, Session>(
            "select * from sessions where token_hash = $1 and revoked_at is null and expires_at > now()",
        )
        .bind(token_hash)            .fetch_optional(&*self.pool)
            .await
            .map_err(vaultlock_common::error::AppError::from)?;
        Ok(session)
    }

    async fn revoke_others(&self, user_id: &Uuid, keep_id: &Uuid) -> AppResult<()> {
        sqlx::query("update sessions set revoked_at = now() where user_id = $1 and id != $2")
            .bind(*user_id)
            .bind(*keep_id)
            .execute(&*self.pool)
            .await
            .map_err(vaultlock_common::error::AppError::from)?;
        Ok(())
    }

    async fn revoke_others_all(&self, user_id: &Uuid) -> AppResult<()> {
        sqlx::query("update sessions set revoked_at = now() where user_id = $1")
            .bind(*user_id)
            .execute(&*self.pool)
            .await
            .map_err(vaultlock_common::error::AppError::from)?;
        Ok(())
    }

    async fn rotate_token(
        &self,
        session_id: &Uuid,
        new_token_hash: &[u8],
        expires_at: time::OffsetDateTime,
    ) -> AppResult<()> {
        sqlx::query("update sessions set token_hash = $2, expires_at = $3 where id = $1")
            .bind(*session_id)
            .bind(new_token_hash)
            .bind(expires_at)
            .execute(&*self.pool)
            .await
            .map_err(vaultlock_common::error::AppError::from)?;
        Ok(())
    }

    async fn revoke_by_device(&self, device_id: Uuid) -> AppResult<()> {
        sqlx::query("update sessions set revoked_at = now() where device_id = $1")
            .bind(device_id)
            .execute(&*self.pool)
            .await
            .map_err(vaultlock_common::error::AppError::from)?;
        Ok(())
    }
}

/// SQLx-backed device repository.
pub struct SqlxDeviceRepository {
    pool: Arc<PgPool>,
}

impl SqlxDeviceRepository {
    /// Create a new SQLx-backed device repository.
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DeviceRepository for SqlxDeviceRepository {
    async fn insert(&self, device: &Device) -> AppResult<()> {
        sqlx::query(
            "insert into devices (id, user_id, name, platform, created_at, last_seen_at, revoked_at)
             values ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(device.id)
        .bind(device.user_id)
        .bind(&device.name)
        .bind(&device.platform)
        .bind(device.created_at)
        .bind(device.last_seen_at)
        .bind(device.revoked_at)            .execute(&*self.pool)
            .await
            .map_err(vaultlock_common::error::AppError::from)?;
        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> AppResult<Option<Device>> {
        let device = sqlx::query_as::<_, Device>("select * from devices where id = $1")
            .bind(id)
            .fetch_optional(&*self.pool)
            .await
            .map_err(vaultlock_common::error::AppError::from)?;
        Ok(device)
    }

    async fn list_by_user(&self, user_id: Uuid) -> AppResult<Vec<Device>> {
        let devices = sqlx::query_as::<_, Device>(
            "select * from devices where user_id = $1 order by created_at desc",
        )
        .bind(user_id)
        .fetch_all(&*self.pool)
        .await
        .map_err(vaultlock_common::error::AppError::from)?;
        Ok(devices)
    }

    async fn revoke(&self, device_id: Uuid) -> AppResult<()> {
        sqlx::query("update devices set revoked_at = now() where id = $1")
            .bind(device_id)
            .execute(&*self.pool)
            .await
            .map_err(vaultlock_common::error::AppError::from)?;
        Ok(())
    }
}

/// SQLx-backed email token repository.
pub struct SqlxEmailTokenRepository {
    pool: Arc<PgPool>,
}

impl SqlxEmailTokenRepository {
    /// Create a new SQLx-backed email token repository.
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl EmailTokenRepository for SqlxEmailTokenRepository {
    async fn insert(&self, token: &EmailToken) -> AppResult<()> {
        sqlx::query(
            "insert into email_tokens (id, token_hash, token_kind, user_id, expires_at, used_at, created_at)
             values ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(token.id)
        .bind(&token.token_hash)
        .bind(token.token_kind.to_string())
        .bind(token.user_id)
        .bind(token.expires_at)
        .bind(token.used_at)
        .bind(token.created_at)            .execute(&*self.pool)
            .await
            .map_err(vaultlock_common::error::AppError::from)?;
        Ok(())
    }

    async fn find_by_hash_and_kind(
        &self,
        hash: &[u8],
        kind: EmailTokenKind,
    ) -> AppResult<Option<EmailToken>> {
        let token = sqlx::query_as::<_, EmailToken>(
            "select * from email_tokens where token_hash = $1 and token_kind = $2 and used_at is null and expires_at > now()",
        )
        .bind(hash)
        .bind(kind.to_string())            .fetch_optional(&*self.pool)
            .await
            .map_err(vaultlock_common::error::AppError::from)?;
        Ok(token)
    }

    async fn mark_used(&self, token: String) -> AppResult<()> {
        let hash = crate::application::hash_token_bytes(&token);
        sqlx::query("update email_tokens set used_at = now() where token_hash = $1")
            .bind(&hash)
            .execute(&*self.pool)
            .await
            .map_err(vaultlock_common::error::AppError::from)?;
        Ok(())
    }
}

/// SQLx-backed device authorisation repository.
pub struct SqlxDeviceAuthRepository {
    pool: Arc<PgPool>,
}

impl SqlxDeviceAuthRepository {
    /// Create a new SQLx-backed device auth repository.
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DeviceAuthRepository for SqlxDeviceAuthRepository {
    async fn insert(&self, auth: &DeviceAuthorization) -> AppResult<()> {
        sqlx::query(
            "insert into device_authorizations (id, device_code_hash, user_code, status, user_id, device_id, device_name, device_platform, interval_secs, expires_at, created_at)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(auth.id)
        .bind(&auth.device_code_hash)
        .bind(&auth.user_code)
        .bind(auth.status.to_string())
        .bind(auth.user_id)
        .bind(auth.device_id)
        .bind(&auth.device_name)
        .bind(&auth.device_platform)
        .bind(auth.interval_secs)
        .bind(auth.expires_at)
        .bind(auth.created_at)            .execute(&*self.pool)
            .await
            .map_err(vaultlock_common::error::AppError::from)?;
        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> AppResult<Option<DeviceAuthorization>> {
        let auth = sqlx::query_as::<_, DeviceAuthorization>(
            "select * from device_authorizations where id = $1",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await
        .map_err(vaultlock_common::error::AppError::from)?;
        Ok(auth)
    }

    async fn find_by_codes(
        &self,
        device_code: &str,
        user_code: &str,
    ) -> AppResult<Option<DeviceAuthorization>> {
        let auth = sqlx::query_as::<_, DeviceAuthorization>(
            "select * from device_authorizations where device_code_hash = $1 and user_code = $2 and status = 'pending' and expires_at > now()",
        )
        .bind(crate::application::hash_token_bytes(device_code))
        .bind(user_code)            .fetch_optional(&*self.pool)
            .await
            .map_err(vaultlock_common::error::AppError::from)?;
        Ok(auth)
    }

    async fn update_status(
        &self,
        id: Uuid,
        status: DeviceAuthStatus,
        user_id: Option<Uuid>,
    ) -> AppResult<()> {
        sqlx::query(
            "update device_authorizations set status = $2, user_id = coalesce($3, user_id) where id = $1",
        )
        .bind(id)
        .bind(status.to_string())
        .bind(user_id)            .execute(&*self.pool)
            .await
            .map_err(vaultlock_common::error::AppError::from)?;
        Ok(())
    }
}
