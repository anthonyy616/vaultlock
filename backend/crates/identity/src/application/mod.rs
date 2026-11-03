//! Application services for identity: registration, login, device flow, sessions.

use std::sync::Arc;

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use base64::Engine;
use rand::Rng;
use rand::rngs::OsRng;

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::{
    AuthResponse, Device, DeviceAuthPollResponse, DeviceAuthRequest, DeviceAuthStatus,
    DeviceAuthorization, EmailToken, EmailTokenKind, LoginRequest, PersonalAccessToken,
    RegisterRequest, Session, SessionTokenKind, User, UserView,
};
use crate::ports::{
    DeviceAuthRepository, DeviceRepository, EmailTokenRepository, SessionRepository, UserRepository,
};
use vaultlock_audit::{AuditContext, actions};
use vaultlock_common::error::{AppError, AppResult};

/// Service for identity operations: registration, login, device flow, sessions.
pub struct AuthService {
    pool: PgPool,
    user_repo: Arc<dyn UserRepository>,
    session_repo: Arc<dyn SessionRepository>,
    device_repo: Arc<dyn DeviceRepository>,
    email_token_repo: Arc<dyn EmailTokenRepository>,
    device_auth_repo: Arc<dyn DeviceAuthRepository>,
    audit: AuditContext,
    session_ttl_secs: i64,
    personal_access_ttl_secs: i64,
    email_token_ttl_secs: i64,
    device_flow_ttl_secs: i64,
    verify_email: bool,
}

impl AuthService {
    /// Create a new auth service.
    pub fn new(
        pool: PgPool,
        audit: AuditContext,
        session_ttl_secs: i64,
        personal_access_ttl_secs: i64,
        email_token_ttl_secs: i64,
        device_flow_ttl_secs: i64,
        verify_email: bool,
    ) -> Self {
        // Use concrete adapter implementations by default; swap behind trait
        // for tests.
        let pool_arc = Arc::new(pool.clone());
        Self {
            pool,
            user_repo: Arc::new(super::adapters::SqlxUserRepository::new(Arc::clone(
                &pool_arc,
            ))),
            session_repo: Arc::new(super::adapters::SqlxSessionRepository::new(Arc::clone(
                &pool_arc,
            ))),
            device_repo: Arc::new(super::adapters::SqlxDeviceRepository::new(Arc::clone(
                &pool_arc,
            ))),
            email_token_repo: Arc::new(super::adapters::SqlxEmailTokenRepository::new(Arc::clone(
                &pool_arc,
            ))),
            device_auth_repo: Arc::new(super::adapters::SqlxDeviceAuthRepository::new(Arc::clone(
                &pool_arc,
            ))),
            audit,
            session_ttl_secs,
            personal_access_ttl_secs,
            email_token_ttl_secs,
            device_flow_ttl_secs,
            verify_email,
        }
    }

    /// Register a new user. Fails if the email is already taken.
    pub async fn register(&self, req: RegisterRequest) -> AppResult<User> {
        let email = req.email.trim().to_lowercase();
        if email.is_empty() {
            return Err(AppError::validation("email", "email must not be empty"));
        }
        if !req.password.chars().all(|c| c != '\0') || req.password.len() < 8 {
            return Err(AppError::validation(
                "password",
                "password must be at least 8 characters",
            ));
        }

        let password_hash = hash_password(&req.password)?;
        let now = OffsetDateTime::now_utc();
        let user = User {
            id: Uuid::now_v7(),
            email: email.clone(),
            display_name: req.display_name,
            password_hash: Some(password_hash),
            recovery_code_hash: None,
            email_verified_at: if self.verify_email { None } else { Some(now) },
            password_changed_at: Some(now),
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        self.user_repo.insert(&user).await?;
        vaultlock_audit::record(
            &self.pool,
            &self.audit,
            actions::AUTH_REGISTERED,
            Some("user"),
            Some(user.id),
            serde_json::json!({ "email": email.len() }),
        )
        .await;
        Ok(user)
    }

    /// Authenticate with email + password. Returns a session and personal access token.
    pub async fn authenticate(&self, req: LoginRequest) -> AppResult<AuthResponse> {
        let email = req.email.trim().to_lowercase();
        let user = self.user_repo.find_by_email(&email).await?.ok_or_else(|| {
            // Avoid user enumeration: same error as invalid password.
            let _ = AppError::Unauthorised;
            AppError::Unauthorised
        })?;

        if user.deleted_at.is_some() {
            return Err(AppError::Unauthorised);
        }

        let password_hash = user.password_hash.as_ref().ok_or(AppError::Unauthorised)?;
        verify_password(&req.password, password_hash)?;

        let now = OffsetDateTime::now_utc();
        let session_id = Uuid::now_v7();
        let expires_at = now + time::Duration::seconds(self.session_ttl_secs);

        let session = Session {
            id: session_id,
            token_hash: hash_token_bytes(&email),
            token_kind: SessionTokenKind::Session,
            user_id: user.id,
            device_id: None,
            expires_at,
            revoked_at: None,
            last_used_at: None,
            created_at: now,
        };

        // Insert session; if a previous session exists for this user, revoke it
        // (single-session-per-user model for simplicity in v0.1).
        self.session_repo.insert(&session).await?;
        self.session_repo
            .revoke_others(&user.id, &session.id)
            .await?;

        let personal_token =
            generate_personal_token(&user.id, None, self.personal_access_ttl_secs)?;
        let device_id = None;

        vaultlock_audit::record(
            &self.pool,
            &self.audit,
            actions::AUTH_LOGIN,
            Some("session"),
            Some(session.id),
            serde_json::json!({ "email_len": email.len() }),
        )
        .await;

        Ok(AuthResponse {
            access_token: personal_token.token,
            token_type: "bearer".to_string(),
            expires_in: self.personal_access_ttl_secs,
            user: user_to_view(&user),
            device_id,
        })
    }

    /// Start a device-authorisation flow (CLI `vaultlock login`).
    pub async fn start_device_flow(
        &self,
        req: DeviceAuthRequest,
    ) -> AppResult<(DeviceAuthorization, DeviceAuthPollResponse)> {
        let device_id = Uuid::now_v7();
        let device_code = Uuid::now_v7().to_string();
        let user_code = generate_user_code();
        let now = OffsetDateTime::now_utc();
        let expires_at = now + time::Duration::seconds(self.device_flow_ttl_secs);

        let device_auth = DeviceAuthorization {
            id: Uuid::now_v7(),
            device_code_hash: hash_token_bytes(&device_code),
            user_code: user_code.clone(),
            status: DeviceAuthStatus::Pending,
            user_id: None,
            device_id: Some(device_id),
            device_name: Some(req.device_name.clone()),
            device_platform: Some(req.device_platform.clone()),
            interval_secs: 5,
            expires_at,
            created_at: now,
        };

        self.device_auth_repo.insert(&device_auth).await?;
        self.device_repo
            .insert(&Device {
                id: device_id,
                user_id: Uuid::nil(),
                name: req.device_name.clone(),
                platform: req.device_platform.clone(),
                created_at: now,
                last_seen_at: None,
                revoked_at: None,
            })
            .await?;

        let _ = vaultlock_audit::record(
            &self.pool,
            &self.audit,
            actions::DEVICE_FLOW_APPROVED,
            Some("device"),
            Some(device_id),
            serde_json::json!({ "device_name_len": req.device_name.len() }),
        )
        .await;

        let poll = DeviceAuthPollResponse {
            device_code: device_code.clone(),
            user_code: user_code.clone(),
            verification_uri: format!("{}/v1/auth/device/verify", ""),
            expires_in: self.device_flow_ttl_secs,
            interval: 5,
        };

        Ok((device_auth, poll))
    }

    /// Poll/poll-style token exchange: the user has entered the user code and the
    /// CLI now exchanges the device code for a personal access token.
    pub async fn exchange_device_code(
        &self,
        device_code: String,
        user_code: String,
    ) -> AppResult<PersonalAccessToken> {
        let device_auth = self
            .device_auth_repo
            .find_by_codes(&device_code, &user_code)
            .await?
            .ok_or(AppError::Unauthorised)?;

        if device_auth.status == DeviceAuthStatus::Expired {
            return Err(AppError::Unauthorised);
        }

        if device_auth.user_id.is_some() {
            // Already approved.
            return self.finalise_device_auth(&device_auth).await;
        }

        // In a full implementation, this would wait for user approval. For the
        // sprint we support a pre-approved path (admin/UI approves the flow) plus
        // a direct approval endpoint below.
        Err(AppError::Unauthorised)
    }

    /// Approve a pending device flow (called by the web/device approval path after
    /// the user confirms). Returns the personal access token.
    pub async fn approve_device_flow(
        &self,
        device_auth_id: Uuid,
        user_id: Uuid,
    ) -> AppResult<PersonalAccessToken> {
        let device_auth = self
            .device_auth_repo
            .find_by_id(device_auth_id)
            .await?
            .ok_or(AppError::NotFound)?;

        if device_auth.status != DeviceAuthStatus::Pending {
            return Err(AppError::Conflict {
                code: "DEVICE_FLOW_NOT_PENDING".to_string(),
                message: "The device flow is not pending.".to_string(),
            });
        }
        if device_auth.expires_at < OffsetDateTime::now_utc() {
            return Err(AppError::Conflict {
                code: "DEVICE_FLOW_EXPIRED".to_string(),
                message: "The device flow has expired.".to_string(),
            });
        }

        let new_status = DeviceAuthStatus::Approved;
        self.device_auth_repo
            .update_status(device_auth_id, new_status, Some(user_id))
            .await?;

        vaultlock_audit::record(
            &self.pool,
            &self.audit,
            actions::DEVICE_FLOW_APPROVED,
            Some("device"),
            Some(device_auth.device_id.unwrap_or_default()),
            serde_json::json!({ "device_auth_id": device_auth_id, "user_id": user_id }),
        )
        .await;

        self.finalise_device_auth(&device_auth).await
    }

    async fn finalise_device_auth(
        &self,
        device_auth: &DeviceAuthorization,
    ) -> AppResult<PersonalAccessToken> {
        let device_id = device_auth.device_id.ok_or(AppError::Internal)?;
        let user_id = device_auth.user_id.ok_or(AppError::Internal)?;
        let token =
            generate_personal_token(&user_id, Some(device_id), self.personal_access_ttl_secs)?;
        Ok(token)
    }

    /// Refresh a personal access token.
    pub async fn refresh_token(&self, old_token: &str) -> AppResult<PersonalAccessToken> {
        let hash = hash_token_bytes(old_token);
        let session = self
            .session_repo
            .find_by_token_hash(&hash)
            .await?
            .ok_or(AppError::Unauthorised)?;

        if session.token_kind != SessionTokenKind::PersonalAccess {
            return Err(AppError::Unauthorised);
        }
        if session.expires_at < OffsetDateTime::now_utc() {
            return Err(AppError::Unauthorised);
        }
        if session.revoked_at.is_some() {
            return Err(AppError::Unauthorised);
        }

        let now = OffsetDateTime::now_utc();
        let expires_at = now + time::Duration::seconds(self.personal_access_ttl_secs);
        let new_token = generate_personal_token(
            &session.user_id,
            session.device_id,
            self.personal_access_ttl_secs,
        )?;

        // Rotate: invalidate the old token hash and issue a new one.
        self.session_repo
            .rotate_token(&session.id, &hash_token_bytes(&new_token.token), expires_at)
            .await?;

        vaultlock_audit::record(
            &self.pool,
            &self.audit,
            actions::AUTH_LOGIN,
            Some("session"),
            Some(session.id),
            serde_json::json!({ "refreshed": true }),
        )
        .await;

        Ok(PersonalAccessToken {
            token: new_token.token,
            expires_at,
            user_id: session.user_id,
            device_id: session.device_id.unwrap_or_default(),
        })
    }

    /// Revoke a session/device.
    pub async fn revoke_device(&self, device_id: Uuid) -> AppResult<()> {
        self.device_repo
            .find_by_id(device_id)
            .await?
            .ok_or(AppError::NotFound)?;

        self.device_repo.revoke(device_id).await?;

        // Revoke all sessions tied to this device.
        self.session_repo.revoke_by_device(device_id).await?;

        vaultlock_audit::record(
            &self.pool,
            &self.audit,
            actions::DEVICE_REVOKED,
            Some("device"),
            Some(device_id),
            serde_json::json!({}),
        )
        .await;

        Ok(())
    }

    /// List devices for the current user.
    pub async fn list_devices(&self, user_id: Uuid) -> AppResult<Vec<Device>> {
        self.device_repo.list_by_user(user_id).await
    }

    /// Get the current user's profile view.
    pub async fn me(&self, user_id: Uuid) -> AppResult<UserView> {
        let user = self.user_repo.find_by_id(user_id).await?;
        let user = user.ok_or(AppError::NotFound)?;
        Ok(user_to_view(&user))
    }

    /// Update display name.
    pub async fn update_profile(
        &self,
        user_id: Uuid,
        display_name: Option<String>,
    ) -> AppResult<UserView> {
        self.user_repo
            .update_display_name(user_id, display_name)
            .await?;
        let user = self
            .user_repo
            .find_by_id(user_id)
            .await?
            .ok_or(AppError::NotFound)?;
        Ok(user_to_view(&user))
    }

    /// Change password. Invalidates all other sessions.
    pub async fn change_password(
        &self,
        user_id: Uuid,
        current_password: String,
        new_password: String,
    ) -> AppResult<()> {
        let user = self
            .user_repo
            .find_by_id(user_id)
            .await?
            .ok_or(AppError::NotFound)?;
        let current_hash = user.password_hash.as_ref().ok_or(AppError::Unauthorised)?;
        verify_password(&current_password, current_hash)?;

        if new_password.len() < 8 {
            return Err(AppError::validation(
                "password",
                "new password must be at least 8 characters",
            ));
        }

        let new_hash = hash_password(&new_password)?;
        self.user_repo.update_password(user_id, new_hash).await?;

        // Invalidate all other sessions for this user.
        self.session_repo.revoke_others_all(&user_id).await?;

        vaultlock_audit::record(
            &self.pool,
            &self.audit,
            actions::AUTH_PASSWORD_CHANGED,
            Some("user"),
            Some(user_id),
            serde_json::json!({}),
        )
        .await;

        Ok(())
    }

    /// Request a password reset email token. Does not reveal whether the email exists.
    pub async fn request_password_reset(&self, email: String) -> AppResult<()> {
        let email = email.trim().to_lowercase();
        if email.is_empty() {
            return Err(AppError::validation("email", "email must not be empty"));
        }
        // Always succeed to avoid user enumeration.
        let user = self.user_repo.find_by_email(&email).await?;
        if let Some(user) = user {
            let now = OffsetDateTime::now_utc();
            let expires_at = now + time::Duration::seconds(self.email_token_ttl_secs);
            let token = Uuid::now_v7().to_string();
            let email_token = EmailToken {
                id: Uuid::now_v7(),
                token_hash: hash_token_bytes(&token),
                token_kind: EmailTokenKind::PasswordReset,
                user_id: user.id,
                expires_at,
                used_at: None,
                created_at: now,
            };
            self.email_token_repo.insert(&email_token).await?;
            // In a real deployment, send the token via email here.
            let _ = email_token;
            let _ = token;
        }
        Ok(())
    }

    /// Validate a password reset token and return the user id.
    pub async fn validate_password_reset_token(&self, token: String) -> AppResult<Uuid> {
        let hash = hash_token_bytes(&token);
        let email_token = self
            .email_token_repo
            .find_by_hash_and_kind(&hash, EmailTokenKind::PasswordReset)
            .await?
            .ok_or(AppError::Unauthorised)?;

        if email_token.expires_at < OffsetDateTime::now_utc() {
            return Err(AppError::Unauthorised);
        }
        if email_token.used_at.is_some() {
            return Err(AppError::Unauthorised);
        }

        Ok(email_token.user_id)
    }

    /// Consume a password reset token and set a new password.
    pub async fn reset_password(&self, token: String, new_password: String) -> AppResult<()> {
        let user_id = self.validate_password_reset_token(token.clone()).await?;
        if new_password.len() < 8 {
            return Err(AppError::validation(
                "password",
                "new password must be at least 8 characters",
            ));
        }
        let new_hash = hash_password(&new_password)?;
        self.user_repo.update_password(user_id, new_hash).await?;
        self.email_token_repo.mark_used(token).await?;

        vaultlock_audit::record(
            &self.pool,
            &self.audit,
            actions::AUTH_PASSWORD_RESET,
            Some("user"),
            Some(user_id),
            serde_json::json!({}),
        )
        .await;

        // Invalidate all other sessions.
        self.session_repo.revoke_others_all(&user_id).await?;

        Ok(())
    }

    /// Request email verification.
    pub async fn request_email_verification(&self, user_id: Uuid) -> AppResult<()> {
        let user = self
            .user_repo
            .find_by_id(user_id)
            .await?
            .ok_or(AppError::NotFound)?;
        if user.email_verified_at.is_some() {
            return Ok(());
        }
        let now = OffsetDateTime::now_utc();
        let expires_at = now + time::Duration::seconds(self.email_token_ttl_secs);
        let token = Uuid::now_v7().to_string();
        let email_token = EmailToken {
            id: Uuid::now_v7(),
            token_hash: hash_token_bytes(&token),
            token_kind: EmailTokenKind::VerifyEmail,
            user_id,
            expires_at,
            used_at: None,
            created_at: now,
        };
        self.email_token_repo.insert(&email_token).await?;
        // In a real deployment, send via email here.
        let _ = email_token;
        let _ = token;
        Ok(())
    }

    /// Verify email with token.
    pub async fn verify_email(&self, token: String) -> AppResult<()> {
        let hash = hash_token_bytes(&token);
        let email_token = self
            .email_token_repo
            .find_by_hash_and_kind(&hash, EmailTokenKind::VerifyEmail)
            .await?
            .ok_or(AppError::Unauthorised)?;

        if email_token.expires_at < OffsetDateTime::now_utc() {
            return Err(AppError::Unauthorised);
        }
        if email_token.used_at.is_some() {
            return Err(AppError::Unauthorised);
        }

        self.user_repo
            .mark_email_verified(email_token.user_id)
            .await?;
        self.email_token_repo.mark_used(token.clone()).await?;

        vaultlock_audit::record(
            &self.pool,
            &self.audit,
            actions::AUTH_EMAIL_VERIFIED,
            Some("user"),
            Some(email_token.user_id),
            serde_json::json!({}),
        )
        .await;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Password hashing
// ---------------------------------------------------------------------------

fn argon2() -> Argon2<'static> {
    Argon2::default()
}

fn hash_password(password: &str) -> AppResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| AppError::Internal)?
        .to_string();
    Ok(hash)
}

fn verify_password(password: &str, password_hash: &str) -> AppResult<()> {
    let parsed = PasswordHash::new(password_hash).map_err(|_| AppError::Unauthorised)?;
    argon2()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| AppError::Unauthorised)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Token handling (hashed storage)
// ---------------------------------------------------------------------------

/// Hash a token string for storage. Uses a SHA-256 digest.
/// This avoids storing plaintext tokens.
pub fn hash_token_bytes(token: &str) -> Vec<u8> {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().to_vec()
}

fn generate_personal_token(
    user_id: &Uuid,
    device_id: Option<Uuid>,
    ttl_secs: i64,
) -> AppResult<PersonalAccessToken> {
    let mut token_bytes = [0u8; 32];
    OsRng.fill(&mut token_bytes);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes);
    let now = OffsetDateTime::now_utc();
    let expires_at = now + time::Duration::seconds(ttl_secs);
    Ok(PersonalAccessToken {
        token,
        expires_at,
        user_id: *user_id,
        device_id: device_id.unwrap_or_default(),
    })
}

fn generate_user_code() -> String {
    // 8-character code: 4 letters + 4 digits, e.g. "ABCD-1234".
    const LETTERS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const DIGITS: &[u8] = b"23456789";
    let mut rng = rand::rngs::OsRng;
    let mut buf = [0u8; 8];
    for slot in buf[..4].iter_mut() {
        *slot = LETTERS[rand::Rng::gen_range(&mut rng, 0..LETTERS.len())];
    }
    for slot in buf[4..].iter_mut() {
        *slot = DIGITS[rand::Rng::gen_range(&mut rng, 0..DIGITS.len())];
    }
    let mut s = String::with_capacity(9);
    for (idx, &b) in buf.iter().enumerate() {
        s.push(b as char);
        if idx == 3 {
            s.push('-');
        }
    }
    s
}

fn user_to_view(user: &User) -> UserView {
    UserView {
        id: user.id,
        email: user.email.clone(),
        display_name: user.display_name.clone(),
        email_verified: user.email_verified_at.is_some(),
        created_at: user.created_at,
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from user registration.
#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    #[error("email already registered")]
    /// The email address is already in use.
    EmailTaken,
    #[error("invalid input")]
    /// The registration request was invalid.
    InvalidInput,
}

/// Errors from authentication.
#[derive(Debug, thiserror::Error)]
pub enum AuthenticateError {
    #[error("invalid credentials")]
    /// The email or password was incorrect.
    InvalidCredentials,
    #[error("account disabled")]
    /// The account has been disabled.
    AccountDisabled,
}

/// Errors from device flow operations.
#[derive(Debug, thiserror::Error)]
pub enum DeviceFlowError {
    #[error("device flow not found or expired")]
    /// The device flow was not found or has expired.
    NotFound,
    #[error("device flow already approved")]
    /// The device flow has already been approved.
    AlreadyApproved,
    #[error("device flow denied")]
    /// The device flow was denied.
    Denied,
}
