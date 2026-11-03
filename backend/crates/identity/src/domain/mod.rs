//! Domain types for identity: users, sessions, devices, tokens.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A user identifier (UUID v7).
pub type UserId = Uuid;
/// A session identifier (UUID v7).
pub type SessionId = Uuid;
/// A device identifier (UUID v7).
pub type DeviceId = Uuid;
/// An email token identifier (UUID v7).
pub type EmailTokenId = Uuid;
/// A device-authorisation identifier (UUID v7).
pub type DeviceAuthId = Uuid;

/// A registered user account.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    /// Unique identifier (UUID v7).
    pub id: UserId,
    /// Email address (lowercased, unique).
    pub email: String,
    /// Optional display name.
    pub display_name: Option<String>,
    /// Argon2 password hash (None for OAuth-only accounts).
    pub password_hash: Option<String>,
    /// Argon2 hash of the recovery code (if set).
    pub recovery_code_hash: Option<String>,
    /// When the email was verified.
    pub email_verified_at: Option<time::OffsetDateTime>,
    /// When the password was last changed.
    pub password_changed_at: Option<time::OffsetDateTime>,
    /// Account creation time.
    pub created_at: time::OffsetDateTime,
    /// Last update time.
    pub updated_at: time::OffsetDateTime,
    /// Soft-delete timestamp (soft-deleted accounts are inactive).
    pub deleted_at: Option<time::OffsetDateTime>,
}

/// A session (browser or personal access token).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Session {
    /// Unique session identifier.
    pub id: SessionId,
    /// SHA-256 hash of the session token (never stored plaintext).
    pub token_hash: Vec<u8>,
    /// Kind of token.
    pub token_kind: SessionTokenKind,
    /// Owner user.
    pub user_id: UserId,
    /// Associated device, if any.
    pub device_id: Option<DeviceId>,
    /// Expiration time.
    pub expires_at: time::OffsetDateTime,
    /// Revocation time (if revoked).
    pub revoked_at: Option<time::OffsetDateTime>,
    /// Last time this session was used.
    pub last_used_at: Option<time::OffsetDateTime>,
    /// Session creation time.
    pub created_at: time::OffsetDateTime,
}

/// Kind of session/token.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq, Eq)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum SessionTokenKind {
    /// A browser/session cookie token.
    Session,
    /// A long-lived personal access token.
    PersonalAccess,
}

impl std::fmt::Display for SessionTokenKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionTokenKind::Session => write!(f, "session"),
            SessionTokenKind::PersonalAccess => write!(f, "personal_access"),
        }
    }
}

/// A registered device.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Device {
    /// Unique device identifier.
    pub id: DeviceId,
    /// Owner user (nil for pending device flows).
    pub user_id: UserId,
    /// Human-readable device name.
    pub name: String,
    /// Platform string (e.g. "cli", "macos").
    pub platform: String,
    /// When the device was registered.
    pub created_at: time::OffsetDateTime,
    /// Last time this device was seen.
    pub last_seen_at: Option<time::OffsetDateTime>,
    /// When the device was revoked.
    pub revoked_at: Option<time::OffsetDateTime>,
}

/// An email verification or password reset token.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct EmailToken {
    /// Unique token identifier.
    pub id: EmailTokenId,
    /// SHA-256 hash of the token (never stored plaintext).
    pub token_hash: Vec<u8>,
    /// Kind of email token.
    pub token_kind: EmailTokenKind,
    /// Target user.
    pub user_id: UserId,
    /// Expiration time.
    pub expires_at: time::OffsetDateTime,
    /// When the token was consumed.
    pub used_at: Option<time::OffsetDateTime>,
    /// Token creation time.
    pub created_at: time::OffsetDateTime,
}

/// Kind of email token.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq, Eq)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum EmailTokenKind {
    /// Email verification token.
    VerifyEmail,
    /// Password reset token.
    PasswordReset,
}

impl std::fmt::Display for EmailTokenKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmailTokenKind::VerifyEmail => write!(f, "verify_email"),
            EmailTokenKind::PasswordReset => write!(f, "password_reset"),
        }
    }
}

/// A CLI device-authorisation flow (OAuth 2.0 Device Authorisation style).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DeviceAuthorization {
    /// Unique flow identifier.
    pub id: DeviceAuthId,
    /// SHA-256 hash of the device code.
    pub device_code_hash: Vec<u8>,
    /// User-facing code to enter on the browser.
    pub user_code: String,
    /// Current status.
    pub status: DeviceAuthStatus,
    /// Approving user (set on approval).
    pub user_id: Option<UserId>,
    /// Associated device.
    pub device_id: Option<DeviceId>,
    /// Device name (if provided).
    pub device_name: Option<String>,
    /// Device platform (if provided).
    pub device_platform: Option<String>,
    /// Recommended poll interval in seconds.
    pub interval_secs: i32,
    /// Expiration time.
    pub expires_at: time::OffsetDateTime,
    /// Flow creation time.
    pub created_at: time::OffsetDateTime,
}

/// Status of a device authorisation flow.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq, Eq)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum DeviceAuthStatus {
    /// Awaiting user approval.
    Pending,
    /// Approved, token issued.
    Approved,
    /// Denied by user.
    Denied,
    /// Expired without approval.
    Expired,
}

impl std::fmt::Display for DeviceAuthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceAuthStatus::Pending => write!(f, "pending"),
            DeviceAuthStatus::Approved => write!(f, "approved"),
            DeviceAuthStatus::Denied => write!(f, "denied"),
            DeviceAuthStatus::Expired => write!(f, "expired"),
        }
    }
}

/// A short-lived personal access token issued to an approved device flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalAccessToken {
    /// The bearer token (base64url-encoded random bytes).
    pub token: String,
    /// When the token expires.
    pub expires_at: time::OffsetDateTime,
    /// Token owner.
    pub user_id: UserId,
    /// Associated device (if any).
    pub device_id: DeviceId,
}

/// A new user registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// Email address.
    pub email: String,
    /// Display name (optional).
    pub display_name: Option<String>,
    /// Password (min 8 chars).
    pub password: String,
}

/// A login attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    /// Email address.
    pub email: String,
    /// Password.
    pub password: String,
}

/// A device-authorisation request from a CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthRequest {
    /// Human-readable device name.
    pub device_name: String,
    /// Platform identifier.
    pub device_platform: String,
}

/// A device-code polling response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthPollResponse {
    /// Device code for polling.
    pub device_code: String,
    /// User code to enter on the browser.
    pub user_code: String,
    /// URI to open in the browser.
    pub verification_uri: String,
    /// Total expiration time in seconds.
    pub expires_in: i64,
    /// Recommended poll interval in seconds.
    pub interval: i64,
}

/// A token exchange request (device code + user code).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenExchangeRequest {
    /// Device code from the polling response.
    pub device_code: String,
    /// User code entered by the user.
    pub user_code: String,
}

/// A session/token pair returned after authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    /// Bearer token.
    pub access_token: String,
    /// Token type (always "bearer").
    pub token_type: String,
    /// Token lifetime in seconds.
    pub expires_in: i64,
    /// Authenticated user view.
    pub user: UserView,
    /// Associated device (if any).
    pub device_id: Option<Uuid>,
}

/// A lightweight user view returned in auth responses and profiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserView {
    /// Unique identifier.
    pub id: Uuid,
    /// Email address.
    pub email: String,
    /// Display name.
    pub display_name: Option<String>,
    /// Whether the email has been verified.
    pub email_verified: bool,
    /// Account creation time.
    pub created_at: time::OffsetDateTime,
}
