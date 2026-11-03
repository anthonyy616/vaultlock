//! Application configuration.
//!
//! Configuration is loaded from environment variables (optionally via a local
//! `.env` for development) and validated **fail-closed**: the process refuses
//! to start when a required setting is missing or malformed. Secrets are
//! never included in debug output.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine;

use crate::error::{AppError, AppResult};

/// Object-storage settings.
#[derive(Debug, Clone)]
pub enum StorageConfig {
    /// Filesystem storage (development and self-host fallback).
    Local {
        /// Root directory for stored objects.
        root: PathBuf,
        /// Bucket-like namespace used in object keys.
        bucket: String,
    },
    /// S3-compatible storage (Cloudflare R2, MinIO/SeaweedFS, other providers).
    S3 {
        /// S3 API endpoint (R2: `https://<account>.r2.cloudflarestorage.com`).
        endpoint: String,
        /// Region identifier (R2 typically `auto`).
        region: String,
        /// Bucket name.
        bucket: String,
        /// Access key ID.
        access_key_id: String,
        /// Secret access key.
        secret_access_key: String,
        /// Optional path-style addressing (required by most S3-compatible stores).
        force_path_style: bool,
    },
}

/// Key-management settings.
#[derive(Debug, Clone)]
pub struct KmsConfig {
    /// Root master key (base64, 32 bytes) used by the built-in KMS.
    /// Keep this material out of ordinary application configuration.
    pub master_key: [u8; 32],
    /// Optional external KMS identifier reserved for future adapters.
    pub external: Option<String>,
}

/// Identity/session/email settings.
#[derive(Debug, Clone)]
pub struct IdentityConfig {
    /// Lifetime of browser/API sessions.
    pub session_ttl: Duration,
    /// Lifetime of email verification and password reset tokens.
    pub email_token_ttl: Duration,
    /// Lifetime of pending CLI device authorisation requests.
    pub device_flow_ttl: Duration,
    /// Lifetime of short-lived access tokens issues to approved device flows.
    pub personal_access_ttl: Duration,
    /// Google OAuth client credentials (optional until configured).
    pub google_oauth: Option<(String, String)>,
    /// GitHub OAuth client credentials (optional until configured).
    pub github_oauth: Option<(String, String)>,
}

/// Full application configuration.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// PostgreSQL connection URL, e.g. `postgres://user:pass@host/db`.
    pub database_url: String,
    /// Bind address for the HTTP server.
    pub bind: SocketAddr,
    /// Public base URL of the API (used for OAuth redirects).
    pub public_url: String,
    /// Browser origin permitted for CORS (the web dashboard).
    pub web_origin: String,
    /// Server-issued token used when composing email links.
    pub email_link_base: String,
    /// Storage configuration.
    pub storage: StorageConfig,
    /// Key-management configuration.
    pub kms: KmsConfig,
    /// Identity configuration.
    pub identity: IdentityConfig,
    /// Absolute cap for any uploaded object (bytes).
    pub max_object_size: u64,
    /// Number of shared background settings.
    pub job_interval: Duration,
}

impl AppConfig {
    /// Load configuration from the process environment, failing closed.
    ///
    /// # Errors
    /// Returns an [`AppError`] describing the first invalid or missing
    /// setting so operators can fix the environment before start-up.
    pub fn from_env() -> AppResult<Self> {
        let database_url = getenv_req("DATABASE_URL")?;
        let bind = getenv_opt("VL_BIND_ADDR").unwrap_or_else(|| "0.0.0.0:8080".to_string());
        let bind = bind
            .parse::<SocketAddr>()
            .map_err(|_| AppError::validation("VL_BIND_ADDR", "invalid socket address"))?;
        let public_url = getenv_opt("VL_PUBLIC_URL").unwrap_or_else(|| format!("http://{bind}"));
        let web_origin =
            getenv_opt("VL_WEB_ORIGIN").unwrap_or_else(|| "http://localhost:3000".to_string());
        let email_link_base =
            getenv_opt("VL_EMAIL_LINK_BASE").unwrap_or_else(|| public_url.clone());
        let storage = load_storage()?;
        let kms = load_kms()?;
        let identity = load_identity()?;
        let max_object_size = getenv_opt("VL_MAX_OBJECT_SIZE")
            .map(trim_leading)
            .unwrap_or_else(|| "107374182400".to_string()) // 100 GiB default cap
            .parse::<u64>()
            .map_err(|_| {
                AppError::validation("VL_MAX_OBJECT_SIZE", "must be an integer byte count")
            })?;
        let job_interval_secs: u64 = getenv_opt("VL_JOB_INTERVAL_SECS")
            .map(trim_leading)
            .unwrap_or_else(|| "60".to_string())
            .parse()
            .map_err(|_| AppError::validation("VL_JOB_INTERVAL_SECS", "must be an integer"))?;
        Ok(Self {
            database_url,
            bind,
            public_url,
            web_origin,
            email_link_base,
            storage,
            kms,
            identity,
            max_object_size,
            job_interval: Duration::from_secs(job_interval_secs.max(5)),
        })
    }
}

fn trim_leading(mut v: String) -> String {
    if let Some(rest) = v.strip_prefix('=') {
        rest.to_string();
        v = rest.to_string();
    }
    v
}

fn getenv_req(key: &str) -> AppResult<String> {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => Ok(v.trim().to_string()),
        _ => Err(AppError::validation(
            key,
            "required environment variable is not set",
        )),
    }
}

fn getenv_opt(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn load_storage() -> AppResult<StorageConfig> {
    match getenv_opt("VL_STORAGE_BACKEND")
        .unwrap_or_else(|| "local".to_string())
        .to_lowercase()
        .as_str()
    {
        "local" => {
            let root = PathBuf::from(
                getenv_opt("VL_LOCAL_STORAGE_ROOT").unwrap_or_else(|| "./data/storage".to_string()),
            );
            let bucket =
                getenv_opt("VL_STORAGE_BUCKET").unwrap_or_else(|| "vaultlock-local".to_string());
            Ok(StorageConfig::Local { root, bucket })
        }
        "s3" => {
            let endpoint = getenv_req("VL_S3_ENDPOINT")?;
            let region = getenv_opt("VL_S3_REGION").unwrap_or_else(|| "auto".to_string());
            let bucket = getenv_req("VL_STORAGE_BUCKET")?;
            let access_key_id = getenv_req("VL_S3_ACCESS_KEY_ID")?;
            let secret_access_key = getenv_req("VL_S3_SECRET_ACCESS_KEY")?;
            let force_path_style = getenv_opt("VL_S3_FORCE_PATH_STYLE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(true);
            Ok(StorageConfig::S3 {
                endpoint,
                region,
                bucket,
                access_key_id,
                secret_access_key,
                force_path_style,
            })
        }
        other => Err(AppError::validation(
            "VL_STORAGE_BACKEND",
            &format!("unknown storage backend `{other}` (supported: local, s3)"),
        )),
    }
}

fn load_kms() -> AppResult<KmsConfig> {
    let raw = getenv_req("VL_MASTER_KEY")?;
    let master_key = parse_master_key(&raw)?;
    Ok(KmsConfig {
        master_key,
        external: getenv_opt("VL_KMS_EXTERNAL"),
    })
}

/// Accepts base64url, base64-standard or hex encoding of exactly 32 bytes.
fn parse_master_key(raw: &str) -> AppResult<[u8; 32]> {
    let trimmed = raw.trim();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .ok()
        .or_else(|| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(trimmed)
                .ok()
        })
        .or_else(|| hex::decode(trimmed).ok());
    match bytes {
        Some(v) if v.len() == 32 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&v);
            Ok(key)
        }
        Some(v) => Err(AppError::validation(
            "VL_MASTER_KEY",
            &format!("must be exactly 32 bytes (received {})", v.len()),
        )),
        None => Err(AppError::validation(
            "VL_MASTER_KEY",
            "must be base64 or hex encoded 32-byte key",
        )),
    }
}

fn load_identity() -> AppResult<IdentityConfig> {
    let session_hours: i64 = getenv_opt("VL_SESSION_TTL_HOURS")
        .map(trim_leading)
        .unwrap_or_else(|| "168".to_string())
        .parse()
        .map_err(|_| AppError::validation("VL_SESSION_TTL_HOURS", "must be an integer"))?;
    let email_minutes: i64 = getenv_opt("VL_EMAIL_TOKEN_TTL_MINUTES")
        .map(trim_leading)
        .unwrap_or_else(|| "60".to_string())
        .parse()
        .map_err(|_| AppError::validation("VL_EMAIL_TOKEN_TTL_MINUTES", "must be an integer"))?;
    let flow_minutes: i64 = getenv_opt("VL_DEVICE_FLOW_TTL_MINUTES")
        .map(trim_leading)
        .unwrap_or_else(|| "10".to_string())
        .parse()
        .map_err(|_| AppError::validation("VL_DEVICE_FLOW_TTL_MINUTES", "must be an integer"))?;
    let personal_hours: i64 = getenv_opt("VL_PERSONAL_TOKEN_TTL_HOURS")
        .map(trim_leading)
        .unwrap_or_else(|| "720".to_string())
        .parse()
        .map_err(|_| AppError::validation("VL_PERSONAL_TOKEN_TTL_HOURS", "must be an integer"))?;

    let google_oauth = oauth_pair("VL_OAUTH_GOOGLE_CLIENT_ID", "VL_OAUTH_GOOGLE_CLIENT_SECRET");
    let github_oauth = oauth_pair("VL_OAUTH_GITHUB_CLIENT_ID", "VL_OAUTH_GITHUB_CLIENT_SECRET");

    Ok(IdentityConfig {
        session_ttl: Duration::from_secs(
            u64::try_from(session_hours.max(1))
                .unwrap_or(168)
                .saturating_mul(3600),
        ),
        email_token_ttl: Duration::from_secs(
            u64::try_from(email_minutes.max(1))
                .unwrap_or(60)
                .saturating_mul(60),
        ),
        device_flow_ttl: Duration::from_secs(
            u64::try_from(flow_minutes.max(1))
                .unwrap_or(10)
                .saturating_mul(60),
        ),
        personal_access_ttl: Duration::from_secs(
            u64::try_from(personal_hours.max(1))
                .unwrap_or(720)
                .saturating_mul(3600),
        ),
        google_oauth,
        github_oauth,
    })
}

fn oauth_pair(id_key: &str, secret_key: &str) -> Option<(String, String)> {
    let id = getenv_opt(id_key);
    let secret = getenv_opt(secret_key);
    match (id, secret) {
        (Some(i), Some(s)) => Some((i, s)),
        _ => None,
    }
}

/// Database connection settings resolved from the base URL for test databases.
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// Full connection URL.
    pub url: String,
}

impl DatabaseConfig {
    /// Build a database configuration from a URL.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }
}
