//! Server configuration loaded from environment (fail-closed).

use std::net::SocketAddr;
use std::path::PathBuf;
use vaultlock_common::config::{AppConfig, DatabaseConfig, IdentityConfig, KmsConfig};

/// Full server configuration.
pub struct Config {
    /// Top-level application config.
    pub app: AppConfig,
    /// Database configuration.
    pub database: DatabaseConfig,
    /// KMS configuration.
    pub kms: KmsConfig,
    /// Identity configuration.
    pub identity: IdentityConfig,
    /// HTTP bind address.
    pub addr: SocketAddr,
    /// Asset/static path for the web frontend (production) or None for dev.
    pub web_assets: Option<PathBuf>,
}

impl Config {
    /// Load from environment. Panics (fails closed) on missing required vars.
    #[allow(clippy::expect_used)]
    pub fn from_env() -> Self {
        let app = AppConfig::from_env().expect("configuration failed");
        let database = DatabaseConfig::new(app.database_url.clone());
        let kms = app.kms.clone();
        let identity = app.identity.clone();

        let addr = app.bind;

        // In production, the web frontend is served as compiled static assets.
        // In development, the Next.js dev server runs separately.
        let web_assets = std::env::var("VL_WEB_ASSETS").ok().map(PathBuf::from);

        Self {
            app,
            database,
            kms,
            identity,
            addr,
            web_assets,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_reads_addr() {
        // Requires DATABASE_URL to be set; skip in env without it.
        if std::env::var("DATABASE_URL").is_ok() {
            let c = Config::from_env();
            assert_eq!(c.addr.port(), 8080);
        }
    }
}
