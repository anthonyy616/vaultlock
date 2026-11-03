//! Shared application state passed to every handler.

use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use vaultlock_audit::AuditContext;
use vaultlock_identity::AuthService;
use vaultlock_key_management::LocalKms;

/// Shared application state.
pub struct AppState {
    /// Database pool.
    pub pool: PgPool,
    /// KMS (built-in LocalKms for v0.1).
    pub kms: Arc<LocalKms>,
    /// Identity service.
    pub identity: Arc<AuthService>,
    /// Audit context (populated per-request by middleware).
    pub audit: AuditContext,
    /// Request ID (per-request, set by middleware).
    pub request_id: String,
}

impl AppState {
    /// Build the shared state. Panics on configuration errors (fail-closed).
    #[allow(clippy::expect_used)]
    pub async fn new() -> Self {
        let config = crate::config::Config::from_env();
        let pool = PgPool::connect(&config.database.url)
            .await
            .expect("failed to connect to PostgreSQL");

        let kms = Arc::new(LocalKms::new(pool.clone(), config.kms.master_key, 1));

        let identity = Arc::new(AuthService::new(
            pool.clone(),
            AuditContext::default(),
            config.identity.session_ttl.as_secs() as i64,
            config.identity.personal_access_ttl.as_secs() as i64,
            config.identity.email_token_ttl.as_secs() as i64,
            config.identity.device_flow_ttl.as_secs() as i64,
            false, // verify_email disabled for dev
        ));

        let request_id = Uuid::new_v4().to_string();

        Self {
            pool,
            kms,
            identity,
            audit: AuditContext::default(),
            request_id,
        }
    }
}

impl AppState {
    /// Clone a per-request state with a fresh request ID and audit context.
    pub fn for_request(&self, request_id: String) -> Arc<Self> {
        Arc::new(Self {
            pool: self.pool.clone(),
            kms: Arc::clone(&self.kms),
            identity: Arc::clone(&self.identity),
            audit: AuditContext {
                request_id: Some(request_id.clone()),
                ..self.audit.clone()
            },
            request_id,
        })
    }
}
