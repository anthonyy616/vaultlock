//! Security-relevant audit logging.
//!
//! Every audit event is a durable row in `audit_events` recording who did what
//! to which resource, when, and correlated with the HTTP request id. Audit
//! rows never contain plaintext secrets, tokens, file names of secret files,
//! or file contents — only structural metadata.

use serde_json::Value;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;
use vaultlock_common::error::AppResult;

/// The exact does-what: stable machine-readable audit action constants.
pub mod actions {
    /// Successful login.
    pub const AUTH_LOGIN: &str = "auth.login";
    /// Failed login attempt.
    pub const AUTH_LOGIN_FAILED: &str = "auth.login_failed";
    /// Account registration.
    pub const AUTH_REGISTERED: &str = "auth.registered";
    /// Email verified.
    pub const AUTH_EMAIL_VERIFIED: &str = "auth.email_verified";
    /// Password reset completed.
    pub const AUTH_PASSWORD_RESET: &str = "auth.password_reset";
    /// Password changed.
    pub const AUTH_PASSWORD_CHANGED: &str = "auth.password_changed";
    /// Device registered.
    pub const DEVICE_REGISTERED: &str = "device.registered";
    /// Device revoked.
    pub const DEVICE_REVOKED: &str = "device.revoked";
    /// CLI device-flow authorisation approved.
    pub const DEVICE_FLOW_APPROVED: &str = "device_flow.approved";
    /// Vault created.
    pub const VAULT_CREATED: &str = "vault.created";
    /// Vault archived.
    pub const VAULT_ARCHIVED: &str = "vault.archived";
    /// Vault deleted.
    pub const VAULT_DELETED: &str = "vault.deleted";
    /// Snapshot committed.
    pub const SNAPSHOT_COMMITTED: &str = "snapshot.committed";
    /// Snapshot restored.
    pub const SNAPSHOT_RESTORED: &str = "snapshot.restored";
    /// Sync conflict detected.
    pub const SYNC_CONFLICT: &str = "sync.conflict_detected";
    /// Secret set created.
    pub const SECRET_SET_CREATED: &str = "secret_set.created";
    /// Secret values updated.
    pub const SECRET_UPDATED: &str = "secret.updated";
    /// Secret retrieval performed.
    pub const SECRET_RETRIEVED: &str = "secret.retrieved";
    /// Secret rotated.
    pub const SECRET_ROTATED: &str = "secret.rotated";
    /// Resource shared.
    pub const SHARED: &str = "sharing.created";
    /// Share revoked.
    pub const SHARING_REVOKED: &str = "sharing.revoked";
    /// External link accessed.
    pub const LINK_ACCESSED: &str = "share_link.accessed";
    /// External link created.
    pub const LINK_CREATED: &str = "share_link.created";
    /// Permission changed.
    pub const PERMISSION_CHANGED: &str = "sharing.permission_changed";
    /// Organisation membership changed.
    pub const ORG_MEMBER_ADDED: &str = "org.member_added";
    /// Member removed.
    pub const ORG_MEMBER_REMOVED: &str = "org.member_removed";
    /// Member invited.
    pub const ORG_INVITED: &str = "org.member_invited";
    /// Organisation created.
    pub const ORG_CREATED: &str = "org.created";
    /// Recovery code generated.
    pub const RECOVERY_GENERATED: &str = "recovery.generated";
    /// Recovery performed.
    pub const RECOVERY_USED: &str = "recovery.used";
    /// Key rotation completed.
    pub const KEY_ROTATED: &str = "key.rotated";
    /// Project created.
    pub const PROJECT_CREATED: &str = "project.created";
}

/// Context of the actor and request that triggered an audit event.
#[derive(Debug, Clone, Default)]
pub struct AuditContext {
    /// Authenticated principal, when known.
    pub actor: Option<Uuid>,
    /// Organisation scope, when the event is organisation-scoped.
    pub org: Option<Uuid>,
    /// HTTP request id for correlation.
    pub request_id: Option<String>,
    /// Client IP (best-effort).
    pub ip: Option<String>,
    /// Client user agent (best-effort, truncated upstream).
    pub user_agent: Option<String>,
}

/// Persist one audit event. Never fails the calling operation: failures are
/// logged server-side (audit is best-effort durability for the request path,
/// durability failures are surfaced to the job/ops monitoring).
pub async fn record(
    pool: &PgPool,
    ctx: &AuditContext,
    action: &str,
    resource_type: Option<&str>,
    resource_id: Option<Uuid>,
    metadata: Value,
) {
    let result = sqlx::query(
        "insert into audit_events
            (id, actor_user_id, org_id, action, resource_type, resource_id, metadata, request_id, ip, user_agent, created_at)
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(Uuid::now_v7())
    .bind(ctx.actor)
    .bind(ctx.org)
    .bind(action)
    .bind(resource_type)
    .bind(resource_id)
    .bind(metadata)
    .bind(ctx.request_id.clone())
    .bind(ctx.ip.clone())
    .bind(ctx.user_agent.clone())
    .bind(OffsetDateTime::now_utc())
    .execute(pool)
    .await;
    if let Err(err) = result {
        tracing::error!(target: "audit", error = %err, action, "audit write failed");
    }
}

/// Persist one audit event, returning a hard error on failure (used where audit
/// durability is required by the callers' own acceptance criteria, e.g. key
/// rotation).
///
/// # Errors
/// Propagates database errors so critical operations fail closed.
pub async fn record_strict(
    pool: &PgPool,
    ctx: &AuditContext,
    action: &str,
    resource_type: Option<&str>,
    resource_id: Option<Uuid>,
    metadata: Value,
) -> AppResult<()> {
    sqlx::query(
        "insert into audit_events
            (id, actor_user_id, org_id, action, resource_type, resource_id, metadata, request_id, ip, user_agent, created_at)
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(Uuid::now_v7())
    .bind(ctx.actor)
    .bind(ctx.org)
    .bind(action)
    .bind(resource_type)
    .bind(resource_id)
    .bind(metadata)
    .bind(ctx.request_id.clone())
    .bind(ctx.ip.clone())
    .bind(ctx.user_agent.clone())
    .bind(OffsetDateTime::now_utc())
    .execute(pool)
    .await
    .map_err(vaultlock_common::error::AppError::from)?;
    Ok(())
}
