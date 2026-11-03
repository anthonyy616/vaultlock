//! Provider-independent key management.
//!
//! [`Kms`] abstracts key creation, wrapping, unwrapping and rotation of
//! data-encryption keys (DEKs). Domain modules depend only on this trait —
//! never on a concrete cloud KMS.
//!
//! v0.1 ships [`LocalKms`]:
//! - A root master key (KEK) supplied through operator configuration
//!   (`VL_MASTER_KEY`), deliberately kept out of ordinary application
//!   configuration.
//! - DEKs are wrapped with AES-256-GCM using a versioned KEK; AAD binds the
//!   key id so wrapped material cannot be replayed to a different key.
//! - Wrapped DEKs live in `kms_keys` with master-version metadata. Rotation
//!   re-wraps the DEK under a new key id (keeping the old row so historical
//!   snapshots that pinned the old key id remain decryptable); the previous
//!   id is retained as `rotated_from` for traceability. The new pointer must
//!   be adopted by the domain resource in the same transaction by the caller.
//!
//! Hosted managed-KMS adapters plug into the same trait without domain
//! changes and are deferred until external credentials are available for
//! verification (see SECURITY docs; DEC-017).

use serde::Serialize;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;
use vaultlock_common::error::{AppError, AppResult};
use vaultlock_encryption::ZeroizingDek;

/// Key id reference within the KMS.
pub type KeyId = Uuid;

/// A wrapped-key record as surfaced by the KMS.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct KeyRecord {
    /// Stable key identifier.
    pub key_id: Uuid,
    /// Master-key (root KEK) version used for wrapping.
    pub master_version: i32,
    /// Wrapped DEK material (opaque to the database).
    pub wrapped_key: Vec<u8>,
    /// Creation timestamp (UTC).
    pub created_at: OffsetDateTime,
    /// Original key id when this entry is a rotation of an earlier key.
    pub rotated_from: Option<Uuid>,
}

/// KMS contract.
#[async_trait::async_trait]
pub trait Kms: Send + Sync {
    /// Create a new DEK. Returns the wrapping record; the plaintext DEK is
    /// returned exactly once, at creation.
    ///
    /// # Errors
    /// Propagates storage/encryption failures as [`AppError::Internal`].
    async fn create_key(
        &self,
        ctx: &vaultlock_audit::AuditContext,
    ) -> AppResult<(KeyRecord, ZeroizingDek)>;

    /// Rotate an existing key id: produce a new key id holding the same DEK
    /// re-wrapped under the current master version. The previous row is
    /// retained (historical snapshots pinned to it remain decryptable).
    ///
    /// # Errors
    /// [`AppError::NotFound`](vaultlock_common::error::AppError) for unknown
    /// keys; internal failures otherwise.
    async fn rotate_key(
        &self,
        key_id: KeyId,
        ctx: &vaultlock_audit::AuditContext,
    ) -> AppResult<KeyRecord>;

    /// Unwrap a DEK by key id. The returned key value zeroises when dropped.
    ///
    /// # Errors
    /// [`AppError::Internal`] on authentication failure or unknown keys; it
    /// never identifies which layer failed, nor which record could not be
    /// authenticated.
    async fn unwrap_dek(&self, key_id: KeyId) -> AppResult<ZeroizingDek>;
}

/// Derive the versioned AES KEK from root master material (domain separation;
/// inputs are already high-entropy 32-byte values).
fn master_cipher_key(master: &[u8; 32], version: u32) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"vaultlock/kek/v1" as &[u8]);
    hasher.update(version.to_be_bytes());
    hasher.update(master);
    hasher.finalize().into()
}

/// Built-in local KMS.
pub struct LocalKms {
    pool: PgPool,
    master: [u8; 32],
    master_version: u32,
}

impl LocalKms {
    /// Construct the KMS over a database pool and the configured master key.
    ///
    /// `master_version` labels the current root material (bump when operators
    /// rotate the master key and re-wrap domain keys).
    #[must_use]
    pub fn new(pool: PgPool, master: [u8; 32], master_version: u32) -> Self {
        Self { pool, master, master_version }
    }

    async fn load_wrapped(&self, key_id: KeyId) -> AppResult<KeyRecord> {
        sqlx::query_as::<_, KeyRecord>(
            "select key_id, master_version, wrapped_key, created_at, rotated_from
             from kms_keys where key_id = $1",
        )
        .bind(key_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(AppError::from)?
        .ok_or(AppError::Internal)
    }
}

#[async_trait::async_trait]
impl Kms for LocalKms {
    async fn create_key(
        &self,
        _ctx: &vaultlock_audit::AuditContext,
    ) -> AppResult<(KeyRecord, ZeroizingDek)> {
        let dek = vaultlock_encryption::generate_dek();
        let key_id = Uuid::now_v7();
        let kek = master_cipher_key(&self.master, self.master_version);
        let wrapped = vaultlock_encryption::wrap_key(&kek, key_id.as_bytes(), &dek)
            .map_err(|_| AppError::Internal)?;
        let created_at = OffsetDateTime::now_utc();
        let version = i32::try_from(self.master_version).unwrap_or(1);
        sqlx::query(
            "insert into kms_keys (key_id, master_version, wrapped_key, created_at, rotated_from)
             values ($1, $2, $3, $4, null)",
        )
        .bind(key_id)
        .bind(version)
        .bind(&wrapped)
        .bind(created_at)
        .execute(&self.pool)
        .await
        .map_err(AppError::from)?;
        Ok((
            KeyRecord {
                key_id,
                master_version: version,
                wrapped_key: wrapped,
                created_at,
                rotated_from: None,
            },
            ZeroizingDek::from_inner(dek),
        ))
    }

    async fn rotate_key(
        &self,
        key_id: KeyId,
        ctx: &vaultlock_audit::AuditContext,
    ) -> AppResult<KeyRecord> {
        let old = self.load_wrapped(key_id).await?;
        let kek_old = master_cipher_key(&self.master, u32::try_from(old.master_version).unwrap_or(1));
        let dek = vaultlock_encryption::unwrap_key(&kek_old, key_id.as_bytes(), &old.wrapped_key)?;
        let new_id = Uuid::now_v7();
        let kek_new = master_cipher_key(&self.master, self.master_version);
        let wrapped = vaultlock_encryption::wrap_key(&kek_new, new_id.as_bytes(), dek.expose())?;
        let created_at = OffsetDateTime::now_utc();
        let version_record = i32::try_from(self.master_version).unwrap_or(1);

        let mut tx = self.pool.begin().await.map_err(AppError::from)?;
        sqlx::query(
            "insert into kms_keys (key_id, master_version, wrapped_key, created_at, rotated_from)
             values ($1, $2, $3, $4, $5)",
        )
        .bind(new_id)
        .bind(version_record)
        .bind(&wrapped)
        .bind(created_at)
        .bind(key_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::from)?;
        tx.commit().await.map_err(AppError::from)?;

        vaultlock_audit::record_strict(
            &self.pool,
            ctx,
            vaultlock_audit::actions::KEY_ROTATED,
            Some("kms_key"),
            Some(key_id),
            serde_json::json!({ "new_key_id": new_id }),
        )
        .await?;

        Ok(KeyRecord {
            key_id: new_id,
            master_version: version_record,
            wrapped_key: wrapped,
            created_at,
            rotated_from: Some(key_id),
        })
    }

    async fn unwrap_dek(&self, key_id: KeyId) -> AppResult<ZeroizingDek> {
        let rec = self.load_wrapped(key_id).await?;
        let kek = master_cipher_key(&self.master, u32::try_from(rec.master_version).unwrap_or(1));
        vaultlock_encryption::unwrap_key(&kek, key_id.as_bytes(), &rec.wrapped_key)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use vaultlock_audit::AuditContext;

    async fn test_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL_ORIG").ok()?;
        let pg = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url.replace("/vaultlock?", "/vaultlock_kms_test?").replace(
                "postgres://database.vaultbox.internal:5432/vaultlock",
                "postgres://localhost:5432/vaultlock",
            ))
            .await
            .ok()?;
        Some(pg)
    }

    #[tokio::test]
    async fn wrap_unwrap_roundtrip_via_db() {
        let Some(pool) = test_pool().await else {
            eprintln!("skipped: no local postgres available");
            return;
        };
        sqlx::query("create table if not exists kms_keys (key_id uuid primary key, master_version int not null, wrapped_key bytea not null, created_at timestamptz not null, rotated_from uuid)")
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("schema: {e}"));
        let master: [u8; 32] = [7u8; 32];
        let kms = LocalKms::new(pool, master, 1);
        let (record, dek) = kms.create_key(&AuditContext::default()).await.unwrap_or_else(|e| panic!("create: {e}"));
        let unwrapped = kms.unwrap_dek(record.key_id).await.unwrap_or_else(|e| panic!("unwrap: {e}"));
        assert_eq!(unwrapped.expose(), dek.expose());
        assert!(kms.unwrap_dek(Uuid::now_v7()).await.is_err());
    }

    #[tokio::test]
    async fn rotate_key_rewraps_and_keeps_history() {
        let Some(pool) = test_pool().await else {
            eprintln!("skipped: no local postgres available");
            return;
        };
        sqlx::query("create table if not exists kms_keys (key_id uuid primary key, master_version int not null, wrapped_key bytea not null, created_at timestamptz not null, rotated_from uuid)")
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("schema: {e}"));
        let master: [u8; 32] = [9u8; 32];
        let kms = LocalKms::new(pool, master, 1);
        let (record, dek) = kms.create_key(&AuditContext::default()).await.unwrap_or_else(|e| panic!("create: {e}"));
        let rotated = kms.rotate_key(record.key_id, &AuditContext::default()).await.unwrap_or_else(|e| panic!("rotate: {e}"));
        assert_eq!(rotated.rotated_from, Some(record.key_id));
        assert_ne!(rotated.key_id, record.key_id);
        // Both old and new ids unwrap to the same DEK.
        let old_dek = kms.unwrap_dek(record.key_id).await.unwrap_or_else(|e| panic!("old unwrap: {e}"));
        let new_dek = kms.unwrap_dek(rotated.key_id).await.unwrap_or_else(|e| panic!("new unwrap: {e}"));
        assert_eq!(old_dek.expose(), dek.expose());
        assert_eq!(new_dek.expose(), dek.expose());
    }
}
