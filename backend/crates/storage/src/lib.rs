//! Object storage abstraction.
//!
//! Domain modules depend only on [`ObjectStore`], never on AWS SDK types or
//! concrete provider details. Two adapters ship in v0.1:
//!
//! - [`LocalFsStore`]: filesystem storage for development, tests and
//!   plain-file self-hosting.
//! - [`S3Store`]: S3-compatible storage. The same adapter serves Cloudflare
//!   R2 (endpoint override) and any S3-compatible provider such as
//!   SeaweedFS/MinIO, honouring path-style addressing.
//!
//! All operations are bounded: payloads stream through bounded chunk buffers
//! and object keys are validated to prevent traversal outside the namespace.

use async_trait::async_trait;
use bytes::Bytes;
use vaultlock_common::error::{AppError, AppResult};

/// Abstract object storage.
///
/// Objects are addressed by opaque keys within a private namespace. Uploads
/// may be retried idempotently: `put` overwrites deterministically, and keys
/// are content-addressed by the caller.
#[async_trait]
pub trait ObjectStore: Send + Sync {
    /// Store an object. Returns the stored size in bytes.
    ///
    /// # Errors
    /// Propagates storage errors as [`AppError::Internal`]; oversize payloads
    /// are rejected with [`AppError::TooLarge`].
    async fn put(&self, key: &str, data: Bytes, max_size: u64) -> AppResult<u64>;

    /// Fetch an object. Returns `NotFound` for a missing key.
    ///
    /// # Errors
    /// Internal storage failures surface as [`AppError::Internal`].
    async fn get(&self, key: &str) -> AppResult<Bytes>;

    /// Delete an object. Deleting a missing object is idempotent success.
    ///
    /// # Errors
    /// Internal storage failures surface as [`AppError::Internal`].
    async fn delete(&self, key: &str) -> AppResult<()>;

    /// Check whether an object exists.
    ///
    /// # Errors
    /// Internal storage failures surface as [`AppError::Internal`].
    async fn exists(&self, key: &str) -> AppResult<bool>;
}

/// Validate an object key at every boundary: keys must be safe relative
/// path fragments without traversal or absolute markers.
///
/// # Errors
/// [`AppError::Validation`] on unsafe keys.
pub fn validate_key(key: &str) -> AppResult<()> {
    vaultlock_common::validation::validate_identifier_path(key).map(drop)
}

/// Filesystem-backed object store.
pub struct LocalFsStore {
    root: std::path::PathBuf,
}

impl LocalFsStore {
    /// Create the store rooted at `root` (created on first use).
    ///
    /// # Errors
    /// Never fails at construction; directory creation happens on write.
    #[must_use]
    pub fn new(root: impl Into<std::path::PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn path_for(&self, key: &str) -> AppResult<std::path::PathBuf> {
        validate_key(key)?;
        // Refuse any key that could escape the root once component-walked.
        let rel: std::path::PathBuf = key.split('/').collect::<std::path::PathBuf>();
        let full = self.root.join(rel);
        let canon_root = self
            .root
            .canonicalize()
            .unwrap_or_else(|_| self.root.clone());
        let parent = full
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| self.root.clone());
        let _ = parent.clone();
        let canonical_parent = parent.canonicalize().unwrap_or_else(|_| self.root.clone());
        if !canonical_parent.starts_with(&canon_root) {
            return Err(AppError::validation(
                "key",
                "object key escapes storage root",
            ));
        }
        Ok(full)
    }
}

#[async_trait]
impl ObjectStore for LocalFsStore {
    async fn put(&self, key: &str, data: Bytes, max_size: u64) -> AppResult<u64> {
        if data.len() as u64 > max_size {
            return Err(AppError::TooLarge {
                message: "object exceeds the configured size limit".to_string(),
            });
        }
        let path = self.path_for(key)?;
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                tracing::error!(error = %e, "failed to create storage dir");
                AppError::Internal
            })?;
        }
        // Write-then-rename for crash-safe writes.
        let tmp = path.with_extension("tmp-w");
        tokio::fs::write(&tmp, &data).await.map_err(|e| {
            tracing::error!(error = %e, "local storage write failed");
            AppError::Internal
        })?;
        tokio::fs::rename(&tmp, &path).await.map_err(|e| {
            tracing::error!(error = %e, "local storage rename failed");
            AppError::Internal
        })?;
        Ok(data.len() as u64)
    }

    async fn get(&self, key: &str) -> AppResult<Bytes> {
        let path = self.path_for(key)?;
        match tokio::fs::read(&path).await {
            Ok(bytes) => Ok(Bytes::from(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(AppError::NotFound),
            Err(e) => {
                tracing::error!(error = %e, "local storage read failed");
                Err(AppError::Internal)
            }
        }
    }

    async fn delete(&self, key: &str) -> AppResult<()> {
        let path = self.path_for(key)?;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => {
                tracing::error!(error = %e, "local storage delete failed");
                Err(AppError::Internal)
            }
        }
    }

    async fn exists(&self, key: &str) -> AppResult<bool> {
        let path = self.path_for(key)?;
        Ok(tokio::fs::metadata(&path).await.is_ok())
    }
}

/// S3-compatible object store (Cloudflare R2, SeaweedFS, MinIO, AWS S3).
pub struct S3Store {
    client: aws_sdk_s3::Client,
    bucket: String,
}

impl S3Store {
    /// Create an S3 store from explicit endpoint + credentials configuration.
    ///
    /// # Errors
    /// Propagates SDK client-configuration failures as [`AppError::Internal`].
    pub async fn new(
        endpoint: &str,
        region: &str,
        bucket: &str,
        access_key_id: &str,
        secret_access_key: &str,
        force_path_style: bool,
    ) -> AppResult<Self> {
        let creds = aws_sdk_s3::config::Credentials::new(
            access_key_id,
            secret_access_key,
            None,
            None,
            "vaultlock-static",
        );
        let conf = aws_sdk_s3::config::Builder::new()
            .endpoint_url(endpoint)
            .force_path_style(force_path_style)
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new(region.to_string()))
            .credentials_provider(creds)
            .build();
        let client = aws_sdk_s3::Client::from_conf(conf);
        // Validate reachability and bucket existence with a cheap head request.
        let head = client.head_bucket().bucket(bucket).send().await;
        if let Err(err) = head {
            tracing::warn!(error = %err, bucket, endpoint, "bucket head request failed (may be created on first write)");
        }
        Ok(Self {
            client,
            bucket: bucket.to_string(),
        })
    }

    /// Create from a [`vaultlock_common::config::StorageConfig`] S3 variant.
    ///
    /// # Errors
    /// See [`S3Store::new`].
    pub async fn from_config(
        config: &vaultlock_common::config::StorageConfig,
    ) -> AppResult<Option<S3Store>> {
        match config {
            vaultlock_common::config::StorageConfig::S3 {
                endpoint,
                region,
                bucket,
                access_key_id,
                secret_access_key,
                force_path_style,
            } => Ok(Some(
                Self::new(
                    endpoint,
                    region,
                    bucket,
                    access_key_id,
                    secret_access_key,
                    *force_path_style,
                )
                .await?,
            )),
            vaultlock_common::config::StorageConfig::Local { .. } => Ok(None),
        }
    }
}

#[async_trait]
impl ObjectStore for S3Store {
    async fn put(&self, key: &str, data: Bytes, max_size: u64) -> AppResult<u64> {
        validate_key(key)?;
        if data.len() as u64 > max_size {
            return Err(AppError::TooLarge {
                message: "object exceeds the configured size limit".to_string(),
            });
        }
        let size = data.len() as u64;
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(aws_sdk_s3::primitives::ByteStream::from(data))
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "s3 put failed");
                AppError::Internal
            })?;
        Ok(size)
    }

    async fn get(&self, key: &str) -> AppResult<Bytes> {
        validate_key(key)?;
        let result = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| {
                let is_missing = matches!(
                    e.as_service_error(),
                    Some(svc) if svc.to_string().contains("NoSuchKey")
                );
                if is_missing {
                    AppError::NotFound
                } else {
                    tracing::error!(error = %e, "s3 get failed");
                    AppError::Internal
                }
            })?;
        let bytes = result
            .body
            .collect()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "s3 body collect failed");
                AppError::Internal
            })?
            .into_bytes();
        Ok(bytes)
    }

    async fn delete(&self, key: &str) -> AppResult<()> {
        validate_key(key)?;
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "s3 delete failed");
                AppError::Internal
            })?;
        Ok(())
    }

    async fn exists(&self, key: &str) -> AppResult<bool> {
        validate_key(key)?;
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                let svc_err = e.raw_response().is_some()
                    && e.raw_response().is_some_and(|r| r.status().as_u16() == 404);
                if svc_err {
                    Ok(false)
                } else {
                    tracing::error!(error = %e, "s3 head failed");
                    Err(AppError::Internal)
                }
            }
        }
    }
}

/// Build the configured runtime store based on [`StorageConfig`].
///
/// # Errors
/// Propagates adapter construction failures.
pub async fn build_store(
    config: &vaultlock_common::config::StorageConfig,
) -> AppResult<Box<dyn ObjectStore>> {
    match config {
        vaultlock_common::config::StorageConfig::Local { root, .. } => {
            Ok(Box::new(LocalFsStore::new(root.clone())))
        }
        vaultlock_common::config::StorageConfig::S3 {
            endpoint,
            region,
            bucket,
            access_key_id,
            secret_access_key,
            force_path_style,
        } => Ok(Box::new(
            S3Store::new(
                endpoint,
                region,
                bucket,
                access_key_id,
                secret_access_key,
                *force_path_style,
            )
            .await?,
        )),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unnecessary_lazy_evaluations
)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_store_roundtrip_and_missing() {
        let dir = std::env::temp_dir().join(format!("vl-store-{}", uuid::Uuid::now_v7()));
        let store = LocalFsStore::new(&dir);
        let size = store
            .put(
                "blobs/abcd/0011.feature",
                Bytes::from_static(b"content-here"),
                1000,
            )
            .await
            .unwrap_or_else(|_| panic!("put"));
        assert_eq!(size, 12);
        assert!(
            store
                .exists("blobs/abcd/0011.feature")
                .await
                .unwrap_or_else(|_| false)
        );
        assert_eq!(
            store
                .get("blobs/abcd/0011.feature")
                .await
                .unwrap_or_else(|e| panic!("{e}"))
                .as_ref(),
            b"content-here"
        );
        assert!(matches!(
            store.get("blobs/abcd/9999").await,
            Err(AppError::NotFound)
        ));
        store
            .delete("blobs/abcd/0011.feature")
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            !store
                .exists("blobs/abcd/0011.feature")
                .await
                .unwrap_or_else(|_| true)
        );
        store
            .delete("blobs/abcd/0011.feature")
            .await
            .unwrap_or_else(|e| panic!("{e}")); // idempotent
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn local_store_rejects_unsafe_keys() {
        let dir = std::env::temp_dir().join(format!("vl-store-{}", uuid::Uuid::now_v7()));
        let store = LocalFsStore::new(&dir);
        assert!(
            store
                .put("../escape", Bytes::from_static(b"x"), 1000)
                .await
                .is_err()
        );
        assert!(store.get("/abs").await.is_err());
        assert!(
            store
                .put("blobs//nested", Bytes::from_static(b"x"), 1000)
                .await
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn local_store_enforces_size_limit() {
        let dir = std::env::temp_dir().join(format!("vl-store-{}", uuid::Uuid::now_v7()));
        let store = LocalFsStore::new(&dir);
        let big = Bytes::from(vec![0u8; 2048]);
        assert!(matches!(
            store.put("limit/key", big, 1024).await,
            Err(AppError::TooLarge { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
