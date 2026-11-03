//! Shared backend utilities: configuration, typed errors, identifiers,
//! pagination, validation and log redaction.
//!
//! This crate is domain-neutral: it must not depend on Axum or on any concrete
//! infrastructure SDK, so every domain crate can build on it.

pub mod config;
pub mod error;
pub mod ids;
pub mod pagination;
pub mod redact;
pub mod validation;

pub use config::{AppConfig, DatabaseConfig, IdentityConfig, KmsConfig, StorageConfig};
pub use error::AppError;
pub use ids::{new_id, Id};
pub use pagination::{Page, PageParams};
pub use validation::validate_identifier_path;
