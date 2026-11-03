//! Typed application errors.
//!
//! Domain and infrastructure layers raise [`AppError`]; the HTTP layer maps it
//! onto the public error envelope. Internal details are never exposed.

use std::fmt;

use serde_json::{Value, json};

/// Application error type shared across the backend.
///
/// Semantic variants carry safe, client-renderable information; anything else
/// becomes an opaque `Internal` error that is logged server-side only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppError {
    /// Request body is malformed, missing or fails validation.
    Validation {
        /// Stable machine-readable field name, e.g. `email`.
        field: String,
        /// A safe, human-readable description.
        message: String,
    },
    /// Authentication is required or the credentials are invalid.
    Unauthorised,
    /// Authenticated but the principal is not allowed to perform this action.
    Forbidden,
    /// The requested resource does not exist (or must not be revealed).
    NotFound,
    /// The request conflicts with current state (e.g. duplicate email).
    Conflict {
        /// Stable machine-readable conflict reason code.
        code: String,
        /// A safe, human-readable description.
        message: String,
    },
    /// Optimistic concurrency precondition failed.
    Precondition {
        /// A safe, human-readable description.
        message: String,
    },
    /// Request payload or file exceeds the configured limit.
    TooLarge {
        /// A safe, human-readable description.
        message: String,
    },
    /// The client has exceeded rate limits and should retry later.
    RateLimited {
        /// Suggested seconds to wait before retrying.
        retry_after_secs: u64,
    },
    /// Unexpected failure. Details are logged but never returned to clients.
    Internal,
}

impl AppError {
    /// Stable error code used in the API error envelope.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AppError::Validation { .. } => "VALIDATION_FAILED",
            AppError::Unauthorised => "UNAUTHORISED",
            AppError::Forbidden => "FORBIDDEN",
            AppError::NotFound => "RESOURCE_NOT_FOUND",
            AppError::Conflict { .. } => "CONFLICT",
            AppError::Precondition { .. } => "PRECONDITION_FAILED",
            AppError::TooLarge { .. } => "PAYLOAD_TOO_LARGE",
            AppError::RateLimited { .. } => "RATE_LIMITED",
            AppError::Internal => "INTERNAL_ERROR",
        }
    }

    /// Client-renderable message. Internal errors expose no detail.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            AppError::Validation { message, .. } => message.clone(),
            AppError::Unauthorised => "Authentication is required.".to_string(),
            AppError::Forbidden => "You do not have access to perform this action.".to_string(),
            AppError::NotFound => "The requested resource was not found.".to_string(),
            AppError::Conflict { message, .. } => message.clone(),
            AppError::Precondition { message } => message.clone(),
            AppError::TooLarge { message } => message.clone(),
            AppError::RateLimited { .. } => "Too many requests. Please retry later.".to_string(),
            AppError::Internal => {
                "An unexpected error occurred. The incident has been logged.".to_string()
            }
        }
    }

    /// Extra safe details for the error envelope (validation fields etc.).
    #[must_use]
    pub fn details(&self) -> Value {
        match self {
            AppError::Validation { field, .. } => json!({ "field": field }),
            AppError::Conflict { code, .. } => json!({ "reason": code }),
            _ => json!({}),
        }
    }

    /// Convenience constructors used across the backend.
    #[must_use]
    pub fn validation(field: &str, message: &str) -> Self {
        AppError::Validation {
            field: field.to_string(),
            message: message.to_string(),
        }
    }

    /// Conflict error with a stable reason code.
    #[must_use]
    pub fn conflict(code: &str, message: &str) -> Self {
        AppError::Conflict {
            code: code.to_string(),
            message: message.to_string(),
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for AppError {}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        tracing::error!(error = %err, "database error");
        match &err {
            sqlx::Error::RowNotFound => AppError::NotFound,
            sqlx::Error::ColumnDecode { index, source, .. } => {
                tracing::error!(column = %index, decode_error = %source, "column decode");
                AppError::Internal
            }
            sqlx::Error::Database(db) if db.constraint().is_some() => AppError::Conflict {
                code: "CONSTRAINT_VIOLATION".to_string(),
                message: "The request conflicts with existing data.".to_string(),
            },
            _ => AppError::Internal,
        }
    }
}

/// Result alias used across the backend.
pub type AppResult<T> = Result<T, AppError>;
