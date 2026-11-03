//! Mapping from domain errors to HTTP responses.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use vaultlock_common::error::AppError;

/// A consistent JSON error envelope.
#[derive(Debug, Serialize)]
pub struct ErrorEnvelope {
    /// Error detail.
    pub error: ErrorDetail,
}

/// Details of an error.
#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    /// Machine-readable error code.
    pub code: String,
    /// Human-readable error message.
    pub message: String,
}

impl IntoResponse for ErrorEnvelope {
    fn into_response(self) -> Response {
        let status = match self.error.code.as_str() {
            "RESOURCE_NOT_FOUND" => StatusCode::NOT_FOUND,
            "UNAUTHORISED" | "FORBIDDEN" => StatusCode::UNAUTHORIZED,
            "CONFLICT" => StatusCode::CONFLICT,
            "VALIDATION_FAILED" => StatusCode::UNPROCESSABLE_ENTITY,
            "RATE_LIMITED" => StatusCode::TOO_MANY_REQUESTS,
            "PAYLOAD_TOO_LARGE" => StatusCode::PAYLOAD_TOO_LARGE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(self)).into_response()
    }
}

impl From<AppError> for ErrorEnvelope {
    fn from(err: AppError) -> Self {
        ErrorEnvelope {
            error: ErrorDetail {
                code: err.code().into(),
                message: err.message(),
            },
        }
    }
}
