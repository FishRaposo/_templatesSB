// File: errors.tpl.rs
// Purpose: Structured error handling using thiserror
// Generated for: {{PROJECT_NAME}}

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Authentication required")]
    Unauthorized,

    #[error("Permission denied")]
    Forbidden,

    #[error("Rate limit exceeded")]
    RateLimited,

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Internal error")]
    Internal(#[from] anyhow::Error),

    #[error("Database error")]
    Database(#[from] sqlx::Error),
}

impl AppError {
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::NotFound(_) => "NOT_FOUND",
            Self::Validation(_) => "VALIDATION_ERROR",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Forbidden => "FORBIDDEN",
            Self::RateLimited => "RATE_LIMITED",
            Self::Conflict(_) => "CONFLICT",
            Self::Internal(_) => "INTERNAL_ERROR",
            Self::Database(_) => "DATABASE_ERROR",
        }
    }

    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Validation(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Internal(_) | Self::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();

        let body = Json(ErrorResponse {
            error: self.error_code().to_string(),
            message: match &self {
                Self::Internal(_) | Self::Database(_) => {
                    "An unexpected error occurred".to_string()
                }
                _ => self.to_string(),
            },
            details: None,
            request_id: None,
        });

        (status, body).into_response()
    }
}

// Result type alias for convenience
pub type Result<T> = std::result::Result<T, AppError>;

// Helper functions
pub fn not_found(resource: &str, id: &str) -> AppError {
    AppError::NotFound(format!("{} with id '{}' not found", resource, id))
}

pub fn validation(message: impl Into<String>) -> AppError {
    AppError::Validation(message.into())
}
