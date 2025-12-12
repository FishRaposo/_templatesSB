// File: error-handling.tpl.rs
// Purpose: Centralized error handling using 'thiserror' and 'anyhow'
// Generated for: {{PROJECT_NAME}}

use thiserror::Error;
use serde::Serialize;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Configuration error: {0}")]
    Configuration(#[from] config::ConfigError),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Validation failed: {0}")]
    Validation(String),

    #[error("Authorization failed: {0}")]
    Unauthorized(String),

    #[error("External service error: {0}")]
    ExternalService(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Standard error response format for APIs
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl AppError {
    pub fn error_code(&self) -> &str {
        match self {
            AppError::Configuration(_) => "CONFIG_ERROR",
            AppError::Database(_) => "DB_ERROR",
            AppError::NotFound(_) => "NOT_FOUND",
            AppError::Validation(_) => "VALIDATION_ERROR",
            AppError::Unauthorized(_) => "UNAUTHORIZED",
            AppError::ExternalService(_) => "SERVICE_UNAVAILABLE",
            AppError::Other(_) => "INTERNAL_ERROR",
        }
    }

    pub fn status_code(&self) -> u16 {
        match self {
            AppError::Configuration(_) => 500,
            AppError::Database(_) => 500,
            AppError::NotFound(_) => 404,
            AppError::Validation(_) => 400,
            AppError::Unauthorized(_) => 401,
            AppError::ExternalService(_) => 503,
            AppError::Other(_) => 500,
        }
    }

    pub fn to_response(&self) -> ErrorResponse {
        ErrorResponse {
            code: self.error_code().to_string(),
            message: self.to_string(),
            details: None,
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;
