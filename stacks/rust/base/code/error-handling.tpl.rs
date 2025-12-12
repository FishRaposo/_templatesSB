// File: error-handling.tpl.rs
// Purpose: Template for unknown implementation
// Generated for: {{PROJECT_NAME}}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Not found")]
    NotFound,

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type AppResult<T> = Result<T, AppError>;
