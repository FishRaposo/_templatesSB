// File: data-validation.tpl.rs
// Purpose: Data validation utilities using the 'validator' crate
// Generated for: {{PROJECT_NAME}}

use validator::{Validate, ValidationErrors};
use serde::{Deserialize, Serialize};

/// Custom validation error structure
#[derive(Debug, Serialize)]
pub struct ValidationErrorDetails {
    pub field: String,
    pub message: String,
}

/// Helper to format validation errors into a user-friendly list
pub fn format_validation_errors(errors: &ValidationErrors) -> Vec<ValidationErrorDetails> {
    let mut details = Vec::new();

    for (field, error_list) in errors.field_errors() {
        for error in error_list {
            let message = error.message.as_ref()
                .map(|cow| cow.to_string())
                .unwrap_or_else(|| format!("Invalid value for code: {}", error.code));
            
            details.push(ValidationErrorDetails {
                field: field.to_string(),
                message,
            });
        }
    }

    details
}

/// Trait for validatable DTOs
pub trait Validatable: Validate {
    fn validate_entity(&self) -> Result<(), Vec<ValidationErrorDetails>> {
        self.validate().map_err(|e| format_validation_errors(&e))
    }
}

// Blanket implementation for any type implementing Validate
impl<T: Validate> Validatable for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use validator::Validate;

    #[derive(Debug, Validate, Deserialize)]
    struct UserSignup {
        #[validate(email)]
        email: String,
        #[validate(length(min = 8))]
        password: String,
        #[validate(range(min = 18, max = 150))]
        age: u8,
    }

    #[test]
    fn test_valid_user() {
        let user = UserSignup {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            age: 25,
        };
        assert!(user.validate_entity().is_ok());
    }

    #[test]
    fn test_invalid_email() {
        let user = UserSignup {
            email: "not-an-email".to_string(),
            password: "password123".to_string(),
            age: 25,
        };
        let res = user.validate_entity();
        assert!(res.is_err());
        let errs = res.unwrap_err();
        assert_eq!(errs[0].field, "email");
    }
}
