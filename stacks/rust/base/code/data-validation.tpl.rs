// File: data-validation.tpl.rs
// Purpose: Template for unknown implementation
// Generated for: {{PROJECT_NAME}}

use validator::Validate;

#[derive(Debug, Validate)]
pub struct CreateUserRequest {
    #[validate(length(min = 1))]
    pub name: String,

    #[validate(email)]
    pub email: String,
}

pub fn validate_create_user(req: &CreateUserRequest) -> Result<(), validator::ValidationErrors> {
    req.validate()
}
