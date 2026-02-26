// File: test-base-scaffold.tpl.rs
// Purpose: Template for unknown implementation
// Generated for: {{PROJECT_NAME}}

#[cfg(test)]
mod test_base {
    use std::time::Duration;

    pub fn default_timeout() -> Duration {
        Duration::from_secs(30)
    }

    pub fn assert_ok<T, E>(res: Result<T, E>) {
        assert!(res.is_ok());
    }
}
