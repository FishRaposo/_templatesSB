// File: testing-utilities.tpl.rs
// Purpose: Test helpers and factories
// Generated for: {{PROJECT_NAME}}

#[cfg(test)]
pub mod test_helpers {
    use std::sync::Once;
    
    static INIT: Once = Once::new();

    /// Initialize logging for tests (runs only once)
    pub fn init_test_logging() {
        INIT.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_test_writer()
                .with_max_level(tracing::Level::DEBUG)
                .try_init();
        });
    }

    /// Macro to asserting that a Result is an Error with a specific substring
    #[macro_export]
    macro_rules! assert_err_contains {
        ($result:expr, $contains:expr) => {
            match $result {
                Ok(_) => panic!("Expected error, got Ok"),
                Err(e) => {
                    let msg = e.to_string();
                    assert!(
                        msg.contains($contains),
                        "Error '{}' did not contain '{}'",
                        msg,
                        $contains
                    );
                }
            }
        };
    }
}

// Example usage
#[cfg(test)]
mod tests {
    use super::test_helpers::*;
    use anyhow::{anyhow, Result};

    fn always_fail() -> Result<()> {
        Err(anyhow!("Connection refused"))
    }

    #[test]
    fn test_error_assertion() {
        init_test_logging();
        assert_err_contains!(always_fail(), "Connection refused");
    }
}
