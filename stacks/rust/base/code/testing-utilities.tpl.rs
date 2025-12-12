// File: testing-utilities.tpl.rs
// Purpose: Template for unknown implementation
// Generated for: {{PROJECT_NAME}}

pub fn assert_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "Expected to find '{needle}' in '{haystack}'"
    );
}
