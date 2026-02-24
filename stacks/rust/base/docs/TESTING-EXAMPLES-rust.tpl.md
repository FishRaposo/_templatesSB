<!--
File: TESTING-EXAMPLES-rust.tpl.md
Purpose: Examples of testing strategies in Rust
Generated for: {{PROJECT_NAME}}
-->

# Testing Examples

## Unit Testing
Rust supports unit tests co-located with code.

```rust
// function to test
fn add(a: i32, b: i32) -> i32 {
    a + b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        assert_eq!(add(2, 2), 4);
    }
}
```

## Mocking with Mockall
Use `mockall` to mock external dependencies.

```rust
use mockall::predicate::*;
use mockall::*;

#[automock]
pub trait Database {
    fn get_user(&self, id: i32) -> Option<String>;
}

#[test]
fn test_service_logic() {
    let mut mock = MockDatabase::new();
    mock.expect_get_user()
        .with(eq(42))
        .returning(|_| Some("Alice".to_string()));

    let service = UserService::new(mock);
    assert_eq!(service.get_name(42), Some("Alice".to_string()));
}
```

## Integration Testing
Place integration tests in the `tests/` directory.

```rust
// tests/api_integration.rs
use my_app::create_app;
use axum_test::TestServer;

#[tokio::test]
async fn test_health_check() {
    let app = create_app().await;
    let server = TestServer::new(app).unwrap();
    
    let response = server.get("/health").await;
    assert_eq!(response.status_code(), 200);
}
```
