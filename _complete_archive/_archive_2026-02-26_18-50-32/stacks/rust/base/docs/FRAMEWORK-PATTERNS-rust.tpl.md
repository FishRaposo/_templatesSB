<!--
File: FRAMEWORK-PATTERNS-rust.tpl.md
Purpose: Common Rust framework patterns
Generated for: {{PROJECT_NAME}}
-->

# Framework Patterns

## Web Server (Axum)
We recommend **Axum** for its ergonomics and integration with the Tokio ecosystem.

```rust
// Standard handler pattern with state
async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) ->  AppResult<Json<UserResponse>> {
    let user = state.service.get_user(id).await?;
    Ok(Json(user.into()))
}
```

## Database Access (SQLx)
We recommend **SQLx** for compile-time checked queries.

```rust
// Repository pattern implementation
async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
    sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE email = $1",
        email
    )
    .fetch_optional(&self.pool)
    .await
    .map_err(Into::into)
}
```

## Async Traits
Until async traits are stabilized in traits natively without overhead, use `async_trait` macro or strict implementation where necessary.

```rust
#[async_trait]
pub trait EmailSender: Send + Sync {
    async fn send(&self, to: &str, body: &str) -> Result<()>;
}
```

## Shared State
Use `Arc` for shared ownership across threads.

```rust
#[derive(Clone)]
pub struct AppState {
    pub db: Pool<Postgres>,
    pub email_service: Arc<dyn EmailSender>,
}
```
