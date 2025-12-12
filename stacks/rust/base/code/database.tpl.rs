// File: database.tpl.rs
// Purpose: SQLx async database patterns with compile-time checked queries
// Generated for: {{PROJECT_NAME}}

use sqlx::{postgres::PgPoolOptions, PgPool, FromRow};
use anyhow::Result;

pub async fn create_pool(database_url: &str) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .min_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect(database_url)
        .await?;

    Ok(pool)
}

// Example model
#[derive(Debug, FromRow)]
pub struct User {
    pub id: i32,
    pub email: String,
    pub name: Option<String>,
}

// Repository trait
#[async_trait::async_trait]
pub trait Repository<T> {
    async fn find_by_id(&self, id: i32) -> Result<Option<T>>;
    async fn find_all(&self, limit: i64, offset: i64) -> Result<Vec<T>>;
    async fn create(&self, entity: &T) -> Result<T>;
    async fn delete(&self, id: i32) -> Result<()>;
}

// User repository implementation
pub struct UserRepository {
    pool: PgPool,
}

impl UserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn find_by_id(&self, id: i32) -> Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            "SELECT id, email, name FROM users WHERE id = $1",
            id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            "SELECT id, email, name FROM users WHERE email = $1",
            email
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn create(&self, email: &str, name: Option<&str>) -> Result<User> {
        let user = sqlx::query_as!(
            User,
            "INSERT INTO users (email, name) VALUES ($1, $2) RETURNING id, email, name",
            email,
            name
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(user)
    }
}
