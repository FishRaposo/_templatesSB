// Universal Template System - Rust Testing Helpers Template
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::sleep;
use mockall::predicate::*;
use mockall::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// MOCK HELPERS
// =============================================================================

// Mock trait for external dependencies
mock! {
    pub Database {
        fn get_user(&self, id: u64) -> Result<Option<User>, DatabaseError>;
        fn save_user(&self, user: &User) -> Result<User, DatabaseError>;
        fn delete_user(&self, id: u64) -> Result<(), DatabaseError>;
    }
}

// Mock HTTP client
mock! {
    pub HttpClient {
        async fn get(&self, url: &str) -> Result<Response, HttpError>;
        async fn post(&self, url: &str, body: &str) -> Result<Response, HttpError>;
        async fn put(&self, url: &str, body: &str) -> Result<Response, HttpError>;
        async fn delete(&self, url: &str) -> Result<Response, HttpError>;
    }
}

// =============================================================================
// TEST DATA FACTORIES
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: u64,
    pub name: String,
    pub email: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Post {
    pub id: u64,
    pub title: String,
    pub content: String,
    pub author_id: u64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug)]
pub enum DatabaseError {
    ConnectionFailed,
    NotFound,
    Duplicate,
    Unknown(String),
}

#[derive(Debug)]
pub enum HttpError {
    NetworkError,
    Timeout,
    BadRequest(String),
    Unauthorized,
    ServerError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub status: u16,
    pub body: String,
    pub headers: HashMap<String, String>,
}

impl User {
    pub fn factory() -> UserFactory {
        UserFactory::new()
    }
}

pub struct UserFactory {
    id: Option<u64>,
    name: Option<String>,
    email: Option<String>,
}

impl UserFactory {
    pub fn new() -> Self {
        Self {
            id: None,
            name: None,
            email: None,
        }
    }

    pub fn with_id(mut self, id: u64) -> Self {
        self.id = Some(id);
        self
    }

    pub fn with_name<S: Into<String>>(mut self, name: S) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn with_email<S: Into<String>>(mut self, email: S) -> Self {
        self.email = Some(email.into());
        self
    }

    pub fn build(self) -> User {
        User {
            id: self.id.unwrap_or(1),
            name: self.name.unwrap_or_else(|| "Test User".to_string()),
            email: self.email.unwrap_or_else(|| "test@example.com".to_string()),
            created_at: chrono::Utc::now(),
        }
    }
}

// =============================================================================
// ASYNC TESTING HELPERS
// =============================================================================

pub async fn wait_for_duration(duration: Duration) {
    sleep(duration).await;
}

pub async fn wait_for_millis(millis: u64) {
    wait_for_duration(Duration::from_millis(millis)).await;
}

// =============================================================================
// ASSERTION HELPERS
// =============================================================================

pub trait ResultExt<T, E> {
    fn unwrap_err_msg(self, msg: &str) -> E;
    fn expect_ok(self, msg: &str) -> T;
    fn expect_err(self, msg: &str) -> E;
}

impl<T, E> ResultExt<T, E> for Result<T, E> {
    fn unwrap_err_msg(self, msg: &str) -> E {
        match self {
            Err(e) => e,
            Ok(_) => panic!("Expected error but got Ok: {}", msg),
        }
    }

    fn expect_ok(self, msg: &str) -> T {
        match self {
            Ok(t) => t,
            Err(_) => panic!("Expected Ok but got error: {}", msg),
        }
    }

    fn expect_err(self, msg: &str) -> E {
        match self {
            Err(e) => e,
            Ok(_) => panic!("Expected error but got Ok: {}", msg),
        }
    }
}

// =============================================================================
// DATABASE TESTING HELPERS
// =============================================================================

pub struct InMemoryDatabase {
    users: HashMap<u64, User>,
    posts: HashMap<u64, Post>,
    next_user_id: u64,
    next_post_id: u64,
}

impl InMemoryDatabase {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            posts: HashMap::new(),
            next_user_id: 1,
            next_post_id: 1,
        }
    }

    pub fn add_user(&mut self, user: User) -> User {
        let id = self.next_user_id;
        self.next_user_id += 1;
        
        let new_user = User { id, ..user };
        self.users.insert(id, new_user.clone());
        new_user
    }

    pub fn get_user(&self, id: u64) -> Option<User> {
        self.users.get(&id).cloned()
    }

    pub fn clear(&mut self) {
        self.users.clear();
        self.posts.clear();
        self.next_user_id = 1;
        self.next_post_id = 1;
    }
}

impl Default for InMemoryDatabase {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// TEST SETUP HELPERS
// =============================================================================

pub fn setup_test_logger() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .is_test(true)
        .try_init();
}

#[macro_export]
macro_rules! test_case {
    ($name:ident, $body:expr) => {
        #[test]
        fn $name() {
            $body
        }
    };
}

#[macro_export]
macro_rules! async_test_case {
    ($name:ident, $body:expr) => {
        #[tokio::test]
        async fn $name() {
            $body
        }
    };
}
