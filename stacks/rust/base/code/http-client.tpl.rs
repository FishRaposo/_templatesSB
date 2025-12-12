// File: http-client.tpl.rs
// Purpose: Robust HTTP client with retries and middleware
// Generated for: {{PROJECT_NAME}}

use reqwest::{Client, ClientBuilder};
use reqwest_middleware::{ClientBuilder as MiddlewareBuilder, ClientWithMiddleware};
use reqwest_retry::{RetryTransientMiddleware, policies::ExponentialBackoff};
use std::time::Duration;
use anyhow::{Context, Result};

pub struct HttpClientFactory;

impl HttpClientFactory {
    /// Creates a production-ready HTTP client with retry logic and standard timeouts
    pub fn create_client() -> Result<ClientWithMiddleware> {
        let retry_policy = ExponentialBackoff::builder()
            .build_with_max_retries(3);

        let client = ClientBuilder::new()
            .timeout(Duration::from_secs(30))
            .pool_idle_timeout(Duration::from_secs(90))
            .user_agent("{{PROJECT_NAME}}/1.0.0")
            .build()
            .context("Failed to build HTTP client")?;

        let client_with_middleware = MiddlewareBuilder::new(client)
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();

        Ok(client_with_middleware)
    }

    /// Creates a client specialized for long-running operations
    pub fn create_long_polling_client() -> Result<ClientWithMiddleware> {
        let client = ClientBuilder::new()
            .timeout(Duration::from_secs(300))
            .build()
            .context("Failed to build long-polling HTTP client")?;

        // No retry middleware for long polling usually, but can be added if needed
        let client_with_middleware = MiddlewareBuilder::new(client)
            .build();

        Ok(client_with_middleware)
    }
}

pub async fn example_usage() -> Result<()> {
    let client = HttpClientFactory::create_client()?;
    let res = client
        .get("https://httpbin.org/get")
        .send()
        .await
        .context("Request failed")?;
    
    println!("Status: {}", res.status());
    Ok(())
}
