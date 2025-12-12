// File: http-client.tpl.rs
// Purpose: Template for unknown implementation
// Generated for: {{PROJECT_NAME}}

use reqwest::Client;

pub struct HttpClient {
    client: Client,
    base_url: String,
}

impl HttpClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.into(),
        }
    }

    pub async fn get_json(&self, path: &str) -> Result<serde_json::Value, reqwest::Error> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self.client.get(url).send().await?;
        resp.json::<serde_json::Value>().await
    }
}
