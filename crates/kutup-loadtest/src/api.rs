//! The HTTP side every virtual user shares: one connection pool, the
//! server's base URL, and the signed-in user's bearer token.

use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::{Client, RequestBuilder, Response};
use serde_json::Value;

/// A refusal's HTTP status, kept as the error so the metrics can name it.
#[derive(Debug)]
pub struct Status(pub u16);

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP {}", self.0)
    }
}

impl std::error::Error for Status {}

/// The pool every user shares: the load generator is one process, as many
/// browsers would be many, so connections are reused per host as a busy
/// reverse proxy would see them.
// The one place a client is built.
#[allow(clippy::disallowed_methods)]
pub fn client(timeout: Duration) -> Result<Client> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    Ok(Client::builder()
        .timeout(timeout)
        .pool_max_idle_per_host(4096)
        .build()?)
}

#[derive(Clone)]
pub struct Api {
    pub http: Client,
    /// `http://host:port`, without `/api`.
    pub base: String,
}

impl Api {
    pub fn url(&self, path: &str) -> String {
        format!("{}/api{path}", self.base)
    }

    pub fn get(&self, path: &str, token: &str) -> RequestBuilder {
        self.http.get(self.url(path)).bearer_auth(token)
    }

    pub fn post(&self, path: &str, token: &str) -> RequestBuilder {
        self.http.post(self.url(path)).bearer_auth(token)
    }

    /// The server's public settings: its name, Chat's capabilities.
    pub async fn settings(&self) -> Result<Value> {
        json(self.http.get(self.url("/auth/settings")).send().await?).await
    }
}

/// The body of a 2xx answer, or its status as the error.
pub async fn ok(response: Response) -> Result<Response> {
    let status = response.status();
    if status.is_success() {
        Ok(response)
    } else {
        let body = response.text().await.unwrap_or_default();
        Err(anyhow::Error::new(Status(status.as_u16())))
            .with_context(|| body.chars().take(200).collect::<String>())
    }
}

/// A 2xx answer's JSON.
pub async fn json(response: Response) -> Result<Value> {
    Ok(ok(response).await?.json().await?)
}
