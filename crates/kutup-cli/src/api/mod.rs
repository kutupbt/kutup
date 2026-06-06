//! HTTP client for the kutup API — mirrors `cmd/kutup/internal/api`.
//!
//! Uses `reqwest::blocking` to keep the synchronous control flow of the Go
//! client. Two clients are kept: a 60 s-total-timeout one for short JSON calls,
//! and a no-total-timeout one for tus PATCH streaming / large downloads where a
//! total deadline would trip on slow uplinks or final-chunk server work.

pub mod devices;
pub mod tus;
pub mod types;
pub mod versions;

use std::cell::RefCell;
use std::time::Duration;

use anyhow::{bail, Result};
use reqwest::blocking::{Client as HttpClient, RequestBuilder, Response};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub use types::*;

/// API client. `token` is interior-mutable so transparent refresh can update it
/// while methods take `&self` (mirrors the Go `SetToken`).
pub struct Client {
    base: String,
    token: RefCell<String>,
    http: HttpClient,
    upload: HttpClient,
}

impl Client {
    pub fn new(base_url: &str, token: &str) -> Client {
        let insecure = matches!(
            std::env::var("KUTUP_INSECURE_TLS").as_deref(),
            Ok("1") | Ok("true")
        );
        let http = HttpClient::builder()
            .timeout(Duration::from_secs(60))
            .connect_timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(insecure)
            .build()
            .expect("build http client");
        let upload = HttpClient::builder()
            .timeout(None) // per-phase only; large bodies must not hit a total deadline
            .connect_timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(insecure)
            .build()
            .expect("build upload client");
        Client {
            base: base_url.trim_end_matches('/').to_string(),
            token: RefCell::new(token.to_string()),
            http,
            upload,
        }
    }

    pub fn set_token(&self, token: &str) {
        *self.token.borrow_mut() = token.to_string();
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api{}", self.base, path)
    }

    fn auth(&self, rb: RequestBuilder) -> RequestBuilder {
        let token = self.token.borrow();
        if token.is_empty() {
            rb
        } else {
            rb.header(AUTHORIZATION, format!("Bearer {token}"))
        }
    }

    /// Short-request builder (60 s total timeout).
    pub(crate) fn request(&self, method: Method, path: &str) -> RequestBuilder {
        self.auth(self.http.request(method, self.url(path)))
    }

    /// Streaming builder (no total timeout) for tus / large downloads.
    pub(crate) fn upload_request(&self, method: Method, path: &str) -> RequestBuilder {
        self.auth(self.upload.request(method, self.url(path)))
    }

    fn get(&self, path: &str) -> Result<Response> {
        Ok(self.request(Method::GET, path).send()?)
    }

    fn post_json<B: Serialize>(&self, path: &str, body: &B) -> Result<Response> {
        Ok(self
            .request(Method::POST, path)
            .header(CONTENT_TYPE, "application/json")
            .json(body)
            .send()?)
    }

    fn put_json<B: Serialize>(&self, path: &str, body: &B) -> Result<Response> {
        Ok(self
            .request(Method::PUT, path)
            .header(CONTENT_TYPE, "application/json")
            .json(body)
            .send()?)
    }

    fn patch_json<B: Serialize>(&self, path: &str, body: &B) -> Result<Response> {
        Ok(self
            .request(Method::PATCH, path)
            .header(CONTENT_TYPE, "application/json")
            .json(body)
            .send()?)
    }

    fn delete(&self, path: &str) -> Result<Response> {
        Ok(self.request(Method::DELETE, path).send()?)
    }

    // --- Auth ---

    pub fn login_preflight(&self, email: &str) -> Result<PreflightResponse> {
        let resp = self.get(&format!("/auth/login/preflight?email={email}"))?;
        decode_json(resp)
    }

    pub fn login(&self, req: &LoginRequest) -> Result<LoginResponse> {
        let resp = self.post_json("/auth/login", req)?;
        decode_json(resp)
    }

    pub fn login_totp(&self, req: &TotpRequest) -> Result<LoginResponse> {
        let resp = self.post_json("/auth/login/2fa", req)?;
        decode_json(resp)
    }

    pub fn refresh_token(&self, refresh_token: &str) -> Result<RefreshResponse> {
        let resp = self.post_json(
            "/auth/refresh",
            &serde_json::json!({ "refreshToken": refresh_token }),
        )?;
        decode_json(resp)
    }

    // --- User ---

    pub fn me(&self) -> Result<UserMe> {
        let resp = self.get("/user/me")?;
        decode_json(resp)
    }

    // --- Collections ---

    pub fn list_collections(&self) -> Result<Vec<Collection>> {
        let resp = self.get("/collections/")?;
        decode_json(resp)
    }

    pub fn create_collection(
        &self,
        req: &CreateCollectionRequest,
    ) -> Result<CreateCollectionResponse> {
        let resp = self.post_json("/collections/", req)?;
        decode_json(resp)
    }

    pub fn rename_collection(&self, id: &str, req: &RenameCollectionRequest) -> Result<()> {
        let resp = self.put_json(&format!("/collections/{id}"), req)?;
        check_ok(resp)
    }

    pub fn delete_collection(&self, id: &str) -> Result<()> {
        let resp = self.delete(&format!("/collections/{id}"))?;
        check_ok(resp)
    }

    pub fn update_collection_color(&self, id: &str, color: &str) -> Result<()> {
        let body = if color.is_empty() {
            serde_json::json!({ "color": null })
        } else {
            serde_json::json!({ "color": color })
        };
        let resp = self.patch_json(&format!("/collections/{id}/color"), &body)?;
        check_ok(resp)
    }

    // --- Files ---

    pub fn list_files(&self, collection_id: &str) -> Result<Vec<File>> {
        let resp = self.get(&format!("/collections/{collection_id}/files"))?;
        decode_json(resp)
    }

    pub fn delete_file(&self, file_id: &str) -> Result<()> {
        let resp = self.delete(&format!("/files/{file_id}"))?;
        check_ok(resp)
    }

    pub fn update_file_metadata(
        &self,
        file_id: &str,
        req: &UpdateFileMetadataRequest,
    ) -> Result<()> {
        let resp = self.put_json(&format!("/files/{file_id}"), req)?;
        check_ok(resp)
    }
}

/// Decodes a JSON response, surfacing HTTP >= 400 as an error with the body.
fn decode_json<T: DeserializeOwned>(resp: Response) -> Result<T> {
    let status = resp.status();
    if status.as_u16() >= 400 {
        let body = resp.text().unwrap_or_default();
        bail!("HTTP {}: {}", status.as_u16(), body);
    }
    Ok(resp.json()?)
}

/// Checks a no-body response for HTTP >= 400.
fn check_ok(resp: Response) -> Result<()> {
    let status = resp.status();
    if status.as_u16() >= 400 {
        let body = resp.text().unwrap_or_default();
        bail!("HTTP {}: {}", status.as_u16(), body);
    }
    Ok(())
}
