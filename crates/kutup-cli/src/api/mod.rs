//! HTTP client for the kutup API — mirrors `cmd/kutup/internal/api`.
//!
//! Uses `reqwest::blocking` to keep the synchronous control flow of the Go
//! client. Two clients are kept: a 60 s-total-timeout one for short JSON calls,
//! and a no-total-timeout one for tus PATCH streaming / large downloads where a
//! total deadline would trip on slow uplinks or final-chunk server work.
//!
//! This module mirrors the Go API client's full surface, so some response-DTO
//! fields are deserialized but not read by any command, and a few protocol
//! methods (e.g. `tus_head` for resume) exist for completeness/future use.
#![allow(dead_code)]

pub mod devices;
pub mod federation;
pub mod files;
pub mod public;
pub mod sharing;
pub mod trash;
pub mod tus;
pub mod types;
pub mod versions;

use std::cell::RefCell;
use std::time::Duration;

use anyhow::Result;
use reqwest::blocking::{Client as HttpClient, RequestBuilder, Response};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub use types::*;

/// Typed HTTP error, carried through anyhow chains so `main` can map exit
/// codes and commands can match on `status` instead of string-parsing.
#[derive(Debug, thiserror::Error)]
#[error("HTTP {status}: {message}")]
pub struct ApiError {
    pub status: u16,
    /// The server's `{"error": "…"}` message when parseable, else the raw
    /// body (or the status reason phrase when the body is empty).
    pub message: String,
}

impl ApiError {
    pub(crate) fn from_parts(status: u16, reason: &str, body: String) -> ApiError {
        let message = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("error")?.as_str().map(str::to_string))
            .unwrap_or_else(|| {
                let trimmed = body.trim().to_string();
                if trimmed.is_empty() {
                    reason.to_string()
                } else {
                    trimmed
                }
            });
        ApiError { status, message }
    }
}

/// Consumes an error response into an `anyhow::Error` carrying [`ApiError`].
pub(crate) fn api_error(resp: Response) -> anyhow::Error {
    let status = resp.status().as_u16();
    let reason = resp.status().canonical_reason().unwrap_or("").to_string();
    let body = resp.text().unwrap_or_default();
    anyhow::Error::new(ApiError::from_parts(status, &reason, body))
}

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

    pub fn register(&self, req: &RegisterRequest) -> Result<()> {
        let resp = self.post_json("/auth/register", req)?;
        check_ok(resp)
    }

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

    // --- 2FA (TOTP) ---

    pub fn setup_totp(&self) -> Result<SetupTotpResponse> {
        let resp = self.post_json("/user/2fa/setup", &serde_json::json!({}))?;
        decode_json(resp)
    }

    pub fn verify_totp(&self, code: &str) -> Result<()> {
        let resp = self.post_json("/user/2fa/verify", &serde_json::json!({ "code": code }))?;
        check_ok(resp)
    }

    /// DELETE-with-body: the backend requires a current code to disable 2FA (so a stolen
    /// session can't silently remove it). Mirrors the Go `DisableTOTP`.
    pub fn disable_totp(&self, code: &str) -> Result<()> {
        let resp = self
            .request(Method::DELETE, "/user/2fa")
            .header(CONTENT_TYPE, "application/json")
            .json(&serde_json::json!({ "code": code }))
            .send()?;
        check_ok(resp)
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

/// Decodes a JSON response, surfacing HTTP >= 400 as an [`ApiError`].
fn decode_json<T: DeserializeOwned>(resp: Response) -> Result<T> {
    if resp.status().as_u16() >= 400 {
        return Err(api_error(resp));
    }
    Ok(resp.json()?)
}

/// Checks a no-body response for HTTP >= 400.
fn check_ok(resp: Response) -> Result<()> {
    if resp.status().as_u16() >= 400 {
        return Err(api_error(resp));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ApiError;

    #[test]
    fn from_parts_extracts_server_error_shape() {
        let e = ApiError::from_parts(
            413,
            "Payload Too Large",
            r#"{"error":"quota exceeded"}"#.into(),
        );
        assert_eq!(e.message, "quota exceeded");
        assert_eq!(e.to_string(), "HTTP 413: quota exceeded");
    }

    #[test]
    fn from_parts_falls_back_to_raw_body() {
        let e = ApiError::from_parts(502, "Bad Gateway", "<html>upstream died</html>".into());
        assert_eq!(e.message, "<html>upstream died</html>");
    }

    #[test]
    fn from_parts_uses_reason_when_body_empty() {
        let e = ApiError::from_parts(404, "Not Found", "  ".into());
        assert_eq!(e.to_string(), "HTTP 404: Not Found");
    }
}
