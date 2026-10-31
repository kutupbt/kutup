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

pub mod account_head;
pub mod assets;
pub mod collab;
pub mod devices;
pub mod federation;
pub mod files;
pub mod identity;
pub mod opaque;
pub mod pass;
pub mod public;
pub mod sessions;
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
    /// The server's machine-readable `code`, when it gave one.
    pub code: Option<String>,
    /// A `409 versionUploading` for an upload of the caller's: its id.
    pub upload_id: Option<String>,
    /// A `409 versionUploading`: seconds since the open upload's last part.
    pub idle_seconds: Option<i64>,
    /// A `409 versionUploading` with `uploadId`: true when the caller is its
    /// uploader (it may go on with it), false for the folder's owner (who
    /// may only cancel it).
    pub yours: Option<bool>,
    /// A `409 name_taken`: what holds the name in that place
    /// (docs/plans/drive-unique-names.md).
    pub name_taken: Option<NameHolder>,
    /// A `409 version_conflict`: the version the file holds now, which a
    /// conditional save (`basedOn`) did not start from: a version id, or
    /// `original` (docs/plans/pass.md, "Saving without overwriting").
    pub version_conflict: Option<String>,
}

/// What holds a taken name, as the server says (any part may be missing).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NameHolder {
    /// `file` or `folder`.
    pub kind: String,
    pub id: String,
    /// A file's content hash, when known.
    pub content_hash: Option<String>,
}

impl ApiError {
    pub(crate) fn from_parts(status: u16, reason: &str, body: String) -> ApiError {
        let parsed = serde_json::from_str::<serde_json::Value>(&body).ok();
        let name_taken = parsed
            .as_ref()
            .filter(|v| {
                status == 409 && v.get("code").and_then(|c| c.as_str()) == Some("name_taken")
            })
            .map(|v| {
                let holder = v.get("holder");
                let text = |key: &str| {
                    holder
                        .and_then(|h| h.get(key))
                        .and_then(|x| x.as_str())
                        .map(str::to_string)
                };
                NameHolder {
                    kind: text("kind").unwrap_or_default(),
                    id: text("id").unwrap_or_default(),
                    content_hash: text("contentHash"),
                }
            });
        let version_conflict = parsed
            .as_ref()
            .filter(|v| {
                status == 409 && v.get("code").and_then(|c| c.as_str()) == Some("version_conflict")
            })
            .and_then(|v| v.get("current")?.as_str().map(str::to_string));
        let code = parsed
            .as_ref()
            .and_then(|v| v.get("code")?.as_str().map(str::to_string));
        let upload_id = parsed
            .as_ref()
            .and_then(|v| v.get("uploadId")?.as_str().map(str::to_string));
        let idle_seconds = parsed.as_ref().and_then(|v| v.get("idleSeconds")?.as_i64());
        let yours = parsed.as_ref().and_then(|v| v.get("yours")?.as_bool());
        let message = parsed
            .and_then(|v| v.get("error")?.as_str().map(str::to_string))
            .unwrap_or_else(|| {
                let trimmed = body.trim().to_string();
                if trimmed.is_empty() {
                    reason.to_string()
                } else {
                    trimmed
                }
            });
        ApiError {
            status,
            message,
            code,
            upload_id,
            idle_seconds,
            yours,
            name_taken,
            version_conflict,
        }
    }
}

/// Percent-encodes one URL path segment (addresses in paths may contain
/// reserved characters like `#`, `?`, or `%`).
pub(crate) fn path_segment(s: &str) -> String {
    let mut u = reqwest::Url::parse("http://x/").expect("static base url");
    u.path_segments_mut().expect("base has a path").push(s);
    u.path()[1..].to_string()
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
        // Every request says it is the CLI: sign-in creates a `cli` session whose
        // refresh token comes back in the body (web apps use a cookie instead).
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "x-kutup-client",
            reqwest::header::HeaderValue::from_static("cli"),
        );
        let http = crate::tls::client_builder()
            .default_headers(headers.clone())
            .timeout(Duration::from_secs(60))
            .connect_timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(insecure)
            .build()
            .expect("build http client");
        let upload = crate::tls::client_builder()
            .default_headers(headers)
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

    pub(crate) fn get(&self, path: &str) -> Result<Response> {
        Ok(self.request(Method::GET, path).send()?)
    }

    pub(crate) fn post_json<B: Serialize>(&self, path: &str, body: &B) -> Result<Response> {
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

    /// Creates the account; sign-up answers the session, as a sign-in does.
    pub fn register(&self, req: &RegisterRequest) -> Result<LoginResponse> {
        let resp = self.post_json("/auth/register", req)?;
        decode_json(resp)
    }

    /// Whether a referral code can admit a sign-up now (uses nothing up).
    pub fn check_registration_code(&self, code: &str) -> Result<()> {
        let resp = self.post_json(
            "/auth/registration-code/check",
            &serde_json::json!({ "code": code }),
        )?;
        check_ok(resp)
    }

    pub fn login_totp(&self, req: &TotpRequest) -> Result<LoginResponse> {
        let resp = self.post_json("/auth/login/2fa", req)?;
        decode_json(resp)
    }

    pub fn recover_preflight(&self, name: &str) -> Result<RecoverPreflightResponse> {
        let resp = self
            .request(Method::GET, "/auth/recover/preflight")
            .query(&[("name", name)])
            .send()?;
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

    /// `grant`: a `totp` grant from a reauth of this session;
    /// `recovery_code`: beside security keys, one of the account's recovery
    /// codes proving the factor it has (empty otherwise).
    pub fn verify_totp(&self, code: &str, grant: &str, recovery_code: &str) -> Result<()> {
        let resp = self.post_json(
            "/user/2fa/verify",
            &serde_json::json!({ "code": code, "grant": grant, "recoveryCode": recovery_code }),
        )?;
        check_ok(resp)
    }

    /// DELETE-with-body: turning 2FA off takes a current code and a `totp`
    /// grant (the password proved again), so a stolen session cannot.
    pub fn disable_totp(&self, code: &str, grant: &str) -> Result<()> {
        let resp = self
            .request(Method::DELETE, "/user/2fa")
            .header(CONTENT_TYPE, "application/json")
            .json(&serde_json::json!({ "code": code, "grant": grant }))
            .send()?;
        check_ok(resp)
    }

    // --- Collections ---

    pub fn settings(&self) -> Result<SettingsResponse> {
        let resp = self.get("/auth/settings")?;
        decode_json(resp)
    }

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

    /// Records what a file's content is recognised by in its folder
    /// (docs/plans/drive-unique-names.md).
    pub fn set_content_hash(&self, file_id: &str, content_hash: &str) -> Result<()> {
        let resp = self.put_json(
            &format!("/files/{file_id}/content-hash"),
            &serde_json::json!({ "contentHash": content_hash }),
        )?;
        check_ok(resp)
    }

    /// Which of `hashes` (1 to [`MAX_ASKED_HASHES`]) no item holds in a
    /// folder, or at the top level for `None`; the caller needs write access
    /// there (docs/plans/drive-unique-names.md).
    pub fn available_hashes(
        &self,
        collection_id: Option<&str>,
        hashes: &[String],
    ) -> Result<Vec<String>> {
        let path = match collection_id {
            Some(id) => format!("/collections/{id}/available-hashes"),
            None => "/drive/top-level-available-hashes".to_string(),
        };
        let resp = self.post_json(&path, &serde_json::json!({ "hashes": hashes }))?;
        let body: serde_json::Value = decode_json(resp)?;
        Ok(body
            .get("available")
            .and_then(|a| a.as_array())
            .into_iter()
            .flatten()
            .filter_map(|h| h.as_str().map(str::to_string))
            .collect())
    }
}

/// How many hashes one `available_hashes` call may ask about.
pub const MAX_ASKED_HASHES: usize = 10;

/// Decodes a JSON response, surfacing HTTP >= 400 as an [`ApiError`].
pub(crate) fn decode_json<T: DeserializeOwned>(resp: Response) -> Result<T> {
    if resp.status().as_u16() >= 400 {
        return Err(api_error(resp));
    }
    Ok(resp.json()?)
}

/// Checks a no-body response for HTTP >= 400.
pub(crate) fn check_ok(resp: Response) -> Result<()> {
    if resp.status().as_u16() >= 400 {
        return Err(api_error(resp));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{path_segment, ApiError};

    #[test]
    fn path_segment_encodes_reserved_chars() {
        assert_eq!(path_segment("a+b@c.d"), "a+b@c.d"); // `+` is literal in paths
        assert_eq!(path_segment("a b#c?d"), "a%20b%23c%3Fd");
        assert_eq!(path_segment("50%off@x.y"), "50%25off@x.y");
    }

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
    fn from_parts_reads_a_version_conflict() {
        let e = ApiError::from_parts(
            409,
            "Conflict",
            r#"{"error":"the file changed since","code":"version_conflict","current":"original"}"#
                .into(),
        );
        assert_eq!(e.version_conflict.as_deref(), Some("original"));
        assert!(
            ApiError::from_parts(409, "Conflict", r#"{"error":"x"}"#.into())
                .version_conflict
                .is_none()
        );
    }

    #[test]
    fn from_parts_keeps_the_code() {
        let e = ApiError::from_parts(
            409,
            "Conflict",
            r#"{"error":"name it there","code":"nameNeeded"}"#.into(),
        );
        assert_eq!(e.code.as_deref(), Some("nameNeeded"));
        assert!(e.name_taken.is_none());
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
