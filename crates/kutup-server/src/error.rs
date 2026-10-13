//! Server error type — mirrors the Fiber handlers' error shape.
//!
//! Every Go handler returns errors as `c.Status(code).JSON(fiber.Map{"error": msg})`
//! (see `handlers.ErrorResponse` in `backend/handlers/models.go`). This type funnels
//! all server errors into that exact wire shape: a JSON body `{"error": "<message>"}`
//! with the matching HTTP status. Construct domain errors with the status-named
//! constructors (`AppError::bad_request(..)`, etc.) so call sites read like the Go
//! `fiber.NewError` / `c.Status(...).JSON(...)` they replace.
//!
//! The status-named constructors and `AppResult` form the error surface for the whole
//! server; some read as dead code until their handler slice lands, so `dead_code` is
//! allowed here and lifted once every handler is wired (server slice 8).
#![allow(dead_code)]

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::models::ErrorResponse;

/// An error returned by a handler, carrying the HTTP status and the user-facing
/// message that lands in the `{"error": ...}` body.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct AppError {
    pub status: StatusCode,
    pub message: String,
    /// Machine-readable fields beside `error` in the body (a client error's
    /// `code` and what it needs to act on it).
    pub details: Option<serde_json::Map<String, serde_json::Value>>,
}

impl AppError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            details: None,
        }
    }

    /// Adds fields beside `error` in a client error's body.
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        if let serde_json::Value::Object(map) = details {
            self.details = Some(map);
        }
        self
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }

    pub fn too_many_requests(message: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // 5xx detail is logged but never leaked verbatim — mirrors the Go handlers,
        // which return a generic "internal server error" while logging the cause.
        if self.status.is_server_error() {
            tracing::error!(status = %self.status, error = %self.message, "request failed");
            return (
                self.status,
                Json(ErrorResponse {
                    error: "internal server error".to_string(),
                }),
            )
                .into_response();
        }
        // Every client error names a `code` apps act on, never the English
        // `error` text: one a handler set, or the status's default
        // (docs/api.md, "Error codes").
        let mut details = self.details.unwrap_or_default();
        details
            .entry("code")
            .or_insert_with(|| serde_json::Value::String(default_code(self.status).into()));
        details.insert("error".into(), serde_json::Value::String(self.message));
        (self.status, Json(serde_json::Value::Object(details))).into_response()
    }
}

/// The `code` a client error carries when its handler set none.
pub(crate) fn default_code(status: StatusCode) -> &'static str {
    match status {
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => "invalid",
        StatusCode::UNAUTHORIZED => "unauthorized",
        StatusCode::FORBIDDEN => "forbidden",
        StatusCode::NOT_FOUND => "notFound",
        StatusCode::CONFLICT => "conflict",
        StatusCode::PAYLOAD_TOO_LARGE => "tooLarge",
        StatusCode::TOO_MANY_REQUESTS => "tooManyRequests",
        _ => "error",
    }
}

/// Maps unexpected `sqlx`/IO/etc. failures to a 500 while preserving the cause in
/// logs. Lets handlers use `?` on `anyhow::Error` and `sqlx::Error`.
impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::internal(format!("{err:#}"))
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        AppError::internal(format!("database error: {err}"))
    }
}

/// Handler result alias — `Ok` is any `IntoResponse`, `Err` is the JSON error above.
pub type AppResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn body_string(err: AppError) -> (StatusCode, String) {
        let resp = err.into_response();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn client_error_passes_message_through() {
        let (status, body) = body_string(AppError::bad_request("bad input")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["error"], "bad input");
        // Every client error carries a code: here the status's default.
        assert_eq!(body["code"], "invalid");
    }

    #[test]
    fn every_code_the_server_uses_is_documented() {
        let api = include_str!("../../../docs/api.md");
        let documented = |code: &str| api.contains(&format!("`{code}`"));
        for status in [400u16, 401, 403, 404, 409, 413, 422, 429] {
            let code = default_code(StatusCode::from_u16(status).unwrap());
            assert!(
                documented(code),
                "default code {code} is not in docs/api.md"
            );
        }
        let mut missing = Vec::new();
        let mut stack = vec![std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src"
        ))];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let source = std::fs::read_to_string(&path).unwrap();
                    let mut rest = source.as_str();
                    while let Some(at) = rest.find("\"code\": \"") {
                        rest = &rest[at + 9..];
                        let code: String = rest
                            .chars()
                            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                            .collect();
                        if !code.is_empty() && !documented(&code) {
                            missing.push(format!("{code} ({})", path.display()));
                        }
                    }
                }
            }
        }
        assert!(
            missing.is_empty(),
            "codes missing from docs/api.md: {missing:?}"
        );
    }

    #[tokio::test]
    async fn client_error_carries_its_details() {
        let error = AppError::conflict("name taken").with_details(
            serde_json::json!({ "code": "name_taken", "holder": { "kind": "file" } }),
        );
        let (status, body) = body_string(error).await;
        assert_eq!(status, StatusCode::CONFLICT);
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["error"], "name taken");
        assert_eq!(body["code"], "name_taken");
        assert_eq!(body["holder"]["kind"], "file");
    }

    #[tokio::test]
    async fn server_error_is_generic() {
        // 5xx detail must not leak — mirrors the Go handlers' generic 500 body.
        let (status, body) = body_string(AppError::internal("secret db dsn leaked")).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, r#"{"error":"internal server error"}"#);
    }
}
