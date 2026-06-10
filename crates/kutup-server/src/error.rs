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
}

impl AppError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
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
        (
            self.status,
            Json(ErrorResponse {
                error: self.message,
            }),
        )
            .into_response()
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
        assert_eq!(body, r#"{"error":"bad input"}"#);
    }

    #[tokio::test]
    async fn server_error_is_generic() {
        // 5xx detail must not leak — mirrors the Go handlers' generic 500 body.
        let (status, body) = body_string(AppError::internal("secret db dsn leaked")).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, r#"{"error":"internal server error"}"#);
    }
}
