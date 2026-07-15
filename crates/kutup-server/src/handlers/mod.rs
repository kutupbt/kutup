//! HTTP handlers — each module mirrors the matching `backend/handlers/*.go` file.

pub mod admin;
pub mod auth;
pub mod chat;
pub mod collab;
pub mod collections;
pub mod devices;
pub mod federation;
pub mod fedproxy;
pub mod file_assets;
pub mod file_versions;
pub mod files;
pub mod shares;
pub mod trash;
pub mod tus;

use std::sync::LazyLock;
use std::time::Duration;

use aws_sdk_s3::primitives::ByteStream;
use axum::body::Body;
use axum::http::{header, HeaderName, HeaderValue};
use axum::response::Response;
use sqlx::PgPool;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::error::{AppError, AppResult};

/// Shared outbound HTTP client for federation calls — mirrors `fedHTTPClient`. Never follows
/// redirects (so a malicious federation server can't 30x to an internal address and bypass
/// the SSRF check applied to the original host) and times out at 30 s.
pub(crate) static FED_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build federation http client")
});

/// A random URL-safe token (base64, no padding) — mirrors `utils.RandomToken`.
pub(crate) fn random_token(byte_len: usize) -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut b = vec![0u8; byte_len];
    rand::thread_rng().fill_bytes(&mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Parses a UUID that came from a trusted source (our own JWT's userId) — a parse failure
/// here is an internal invariant break, not a client error.
pub(crate) fn trusted_uuid(s: &str) -> AppResult<Uuid> {
    Uuid::parse_str(s).map_err(|_| AppError::internal("invalid user id"))
}

/// Access check for a collection — owner or share recipient. Mirrors
/// `FilesHandler.canAccessCollection`.
pub(crate) async fn can_access_collection(pool: &PgPool, user_id: Uuid, coll_id: Uuid) -> bool {
    // Trashed collections are invisible to normal access; only the trash endpoints see them.
    let owner: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM collections WHERE id = $1 AND owner_user_id = $2 AND deleted_at IS NULL",
    )
    .bind(coll_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();
    if owner.unwrap_or(0) > 0 {
        return true;
    }
    let shared: Option<i64> = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM collection_shares cs
           JOIN collections c ON c.id = cs.collection_id AND c.deleted_at IS NULL
           WHERE cs.collection_id = $1 AND cs.recipient_user_id = $2"#,
    )
    .bind(coll_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();
    shared.unwrap_or(0) > 0
}

/// Access check for a file — owner of its collection or a share recipient. Mirrors
/// `FileVersionsHandler.canAccessFile` / `FileAssetsHandler.canAccessFile`.
pub(crate) async fn can_access_file(pool: &PgPool, user_id: Uuid, file_id: Uuid) -> bool {
    let row: Option<(Uuid, bool)> = sqlx::query_as(
        r#"SELECT c.owner_user_id,
                  EXISTS(SELECT 1 FROM collection_shares cs
                         WHERE cs.collection_id = c.id AND cs.recipient_user_id = $2)
           FROM files f JOIN collections c ON c.id = f.collection_id
           WHERE f.id = $1 AND f.deleted_at IS NULL AND c.deleted_at IS NULL"#,
    )
    .bind(file_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();
    matches!(row, Some((owner, shared)) if owner == user_id || shared)
}

/// Streams an S3 object body to the client as `application/octet-stream`, mirroring the
/// Go handlers' `c.SendStream(body, size)` (lazy, no full-buffering). `extra` carries the
/// version-download headers (`X-Kutup-*`). `Content-Length` is set when `size > 0`.
fn octet_stream_response(body: ByteStream, size: i64, extra: &[(HeaderName, String)]) -> Response {
    let stream = ReaderStream::new(body.into_async_read());
    let mut builder = Response::builder().header(header::CONTENT_TYPE, "application/octet-stream");
    if size > 0 {
        builder = builder.header(header::CONTENT_LENGTH, size);
    }
    for (name, value) in extra {
        if let Ok(v) = HeaderValue::from_str(value) {
            builder = builder.header(name, v);
        }
    }
    builder
        .body(Body::from_stream(stream))
        .expect("valid octet-stream response")
}
