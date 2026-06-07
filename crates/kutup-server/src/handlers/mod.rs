//! HTTP handlers — each module mirrors the matching `backend/handlers/*.go` file.

pub mod auth;
pub mod collections;
pub mod devices;
pub mod file_assets;
pub mod file_versions;
pub mod files;
pub mod tus;

use aws_sdk_s3::primitives::ByteStream;
use axum::body::Body;
use axum::http::{header, HeaderName, HeaderValue};
use axum::response::Response;
use sqlx::PgPool;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::error::{AppError, AppResult};

/// Parses a UUID that came from a trusted source (our own JWT's userId) — a parse failure
/// here is an internal invariant break, not a client error.
pub(crate) fn trusted_uuid(s: &str) -> AppResult<Uuid> {
    Uuid::parse_str(s).map_err(|_| AppError::internal("invalid user id"))
}

/// Access check for a collection — owner or share recipient. Mirrors
/// `FilesHandler.canAccessCollection`.
pub(crate) async fn can_access_collection(pool: &PgPool, user_id: Uuid, coll_id: Uuid) -> bool {
    let owner: Option<i64> =
        sqlx::query_scalar("SELECT COUNT(*) FROM collections WHERE id = $1 AND owner_user_id = $2")
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
        "SELECT COUNT(*) FROM collection_shares WHERE collection_id = $1 AND recipient_user_id = $2",
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
           WHERE f.id = $1"#,
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
