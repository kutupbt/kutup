//! HTTP handlers — each module mirrors the matching `backend/handlers/*.go` file.

pub mod account_heads;
pub mod accounts;
pub mod admin;
pub mod auth;
pub mod calendar;
pub mod chat;
pub mod chat_backup;
pub mod chat_contact_list;
pub mod chat_group_capabilities;
pub mod chat_group_list;
pub mod chat_link_preview;
pub mod chat_media;
pub mod chat_identity;
pub mod chat_multi;
pub mod collab;
pub mod collections;
pub mod contacts;
pub mod devices;
pub mod drive_move;
pub mod feedback;
pub mod file_assets;
pub mod file_shares;
pub mod file_thumbnails;
pub mod file_versions;
pub mod files;
pub mod folder_access;
pub mod identity;
pub mod link_reports;
pub mod mail;
pub mod mail_auto_reply;
pub mod mail_domains;
pub mod mail_domains_admin;
pub mod mail_filters;
pub mod mail_folders;
pub mod mail_forwardings;
pub mod mail_groups;
pub mod mail_identity;
pub mod mail_image_senders;
pub mod mail_images;
pub mod mail_keys;
pub mod mail_notifications;
pub mod mail_outbox;
pub mod mail_send;
pub mod mail_sender_rules;
pub mod mail_sending;
pub mod mail_settings;
pub mod name_hashes;
pub mod opaque;
pub mod pass;
pub mod pass_icons;
pub mod rate_limits;
pub mod registration_codes;
pub mod renames;
pub mod security_events;
pub mod sessions;
pub mod shares;
pub mod storage;
pub mod trash;
pub mod tus;
pub mod tus_versions;

use aws_sdk_s3::primitives::ByteStream;
use axum::body::Body;
use axum::http::{header, HeaderName, HeaderValue};
use axum::response::Response;
use sqlx::PgPool;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::error::{AppError, AppResult};

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
/// A failed query is an error, never "no".
pub(crate) async fn can_access_collection(
    pool: &PgPool,
    user_id: Uuid,
    coll_id: Uuid,
) -> Result<bool, sqlx::Error> {
    // Trashed collections are invisible to normal access; only the trash endpoints see them.
    let owner: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM collections WHERE id = $1 AND owner_user_id = $2 AND deleted_at IS NULL",
    )
    .bind(coll_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    if owner.unwrap_or(0) > 0 {
        return Ok(true);
    }
    let shared: Option<i64> = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM collection_shares cs
           JOIN collections c ON c.id = cs.collection_id AND c.deleted_at IS NULL
           WHERE cs.collection_id = $1 AND cs.recipient_user_id = $2"#,
    )
    .bind(coll_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(shared.unwrap_or(0) > 0)
}

/// Access check for a file — owner of its collection, a recipient of the
/// folder, or a recipient of the file itself (docs/plans/drive-file-sharing.md).
/// A failed query is an error, never "no".
pub(crate) async fn can_access_file(
    pool: &PgPool,
    user_id: Uuid,
    file_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let row: Option<(Uuid, bool)> = sqlx::query_as(
        r#"SELECT c.owner_user_id,
                  EXISTS(SELECT 1 FROM collection_shares cs
                         WHERE cs.collection_id = c.id AND cs.recipient_user_id = $2)
                  OR EXISTS(SELECT 1 FROM file_shares fs
                            WHERE fs.file_id = f.id AND fs.recipient_user_id = $2)
                  -- A photo in an album its owner or a member can open
                  -- (docs/plans/photos.md): reading only.
                  OR EXISTS(SELECT 1 FROM album_items ai
                            JOIN collections a ON a.id = ai.album_id AND a.deleted_at IS NULL
                            WHERE ai.file_id = f.id
                              AND (a.owner_user_id = $2 OR EXISTS(
                                  SELECT 1 FROM collection_shares acs
                                  WHERE acs.collection_id = a.id AND acs.recipient_user_id = $2)))
           FROM files f JOIN collections c ON c.id = f.collection_id
           WHERE f.id = $1 AND f.deleted_at IS NULL AND c.deleted_at IS NULL"#,
    )
    .bind(file_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(matches!(row, Some((owner, shared)) if owner == user_id || shared))
}

/// Streams an S3 object body to the client as `application/octet-stream`, mirroring the
/// Go handlers' `c.SendStream(body, size)` (lazy, no full-buffering). `extra` carries the
/// version-download headers (`X-Kutup-*`). `Content-Length` is set when `size > 0`.
pub(crate) fn octet_stream_response(
    body: ByteStream,
    size: i64,
    extra: &[(HeaderName, String)],
) -> Response {
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

#[cfg(test)]
mod permission_tests {
    use super::*;

    /// A pool whose every query fails (nothing listens there).
    fn failing_pool() -> PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(200))
            .connect_lazy("postgres://nobody:nothing@127.0.0.1:9/none")
            .unwrap()
    }

    #[tokio::test]
    async fn a_failed_check_is_an_error_never_no() {
        let pool = failing_pool();
        let (user, id) = (Uuid::new_v4(), Uuid::new_v4());
        assert!(can_access_collection(&pool, user, id).await.is_err());
        assert!(can_access_file(&pool, user, id).await.is_err());
        assert!(crate::drive_writes::can_write_file(&pool, user, id)
            .await
            .is_err());
    }
}
