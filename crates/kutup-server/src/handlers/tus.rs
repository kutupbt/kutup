//! tus.io 1.0 resumable upload endpoint — mirrors `backend/handlers/tus.go`.
//!
//! The multipart POST in `files.rs` buffers the whole encrypted blob and restarts from
//! byte zero on any blip; tus gives bounded memory (S3 multipart) + resume (offset
//! bookkeeping) + an encrypted-metadata commit up-front. Flow:
//!
//!   OPTIONS /api/uploads        — discovery (anonymous)
//!   POST    /api/uploads        — create session, allocate the S3 multipart
//!   PATCH   /api/uploads/{id}    — append one part, bump the offset; the final PATCH
//!                                  completes the multipart, inserts the `files` row,
//!                                  commits the quota soft-reservation, deletes the row
//!   HEAD    /api/uploads/{id}    — resume: returns the current Upload-Offset
//!   DELETE  /api/uploads/{id}    — cancel: abort the multipart, free reserved quota
//!
//! Quota is soft-reserved: available bytes for a new upload are
//! `storage_quota_bytes - storage_used_bytes - SUM(uploads.total_bytes - received_bytes)`,
//! so a half-uploaded 50 GB file blocks a concurrent 50 GB attempt without polluting
//! `storage_used_bytes`. Final commit happens atomically with the `files` INSERT.
//!
//! Unlike the JSON handlers, the tus error bodies are plain text + carry the
//! `Tus-Resumable` header, matching Fiber's `c.SendString` — so responses are built
//! directly here rather than via `AppError` (whose body is `{"error": …}` JSON).

use aws_sdk_s3::primitives::ByteStream;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use uuid::Uuid;

use crate::middleware::AuthUser;
use crate::storage::CompletedPart;
use crate::AppState;

/// The protocol version we advertise + require. Clients send `Tus-Resumable: 1.0.0` on
/// every non-OPTIONS request; mismatch → 412. Mirrors `tusVersion`.
const TUS_VERSION: &str = "1.0.0";

/// S3's lower bound on every multipart part except the last (5 MiB). Mirrors `minPartSize`.
const MIN_PART_SIZE: i64 = 5 * 1024 * 1024;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Plain-text tus response carrying the `Tus-Resumable` header — mirrors the bodies
/// Fiber produced via `c.Status(...).SendString(...)`.
fn tus_text(status: StatusCode, body: &'static str) -> Response {
    (status, [("Tus-Resumable", TUS_VERSION)], body).into_response()
}

/// Enforces the protocol-version header on every non-OPTIONS request — mirrors
/// `requireTusResumable`. Returns the 412 response if it doesn't match.
fn require_tus_resumable(headers: &HeaderMap) -> Option<Response> {
    if headers.get("Tus-Resumable").and_then(|v| v.to_str().ok()) == Some(TUS_VERSION) {
        return None;
    }
    Some(
        (
            StatusCode::PRECONDITION_FAILED,
            [("Tus-Resumable", TUS_VERSION), ("Tus-Version", TUS_VERSION)],
            "Tus-Resumable header must be 1.0.0",
        )
            .into_response(),
    )
}

/// Decodes the `Upload-Metadata` header: comma-separated `key <base64>` pairs (values are
/// base64-encoded UTF-8). Flag-style keys with no value are ignored. Mirrors
/// `parseUploadMetadata`. `Err` carries a 400 body for a bad base64 value.
fn parse_upload_metadata(
    header: &str,
) -> Result<std::collections::HashMap<String, String>, String> {
    let mut out = std::collections::HashMap::new();
    if header.is_empty() {
        return Ok(out);
    }
    for pair in header.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let mut parts = pair.splitn(2, ' ');
        let key = parts.next().unwrap_or("").trim();
        if key.is_empty() {
            continue;
        }
        let Some(val) = parts.next() else {
            // flag-style key with no value; ignored
            continue;
        };
        let raw = base64::engine::general_purpose::STANDARD
            .decode(val.trim())
            .map_err(|_| format!("upload-metadata: bad base64 for {key:?}"))?;
        let s = String::from_utf8(raw)
            .map_err(|_| format!("upload-metadata: bad base64 for {key:?}"))?;
        out.insert(key.to_string(), s);
    }
    Ok(out)
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

// ---------------------------------------------------------------------------
// OPTIONS /api/uploads — discovery
// ---------------------------------------------------------------------------

/// Advertises the supported protocol version + extensions. No auth — the spec treats this
/// as discovery. `Tus-Max-Size` is a conservative ceiling (1 TiB); the real check is the
/// per-user quota gate at create time. Mirrors `Options`.
pub async fn options() -> Response {
    (
        StatusCode::NO_CONTENT,
        [
            ("Tus-Resumable", TUS_VERSION),
            ("Tus-Version", TUS_VERSION),
            ("Tus-Extension", "creation,termination"),
            ("Tus-Max-Size", "1099511627776"), // 1 TiB
        ],
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// POST /api/uploads — Create
// ---------------------------------------------------------------------------

/// Opens a new tus upload session — mirrors `Create`. Requires `Upload-Length` and an
/// `Upload-Metadata` carrying `collectionId, encryptedMetadata, metadataNonce,
/// encryptedFileKey, fileKeyNonce`. Returns 201 with `Location`, `Upload-Offset: 0` and a
/// `{"fileId": …}` body (tus-js-client surfaces it to the browser path).
pub async fn create(State(state): State<AppState>, user: AuthUser, headers: HeaderMap) -> Response {
    if let Some(resp) = require_tus_resumable(&headers) {
        return resp;
    }
    let user_id = match Uuid::parse_str(&user.user_id) {
        Ok(u) => u,
        Err(_) => return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "invalid user id"),
    };

    let total_bytes_str = header_str(&headers, "Upload-Length");
    if total_bytes_str.is_empty() {
        return tus_text(StatusCode::BAD_REQUEST, "Upload-Length header required");
    }
    let total_bytes: i64 = match total_bytes_str.parse() {
        Ok(n) if n >= 0 => n,
        _ => {
            return tus_text(
                StatusCode::BAD_REQUEST,
                "Upload-Length must be a non-negative integer",
            )
        }
    };

    let meta = match parse_upload_metadata(header_str(&headers, "Upload-Metadata")) {
        Ok(m) => m,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, [("Tus-Resumable", TUS_VERSION)], e).into_response()
        }
    };
    let empty = String::new();
    let coll_id = meta.get("collectionId").unwrap_or(&empty);
    let enc_metadata = meta.get("encryptedMetadata").unwrap_or(&empty);
    let metadata_nonce = meta.get("metadataNonce").unwrap_or(&empty);
    let enc_file_key = meta.get("encryptedFileKey").unwrap_or(&empty);
    let file_key_nonce = meta.get("fileKeyNonce").unwrap_or(&empty);
    if coll_id.is_empty()
        || enc_metadata.is_empty()
        || metadata_nonce.is_empty()
        || enc_file_key.is_empty()
        || file_key_nonce.is_empty()
    {
        return tus_text(
            StatusCode::BAD_REQUEST,
            "Upload-Metadata must include collectionId, encryptedMetadata, \
             metadataNonce, encryptedFileKey, fileKeyNonce",
        );
    }
    // The storage path uses the raw collectionId string (matches Go's fmt.Sprintf).
    let coll_uuid = match Uuid::parse_str(coll_id) {
        Ok(u) => u,
        // A bad collectionId can't be owned/shared → forbidden, as in Go (the COUNT/share
        // lookups fail and isOwner stays false / the share read errors).
        Err(_) => return tus_text(StatusCode::FORBIDDEN, "forbidden"),
    };

    let mut tx = match state.pool.begin().await {
        Ok(t) => t,
        Err(_) => return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db begin"),
    };

    // Permission check + quota gate, mirroring files.rs upload.
    let owner_n: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM collections WHERE id=$1 AND owner_user_id=$2")
            .bind(coll_uuid)
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap_or(0);
    let is_owner = owner_n > 0;

    let mut upload_quota_bytes: Option<i64> = None;
    if !is_owner {
        let share: Option<(bool, Option<i64>)> = sqlx::query_as(
            "SELECT can_upload, upload_quota_bytes FROM collection_shares \
             WHERE collection_id=$1 AND recipient_user_id=$2",
        )
        .bind(coll_uuid)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
        match share {
            Some((true, q)) => upload_quota_bytes = q,
            _ => return tus_text(StatusCode::FORBIDDEN, "forbidden"),
        }
    }

    // User-level quota: committed + reserved (in-flight) + this one ≤ cap. FOR UPDATE
    // locks the user row so concurrent Creates can't race past the cap together.
    let user_row: Result<(i64, i64), _> = sqlx::query_as(
        "SELECT storage_quota_bytes, storage_used_bytes FROM users WHERE id=$1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await;
    let (quota, used) = match user_row {
        Ok(v) => v,
        Err(_) => return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db read user"),
    };
    let reserved: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(total_bytes - received_bytes), 0) FROM uploads WHERE user_id=$1",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);
    if used + reserved + total_bytes > quota {
        return tus_text(StatusCode::PAYLOAD_TOO_LARGE, "storage quota exceeded");
    }

    // Per-share upload-quota check, same as files.rs.
    if !is_owner {
        if let Some(share_quota) = upload_quota_bytes {
            let used_share: i64 = sqlx::query_scalar(
                "SELECT COALESCE(SUM(encrypted_size_bytes),0) FROM files \
                 WHERE collection_id=$1 AND uploader_user_id=$2",
            )
            .bind(coll_uuid)
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap_or(0);
            let reserved_share: i64 = sqlx::query_scalar(
                "SELECT COALESCE(SUM(total_bytes - received_bytes),0) FROM uploads \
                 WHERE collection_id=$1 AND user_id=$2",
            )
            .bind(coll_uuid)
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap_or(0);
            if used_share + reserved_share + total_bytes > share_quota {
                return tus_text(StatusCode::PAYLOAD_TOO_LARGE, "share upload quota exceeded");
            }
        }
    }

    // Allocate the upload-session id + file id up-front; open the S3 multipart directly at
    // the canonical {userId}/{collectionId}/{fileId} key (no temp→final copy — S3 hides
    // incomplete multiparts from GetObject until Complete runs).
    let upload_id = Uuid::new_v4();
    let file_id = Uuid::new_v4();
    let storage_path = format!("{}/{}/{}", user.user_id, coll_id, file_id);
    let s3_upload_id = match state.storage.create_multipart(&storage_path).await {
        Ok(id) => id,
        Err(_) => {
            return tus_text(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage create multipart",
            )
        }
    };

    let ins = sqlx::query(
        "INSERT INTO uploads \
            (id, user_id, collection_id, file_id, total_bytes, \
             encrypted_metadata, metadata_nonce, encrypted_file_key, file_key_nonce, \
             storage_path, s3_upload_id) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(upload_id)
    .bind(user_id)
    .bind(coll_uuid)
    .bind(file_id)
    .bind(total_bytes)
    .bind(enc_metadata)
    .bind(metadata_nonce)
    .bind(enc_file_key)
    .bind(file_key_nonce)
    .bind(&storage_path)
    .bind(&s3_upload_id)
    .execute(&mut *tx)
    .await;
    if ins.is_err() {
        let _ = state
            .storage
            .abort_multipart(&storage_path, &s3_upload_id)
            .await;
        return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db insert upload");
    }
    if tx.commit().await.is_err() {
        let _ = state
            .storage
            .abort_multipart(&storage_path, &s3_upload_id)
            .await;
        return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db commit");
    }

    (
        StatusCode::CREATED,
        [
            ("Tus-Resumable", TUS_VERSION.to_string()),
            ("Location", format!("/api/uploads/{upload_id}")),
            ("Upload-Offset", "0".to_string()),
            ("Content-Type", "application/json".to_string()),
        ],
        format!("{{\"fileId\":\"{file_id}\"}}"),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// HEAD /api/uploads/{id} — resume
// ---------------------------------------------------------------------------

/// Returns the current `Upload-Offset` so the client can resume — mirrors `Head`. 404 if
/// the upload doesn't exist / isn't owned by the caller.
pub async fn head(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Some(resp) = require_tus_resumable(&headers) {
        return resp;
    }
    let user_id = match Uuid::parse_str(&user.user_id) {
        Ok(u) => u,
        Err(_) => return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "invalid user id"),
    };
    let upload_id = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return tus_text(StatusCode::NOT_FOUND, ""),
    };

    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT total_bytes, received_bytes FROM uploads WHERE id=$1 AND user_id=$2",
    )
    .bind(upload_id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((total_bytes, received_bytes)) = row else {
        return tus_text(StatusCode::NOT_FOUND, "");
    };

    (
        StatusCode::OK,
        [
            ("Tus-Resumable", TUS_VERSION.to_string()),
            ("Upload-Offset", received_bytes.to_string()),
            ("Upload-Length", total_bytes.to_string()),
            ("Cache-Control", "no-store".to_string()),
        ],
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// PATCH /api/uploads/{id} — extend
// ---------------------------------------------------------------------------

/// Appends bytes — mirrors `Patch`. Each PATCH becomes one S3 multipart part; parts before
/// the final must be ≥ 5 MiB. The PATCH that brings `received_bytes == total_bytes` runs the
/// finaliser: complete-multipart, INSERT `files`, bump `storage_used_bytes`, DELETE the row;
/// it returns `X-Kutup-File-Id`.
pub async fn patch(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(resp) = require_tus_resumable(&headers) {
        return resp;
    }
    if header_str(&headers, "Content-Type") != "application/offset+octet-stream" {
        return tus_text(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/offset+octet-stream",
        );
    }
    let user_id = match Uuid::parse_str(&user.user_id) {
        Ok(u) => u,
        Err(_) => return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "invalid user id"),
    };
    let upload_id = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return tus_text(StatusCode::NOT_FOUND, ""),
    };

    let client_offset: i64 = match header_str(&headers, "Upload-Offset").parse() {
        Ok(n) if n >= 0 => n,
        _ => {
            return tus_text(
                StatusCode::BAD_REQUEST,
                "Upload-Offset must be a non-negative integer",
            )
        }
    };

    let chunk_len = body.len() as i64;
    if chunk_len == 0 {
        return tus_text(StatusCode::BAD_REQUEST, "empty body");
    }

    // Read + lock the upload row FOR UPDATE so the finaliser is race-free against a
    // concurrent PATCH on the same upload.
    let mut tx = match state.pool.begin().await {
        Ok(t) => t,
        Err(_) => return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db begin"),
    };

    type UploadRow = (
        Uuid,              // collection_id
        Uuid,              // file_id
        i64,               // total_bytes
        i64,               // received_bytes
        String,            // encrypted_metadata
        String,            // metadata_nonce
        String,            // encrypted_file_key
        String,            // file_key_nonce
        String,            // storage_path
        String,            // s3_upload_id
        serde_json::Value, // s3_part_etags
    );
    let row: Option<UploadRow> = sqlx::query_as(
        "SELECT collection_id, file_id, total_bytes, received_bytes, \
                encrypted_metadata, metadata_nonce, encrypted_file_key, file_key_nonce, \
                storage_path, s3_upload_id, s3_part_etags \
         FROM uploads WHERE id=$1 AND user_id=$2 FOR UPDATE",
    )
    .bind(upload_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let Some((
        coll_id,
        file_id,
        total_bytes,
        received_bytes,
        enc_metadata,
        metadata_nonce,
        enc_file_key,
        file_key_nonce,
        storage_path,
        s3_upload_id,
        part_etags_json,
    )) = row
    else {
        return tus_text(StatusCode::NOT_FOUND, "");
    };

    if client_offset != received_bytes {
        return (
            StatusCode::CONFLICT,
            [
                ("Tus-Resumable", TUS_VERSION.to_string()),
                ("Upload-Offset", received_bytes.to_string()),
            ],
            "Upload-Offset mismatch",
        )
            .into_response();
    }
    if received_bytes + chunk_len > total_bytes {
        return tus_text(StatusCode::PAYLOAD_TOO_LARGE, "chunk exceeds Upload-Length");
    }

    let mut parts: Vec<CompletedPart> = match serde_json::from_value(part_etags_json) {
        Ok(p) => p,
        Err(_) => return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "corrupt part etags"),
    };
    let next_part = parts.len() as i32 + 1;
    let is_final_part = received_bytes + chunk_len == total_bytes;
    if !is_final_part && chunk_len < MIN_PART_SIZE {
        return (
            StatusCode::BAD_REQUEST,
            [("Tus-Resumable", TUS_VERSION)],
            format!("non-final part must be at least {MIN_PART_SIZE} bytes (got {chunk_len})"),
        )
            .into_response();
    }

    // Stream the chunk to S3 as one multipart part.
    let etag = match state
        .storage
        .upload_part(
            &storage_path,
            &s3_upload_id,
            next_part,
            ByteStream::from(body.to_vec()),
            chunk_len,
        )
        .await
    {
        Ok(e) => e,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("Tus-Resumable", TUS_VERSION)],
                format!("storage upload part: {e}"),
            )
                .into_response()
        }
    };
    parts.push(CompletedPart {
        part_number: next_part,
        etag,
    });
    let parts_json = serde_json::to_value(&parts).unwrap_or(serde_json::Value::Null);
    let new_received = received_bytes + chunk_len;

    if sqlx::query(
        "UPDATE uploads SET received_bytes=$1, s3_part_etags=$2, updated_at=NOW() WHERE id=$3",
    )
    .bind(new_received)
    .bind(&parts_json)
    .bind(upload_id)
    .execute(&mut *tx)
    .await
    .is_err()
    {
        return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db update");
    }

    if !is_final_part {
        if tx.commit().await.is_err() {
            return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db commit");
        }
        return (
            StatusCode::NO_CONTENT,
            [
                ("Tus-Resumable", TUS_VERSION.to_string()),
                ("Upload-Offset", new_received.to_string()),
            ],
        )
            .into_response();
    }

    // --- finaliser path ---
    // complete-multipart (stitched in place at the canonical key) → INSERT files → bump
    // quota → DELETE the uploads row. Complete runs before the DB commit, so a crash
    // between them leaves an orphan S3 object for the orphan-sweep job.
    if let Err(e) = state
        .storage
        .complete_multipart(&storage_path, &s3_upload_id, &parts)
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("Tus-Resumable", TUS_VERSION)],
            format!("storage complete multipart: {e}"),
        )
            .into_response();
    }

    if sqlx::query(
        "INSERT INTO files \
            (id, collection_id, uploader_user_id, \
             encrypted_metadata, metadata_nonce, encrypted_file_key, file_key_nonce, \
             storage_path, encrypted_size_bytes) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(file_id)
    .bind(coll_id)
    .bind(user_id)
    .bind(&enc_metadata)
    .bind(&metadata_nonce)
    .bind(&enc_file_key)
    .bind(&file_key_nonce)
    .bind(&storage_path)
    .bind(total_bytes)
    .execute(&mut *tx)
    .await
    .is_err()
    {
        let _ = state.storage.delete(&storage_path).await;
        return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db insert file");
    }
    if sqlx::query("UPDATE users SET storage_used_bytes = storage_used_bytes + $1 WHERE id=$2")
        .bind(total_bytes)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .is_err()
    {
        let _ = state.storage.delete(&storage_path).await;
        return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db quota update");
    }
    if sqlx::query("DELETE FROM uploads WHERE id=$1")
        .bind(upload_id)
        .execute(&mut *tx)
        .await
        .is_err()
    {
        let _ = state.storage.delete(&storage_path).await;
        return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db delete upload");
    }
    if tx.commit().await.is_err() {
        let _ = state.storage.delete(&storage_path).await;
        return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db commit");
    }

    (
        StatusCode::NO_CONTENT,
        [
            ("Tus-Resumable", TUS_VERSION.to_string()),
            ("Upload-Offset", new_received.to_string()),
            ("X-Kutup-File-Id", file_id.to_string()),
        ],
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// DELETE /api/uploads/{id} — cancel
// ---------------------------------------------------------------------------

/// Cancels an in-flight upload — mirrors `Delete`. Aborts the S3 multipart (freeing
/// SeaweedFS staging), then removes the DB row (freeing reserved quota). Abort-before-row
/// ordering keeps a failed abort recoverable from the row. 404 if not owned by the caller.
pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Some(resp) = require_tus_resumable(&headers) {
        return resp;
    }
    let user_id = match Uuid::parse_str(&user.user_id) {
        Ok(u) => u,
        Err(_) => return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "invalid user id"),
    };
    let upload_id = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return tus_text(StatusCode::NOT_FOUND, ""),
    };

    let row: Option<(String, String)> =
        sqlx::query_as("SELECT storage_path, s3_upload_id FROM uploads WHERE id=$1 AND user_id=$2")
            .bind(upload_id)
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten();
    let Some((storage_path, s3_upload_id)) = row else {
        return tus_text(StatusCode::NOT_FOUND, "");
    };

    if let Err(e) = state
        .storage
        .abort_multipart(&storage_path, &s3_upload_id)
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("Tus-Resumable", TUS_VERSION)],
            format!("storage abort: {e}"),
        )
            .into_response();
    }
    if sqlx::query("DELETE FROM uploads WHERE id=$1 AND user_id=$2")
        .bind(upload_id)
        .bind(user_id)
        .execute(&state.pool)
        .await
        .is_err()
    {
        return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db delete");
    }

    tus_text(StatusCode::NO_CONTENT, "")
}

#[cfg(test)]
mod tests {
    use super::parse_upload_metadata;
    use base64::Engine;

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    #[test]
    fn parses_metadata_pairs() {
        let header = format!(
            "collectionId {}, encryptedMetadata {}",
            b64("coll-1"),
            b64("blob")
        );
        let m = parse_upload_metadata(&header).unwrap();
        assert_eq!(m.get("collectionId").unwrap(), "coll-1");
        assert_eq!(m.get("encryptedMetadata").unwrap(), "blob");
    }

    #[test]
    fn empty_header_is_empty_map() {
        assert!(parse_upload_metadata("").unwrap().is_empty());
    }

    #[test]
    fn flag_key_without_value_ignored() {
        let m = parse_upload_metadata("flagKey").unwrap();
        assert!(m.is_empty());
    }

    #[test]
    fn bad_base64_errs() {
        assert!(parse_upload_metadata("k !!!notbase64!!!").is_err());
    }
}
