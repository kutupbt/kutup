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

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use kutup_crypto::drive_envelope::DriveEnvelopeContextV1;
use kutup_crypto::drive_object::{DriveFileBlobContextV1, FILE_BLOB_PREFIX_BYTES};
use uuid::Uuid;

use crate::drive_writes::Room;
use crate::handlers::files::{canonical_uuid, validate_envelope, validate_file_blob_prefix};
use crate::middleware::AuthUser;
use crate::storage::{CompletedPart, MultipartUpload};
use crate::AppState;

/// The protocol version we advertise + require. Clients send `Tus-Resumable: 1.0.0` on
/// every non-OPTIONS request; mismatch → 412. Mirrors `tusVersion`.
pub(crate) const TUS_VERSION: &str = "1.0.0";

/// S3's lower bound on every multipart part except the last (5 MiB). Mirrors `minPartSize`.
pub(crate) use crate::storage::MIN_PART_SIZE;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Plain-text tus response carrying the `Tus-Resumable` header — mirrors the bodies
/// Fiber produced via `c.Status(...).SendString(...)`.
pub(crate) fn tus_text(status: StatusCode, body: &'static str) -> Response {
    (status, [("Tus-Resumable", TUS_VERSION)], body).into_response()
}

/// An `AppError` (its JSON body, a refused name's details) as a tus answer.
fn tus_error(error: crate::error::AppError) -> Response {
    let mut response = error.into_response();
    response.headers_mut().insert(
        "Tus-Resumable",
        axum::http::HeaderValue::from_static(TUS_VERSION),
    );
    response
}

/// Enforces the protocol-version header on every non-OPTIONS request — mirrors
/// `requireTusResumable`. Returns the 412 response if it doesn't match.
pub(crate) fn require_tus_resumable(headers: &HeaderMap) -> Option<Response> {
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
pub(crate) fn parse_upload_metadata(
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
        if out.insert(key.to_string(), s).is_some() {
            return Err(format!("upload-metadata: duplicate key {key:?}"));
        }
    }
    Ok(out)
}

pub(crate) fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
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
/// `Upload-Metadata` carrying `fileId, collectionId, metadataEnvelope,
/// fileKeyEnvelope`. Returns 201 with `Location`, `Upload-Offset: 0` and a
/// `{"fileId": …}` body (tus-js-client surfaces it to the browser path).
#[utoipa::path(
    post,
    path = "/api/uploads",
    tag = "tus",
    operation_id = "tusCreate",
    security(("BearerAuth" = [])),
    params(
        ("Tus-Resumable" = String, Header, description = "Must be 1.0.0"),
        ("Upload-Length" = i64, Header, description = "Total upload size in bytes"),
        ("Upload-Metadata" = String, Header, description = "Comma-separated `key <base64>` pairs: fileId, collectionId, metadataEnvelope, fileKeyEnvelope")
    ),
    responses((status = 201, description = "Session created; `Location` + `Upload-Offset: 0` headers and a `{\"fileId\": …}` body"))
)]
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
        Ok(n) if n >= (FILE_BLOB_PREFIX_BYTES + kutup_crypto::stream::ABYTES) as i64 => n,
        _ => {
            return tus_text(
                StatusCode::BAD_REQUEST,
                "Upload-Length is too small for a Drive file blob",
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
    let file_id_text = meta.get("fileId").unwrap_or(&empty);
    let coll_id = meta.get("collectionId").unwrap_or(&empty);
    let metadata_envelope = meta.get("metadataEnvelope").unwrap_or(&empty);
    let file_key_envelope = meta.get("fileKeyEnvelope").unwrap_or(&empty);
    // The name's hash (docs/plans/drive-unique-names.md), from clients that
    // keep names unique.
    let name_hash =
        match crate::drive_names::parse_name_hash(meta.get("nameHash").map(String::as_str)) {
            Ok(hash) => hash,
            Err(_) => return tus_text(StatusCode::BAD_REQUEST, "invalid name hash"),
        };
    if meta.len() != 4 + usize::from(name_hash.is_some())
        || file_id_text.is_empty()
        || coll_id.is_empty()
        || metadata_envelope.is_empty()
        || file_key_envelope.is_empty()
    {
        return tus_text(
            StatusCode::BAD_REQUEST,
            "Upload-Metadata must contain exactly fileId, collectionId, \
             metadataEnvelope, fileKeyEnvelope",
        );
    }
    let file_id = match canonical_uuid(file_id_text) {
        Ok(id) => id,
        Err(_) => return tus_text(StatusCode::BAD_REQUEST, "invalid file id"),
    };
    let coll_uuid = match Uuid::parse_str(coll_id) {
        Ok(u) if u.to_string() == *coll_id => u,
        _ => return tus_text(StatusCode::FORBIDDEN, "forbidden"),
    };

    let mut tx = match state.pool.begin().await {
        Ok(t) => t,
        Err(_) => return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db begin"),
    };

    // Permission check + quota gate, mirroring files.rs upload.
    let collection: Option<(Uuid, i32)> = sqlx::query_as(
        "SELECT owner_user_id, key_epoch FROM collections WHERE id=$1 AND deleted_at IS NULL",
    )
    .bind(coll_uuid)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let Some((owner_user_id, key_epoch)) = collection else {
        return tus_text(StatusCode::FORBIDDEN, "forbidden");
    };
    let is_owner = owner_user_id == user_id;

    if !is_owner {
        let can_upload: Option<bool> = sqlx::query_scalar(
            "SELECT cs.can_upload FROM collection_shares cs \
             JOIN collections c ON c.id = cs.collection_id AND c.deleted_at IS NULL \
             WHERE cs.collection_id=$1 AND cs.recipient_user_id=$2",
        )
        .bind(coll_uuid)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
        if can_upload != Some(true) {
            return tus_text(StatusCode::FORBIDDEN, "forbidden");
        }
    }

    let epoch = match u32::try_from(key_epoch) {
        Ok(epoch) => epoch,
        Err(_) => return tus_text(StatusCode::CONFLICT, "invalid collection epoch"),
    };
    // A new file's key is generation 1, wrapped at the folder's epoch.
    let file_key_context = match DriveEnvelopeContextV1::file_key(file_id_text, coll_id, epoch, 1) {
        Ok(context) => context,
        Err(_) => return tus_text(StatusCode::BAD_REQUEST, "invalid Drive envelope"),
    };
    let metadata_context = match DriveEnvelopeContextV1::file_metadata(file_id_text, 1, 1) {
        Ok(context) => context,
        Err(_) => return tus_text(StatusCode::BAD_REQUEST, "invalid Drive envelope"),
    };
    if let Err(error) = validate_envelope(file_key_envelope, file_key_context)
        .and_then(|()| validate_envelope(metadata_envelope, metadata_context))
    {
        // 409 when the folder key rotated since the client read it.
        return tus_text(
            error.status,
            if error.status == StatusCode::CONFLICT {
                "folder key changed"
            } else {
                "invalid Drive envelope"
            },
        );
    }

    // The id, then room: the user's quota less what their open uploads have
    // reserved, and the share's limit when uploading into someone's folder.
    // Both hold until commit (the user's row stays locked).
    match crate::drive_writes::claim_file_id(&mut tx, file_id, None).await {
        Ok(true) => {}
        Ok(false) => return tus_text(StatusCode::CONFLICT, "file id already in use"),
        Err(_) => return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db claim file id"),
    }
    match crate::drive_writes::check_room(&mut tx, user_id, coll_uuid, total_bytes, None).await {
        Ok(Room::Enough) => {}
        Ok(Room::Quota) => {
            return tus_text(StatusCode::PAYLOAD_TOO_LARGE, "storage quota exceeded")
        }
        Ok(Room::ShareLimit) => {
            return tus_text(StatusCode::PAYLOAD_TOO_LARGE, "share upload quota exceeded")
        }
        Err(_) => return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db quota"),
    }

    // A name already here refuses the upload before anything is sent.
    if let Some(hash) = &name_hash {
        let place = crate::drive_names::Place::Folder(coll_uuid);
        if let Err(error) = crate::drive_names::lock_place(&mut tx, place).await {
            return tus_error(error);
        }
        if let Err(error) = crate::drive_names::ensure_name_free(&mut tx, place, hash, None).await {
            return tus_error(error);
        }
    }

    // Allocate the upload-session id; the client allocated the file id before
    // constructing its object-bound envelopes. Open the S3 multipart directly at
    // the canonical {userId}/{collectionId}/{fileId} key (no temp→final copy — S3 hides
    // incomplete multiparts from GetObject until Complete runs).
    let upload_id = Uuid::new_v4();
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
             metadata_envelope, file_key_envelope, key_epoch, metadata_revision, \
             storage_path, s3_upload_id, name_hash) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
    )
    .bind(upload_id)
    .bind(user_id)
    .bind(coll_uuid)
    .bind(file_id)
    .bind(total_bytes)
    .bind(metadata_envelope)
    .bind(file_key_envelope)
    .bind(key_epoch)
    .bind(1_i64)
    .bind(&storage_path)
    .bind(&s3_upload_id)
    .bind(&name_hash)
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
#[utoipa::path(
    head,
    path = "/api/uploads/{id}",
    tag = "tus",
    operation_id = "tusHead",
    security(("BearerAuth" = [])),
    params(
        ("id" = String, Path, description = "Upload-session id"),
        ("Tus-Resumable" = String, Header, description = "Must be 1.0.0")
    ),
    responses((status = 200, description = "`Upload-Offset` + `Upload-Length` headers for resuming"))
)]
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
#[utoipa::path(
    patch,
    path = "/api/uploads/{id}",
    tag = "tus",
    operation_id = "tusPatch",
    security(("BearerAuth" = [])),
    params(
        ("id" = String, Path, description = "Upload-session id"),
        ("Tus-Resumable" = String, Header, description = "Must be 1.0.0"),
        ("Upload-Offset" = i64, Header, description = "Byte offset this chunk starts at")
    ),
    request_body(
        content = Vec<u8>,
        content_type = "application/offset+octet-stream",
        description = "One chunk of the encrypted blob (non-final chunks must be ≥ 5 MiB)"
    ),
    responses((status = 204, description = "Chunk appended; the final chunk also returns `X-Kutup-File-Id`"))
)]
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
        String,            // metadata_envelope
        String,            // file_key_envelope
        i32,               // key_epoch
        i64,               // metadata_revision
        String,            // storage_path
        String,            // s3_upload_id
        serde_json::Value, // s3_part_etags
        Vec<u8>,           // pending_bytes
        Option<String>,    // name_hash
    );
    let row: Option<UploadRow> = sqlx::query_as(
        "SELECT collection_id, file_id, total_bytes, received_bytes, \
                metadata_envelope, file_key_envelope, key_epoch, metadata_revision, \
                storage_path, s3_upload_id, s3_part_etags, pending_bytes, name_hash \
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
        metadata_envelope,
        file_key_envelope,
        key_epoch,
        metadata_revision,
        storage_path,
        s3_upload_id,
        part_etags_json,
        pending,
        name_hash,
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
    if received_bytes == 0 {
        let context = match DriveFileBlobContextV1::new(&file_id.to_string(), 1) {
            Ok(context) => context,
            Err(_) => return tus_text(StatusCode::BAD_REQUEST, "invalid Drive file blob"),
        };
        if validate_file_blob_prefix(&body, context).is_err() {
            return tus_text(StatusCode::BAD_REQUEST, "invalid Drive file blob");
        }
    }

    let mut parts: Vec<CompletedPart> = match serde_json::from_value(part_etags_json) {
        Ok(p) => p,
        Err(_) => return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "corrupt part etags"),
    };
    let is_final_part = received_bytes + chunk_len == total_bytes;
    if !is_final_part && chunk_len < MIN_PART_SIZE {
        return (
            StatusCode::BAD_REQUEST,
            [("Tus-Resumable", TUS_VERSION)],
            format!("non-final part must be at least {MIN_PART_SIZE} bytes (got {chunk_len})"),
        )
            .into_response();
    }

    // Store the chunk as equal-sized parts; what does not fill one waits in
    // the row for the next chunk.
    let pending = match state
        .storage
        .append_equal_parts(
            MultipartUpload {
                key: &storage_path,
                upload_id: &s3_upload_id,
                total_bytes,
            },
            &mut parts,
            &pending,
            &body,
            is_final_part,
        )
        .await
    {
        Ok(pending) => pending,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("Tus-Resumable", TUS_VERSION)],
                format!("storage upload part: {e}"),
            )
                .into_response()
        }
    };
    let parts_json = serde_json::to_value(&parts).unwrap_or(serde_json::Value::Null);
    let new_received = received_bytes + chunk_len;

    if sqlx::query(
        "UPDATE uploads SET received_bytes=$1, s3_part_etags=$2, pending_bytes=$3, updated_at=NOW() WHERE id=$4",
    )
    .bind(new_received)
    .bind(&parts_json)
    .bind(&pending)
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
    // Everything the create checked must still hold now that the file lands:
    // the uploader may still write here, the folder is live at the epoch the
    // envelopes are bound to, the id is still free, and the file still fits
    // (a quota lowered meanwhile). Refused, the upload is discarded.
    if let Some(refusal) = finalize_refusal(
        &mut tx,
        user_id,
        upload_id,
        coll_id,
        file_id,
        key_epoch,
        total_bytes,
    )
    .await
    {
        drop(tx);
        let _ = state
            .storage
            .abort_multipart(&storage_path, &s3_upload_id)
            .await;
        let _ = sqlx::query("DELETE FROM uploads WHERE id=$1")
            .bind(upload_id)
            .execute(&state.pool)
            .await;
        return refusal;
    }

    // The name it was started under must still be free: another upload or a
    // rename may have taken it meanwhile. Checked before the parts are
    // stitched, under the folder's name lock, which is held to the commit.
    if let Some(hash) = &name_hash {
        let place = crate::drive_names::Place::Folder(coll_id);
        let taken = match crate::drive_names::lock_place(&mut tx, place).await {
            Ok(()) => crate::drive_names::ensure_name_free(&mut tx, place, hash, None)
                .await
                .err(),
            Err(error) => Some(error),
        };
        if let Some(error) = taken {
            // Released first: the row it locks is deleted below.
            drop(tx);
            let _ = state
                .storage
                .abort_multipart(&storage_path, &s3_upload_id)
                .await;
            let _ = sqlx::query("DELETE FROM uploads WHERE id=$1")
                .bind(upload_id)
                .execute(&state.pool)
                .await;
            return tus_error(error);
        }
    }

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
             metadata_envelope, file_key_envelope, key_epoch, key_generation, \
             metadata_revision, storage_path, encrypted_size_bytes, original_key_generation, \
             name_hash) \
         VALUES ($1,$2,$3,$4,$5,$6,1,$7,$8,$9,1,$10)",
    )
    .bind(file_id)
    .bind(coll_id)
    .bind(user_id)
    .bind(&metadata_envelope)
    .bind(&file_key_envelope)
    .bind(key_epoch)
    .bind(metadata_revision)
    .bind(&storage_path)
    .bind(total_bytes)
    .bind(&name_hash)
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

/// The finaliser's re-checks (see `patch`): the refusal, if one applies.
async fn finalize_refusal(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    upload_id: Uuid,
    coll_id: Uuid,
    file_id: Uuid,
    key_epoch: i32,
    total_bytes: i64,
) -> Option<Response> {
    let db = || {
        Some(tus_text(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db finalize check",
        ))
    };
    let folder: Option<(Uuid, i32, Option<bool>)> = match sqlx::query_as(
        "SELECT c.owner_user_id, c.key_epoch,
                (SELECT cs.can_upload FROM collection_shares cs
                 WHERE cs.collection_id = c.id AND cs.recipient_user_id = $2)
         FROM collections c WHERE c.id = $1 AND c.deleted_at IS NULL FOR SHARE",
    )
    .bind(coll_id)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await
    {
        Ok(folder) => folder,
        Err(_) => return db(),
    };
    let Some((owner, epoch, can_upload)) = folder else {
        return Some(tus_text(StatusCode::CONFLICT, "folder no longer available"));
    };
    if owner != user_id && can_upload != Some(true) {
        return Some(tus_text(StatusCode::FORBIDDEN, "forbidden"));
    }
    if epoch != key_epoch {
        return Some(tus_text(
            StatusCode::CONFLICT,
            "folder key changed during upload",
        ));
    }
    match crate::drive_writes::claim_file_id(tx, file_id, Some(upload_id)).await {
        Ok(true) => {}
        Ok(false) => return Some(tus_text(StatusCode::CONFLICT, "file id already in use")),
        Err(_) => return db(),
    }
    match crate::drive_writes::check_room(tx, user_id, coll_id, total_bytes, Some(upload_id)).await
    {
        Ok(Room::Enough) => None,
        Ok(Room::Quota) => Some(tus_text(
            StatusCode::PAYLOAD_TOO_LARGE,
            "storage quota exceeded",
        )),
        Ok(Room::ShareLimit) => Some(tus_text(
            StatusCode::PAYLOAD_TOO_LARGE,
            "share upload quota exceeded",
        )),
        Err(_) => db(),
    }
}

// ---------------------------------------------------------------------------
// DELETE /api/uploads/{id} — cancel
// ---------------------------------------------------------------------------

/// Cancels an in-flight upload — mirrors `Delete`. Aborts the S3 multipart (freeing
/// SeaweedFS staging), then removes the DB row (freeing reserved quota). Abort-before-row
/// ordering keeps a failed abort recoverable from the row. 404 if not owned by the caller.
#[utoipa::path(
    delete,
    path = "/api/uploads/{id}",
    tag = "tus",
    operation_id = "tusDelete",
    security(("BearerAuth" = [])),
    params(
        ("id" = String, Path, description = "Upload-session id"),
        ("Tus-Resumable" = String, Header, description = "Must be 1.0.0")
    ),
    responses((status = 204, description = "Upload cancelled; reserved quota freed"))
)]
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
            "collectionId {}, metadataEnvelope {}",
            b64("coll-1"),
            b64("blob")
        );
        let m = parse_upload_metadata(&header).unwrap();
        assert_eq!(m.get("collectionId").unwrap(), "coll-1");
        assert_eq!(m.get("metadataEnvelope").unwrap(), "blob");
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

    #[test]
    fn duplicate_metadata_keys_are_rejected() {
        let header = format!("fileId {}, fileId {}", b64("a"), b64("b"));
        assert!(parse_upload_metadata(&header).is_err());
    }
}
