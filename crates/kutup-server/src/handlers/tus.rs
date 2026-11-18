//! tus.io 1.0 resumable upload endpoint — mirrors `backend/handlers/tus.go`.
//!
//! The multipart POST in `drive_files.rs` buffers the whole encrypted blob and restarts from
//! byte zero on any blip; tus gives bounded memory (S3 multipart) + resume (offset
//! bookkeeping) + a commit of the encrypted metadata once the content is up. Flow:
//!
//!   OPTIONS /api/v1/drive/uploads        — discovery (anonymous)
//!   POST    /api/v1/drive/uploads        — create session, allocate the S3 multipart
//!   PATCH   /api/v1/drive/uploads/{id}    — append one part, bump the offset; the final PATCH
//!                                  completes the multipart, checks the stored object
//!                                  and leaves an uploaded revision (the row kept, its
//!                                  reservation held), made current by
//!                                  `revision_commit::commit`
//!   HEAD    /api/v1/drive/uploads/{id}    — resume: returns the current Upload-Offset
//!   DELETE  /api/v1/drive/uploads/{id}    — cancel: abort the multipart, free reserved quota
//!
//! Quota is soft-reserved: available bytes for a new upload are
//! `storage_quota_bytes - storage_used_bytes - SUM(uploads.total_bytes - received_bytes)`,
//! so a half-uploaded 50 GB file blocks a concurrent 50 GB attempt without polluting
//! `storage_used_bytes`. The revision's commit charges it, atomically with the
//! `drive_files` INSERT.
//!
//! Unlike the JSON handlers, the tus error bodies are plain text + carry the
//! `Tus-Resumable` header, matching Fiber's `c.SendString` — so responses are built
//! directly here rather than via `AppError` (whose body is `{"error": …}` JSON).

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use kutup_crypto::blocks::TRAILER_LEN;
use kutup_crypto::drive_envelope::DriveEnvelopeContextV1;
use uuid::Uuid;

use crate::drive_blob::BlockBlob;
use crate::drive_writes::Room;
use crate::error::{AppError, AppResult};
use crate::handlers::files::{canonical_uuid, validate_envelope};
use crate::middleware::AuthAccount;
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
pub(crate) fn tus_error(error: crate::error::AppError) -> Response {
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
// OPTIONS /api/v1/drive/uploads — discovery
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
// POST /api/v1/drive/uploads — Create
// ---------------------------------------------------------------------------

/// Opens a new tus upload session — mirrors `Create`. Requires `Upload-Length` and an
/// `Upload-Metadata` carrying `fileId, collectionId, metadataEnvelope,
/// fileKeyEnvelope`. Returns 201 with `Location`, `Upload-Offset: 0` and a
/// `{"fileId": …}` body (tus-js-client surfaces it to the browser path).
#[utoipa::path(
    post,
    path = "/api/v1/drive/uploads",
    tag = "drive",
    operation_id = "tusCreate",
    security(("BearerAuth" = [])),
    params(
        ("Tus-Resumable" = String, Header, description = "Must be 1.0.0"),
        ("Upload-Length" = i64, Header, description = "Total upload size in bytes"),
        ("Upload-Metadata" = String, Header, description = "Comma-separated `key <base64>` pairs. A new file: fileId, collectionId, fileKeyEnvelope, nameHash and revisionId. A new version of a file: versionOf, revisionId, and optional contentHash and basedOn. The upload lands as an uploaded revision, current only once committed (`POST /api/v1/drive/files/{id}/revisions/{revisionId}/commit`)")
    ),
    responses((status = 201, description = "Session created; `Location` + `Upload-Offset: 0` headers and a `{\"fileId\": …}` body"))
)]
pub async fn create(
    State(state): State<AppState>,
    user: AuthAccount,
    headers: HeaderMap,
) -> Response {
    if let Some(resp) = require_tus_resumable(&headers) {
        return resp;
    }
    let user_id = match Uuid::parse_str(&user.account_id) {
        Ok(u) => u,
        Err(_) => return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "invalid user id"),
    };

    let total_bytes_str = header_str(&headers, "Upload-Length");
    if total_bytes_str.is_empty() {
        return tus_text(StatusCode::BAD_REQUEST, "Upload-Length header required");
    }
    let total_bytes: i64 = match total_bytes_str.parse() {
        Ok(n) if n >= 0 => n,
        _ => return tus_text(StatusCode::BAD_REQUEST, "invalid Upload-Length"),
    };

    let meta = match parse_upload_metadata(header_str(&headers, "Upload-Metadata")) {
        Ok(m) => m,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, [("Tus-Resumable", TUS_VERSION)], e).into_response()
        }
    };
    // The blob is in the block format, bound to the revision `revisionId`
    // names (docs/plans/drive-block-format.md §3).
    let blob = match BlockBlob::from_revision(meta.get("revisionId").map(String::as_str)) {
        Ok(blob) => blob,
        Err(error) => return tus_error(error),
    };
    if (total_bytes as u64) < BlockBlob::min_len() {
        return tus_text(
            StatusCode::BAD_REQUEST,
            "Upload-Length is too small for a Drive file blob",
        );
    }
    // A new version of a file already here (`tus_versions`).
    if meta.contains_key("versionOf") {
        return super::tus_versions::create(&state, user_id, total_bytes, blob, &meta).await;
    }
    // The upload limit is a setting, the site's or the account's own.
    match crate::site_settings::DRIVE_UPLOAD_MAX_BYTES
        .load_for(&state.pool, user_id)
        .await
    {
        Ok(limit) if total_bytes <= limit => {}
        Ok(_) => {
            return tus_text(
                StatusCode::PAYLOAD_TOO_LARGE,
                "larger than this server's upload limit",
            )
        }
        Err(_) => return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db read"),
    }
    let empty = String::new();
    let file_id_text = meta.get("fileId").unwrap_or(&empty);
    let coll_id = meta.get("collectionId").unwrap_or(&empty);
    let file_key_envelope = meta.get("fileKeyEnvelope").unwrap_or(&empty);
    // The name's hash (docs/plans/drive-unique-names.md): every upload has one.
    let name_hash =
        match crate::drive_names::require_name_hash(meta.get("nameHash").map(String::as_str)) {
            Ok(hash) => hash,
            // Its JSON body carries the code (`nameNeeded` when missing).
            Err(error) => return tus_error(error),
        };
    // The metadata comes with the commit, once the manifest's digest is
    // known (docs/plans/drive-block-format.md §10 slice 3).
    if meta.len() != 5
        || file_id_text.is_empty()
        || coll_id.is_empty()
        || file_key_envelope.is_empty()
    {
        return tus_text(
            StatusCode::BAD_REQUEST,
            "Upload-Metadata must contain exactly fileId, collectionId, \
             fileKeyEnvelope, nameHash and revisionId",
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
    let collection: Option<(Uuid, i32)> = match sqlx::query_as(
        "SELECT owner_account_id, key_epoch FROM drive_collections WHERE id=$1 AND deleted_at IS NULL",
    )
    .bind(coll_uuid)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, "upload: a database read failed");
            return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db read");
        }
    };
    let Some((owner_account_id, key_epoch)) = collection else {
        return tus_text(StatusCode::FORBIDDEN, "forbidden");
    };
    let is_owner = owner_account_id == user_id;

    if !is_owner {
        let can_upload: Option<bool> = match sqlx::query_scalar(
            "SELECT cs.can_upload FROM drive_collection_shares cs \
             JOIN drive_collections c ON c.id = cs.collection_id AND c.deleted_at IS NULL \
             WHERE cs.collection_id=$1 AND cs.recipient_account_id=$2",
        )
        .bind(coll_uuid)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(%error, "upload: a database read failed");
                return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db read");
            }
        };
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
    if let Err(error) = validate_envelope(file_key_envelope, file_key_context) {
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
    let revision = blob.revision_id;
    if let Err(error) = crate::drive_blob::ensure_revision_free(&mut tx, revision, None).await {
        return tus_error(error);
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
    {
        let place = crate::drive_names::Place::Folder(coll_uuid);
        if let Err(error) = crate::drive_names::lock_place(&mut tx, place).await {
            return tus_error(error);
        }
        if let Err(error) =
            crate::drive_names::ensure_name_free(&mut tx, place, &name_hash, None).await
        {
            return tus_error(error);
        }
    }

    // Allocate the upload-session id; the client allocated the file id before
    // constructing its object-bound envelopes. Open the S3 multipart directly at
    // the revision's canonical key (no temp→final copy — S3 hides incomplete
    // multiparts from GetObject until Complete runs).
    let upload_id = Uuid::new_v4();
    let storage_path = crate::file_content::revision_path(file_id, revision);
    let s3_upload_id = match state.storage.create_multipart(&storage_path).await {
        Ok(id) => id,
        Err(_) => {
            return tus_text(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage create multipart",
            )
        }
    };

    // The metadata comes with the commit: NULL, never the columns' old
    // default (`uploads_metadata_at_commit`).
    let ins = sqlx::query(
        "INSERT INTO drive_uploads \
            (id, account_id, collection_id, file_id, total_bytes, \
             file_key_envelope, key_epoch, \
             storage_path, s3_upload_id, name_hash, revision_id, blob_suite, \
             metadata_envelope, metadata_revision) \
         VALUES ($1,$2,$3,$4,$5,kutup_unb64($6),$7,$8,$9,decode($10, 'hex'),$11,$12,NULL,NULL)",
    )
    .bind(upload_id)
    .bind(user_id)
    .bind(coll_uuid)
    .bind(file_id)
    .bind(total_bytes)
    .bind(file_key_envelope)
    .bind(key_epoch)
    .bind(&storage_path)
    .bind(&s3_upload_id)
    .bind(&name_hash)
    .bind(revision)
    .bind(crate::drive_blob::BLOCK_SUITE)
    .execute(&mut *tx)
    .await;
    if let Err(error) = ins {
        tracing::error!(%error, "upload: inserting the upload row failed");
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
            ("Location", format!("/api/v1/drive/uploads/{upload_id}")),
            ("Upload-Offset", "0".to_string()),
            ("Content-Type", "application/json".to_string()),
        ],
        format!("{{\"fileId\":\"{file_id}\"}}"),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// HEAD /api/v1/drive/uploads/{id} — resume
// ---------------------------------------------------------------------------

/// Returns the current `Upload-Offset` so the client can resume — mirrors `Head`. 404 if
/// the upload doesn't exist / isn't owned by the caller.
#[utoipa::path(
    head,
    path = "/api/v1/drive/uploads/{id}",
    tag = "drive",
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
    user: AuthAccount,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Some(resp) = require_tus_resumable(&headers) {
        return resp;
    }
    let user_id = match Uuid::parse_str(&user.account_id) {
        Ok(u) => u,
        Err(_) => return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "invalid user id"),
    };
    let upload_id = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return tus_text(StatusCode::NOT_FOUND, ""),
    };

    let row: Option<(i64, i64)> = match sqlx::query_as(
        "SELECT total_bytes, received_bytes FROM drive_uploads WHERE id=$1 AND account_id=$2",
    )
    .bind(upload_id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, "upload: a database read failed");
            return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db read");
        }
    };
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
// PATCH /api/v1/drive/uploads/{id} — extend
// ---------------------------------------------------------------------------

/// Appends bytes — mirrors `Patch`. Each PATCH becomes one S3 multipart part; parts before
/// the final must be ≥ 5 MiB. The PATCH that brings `received_bytes == total_bytes` runs the
/// finaliser: complete-multipart, INSERT `drive_files`, bump `storage_used_bytes`, DELETE the row;
/// it returns `X-Kutup-File-Id`.
#[utoipa::path(
    patch,
    path = "/api/v1/drive/uploads/{id}",
    tag = "drive",
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
    responses(
        (status = 204, description = "Chunk appended; the final chunk also returns `X-Kutup-File-Id` (and `X-Kutup-Version-Id` for a version); it leaves an uploaded revision, to be committed"),
        (status = 409, description = "`Upload-Offset` mismatch, or the upload is complete and waits for its commit")
    )
)]
pub async fn patch(
    State(state): State<AppState>,
    user: AuthAccount,
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
    let user_id = match Uuid::parse_str(&user.account_id) {
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

    #[derive(sqlx::FromRow)]
    struct UploadRow {
        collection_id: Uuid,
        file_id: Uuid,
        total_bytes: i64,
        received_bytes: i64,
        /// None for a version.
        file_key_envelope: Option<String>,
        key_epoch: i32,
        storage_path: String,
        s3_upload_id: String,
        s3_part_etags: serde_json::Value,
        pending_bytes: Vec<u8>,
        name_hash: Option<String>,
        /// `file` or `version`; the rest are a version's.
        kind: String,
        key_generation: Option<i32>,
        content_hash: Option<String>,
        based_on: Option<String>,
        revision_id: Uuid,
        /// An uploaded revision, waiting for its commit.
        uploaded: bool,
    }
    let row: Option<UploadRow> = match sqlx::query_as(
        "SELECT collection_id, file_id, total_bytes, received_bytes, \
                kutup_b64(file_key_envelope) AS file_key_envelope, key_epoch, \
                storage_path, s3_upload_id, s3_part_etags, pending_bytes, \
                encode(name_hash, 'hex') AS name_hash, \
                kind, key_generation, encode(content_hash, 'hex') AS content_hash, based_on, revision_id, \
                uploaded_at IS NOT NULL AS uploaded \
         FROM drive_uploads WHERE id=$1 AND account_id=$2 FOR UPDATE",
    )
    .bind(upload_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, "upload: a database read failed");
            return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db read");
        }
    };
    let Some(UploadRow {
        collection_id: coll_id,
        file_id,
        total_bytes,
        received_bytes,
        file_key_envelope,
        key_epoch,
        storage_path,
        s3_upload_id,
        s3_part_etags: part_etags_json,
        pending_bytes: pending,
        name_hash,
        kind,
        key_generation: version_key_generation,
        content_hash: version_content_hash,
        based_on,
        revision_id,
        uploaded,
    }) = row
    else {
        return tus_text(StatusCode::NOT_FOUND, "");
    };
    // Every byte is here and checked: what is left is the commit
    // (`POST /api/v1/drive/files/{id}/revisions/{revisionId}/commit`).
    if uploaded {
        return (
            StatusCode::CONFLICT,
            [
                ("Tus-Resumable", TUS_VERSION.to_string()),
                ("Upload-Offset", received_bytes.to_string()),
            ],
            "upload complete: commit its revision",
        )
            .into_response();
    }
    let blob = BlockBlob { revision_id };

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
    // A new version's writer must still be allowed to write the file: one
    // whose access was taken away loses the upload (and the file's slot).
    if kind == "version" {
        match crate::drive_writes::can_write_file(&state.pool, user_id, file_id).await {
            Ok(true) => {}
            Ok(false) => {
                drop(tx);
                let _ = state
                    .storage
                    .abort_multipart(&storage_path, &s3_upload_id)
                    .await;
                let _ = sqlx::query("DELETE FROM drive_uploads WHERE id=$1")
                    .bind(upload_id)
                    .execute(&state.pool)
                    .await;
                return tus_text(StatusCode::FORBIDDEN, "forbidden");
            }
            Err(_) => return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db read"),
        }
    }
    if received_bytes + chunk_len > total_bytes {
        return tus_text(StatusCode::PAYLOAD_TOO_LARGE, "chunk exceeds Upload-Length");
    }
    if received_bytes == 0 {
        // A new file's key is generation 1; a version's, the file's key when it started.
        let generation = version_key_generation.map_or(1, |g| g.max(1) as u32);
        if let Err(error) = blob.check_head(&body, file_id, generation) {
            return tus_error(error);
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
        "UPDATE drive_uploads SET received_bytes=$1, s3_part_etags=$2, pending_bytes=$3, updated_at=NOW() WHERE id=$4",
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
    if kind == "version" {
        let Some(key_generation) = version_key_generation else {
            return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "corrupt version upload");
        };
        return super::tus_versions::finish(
            &state,
            tx,
            super::tus_versions::Landing {
                account_id: user_id,
                upload_id,
                file_id,
                collection_id: coll_id,
                total_bytes,
                metadata: None,
                storage_path,
                s3_upload_id,
                key_generation,
                content_hash: version_content_hash,
                based_on,
                revision_id,
                // It comes with the commit.
                revision_content_envelope: None,
            },
            &parts,
        )
        .await;
    }
    if file_key_envelope.is_none() {
        return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "corrupt upload");
    }
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
        let _ = sqlx::query("DELETE FROM drive_uploads WHERE id=$1")
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
            let _ = sqlx::query("DELETE FROM drive_uploads WHERE id=$1")
                .bind(upload_id)
                .execute(&state.pool)
                .await;
            return tus_error(error);
        }
    }

    // Complete the multipart (stitched in place at the canonical key), then
    // check the stored object's structure from its trailer. It lands as an
    // uploaded revision: stored, checked and reserved, but not a file until
    // its commit (docs/plans/drive-block-format.md §10 slice 3).
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
    if let Err(error) = check_stored_tail(&state, &storage_path, total_bytes).await {
        drop(tx);
        drop_landed(&state, &storage_path, upload_id).await;
        return tus_error(error);
    }
    mark_uploaded(
        &state,
        tx,
        upload_id,
        file_id,
        None,
        &storage_path,
        new_received,
    )
    .await
}

/// Checks a completed object's structure from its trailer, read with one
/// ranged GET (docs/plans/drive-block-format.md §3).
pub(super) async fn check_stored_tail(state: &AppState, path: &str, total: i64) -> AppResult<()> {
    let total = total as u64;
    let trailer = state
        .storage
        .get_object_range(path, total - TRAILER_LEN as u64, total - 1, total)
        .await
        .map_err(|_| AppError::internal("storage read trailer"))?
        .collect()
        .await
        .map_err(|_| AppError::internal("storage read trailer"))?
        .into_bytes();
    BlockBlob::check_tail(total, &trailer)
}

/// After the parts were stitched, storing the file failed: the upload cannot
/// go on, so its object and its row go (the row would otherwise hold the file
/// id and the reserved room until the sweep, which could not abort it).
/// Call it with the transaction dropped: it holds the row's lock.
async fn drop_landed(state: &AppState, storage_path: &str, upload_id: Uuid) {
    let _ = state.storage.delete(storage_path).await;
    let _ = sqlx::query("DELETE FROM drive_uploads WHERE id=$1")
        .bind(upload_id)
        .execute(&state.pool)
        .await;
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
    landing_check(
        tx,
        user_id,
        upload_id,
        coll_id,
        file_id,
        key_epoch,
        total_bytes,
    )
    .await
    .err()
    .map(tus_error)
}

/// What a new file's upload must still hold when it lands, and again when
/// an uploaded revision is committed: the uploader may still write into the
/// folder, the folder is live at the epoch the envelopes are bound to, the
/// id is still free, and the file still fits (a quota lowered meanwhile).
pub(super) async fn landing_check(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    upload_id: Uuid,
    coll_id: Uuid,
    file_id: Uuid,
    key_epoch: i32,
    total_bytes: i64,
) -> AppResult<()> {
    let folder: Option<(Uuid, i32, Option<bool>)> = sqlx::query_as(
        "SELECT c.owner_account_id, c.key_epoch,
                (SELECT cs.can_upload FROM drive_collection_shares cs
                 WHERE cs.collection_id = c.id AND cs.recipient_account_id = $2)
         FROM drive_collections c WHERE c.id = $1 AND c.deleted_at IS NULL FOR SHARE",
    )
    .bind(coll_id)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((owner, epoch, can_upload)) = folder else {
        return Err(AppError::conflict("folder no longer available"));
    };
    if owner != user_id && can_upload != Some(true) {
        return Err(AppError::forbidden("forbidden"));
    }
    if epoch != key_epoch {
        return Err(AppError::conflict("folder key changed during upload"));
    }
    if !crate::drive_writes::claim_file_id(tx, file_id, Some(upload_id)).await? {
        return Err(AppError::conflict("file id already in use"));
    }
    crate::drive_writes::check_room(tx, user_id, coll_id, total_bytes, Some(upload_id))
        .await?
        .into_result()
}

/// A new file's row, as an upload lands it.
pub(super) struct NewFile<'a> {
    pub file_id: Uuid,
    pub collection_id: Uuid,
    pub uploader: Uuid,
    pub metadata_envelope: &'a str,
    pub metadata_revision: i64,
    pub file_key_envelope: &'a str,
    pub key_epoch: i32,
    pub storage_path: &'a str,
    pub size: i64,
    pub name_hash: Option<&'a str>,
    pub content_hash: Option<&'a str>,
    pub revision_id: Uuid,
    /// The revision's sealed content record (it commits with the revision).
    pub revision_content_envelope: &'a str,
}

/// Inserts a landed new file (its key at generation 1).
pub(super) async fn insert_file(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    file: NewFile<'_>,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO drive_files \
            (id, collection_id, uploader_account_id, \
             metadata_envelope, file_key_envelope, key_epoch, key_generation, \
             metadata_revision, storage_path, encrypted_size_bytes, original_key_generation, \
             name_hash, content_hash, content_revision_id, \
             blob_suite, revision_content_envelope) \
         VALUES ($1,$2,$3,kutup_unb64($4),kutup_unb64($5),$6,1,$7,$8,$9,1,decode($10, 'hex'), \
                 decode($11, 'hex'),$12,$13,kutup_unb64($14))",
    )
    .bind(file.file_id)
    .bind(file.collection_id)
    .bind(file.uploader)
    .bind(file.metadata_envelope)
    .bind(file.file_key_envelope)
    .bind(file.key_epoch)
    .bind(file.metadata_revision)
    .bind(file.storage_path)
    .bind(file.size)
    .bind(file.name_hash)
    .bind(file.content_hash)
    .bind(file.revision_id)
    .bind(crate::drive_blob::BLOCK_SUITE)
    .bind(file.revision_content_envelope)
    .execute(&mut **tx)
    .await
    .map(|_| ())
}

/// A block-format upload's last part landed and its object checked: the row
/// stays as an uploaded revision (its reservation, the file id and, for a
/// version, the file's one upload slot held) until its commit or the sweep.
/// Answers the final PATCH's `204`, naming the file (and the version).
pub(super) async fn mark_uploaded(
    state: &AppState,
    mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
    upload_id: Uuid,
    file_id: Uuid,
    version_id: Option<Uuid>,
    storage_path: &str,
    total_bytes: i64,
) -> Response {
    let marked = sqlx::query(
        "UPDATE drive_uploads SET uploaded_at = NOW(), updated_at = NOW(),
                            pending_bytes = '\\x'::bytea, s3_part_etags = '[]'::jsonb
         WHERE id = $1",
    )
    .bind(upload_id)
    .execute(&mut *tx)
    .await;
    let committed = match marked {
        Ok(_) => tx.commit().await.is_ok(),
        Err(_) => {
            drop(tx);
            false
        }
    };
    if !committed {
        // A commit can fail in the reporting after it took effect: the
        // object of a revision marked uploaded stays.
        let landed: sqlx::Result<bool> = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM drive_uploads WHERE id = $1 AND uploaded_at IS NOT NULL)",
        )
        .bind(upload_id)
        .fetch_one(&state.pool)
        .await;
        match landed {
            Ok(true) => {}
            Ok(false) => {
                drop_landed(state, storage_path, upload_id).await;
                return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db commit");
            }
            Err(_) => {
                return tus_text(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "db commit (outcome unknown)",
                )
            }
        }
    }
    let mut response = (
        StatusCode::NO_CONTENT,
        [
            ("Tus-Resumable", TUS_VERSION.to_string()),
            ("Upload-Offset", total_bytes.to_string()),
            ("X-Kutup-File-Id", file_id.to_string()),
        ],
    )
        .into_response();
    if let Some(version) = version_id {
        if let Ok(value) = axum::http::HeaderValue::from_str(&version.to_string()) {
            response.headers_mut().insert("X-Kutup-Version-Id", value);
        }
    }
    response
}

// ---------------------------------------------------------------------------
// DELETE /api/v1/drive/uploads/{id} — cancel
// ---------------------------------------------------------------------------

/// Cancels an in-flight upload — mirrors `Delete`. Removes the DB row (freeing
/// reserved quota) and, once that is committed, aborts the S3 multipart (freeing
/// SeaweedFS staging) or deletes the object of an uploaded revision not yet
/// committed. Row-before-bytes: a commit takes the same row, so it either made
/// the revision current first (and this answers 404) or finds no row; the
/// object of a revision that can still be committed is never deleted. 404 if
/// not owned by the caller.
#[utoipa::path(
    delete,
    path = "/api/v1/drive/uploads/{id}",
    tag = "drive",
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
    user: AuthAccount,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Some(resp) = require_tus_resumable(&headers) {
        return resp;
    }
    let user_id = match Uuid::parse_str(&user.account_id) {
        Ok(u) => u,
        Err(_) => return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "invalid user id"),
    };
    let upload_id = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return tus_text(StatusCode::NOT_FOUND, ""),
    };

    // The uploader's own upload, or an upload of a new version of a file in
    // one of the caller's folders: an owner can free their file's one upload
    // slot from someone who left it open. Locked for the whole cancel: a last
    // part landing meanwhile holds the row, and once it lands the row is gone
    // and this answers 404 (the upload finished), never 204.
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db begin"),
    };
    let row: Option<(String, String, bool)> = match sqlx::query_as(
        "SELECT u.storage_path, u.s3_upload_id, u.uploaded_at IS NOT NULL FROM drive_uploads u
         WHERE u.id = $1 AND (u.account_id = $2 OR (u.kind = 'version' AND EXISTS (
             SELECT 1 FROM drive_files f JOIN drive_collections c ON c.id = f.collection_id
             WHERE f.id = u.file_id AND c.owner_account_id = $2)))
         FOR UPDATE OF u",
    )
    .bind(upload_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, "upload: a database read failed");
            return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db read");
        }
    };
    let Some((storage_path, s3_upload_id, uploaded)) = row else {
        return tus_text(StatusCode::NOT_FOUND, "");
    };

    let deleted = sqlx::query("DELETE FROM drive_uploads WHERE id=$1")
        .bind(upload_id)
        .execute(&mut *tx)
        .await;
    if deleted.is_err() || tx.commit().await.is_err() {
        return tus_text(StatusCode::INTERNAL_SERVER_ERROR, "db delete");
    }
    // The row is gone: nothing can commit these bytes. An uploaded revision
    // not committed yet loses its whole object, an open upload its parts. The
    // upload is cancelled either way; bytes that could not be removed are
    // logged (an object is found by the orphan sweep).
    if let Err(error) =
        crate::drive_blob::drop_upload_bytes(&state.storage, &storage_path, &s3_upload_id, uploaded)
            .await
    {
        tracing::warn!(%error, upload = %upload_id, path = %storage_path, "upload cancel: bytes left behind");
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
