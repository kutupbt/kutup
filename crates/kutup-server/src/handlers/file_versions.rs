//! File version handlers — mirrors `backend/handlers/file_versions.go`.
//!
//! Version history (docs/plans/drive-versions-v2.md): list, download, patch
//! label/keep-forever, and create — one request that stores the sealed version as
//! its own object, charges its measured size, records the row and truncates the
//! collaboration update log, atomically.

use aws_sdk_s3::primitives::ByteStream;
use axum::extract::{Multipart, Path, State};
use axum::http::{HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use kutup_crypto::drive_object::DriveFileBlobContextV1;
use serde::{Deserialize, Serialize};
use std::io::Write;
use tempfile::NamedTempFile;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::files::validate_file_blob_file;
use crate::handlers::{can_access_file, octet_stream_response, trusted_uuid};
use crate::middleware::AuthUser;
use crate::AppState;

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VersionRow {
    id: String,
    s3_version_id: String,
    storage_path: String,
    seq_at_snapshot: i64,
    doc_key_id: i64,
    author_user_id: String,
    size_bytes: i64,
    label: Option<String>,
    keep_forever: bool,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    /// `file`: the whole file (office, whiteboard, restored); `yjs`: a note's state.
    kind: String,
    /// The key generation it was sealed at: open it with that generation's
    /// file key.
    key_generation: i32,
    /// Saved by someone on another server (`user@server`); the owner is
    /// `authorUserId` then.
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_author: Option<String>,
}

pub(crate) type VersionTuple = (
    Uuid,
    String,
    String,
    i64,
    i64,
    Uuid,
    i64,
    Option<String>,
    bool,
    OffsetDateTime,
    String,
    i32,
    Option<String>,
);

pub(crate) fn to_version_row(t: VersionTuple) -> VersionRow {
    let (
        id,
        s3v,
        path,
        seq,
        dk,
        author,
        size,
        label,
        keep,
        created,
        kind,
        key_generation,
        remote_author,
    ) = t;
    VersionRow {
        id: id.to_string(),
        s3_version_id: s3v,
        storage_path: path,
        seq_at_snapshot: seq,
        doc_key_id: dk,
        author_user_id: author.to_string(),
        size_bytes: size,
        label,
        keep_forever: keep,
        created_at: created,
        kind,
        key_generation,
        remote_author,
    }
}

pub(crate) const VERSION_SELECT: &str = r#"SELECT id, s3_version_id, storage_path, seq_at_snapshot,
       doc_key_id, author_user_id, size_bytes, label, keep_forever, created_at, kind, key_generation,
       remote_author
FROM file_versions"#;

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct PatchVersionRequest {
    label: Option<String>,
    keep_forever: Option<bool>,
}

/// `GET /api/files/{fileId}/versions` — mirrors `List`.
#[utoipa::path(
    get,
    path = "/api/files/{fileId}/versions",
    tag = "versions",
    operation_id = "listFileVersions",
    security(("BearerAuth" = [])),
    params(("fileId" = String, Path, description = "File id")),
    responses((status = 200, description = "Version history, newest first", body = Vec<VersionRow>))
)]
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Path(file_id): Path<String>,
) -> AppResult<Response> {
    let (user_id, fid) = ids(&user.user_id, &file_id)?;
    if !can_access_file(&state.pool, user_id, fid).await {
        return Err(AppError::forbidden("forbidden"));
    }
    let rows: Vec<VersionTuple> = sqlx::query_as(&format!(
        "{VERSION_SELECT} WHERE file_id = $1 ORDER BY created_at DESC"
    ))
    .bind(fid)
    .fetch_all(&state.pool)
    .await?;
    let out: Vec<VersionRow> = rows.into_iter().map(to_version_row).collect();
    Ok(Json(out).into_response())
}

/// `GET /api/files/{fileId}/versions/{vid}/download` — mirrors `Download`.
#[utoipa::path(
    get,
    path = "/api/files/{fileId}/versions/{vid}/download",
    tag = "versions",
    operation_id = "downloadFileVersion",
    security(("BearerAuth" = [])),
    params(
        ("fileId" = String, Path, description = "File id"),
        ("vid" = String, Path, description = "Version id")
    ),
    responses((status = 200, description = "The encrypted snapshot blob (octet-stream) + x-kutup-doc-key-id / x-kutup-seq / x-kutup-s3-version headers"))
)]
pub async fn download(
    State(state): State<AppState>,
    user: AuthUser,
    Path((file_id, vid)): Path<(String, String)>,
) -> AppResult<Response> {
    let (user_id, fid) = ids(&user.user_id, &file_id)?;
    let vid = Uuid::parse_str(&vid).map_err(|_| AppError::not_found("not found"))?;
    if !can_access_file(&state.pool, user_id, fid).await {
        return Err(AppError::forbidden("forbidden"));
    }

    let row: Option<(String, String, i64, i64)> = sqlx::query_as(
        "SELECT storage_path, s3_version_id, doc_key_id, seq_at_snapshot FROM file_versions WHERE id = $1 AND file_id = $2",
    )
    .bind(vid)
    .bind(fid)
    .fetch_optional(&state.pool)
    .await?;
    let Some((path, s3_version, doc_key_id, seq)) = row else {
        return Err(AppError::not_found("not found"));
    };

    // v2 versions are objects of their own; older ones S3 versions of one key.
    let (body, size) = if s3_version.is_empty() {
        state.storage.get_object(&path).await
    } else {
        state.storage.get_object_version(&path, &s3_version).await
    }
    .map_err(|_| AppError::internal("storage"))?;
    let extra = vec![
        (
            HeaderName::from_static("x-kutup-doc-key-id"),
            doc_key_id.to_string(),
        ),
        (HeaderName::from_static("x-kutup-seq"), seq.to_string()),
        (HeaderName::from_static("x-kutup-s3-version"), s3_version),
    ];
    Ok(octet_stream_response(body, size, &extra))
}

/// `PATCH /api/files/{fileId}/versions/{vid}` — mirrors `Patch`.
#[utoipa::path(
    patch,
    path = "/api/files/{fileId}/versions/{vid}",
    tag = "versions",
    operation_id = "patchFileVersion",
    security(("BearerAuth" = [])),
    params(
        ("fileId" = String, Path, description = "File id"),
        ("vid" = String, Path, description = "Version id")
    ),
    request_body = PatchVersionRequest,
    responses((status = 200, description = "The updated version", body = VersionRow))
)]
pub async fn patch(
    State(state): State<AppState>,
    user: AuthUser,
    Path((file_id, vid)): Path<(String, String)>,
    Json(req): Json<PatchVersionRequest>,
) -> AppResult<Response> {
    let (user_id, fid) = ids(&user.user_id, &file_id)?;
    let vid = Uuid::parse_str(&vid).map_err(|_| AppError::not_found("not found"))?;
    // Naming or pinning a version changes what retention keeps: an editor's call.
    if !crate::drive_writes::can_write_file(&state.pool, user_id, fid).await {
        return Err(AppError::forbidden("forbidden"));
    }
    let label = req.label.map(|l| l.trim().to_string());
    if label
        .as_ref()
        .is_some_and(|l| l.chars().count() > MAX_LABEL_CHARS)
    {
        return Err(AppError::bad_request("label is too long"));
    }

    if let Some(label) = label {
        sqlx::query(
            "UPDATE file_versions SET label = NULLIF($1, '') WHERE id = $2 AND file_id = $3",
        )
        .bind(label)
        .bind(vid)
        .bind(fid)
        .execute(&state.pool)
        .await?;
    }
    if let Some(keep) = req.keep_forever {
        sqlx::query("UPDATE file_versions SET keep_forever = $1 WHERE id = $2 AND file_id = $3")
            .bind(keep)
            .bind(vid)
            .bind(fid)
            .execute(&state.pool)
            .await?;
    }

    let row: Option<VersionTuple> =
        sqlx::query_as(&format!("{VERSION_SELECT} WHERE id = $1 AND file_id = $2"))
            .bind(vid)
            .bind(fid)
            .fetch_optional(&state.pool)
            .await?;
    let Some(t) = row else {
        return Err(AppError::not_found("not found"));
    };
    Ok(Json(to_version_row(t)).into_response())
}

/// The longest version name, in characters.
const MAX_LABEL_CHARS: usize = 200;

/// Where a version's object lives: its own key, never an S3 object version.
pub(crate) fn version_storage_path(file_id: Uuid, version_id: Uuid) -> String {
    format!("files/{file_id}/versions/{version_id}")
}

/// `POST /api/files/{fileId}/versions` — store a version (multipart).
#[utoipa::path(
    post,
    path = "/api/files/{fileId}/versions",
    tag = "versions",
    operation_id = "createFileVersion",
    security(("BearerAuth" = [])),
    params(("fileId" = String, Path, description = "File id")),
    request_body(
        content = Vec<u8>,
        content_type = "multipart/form-data",
        description = "`file` (the sealed Drive file blob), `kind` (`file` | `yjs`), `seqAtSnapshot`, `docKeyId`, optional `label`, `keepForever`"
    ),
    responses(
        (status = 201, description = "The stored version", body = VersionRow),
        (status = 413, description = "Storage quota exceeded")
    )
)]
pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Path(file_id): Path<String>,
    mut multipart: Multipart,
) -> AppResult<Response> {
    let (user_id, fid) = ids(&user.user_id, &file_id)?;
    if !crate::drive_writes::can_write_file(&state.pool, user_id, fid).await {
        return Err(AppError::forbidden("forbidden"));
    }

    let mut tmp: Option<(NamedTempFile, i64)> = None;
    let mut fields = std::collections::HashMap::<String, String>::new();
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::bad_request("invalid form"))?
    {
        let name = field.name().unwrap_or("").to_string();
        if name == "file" {
            let mut file = NamedTempFile::new().map_err(|_| AppError::internal("temp file"))?;
            let mut size: i64 = 0;
            while let Some(chunk) = field
                .chunk()
                .await
                .map_err(|_| AppError::bad_request("invalid form"))?
            {
                file.write_all(&chunk)
                    .map_err(|_| AppError::internal("temp write"))?;
                size += chunk.len() as i64;
            }
            tmp = Some((file, size));
        } else if !name.is_empty() {
            // Small scalar fields only.
            let mut value = Vec::new();
            while let Some(chunk) = field
                .chunk()
                .await
                .map_err(|_| AppError::bad_request("invalid form"))?
            {
                if value.len() + chunk.len() > 4096 || fields.len() >= 8 {
                    return Err(AppError::bad_request("form field too large"));
                }
                value.extend_from_slice(&chunk);
            }
            let value =
                String::from_utf8(value).map_err(|_| AppError::bad_request("invalid form"))?;
            fields.insert(name, value);
        }
    }
    let Some((tmp_file, size)) = tmp else {
        return Err(AppError::bad_request("missing file"));
    };
    let created = store_version(&state, fid, user_id, None, &fields, tmp_file, size).await?;
    Ok((StatusCode::CREATED, Json(created)).into_response())
}

/// Stores a version from its form fields and sealed blob: checked, charged to
/// `payer`, recorded, and the collaboration log trimmed up to its position.
/// `remote_author` names an editor on another server (the owner pays then).
pub(crate) async fn store_version(
    state: &AppState,
    fid: Uuid,
    payer: Uuid,
    remote_author: Option<&str>,
    fields: &std::collections::HashMap<String, String>,
    tmp_file: NamedTempFile,
    size: i64,
) -> AppResult<VersionRow> {
    let kind = match fields.get("kind").map(String::as_str) {
        Some("file") => "file",
        Some("yjs") => "yjs",
        _ => return Err(AppError::bad_request("kind must be file or yjs")),
    };
    let number = |name: &str| -> AppResult<i64> {
        fields
            .get(name)
            .map_or(Ok(0), |v| v.parse::<i64>())
            .map_err(|_| AppError::bad_request(format!("invalid {name}")))
    };
    let seq_at_snapshot = number("seqAtSnapshot")?;
    let doc_key_id = number("docKeyId")?;
    if seq_at_snapshot < 0 || doc_key_id < 0 {
        return Err(AppError::bad_request(
            "seqAtSnapshot and docKeyId must be non-negative",
        ));
    }
    let label = fields
        .get("label")
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty());
    if label
        .as_ref()
        .is_some_and(|l| l.chars().count() > MAX_LABEL_CHARS)
    {
        return Err(AppError::bad_request("label is too long"));
    }
    let keep_forever = fields.get("keepForever").is_some_and(|v| v == "true");

    // The same typed, file-bound blob as an upload; the server checks only its
    // public header.
    let (collection_id, key_generation): (Uuid, i32) = sqlx::query_as(
        "SELECT collection_id, key_generation FROM files WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(fid)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("not found"))?;
    let generation =
        u32::try_from(key_generation).map_err(|_| AppError::conflict("invalid key generation"))?;
    let blob_context = DriveFileBlobContextV1::new(&fid.to_string(), generation)
        .map_err(|_| AppError::bad_request("invalid Drive file blob"))?;
    validate_file_blob_file(&tmp_file, blob_context)?;

    let version_id = Uuid::new_v4();
    let storage_path = version_storage_path(fid, version_id);

    let mut tx = state.pool.begin().await?;
    // Sealed under the file key read above; a re-key since would put new
    // content under a key the folder has left.
    crate::drive_writes::lock_file_key(&mut tx, fid, key_generation).await?;
    // The measured size, never a client's claim.
    crate::drive_writes::check_room(&mut tx, payer, collection_id, size, None)
        .await?
        .into_result()?;
    // A version claims the collaboration log up to its position; never past
    // the log's head (a made-up position must not trim edits it lacks). Under
    // the relay's per-file lock, so no frame lands in between.
    let seq_at_snapshot = if seq_at_snapshot > 0 {
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(super::collab::log_lock_key(fid))
            .execute(&mut *tx)
            .await?;
        seq_at_snapshot.min(super::collab::log_head(&mut *tx, fid).await?)
    } else {
        0
    };
    let created: VersionTuple = sqlx::query_as(
        r#"INSERT INTO file_versions (id, file_id, s3_version_id, storage_path, seq_at_snapshot,
                                      doc_key_id, author_user_id, size_bytes, label, keep_forever, kind,
                                      key_generation, remote_author)
           VALUES ($1, $2, '', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
           RETURNING id, s3_version_id, storage_path, seq_at_snapshot, doc_key_id,
                     author_user_id, size_bytes, label, keep_forever, created_at, kind, key_generation,
                     remote_author"#,
    )
    .bind(version_id)
    .bind(fid)
    .bind(&storage_path)
    .bind(seq_at_snapshot)
    .bind(doc_key_id)
    .bind(payer)
    .bind(size)
    .bind(&label)
    .bind(keep_forever)
    .bind(kind)
    .bind(key_generation)
    .bind(remote_author)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("UPDATE users SET storage_used_bytes = storage_used_bytes + $1 WHERE id = $2")
        .bind(size)
        .bind(payer)
        .execute(&mut *tx)
        .await?;
    // A new version is an edit: the file (and so its folder) was modified now.
    // New content: the hash it was recognised by no longer holds; the client
    // records the new one (docs/plans/drive-unique-names.md).
    sqlx::query("UPDATE files SET updated_at = NOW(), content_hash = NULL WHERE id = $1")
        .bind(fid)
        .execute(&mut *tx)
        .await?;
    // Everything up to this point of the collaboration log is in the version.
    // Under the relay's own per-file lock, so no frame lands in between; never
    // past the log's head, and only for the document key the log is under (a
    // stale or made-up position must not wipe edits the version lacks).
    // The trimmed stretch is in this version; the floor keeps positions
    // counting from its end.
    //
    // Whole-file versions (office documents) record their position but trim
    // nothing: ONLYOFFICE's edits name objects created during the editing
    // session, so a tab joining a live session must load the version that
    // session started from and replay every edit since. The log is trimmed
    // when a new session starts (`collab::claim_base`).
    if seq_at_snapshot > 0 && kind == "yjs" {
        sqlx::query(
            "DELETE FROM file_update_log l USING files f
             WHERE l.file_id = $1 AND f.id = $1 AND f.current_doc_key_id = $3 AND l.seq <= $2",
        )
        .bind(fid)
        .bind(seq_at_snapshot)
        .bind(doc_key_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE files SET collab_log_floor = GREATEST(collab_log_floor, $2)
             WHERE id = $1 AND current_doc_key_id = $3",
        )
        .bind(fid)
        .bind(seq_at_snapshot)
        .bind(doc_key_id)
        .execute(&mut *tx)
        .await?;
    }

    // Stored with the transaction open: if the store fails nothing is
    // recorded; if the commit fails the object is removed again.
    let body = ByteStream::from_path(tmp_file.path())
        .await
        .map_err(|_| AppError::internal("read upload"))?;
    state
        .storage
        .upload(&storage_path, body, size)
        .await
        .map_err(|_| AppError::internal("storage"))?;
    if tx.commit().await.is_err() {
        let _ = state.storage.delete(&storage_path).await;
        return Err(AppError::internal("commit"));
    }
    Ok(to_version_row(created))
}

/// Parses the trusted user id + the file-id path param (bad file id ⇒ 404).
fn ids(user_id: &str, file_id: &str) -> AppResult<(Uuid, Uuid)> {
    let uid = trusted_uuid(user_id)?;
    let fid = Uuid::parse_str(file_id).map_err(|_| AppError::not_found("not found"))?;
    Ok((uid, fid))
}
