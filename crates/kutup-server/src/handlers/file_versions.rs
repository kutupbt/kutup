//! File version handlers — mirrors `backend/handlers/file_versions.go`.
//!
//! Version history for collaborative docs: list, download a specific S3 version, patch
//! label/keep-forever, upload a snapshot blob (versioned PUT), and record a snapshot row
//! (quota tx + update-log truncation).

use aws_sdk_s3::primitives::ByteStream;
use axum::extract::{Multipart, Path, State};
use axum::http::{HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::io::Write;
use tempfile::NamedTempFile;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::{can_access_file, octet_stream_response, trusted_uuid};
use crate::middleware::AuthUser;
use crate::models::UploadResult;
use crate::AppState;

#[derive(Debug, Serialize)]
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
}

type VersionTuple = (
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
);

fn to_version_row(t: VersionTuple) -> VersionRow {
    let (id, s3v, path, seq, dk, author, size, label, keep, created) = t;
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
    }
}

const VERSION_SELECT: &str = r#"SELECT id, s3_version_id, storage_path, seq_at_snapshot,
       doc_key_id, author_user_id, size_bytes, label, keep_forever, created_at
FROM file_versions"#;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PatchVersionRequest {
    label: Option<String>,
    keep_forever: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RecordSnapshotRequest {
    s3_version_id: String,
    storage_path: String,
    seq_at_snapshot: i64,
    doc_key_id: i64,
    size_bytes: i64,
    label: String,
    keep_forever: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotBlobResponse {
    storage_path: String,
    s3_version_id: String,
}

/// `GET /api/files/{fileId}/versions` — mirrors `List`.
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

    let (body, size) = state
        .storage
        .get_object_version(&path, &s3_version)
        .await
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
pub async fn patch(
    State(state): State<AppState>,
    user: AuthUser,
    Path((file_id, vid)): Path<(String, String)>,
    Json(req): Json<PatchVersionRequest>,
) -> AppResult<Response> {
    let (user_id, fid) = ids(&user.user_id, &file_id)?;
    let vid = Uuid::parse_str(&vid).map_err(|_| AppError::not_found("not found"))?;
    if !can_access_file(&state.pool, user_id, fid).await {
        return Err(AppError::forbidden("forbidden"));
    }

    if let Some(label) = req.label {
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

/// `POST /api/files/{fileId}/snapshot-blob` — mirrors `UploadSnapshotBlob`.
pub async fn upload_snapshot_blob(
    State(state): State<AppState>,
    user: AuthUser,
    Path(file_id): Path<String>,
    mut multipart: Multipart,
) -> AppResult<Response> {
    let (user_id, fid) = ids(&user.user_id, &file_id)?;
    if !can_access_file(&state.pool, user_id, fid).await {
        return Err(AppError::forbidden("forbidden"));
    }

    let mut tmp: Option<(NamedTempFile, i64)> = None;
    loop {
        let field = multipart
            .next_field()
            .await
            .map_err(|_| AppError::bad_request("missing file"))?;
        let Some(mut field) = field else { break };
        if field.name() == Some("file") {
            let mut file = NamedTempFile::new().map_err(|_| AppError::internal("temp file"))?;
            let mut size: i64 = 0;
            while let Some(chunk) = field
                .chunk()
                .await
                .map_err(|_| AppError::bad_request("missing file"))?
            {
                file.write_all(&chunk)
                    .map_err(|_| AppError::internal("temp write"))?;
                size += chunk.len() as i64;
            }
            tmp = Some((file, size));
        }
    }
    let Some((tmp_file, size)) = tmp else {
        return Err(AppError::bad_request("missing file"));
    };

    let storage_path = format!("files/{fid}/snapshot");
    let body = ByteStream::from_path(tmp_file.path())
        .await
        .map_err(|_| AppError::internal("read upload"))?;
    let version_id = state
        .storage
        .put_object_versioned(&storage_path, body, size)
        .await
        .map_err(|_| AppError::internal("storage"))?;

    Ok(Json(SnapshotBlobResponse {
        storage_path,
        s3_version_id: version_id,
    })
    .into_response())
}

/// `POST /api/files/{fileId}/versions` — mirrors `Record`.
pub async fn record(
    State(state): State<AppState>,
    user: AuthUser,
    Path(file_id): Path<String>,
    Json(req): Json<RecordSnapshotRequest>,
) -> AppResult<Response> {
    let (user_id, fid) = ids(&user.user_id, &file_id)?;
    if !can_access_file(&state.pool, user_id, fid).await {
        return Err(AppError::forbidden("forbidden"));
    }
    if req.s3_version_id.is_empty() || req.storage_path.is_empty() {
        return Err(AppError::bad_request(
            "s3VersionId and storagePath are required",
        ));
    }
    if req.size_bytes < 0 {
        return Err(AppError::bad_request("sizeBytes must be non-negative"));
    }

    let mut tx = state.pool.begin().await?;
    let (quota, used): (i64, i64) = sqlx::query_as(
        "SELECT storage_quota_bytes, storage_used_bytes FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    if used + req.size_bytes > quota {
        return Err(AppError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "storage quota exceeded",
        ));
    }

    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO file_versions (file_id, s3_version_id, storage_path, seq_at_snapshot,
                                      doc_key_id, author_user_id, size_bytes, label, keep_forever)
           VALUES ($1,$2,$3,$4,$5,$6,$7, NULLIF($8, ''),$9) RETURNING id"#,
    )
    .bind(fid)
    .bind(&req.s3_version_id)
    .bind(&req.storage_path)
    .bind(req.seq_at_snapshot)
    .bind(req.doc_key_id)
    .bind(user_id)
    .bind(req.size_bytes)
    .bind(&req.label)
    .bind(req.keep_forever)
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query("UPDATE users SET storage_used_bytes = storage_used_bytes + $1 WHERE id = $2")
        .bind(req.size_bytes)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    // Truncate the update log in the same tx (best-effort; a failure only leaves replayable
    // log rows behind, so we log and continue rather than abort the snapshot).
    if let Err(e) = sqlx::query("DELETE FROM file_update_log WHERE file_id = $1 AND seq <= $2")
        .bind(fid)
        .bind(req.seq_at_snapshot)
        .execute(&mut *tx)
        .await
    {
        tracing::warn!(file = %fid, seq = req.seq_at_snapshot, "file_update_log truncate failed: {e}");
    }

    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(UploadResult { id: id.to_string() }),
    )
        .into_response())
}

/// Parses the trusted user id + the file-id path param (bad file id ⇒ 404).
fn ids(user_id: &str, file_id: &str) -> AppResult<(Uuid, Uuid)> {
    let uid = trusted_uuid(user_id)?;
    let fid = Uuid::parse_str(file_id).map_err(|_| AppError::not_found("not found"))?;
    Ok((uid, fid))
}
