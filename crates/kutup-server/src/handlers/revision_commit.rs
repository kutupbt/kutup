//! The commit of an uploaded revision (docs/plans/drive-block-format.md §10
//! slice 3, "The commit, as Proton's"). A block-format upload lands as an
//! *uploaded revision*: stored, checked and counted in quota, but not
//! current, since the metadata commits to the manifest's digest, known only
//! after the last block. `POST /api/files/{id}/revisions/{revisionId}/commit`
//! brings the sealed metadata and, in one transaction, makes the revision
//! current: a new file appears in its folder, or a new version becomes the
//! file's content with the content it replaced kept in its history.
//!
//! Until then the revision is only its upload row (`uploads.uploaded_at`):
//! a new file has no `files` row, so no listing, search, share, trash or
//! count sees it. An upload never committed is swept with the abandoned
//! uploads, its object deleted and its reservation released.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use kutup_crypto::drive_envelope::DriveEnvelopeContextV1;
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

use super::files::validate_envelope;
use super::tus_versions::Landing;
use crate::drive_blob::{revision_conflict, BlobFormat};
use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommitRevisionRequest {
    /// The file's next metadata (`FileMetadataV2`, committing to this
    /// revision and its manifest's digest), sealed at `metadataRevision`.
    metadata_envelope: String,
    /// Exactly the file's current metadata revision + 1; 1 for a new file.
    metadata_revision: i64,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CommitRevisionResponse {
    file_id: String,
    /// Now the file's current content (a version's id, for a version).
    revision_id: String,
    metadata_revision: i64,
    /// `file`: a new file appeared; `version`: the file's content changed.
    kind: String,
}

/// An uploaded revision's row, locked for its commit.
#[derive(sqlx::FromRow)]
struct Uploaded {
    id: Uuid,
    user_id: Uuid,
    kind: String,
    collection_id: Uuid,
    total_bytes: i64,
    file_key_envelope: Option<String>,
    key_epoch: i32,
    storage_path: String,
    s3_upload_id: String,
    name_hash: Option<String>,
    key_generation: Option<i32>,
    content_hash: Option<String>,
    based_on: Option<String>,
    uploaded: bool,
}

/// `POST /api/files/{id}/revisions/{revisionId}/commit`
#[utoipa::path(
    post,
    path = "/api/files/{id}/revisions/{revisionId}/commit",
    tag = "files",
    operation_id = "commitFileRevision",
    security(("BearerAuth" = [])),
    params(
        ("id" = String, Path, description = "File id"),
        ("revisionId" = String, Path, description = "The uploaded revision (the block-format upload's `revisionId`)")
    ),
    request_body = CommitRevisionRequest,
    responses(
        (status = 200, description = "The revision is the file's current content", body = CommitRevisionResponse),
        (status = 400, description = "An envelope not sealed for this file, key generation and metadata revision"),
        (status = 403, description = "The caller may no longer write the file or into its folder"),
        (status = 404, description = "No uploaded revision of this file by the caller"),
        (status = 409, description = "`code: revision_conflict`: `metadataRevision` is not the current + 1 (1 for a new file). `code: alreadyCommitted`: the revision is already current or in the history. `code: notUploaded`: the upload is still in progress. `code: version_conflict`: the file no longer holds the version the upload was based on. `code: name_taken`, a key change or a folder gone: the commit cannot apply (cancel the upload)"),
        (status = 413, description = "The quota was lowered below what the revision needs")
    )
)]
pub async fn commit(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, revision)): Path<(String, String)>,
    Json(request): Json<CommitRevisionRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let file_id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let revision_id = Uuid::parse_str(&revision).map_err(|_| AppError::not_found("not found"))?;
    if request.metadata_envelope.is_empty() || request.metadata_revision < 1 {
        return Err(AppError::bad_request(
            "metadataEnvelope and a positive metadataRevision are required",
        ));
    }

    let mut tx = state.pool.begin().await?;
    // The upload row first: the lock order its last part takes (`tus::patch`).
    let row: Option<Uploaded> = sqlx::query_as(
        "SELECT id, user_id, kind, collection_id, total_bytes, file_key_envelope, key_epoch,
                storage_path, s3_upload_id, name_hash, key_generation, content_hash, based_on,
                uploaded_at IS NOT NULL AS uploaded
         FROM uploads WHERE file_id = $1 AND revision_id = $2 AND blob_suite = 2
         FOR UPDATE",
    )
    .bind(file_id)
    .bind(revision_id)
    .fetch_optional(&mut *tx)
    .await?;
    // Only its uploader commits it.
    let Some(row) = row.filter(|row| row.user_id == user_id) else {
        drop(tx);
        return Err(already_committed(&state, user_id, file_id, revision_id).await?);
    };
    if !row.uploaded {
        return Err(AppError::conflict("the upload is still in progress")
            .with_details(serde_json::json!({ "code": "notUploaded" })));
    }
    let metadata = (request.metadata_envelope, request.metadata_revision);
    let kind = row.kind.clone();
    match kind.as_str() {
        "file" => commit_file(&mut tx, user_id, file_id, revision_id, row, &metadata).await?,
        "version" => {
            let landing = Landing {
                user_id,
                upload_id: row.id,
                file_id,
                collection_id: row.collection_id,
                total_bytes: row.total_bytes,
                metadata: Some(metadata.clone()),
                storage_path: row.storage_path,
                s3_upload_id: row.s3_upload_id,
                key_generation: row
                    .key_generation
                    .ok_or_else(|| AppError::internal("corrupt version upload"))?,
                content_hash: row.content_hash,
                based_on: row.based_on,
                revision_id,
                format: BlobFormat::Blocks { revision_id },
            };
            let seq = super::tus_versions::commit(&state, &mut tx, &landing).await?;
            tx.commit().await?;
            super::tus_versions::announce(&state, file_id, revision_id, seq).await;
            return Ok(committed(file_id, revision_id, metadata.1, "version"));
        }
        _ => return Err(AppError::internal("corrupt upload")),
    }
    tx.commit().await?;
    Ok(committed(file_id, revision_id, metadata.1, "file"))
}

fn committed(file_id: Uuid, revision_id: Uuid, metadata_revision: i64, kind: &str) -> Response {
    Json(CommitRevisionResponse {
        file_id: file_id.to_string(),
        revision_id: revision_id.to_string(),
        metadata_revision,
        kind: kind.to_owned(),
    })
    .into_response()
}

/// No uploaded revision to commit: `409 alreadyCommitted` when the revision
/// is already the file's (and the caller may see the file), else `404`.
async fn already_committed(
    state: &AppState,
    user_id: Uuid,
    file_id: Uuid,
    revision_id: Uuid,
) -> AppResult<AppError> {
    let stored: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM files WHERE id = $1 AND content_revision_id = $2)
             OR EXISTS (SELECT 1 FROM file_versions WHERE id = $2 AND file_id = $1)",
    )
    .bind(file_id)
    .bind(revision_id)
    .fetch_one(&state.pool)
    .await?;
    if stored && crate::handlers::can_access_file(&state.pool, user_id, file_id).await? {
        return Ok(AppError::conflict("the revision is already committed")
            .with_details(serde_json::json!({ "code": "alreadyCommitted" })));
    }
    Ok(AppError::not_found("not found"))
}

/// A new file's first commit: what its upload had to hold when it landed
/// holds still, its name is still free, and its metadata is revision 1. The
/// file row goes in, its bytes are charged and the upload row goes.
async fn commit_file(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    file_id: Uuid,
    revision_id: Uuid,
    row: Uploaded,
    (metadata_envelope, metadata_revision): &(String, i64),
) -> AppResult<()> {
    let (Some(file_key_envelope), Some(name_hash)) = (&row.file_key_envelope, &row.name_hash)
    else {
        return Err(AppError::internal("corrupt upload"));
    };
    if *metadata_revision != 1 {
        return Err(revision_conflict());
    }
    // A new file's key is generation 1.
    validate_envelope(
        metadata_envelope,
        DriveEnvelopeContextV1::file_metadata(&file_id.to_string(), 1, 1)
            .map_err(|_| AppError::bad_request("invalid Drive envelope"))?,
    )?;
    super::tus::landing_check(
        tx,
        user_id,
        row.id,
        row.collection_id,
        file_id,
        row.key_epoch,
        row.total_bytes,
    )
    .await?;
    let place = crate::drive_names::Place::Folder(row.collection_id);
    crate::drive_names::lock_place(tx, place).await?;
    crate::drive_names::ensure_name_free(tx, place, name_hash, None).await?;
    super::tus::insert_file(
        tx,
        super::tus::NewFile {
            file_id,
            collection_id: row.collection_id,
            uploader: user_id,
            metadata_envelope,
            metadata_revision: 1,
            file_key_envelope,
            key_epoch: row.key_epoch,
            storage_path: &row.storage_path,
            size: row.total_bytes,
            name_hash: Some(name_hash),
            content_hash: None,
            revision_id,
        },
    )
    .await
    .map_err(crate::drive_names::map_unique_violation)?;
    crate::storage_pool::charge(
        &mut **tx,
        crate::storage_pool::Payer::Account(user_id),
        row.total_bytes,
    )
    .await?;
    sqlx::query("DELETE FROM uploads WHERE id = $1")
        .bind(row.id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
