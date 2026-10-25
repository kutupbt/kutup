//! A tus upload that ends as a new version of an existing file
//! (docs/plans/drive-unique-names.md, "Replace"), as Proton Drive's revisions:
//! resumable at any size, checked when it starts (so a conflict fails before
//! the content is sent) and again when it lands, where the content, the new
//! metadata (size, SHA-256) and the content hash are stored in one
//! transaction. One open upload per file (`uploads.file_id` is unique), as
//! Proton allows one draft revision.

use std::collections::HashMap;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use kutup_crypto::drive_envelope::DriveEnvelopeContextV1;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::file_versions::{check_based_on, current_whole_version, parse_based_on};
use super::files::{canonical_uuid, validate_envelope};
use super::tus::{tus_error, TUS_VERSION};
use crate::drive_blob::BlobFormat;
use crate::error::{AppError, AppResult};
use crate::storage::CompletedPart;
use crate::AppState;

/// The `Upload-Metadata` keys of a version upload.
const KEYS: [&str; 6] = [
    "versionOf",
    "metadataEnvelope",
    "metadataRevision",
    "contentHash",
    "basedOn",
    "revisionId",
];

/// The file a version upload may still be written to, read under its row lock:
/// `(collection, key generation, metadata revision)`.
async fn lock_file(
    tx: &mut Transaction<'_, Postgres>,
    file_id: Uuid,
) -> AppResult<(Uuid, i32, i64)> {
    sqlx::query_as(
        "SELECT collection_id, key_generation, metadata_revision
         FROM files WHERE id = $1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(file_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| AppError::not_found("not found"))
}

fn revision_conflict() -> AppError {
    AppError::conflict("metadata revision must advance exactly once")
        .with_details(serde_json::json!({ "code": "revision_conflict" }))
}

/// What a version upload must hold both when it starts and when it lands:
/// the caller may write the file, the file holds what the upload was based
/// on, its key has not changed, the metadata is its next revision, and the
/// upload fits. Takes the file's row lock. Returns its collection.
#[allow(clippy::too_many_arguments)]
async fn check(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    file_id: Uuid,
    key_generation: Option<i32>,
    metadata_envelope: &str,
    metadata_revision: i64,
    based_on: Option<&str>,
    total_bytes: i64,
    except_upload: Option<Uuid>,
) -> AppResult<(Uuid, i32)> {
    if !crate::drive_writes::can_write_file(&state.pool, user_id, file_id).await? {
        return Err(AppError::forbidden("forbidden"));
    }
    let (collection_id, generation, revision) = lock_file(tx, file_id).await?;
    check_based_on(
        parse_based_on(based_on)?,
        current_whole_version(tx, file_id).await?,
    )?;
    // Sealed under the key it started with: a re-key since refuses it.
    crate::drive_writes::lock_file_key(tx, file_id, key_generation.unwrap_or(generation)).await?;
    if revision.checked_add(1) != Some(metadata_revision) {
        return Err(revision_conflict());
    }
    validate_envelope(
        metadata_envelope,
        DriveEnvelopeContextV1::file_metadata(
            &file_id.to_string(),
            u32::try_from(generation).map_err(|_| AppError::conflict("invalid key generation"))?,
            u64::try_from(metadata_revision)
                .map_err(|_| AppError::bad_request("invalid metadata revision"))?,
        )
        .map_err(|_| AppError::bad_request("invalid Drive envelope"))?,
    )?;
    crate::drive_writes::check_room(tx, user_id, collection_id, total_bytes, except_upload)
        .await?
        .into_result()?;
    Ok((collection_id, generation))
}

/// `POST /api/uploads` with `versionOf`: opens a version upload. `201` as a
/// new file's; `409` with code `versionUploading` while another upload of a
/// new version of this file is open, with `idleSeconds` since its last part
/// (one idle a while was left by a crash, one active is still running), and
/// its `uploadId` when the caller uploads it (`yours: true`: go on with it or
/// cancel it) or owns the folder (`yours: false`: may cancel it).
pub(super) async fn create(
    state: &AppState,
    user_id: Uuid,
    total_bytes: i64,
    format: BlobFormat,
    meta: &HashMap<String, String>,
) -> Response {
    match open(state, user_id, total_bytes, format, meta).await {
        Ok(response) => response,
        Err(error) => tus_error(error),
    }
}

async fn open(
    state: &AppState,
    user_id: Uuid,
    total_bytes: i64,
    format: BlobFormat,
    meta: &HashMap<String, String>,
) -> AppResult<Response> {
    if meta.keys().any(|key| !KEYS.contains(&key.as_str())) {
        return Err(AppError::bad_request(
            "a version's Upload-Metadata holds only versionOf, metadataEnvelope, \
             metadataRevision, contentHash, basedOn and revisionId",
        ));
    }
    // The version limit is a site setting.
    if total_bytes
        > crate::site_settings::DRIVE_VERSION_MAX_BYTES
            .load(&state.pool)
            .await?
    {
        return Err(AppError::payload_too_large(
            "larger than this server's version limit",
        ));
    }
    let file_id = meta
        .get("versionOf")
        .and_then(|id| canonical_uuid(id).ok())
        .ok_or_else(|| AppError::bad_request("invalid versionOf"))?;
    let metadata_envelope = meta
        .get("metadataEnvelope")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::bad_request("metadataEnvelope is required"))?;
    let metadata_revision: i64 = meta
        .get("metadataRevision")
        .and_then(|value| value.parse().ok())
        .filter(|revision| *revision > 1)
        .ok_or_else(|| AppError::bad_request("metadataRevision must be greater than 1"))?;
    let content_hash = meta.get("contentHash");
    if content_hash.is_some_and(|hash| !crate::drive_names::is_hash(hash)) {
        return Err(AppError::bad_request("invalid content hash"));
    }
    let based_on = meta.get("basedOn").map(String::as_str);

    let mut tx = state.pool.begin().await?;
    let (collection_id, key_generation) = check(
        state,
        &mut tx,
        user_id,
        file_id,
        None,
        metadata_envelope,
        metadata_revision,
        based_on,
        total_bytes,
        None,
    )
    .await?;
    let open: Option<(Uuid, Uuid, i64)> = sqlx::query_as(
        "SELECT id, user_id, EXTRACT(EPOCH FROM NOW() - updated_at)::bigint
         FROM uploads WHERE file_id = $1",
    )
    .bind(file_id)
    .fetch_optional(&mut *tx)
    .await?;
    let owns_folder: bool =
        sqlx::query_scalar("SELECT owner_user_id = $2 FROM collections WHERE id = $1")
            .bind(collection_id)
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
    if let Some((upload_id, uploader, idle_seconds)) = open {
        // How long since its last part tells a crashed upload (cancel it)
        // from one still running on another device (wait for it).
        let mut details =
            serde_json::json!({ "code": "versionUploading", "idleSeconds": idle_seconds.max(0) });
        // Its uploader may go on with it or cancel it; the folder's owner may
        // cancel it (tus DELETE), so nobody can hold their file's slot.
        if uploader == user_id || owns_folder {
            details["uploadId"] = upload_id.to_string().into();
            details["yours"] = (uploader == user_id).into();
        }
        return Err(
            AppError::conflict("a new version of this file is being uploaded")
                .with_details(details),
        );
    }
    let key_epoch: i32 = sqlx::query_scalar("SELECT key_epoch FROM files WHERE id = $1")
        .bind(file_id)
        .fetch_one(&mut *tx)
        .await?;

    // The revision is the version's id: the client's for the block format.
    let revision = format.revision_id();
    crate::drive_blob::ensure_revision_free(&mut tx, revision, None).await?;
    let upload_id = Uuid::new_v4();
    let storage_path = crate::file_content::revision_path(file_id, revision);
    let s3_upload_id = state
        .storage
        .create_multipart(&storage_path)
        .await
        .map_err(|_| AppError::internal("storage create multipart"))?;
    let inserted = sqlx::query(
        "INSERT INTO uploads
            (id, user_id, collection_id, file_id, total_bytes, metadata_envelope,
             key_epoch, metadata_revision, storage_path, s3_upload_id,
             kind, key_generation, content_hash, based_on, revision_id, blob_suite)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'version',$11,$12,$13,$14,$15)",
    )
    .bind(upload_id)
    .bind(user_id)
    .bind(collection_id)
    .bind(file_id)
    .bind(total_bytes)
    .bind(metadata_envelope)
    .bind(key_epoch)
    .bind(metadata_revision)
    .bind(&storage_path)
    .bind(&s3_upload_id)
    .bind(key_generation)
    .bind(content_hash)
    .bind(based_on)
    .bind(revision)
    .bind(format.suite())
    .execute(&mut *tx)
    .await;
    let committed = match inserted {
        Ok(_) => tx.commit().await.map_err(AppError::from),
        Err(error) => Err(error.into()),
    };
    if let Err(error) = committed {
        let _ = state
            .storage
            .abort_multipart(&storage_path, &s3_upload_id)
            .await;
        return Err(error);
    }
    Ok((
        StatusCode::CREATED,
        [
            ("Tus-Resumable", TUS_VERSION.to_string()),
            ("Location", format!("/api/uploads/{upload_id}")),
            ("Upload-Offset", "0".to_string()),
            ("Content-Type", "application/json".to_string()),
        ],
        format!("{{\"fileId\":\"{file_id}\",\"versionId\":\"{revision}\"}}"),
    )
        .into_response())
}

/// A version upload's last part arrived: its row as `patch` read it.
pub(super) struct Landing {
    pub user_id: Uuid,
    pub upload_id: Uuid,
    pub file_id: Uuid,
    /// The folder the file was in when the upload started (its content hash
    /// is keyed for that folder).
    pub collection_id: Uuid,
    pub total_bytes: i64,
    pub metadata_envelope: String,
    pub metadata_revision: i64,
    pub storage_path: String,
    pub s3_upload_id: String,
    pub key_generation: i32,
    pub content_hash: Option<String>,
    pub based_on: Option<String>,
    /// The version's id.
    pub revision_id: Uuid,
    pub format: BlobFormat,
}

/// Stores the version, its metadata and content hash, in the transaction
/// `patch` opened (the upload row locked). A refusal discards the upload at
/// once, so a losing writer leaves nothing behind.
pub(super) async fn finish(
    state: &AppState,
    mut tx: Transaction<'_, Postgres>,
    landing: Landing,
    parts: &[CompletedPart],
) -> Response {
    // One lock order with the collaboration relay (`collab::trim_log`): the
    // file's log lock first, then its row (taken in `check`).
    if sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(super::collab::log_lock_key(landing.file_id))
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return tus_error(AppError::internal("db lock"));
    }
    let checked = check(
        state,
        &mut tx,
        landing.user_id,
        landing.file_id,
        Some(landing.key_generation),
        &landing.metadata_envelope,
        landing.metadata_revision,
        landing.based_on.as_deref(),
        landing.total_bytes,
        Some(landing.upload_id),
    )
    .await;
    let collection_now = match checked {
        Ok((collection, _)) => collection,
        // A refusal (no longer allowed, gone, changed meanwhile, too large)
        // discards the upload at once; anything else (the database failing)
        // keeps it, so the last part can be sent again.
        Err(error) if refuses(&error) => {
            drop(tx);
            discard(state, &landing).await;
            return tus_error(error);
        }
        Err(error) => return tus_error(error),
    };
    if let Err(error) = state
        .storage
        .complete_multipart(&landing.storage_path, &landing.s3_upload_id, parts)
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("Tus-Resumable", TUS_VERSION)],
            format!("storage complete multipart: {error}"),
        )
            .into_response();
    }
    // The block format's structure, from the stored object's trailer.
    if let Err(error) = super::tus::check_stored_tail(
        state,
        &landing.storage_path,
        landing.total_bytes,
        landing.format,
    )
    .await
    {
        drop(tx);
        let _ = state.storage.delete(&landing.storage_path).await;
        let _ = sqlx::query("DELETE FROM uploads WHERE id = $1")
            .bind(landing.upload_id)
            .execute(&state.pool)
            .await;
        return tus_error(error);
    }
    // Moved meanwhile: the content hash was keyed for the folder it left.
    let content_hash = landing
        .content_hash
        .clone()
        .filter(|_| collection_now == landing.collection_id);
    let stored = match record(&mut tx, &landing, content_hash.as_deref()).await {
        Ok(seq) => match tx.commit().await {
            Ok(()) => Ok(seq),
            // A commit can fail in the reporting after it took effect: look
            // before deleting the object of a version that landed.
            Err(error) => match landed_version(state, landing.revision_id).await {
                Ok(Some(seq)) => Ok(seq),
                Ok(None) => Err(AppError::from(error)),
                // Not known whether it landed: keep everything (the object
                // and, if it did not land, the row for the sweep) and say so.
                Err(_) => return tus_error(AppError::internal("db commit (outcome unknown)")),
            },
        },
        Err(error) => {
            // Released before the row is deleted below: it holds the row's lock.
            drop(tx);
            Err(error)
        }
    };
    match stored {
        Ok(seq) => {
            // Editors on other servers hold the old base: they reconnect.
            state.collab_federation.close_file(state, landing.file_id);
            // Tabs editing the file here reopen from the new content.
            super::collab::replace_base(
                state,
                landing.file_id,
                &landing.revision_id.to_string(),
                seq,
            )
            .await;
            (
                StatusCode::NO_CONTENT,
                [
                    ("Tus-Resumable", TUS_VERSION.to_string()),
                    ("Upload-Offset", landing.total_bytes.to_string()),
                    ("X-Kutup-File-Id", landing.file_id.to_string()),
                    ("X-Kutup-Version-Id", landing.revision_id.to_string()),
                ],
            )
                .into_response()
        }
        _ => {
            // The parts are already stitched: the upload cannot go on. Its
            // object and row go, so the file's one upload slot frees.
            let _ = state.storage.delete(&landing.storage_path).await;
            let _ = sqlx::query("DELETE FROM uploads WHERE id = $1")
                .bind(landing.upload_id)
                .execute(&state.pool)
                .await;
            tus_error(AppError::internal("db store version"))
        }
    }
}

/// The version's recorded log position, if it was stored after all.
async fn landed_version(state: &AppState, version_id: Uuid) -> sqlx::Result<Option<i64>> {
    sqlx::query_scalar("SELECT seq_at_snapshot FROM file_versions WHERE id = $1")
        .bind(version_id)
        .fetch_optional(&state.pool)
        .await
}

/// Whether a check's error refuses the upload for good (rather than failing
/// to look).
fn refuses(error: &AppError) -> bool {
    matches!(
        error.status,
        StatusCode::FORBIDDEN
            | StatusCode::NOT_FOUND
            | StatusCode::CONFLICT
            | StatusCode::PAYLOAD_TOO_LARGE
            | StatusCode::BAD_REQUEST
    )
}

/// Drops a version upload: its stored parts and its row.
pub(super) async fn discard(state: &AppState, landing: &Landing) {
    let _ = state
        .storage
        .abort_multipart(&landing.storage_path, &landing.s3_upload_id)
        .await;
    let _ = sqlx::query("DELETE FROM uploads WHERE id = $1")
        .bind(landing.upload_id)
        .execute(&state.pool)
        .await;
}

/// Stores the version and returns its position in the collaboration log.
async fn record(
    tx: &mut Transaction<'_, Postgres>,
    landing: &Landing,
    content_hash: Option<&str>,
) -> AppResult<i64> {
    let parent = current_whole_version(tx, landing.file_id).await?;
    // The new content replaces everything edited so far: it stands at the
    // log's head, so whoever opens it next replays nothing older (as a
    // restore from the editor does). Under the relay's per-file lock (taken
    // in `finish`), so no edit lands in between.
    let seq = super::collab::log_head(&mut **tx, landing.file_id).await?;
    let doc_key_id: i64 = sqlx::query_scalar("SELECT current_doc_key_id FROM files WHERE id = $1")
        .bind(landing.file_id)
        .fetch_one(&mut **tx)
        .await?;
    // Stamped when stored, as a multipart save (`file_versions::store_version`).
    sqlx::query(
        r#"INSERT INTO file_versions (id, file_id, storage_path, seq_at_snapshot, doc_key_id,
                                      author_user_id, size_bytes, keep_forever, kind,
                                      key_generation, parent_version_id, created_at)
           VALUES ($1, $2, $3, $8, $9, $4, $5, false, 'file', $6, $7, clock_timestamp())"#,
    )
    .bind(landing.revision_id)
    .bind(landing.file_id)
    .bind(&landing.storage_path)
    .bind(landing.user_id)
    .bind(landing.total_bytes)
    .bind(landing.key_generation)
    .bind(parent)
    .bind(seq)
    .bind(doc_key_id)
    .execute(&mut **tx)
    .await?;
    sqlx::query("UPDATE users SET storage_used_bytes = storage_used_bytes + $1 WHERE id = $2")
        .bind(landing.total_bytes)
        .bind(landing.user_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "UPDATE files SET metadata_envelope = $2, metadata_revision = $3, content_hash = $4,
                          updated_at = NOW()
         WHERE id = $1",
    )
    .bind(landing.file_id)
    .bind(&landing.metadata_envelope)
    .bind(landing.metadata_revision)
    .bind(content_hash)
    .execute(&mut **tx)
    .await?;
    sqlx::query("DELETE FROM uploads WHERE id = $1")
        .bind(landing.upload_id)
        .execute(&mut **tx)
        .await?;
    Ok(seq)
}
