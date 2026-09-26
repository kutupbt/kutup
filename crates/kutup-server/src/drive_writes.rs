//! Rules every Drive writer shares: who may change a file, how much a user
//! may still store, and how a new file id is claimed. Kept in one place so
//! the upload, tus, version, asset, thumbnail and federation paths cannot
//! drift apart again.

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

/// Whether `user_id` may change the file's content or its derived objects
/// (versions, assets, thumbnails, collaborative edits): the folder owner, or
/// a recipient whose share lets them add files ("can edit"), or a recipient
/// of the file itself with "can edit". A read-only recipient may open and
/// download, nothing more.
pub async fn can_write_file(pool: &PgPool, user_id: Uuid, file_id: Uuid) -> bool {
    sqlx::query_scalar::<_, bool>(&format!(
        r#"SELECT c.owner_user_id = $2
                  OR EXISTS(SELECT 1 FROM collection_shares cs
                            WHERE cs.collection_id = c.id AND cs.recipient_user_id = $2
                              AND cs.can_upload)
                  OR EXISTS(SELECT 1 FROM file_shares fs
                            WHERE fs.file_id = f.id AND fs.recipient_user_id = $2
                              AND fs.can_edit AND {FILE_SHARE_CURRENT})
           FROM files f JOIN collections c ON c.id = f.collection_id
           WHERE f.id = $1 AND f.deleted_at IS NULL AND c.deleted_at IS NULL"#,
    ))
    .bind(file_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .unwrap_or(false)
}

/// A file share allows edits only while it opens the file's current key and
/// that key is wrapped at the folder's current epoch: otherwise what the
/// editor writes would be readable by someone removed from the folder, or
/// sealed under a key the owner has not handed on yet. The owner's app brings
/// such shares up to date (docs/plans/drive-file-sharing.md); meanwhile the
/// recipient can still read. Aliases: `fs`, `f`, `c`.
pub const FILE_SHARE_CURRENT: &str =
    "fs.key_generation = f.key_generation AND f.key_epoch = c.key_epoch";

/// Whether `user_id` edits the file through a share of the file itself, at
/// its current key (so may also rename it, as Google Drive lets editors).
pub async fn is_file_share_editor(pool: &PgPool, user_id: Uuid, file_id: Uuid) -> bool {
    sqlx::query_scalar::<_, bool>(&format!(
        r#"SELECT EXISTS(SELECT 1 FROM file_shares fs
                  JOIN files f ON f.id = fs.file_id
                  JOIN collections c ON c.id = f.collection_id
                  WHERE fs.file_id = $1 AND fs.recipient_user_id = $2 AND fs.can_edit
                    AND f.deleted_at IS NULL AND c.deleted_at IS NULL
                    AND {FILE_SHARE_CURRENT})"#,
    ))
    .bind(file_id)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or(false)
}

/// Locks the user's row, which serialises every Drive charge to them, and
/// returns how many more bytes they may store: quota − used − what their
/// open tus uploads have reserved. A tus upload reserves its whole declared
/// length until it is finalised (its received bytes are not charged yet
/// either). `except_upload` leaves out the upload being finalised.
pub async fn lock_headroom(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    except_upload: Option<Uuid>,
) -> sqlx::Result<i64> {
    let (quota, used): (i64, i64) = sqlx::query_as(
        "SELECT storage_quota_bytes, storage_used_bytes FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_one(&mut **tx)
    .await?;
    let reserved: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(total_bytes), 0)::bigint FROM uploads
         WHERE user_id = $1 AND id IS DISTINCT FROM $2",
    )
    .bind(user_id)
    .bind(except_upload)
    .fetch_one(&mut **tx)
    .await?;
    Ok(quota.saturating_sub(used).saturating_sub(reserved))
}

/// How many more bytes a share recipient may add to a folder under the
/// share's upload limit: everything they stored there counts against it —
/// files (stored or in flight, trashed included), and the versions, assets
/// and thumbnails they saved on its files. Call after [`lock_headroom`] for
/// the same user, whose row lock serialises this too.
pub async fn share_headroom(
    tx: &mut Transaction<'_, Postgres>,
    collection_id: Uuid,
    user_id: Uuid,
    limit: i64,
    except_upload: Option<Uuid>,
) -> sqlx::Result<i64> {
    let used: i64 = sqlx::query_scalar(
        "SELECT COALESCE((SELECT SUM(CASE WHEN original_pruned THEN 0 ELSE encrypted_size_bytes END)
                          FROM files WHERE collection_id = $1 AND uploader_user_id = $2), 0)::bigint
              + COALESCE((SELECT SUM(total_bytes) FROM uploads
                          WHERE collection_id = $1 AND user_id = $2 AND id IS DISTINCT FROM $3), 0)::bigint
              + COALESCE((SELECT SUM(v.size_bytes) FROM file_versions v JOIN files f ON f.id = v.file_id
                          WHERE f.collection_id = $1 AND v.author_user_id = $2), 0)::bigint
              + COALESCE((SELECT SUM(a.size_bytes) FROM file_assets a JOIN files f ON f.id = a.file_id
                          WHERE f.collection_id = $1 AND a.uploader_user_id = $2), 0)::bigint
              + COALESCE((SELECT SUM(t.size_bytes) FROM file_thumbnails t JOIN files f ON f.id = t.file_id
                          WHERE f.collection_id = $1 AND t.uploader_user_id = $2), 0)::bigint",
    )
    .bind(collection_id)
    .bind(user_id)
    .bind(except_upload)
    .fetch_one(&mut **tx)
    .await?;
    Ok(limit.saturating_sub(used))
}

/// Claims a client-chosen id for a new file until the transaction ends:
/// concurrent writers of the same id queue here, and an id already held by a
/// stored file or another open upload is refused (`false`). A writer that
/// wins may then store at the id's key without overwriting anyone's bytes,
/// and may delete that key again if its transaction fails.
pub async fn claim_file_id(
    tx: &mut Transaction<'_, Postgres>,
    file_id: Uuid,
    except_upload: Option<Uuid>,
) -> sqlx::Result<bool> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("new-file-id:{file_id}"))
        .execute(&mut **tx)
        .await?;
    let taken: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM files WHERE id = $1)
             OR EXISTS (SELECT 1 FROM uploads WHERE file_id = $1 AND id IS DISTINCT FROM $2)",
    )
    .bind(file_id)
    .bind(except_upload)
    .fetch_one(&mut **tx)
    .await?;
    Ok(!taken)
}

/// What stops a write, if anything.
#[derive(Debug, PartialEq, Eq)]
pub enum Room {
    Enough,
    /// The user's own storage quota.
    Quota,
    /// The upload limit on the share they are writing through.
    ShareLimit,
}

/// Whether `user_id` may store `add` more bytes in `collection_id`: within
/// their own quota and, when writing into someone else's folder, within the
/// share's upload limit. Locks the user's row until the transaction ends, so
/// the answer holds until the charge is committed. A negative `add` (a
/// replacement that shrinks) always fits.
pub async fn check_room(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    collection_id: Uuid,
    add: i64,
    except_upload: Option<Uuid>,
) -> sqlx::Result<Room> {
    let headroom = lock_headroom(tx, user_id, except_upload).await?;
    if add <= 0 {
        return Ok(Room::Enough);
    }
    if add > headroom {
        return Ok(Room::Quota);
    }
    let limit: Option<i64> = sqlx::query_scalar(
        "SELECT cs.upload_quota_bytes FROM collection_shares cs
         JOIN collections c ON c.id = cs.collection_id
         WHERE cs.collection_id = $1 AND cs.recipient_user_id = $2 AND c.owner_user_id <> $2",
    )
    .bind(collection_id)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?
    .flatten();
    if let Some(limit) = limit {
        if add > share_headroom(tx, collection_id, user_id, limit, except_upload).await? {
            return Ok(Room::ShareLimit);
        }
    }
    Ok(Room::Enough)
}

impl Room {
    /// The HTTP refusal for a write that does not fit.
    pub fn into_result(self) -> crate::error::AppResult<()> {
        use crate::error::AppError;
        use axum::http::StatusCode;
        match self {
            Room::Enough => Ok(()),
            Room::Quota => Err(AppError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "storage quota exceeded",
            )),
            Room::ShareLimit => Err(AppError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "share upload quota exceeded",
            )),
        }
    }
}

/// Holds the file at key generation `expected_generation` until the
/// transaction ends, and requires its key to be wrapped at its folder's
/// current epoch: new content is sealed only under keys no removed member
/// holds (docs/plans/drive-share-revocation.md, docs/plans/drive-move.md).
/// `409 file key changed` if a re-key moved the file on meanwhile; `409 file
/// needs a re-key` if the folder rotated since the file was last keyed. A
/// re-key, move or rotation waits for the transaction.
pub async fn lock_file_key(
    tx: &mut Transaction<'_, Postgres>,
    file_id: Uuid,
    expected_generation: i32,
) -> crate::error::AppResult<()> {
    let keys: Option<(i32, i32, i32)> = sqlx::query_as(
        "SELECT f.key_generation, f.key_epoch, c.key_epoch
         FROM files f JOIN collections c ON c.id = f.collection_id
         WHERE f.id = $1 AND f.deleted_at IS NULL FOR SHARE",
    )
    .bind(file_id)
    .fetch_optional(&mut **tx)
    .await?;
    match keys {
        Some((generation, _, _)) if generation != expected_generation => {
            Err(crate::error::AppError::conflict("file key changed"))
        }
        Some((_, wrapped_at, folder)) if wrapped_at != folder => {
            Err(crate::error::AppError::conflict("file needs a re-key"))
        }
        Some(_) => Ok(()),
        None => Err(crate::error::AppError::not_found("not found")),
    }
}
