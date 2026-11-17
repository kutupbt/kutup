//! Names unique in a folder (docs/plans/drive-unique-names.md). Clients
//! send each name's hash (an HMAC under the folder's hash key, see
//! `kutup_crypto::drive_names`); the server never reads a name, only keeps
//! the hashes apart. A folder's files and its subfolders share one set of
//! names, as on a disk or in a ZIP; top-level folders share one per owner.

use serde_json::json;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::error::{AppError, AppResult};

/// Where a name lives.
#[derive(Clone, Copy, Debug)]
pub enum Place {
    /// In a folder, among its files and subfolders.
    Folder(Uuid),
    /// At an owner's top level (folders with no parent).
    TopLevel(Uuid),
}

impl Place {
    pub fn of(parent: Option<Uuid>, owner: Uuid) -> Self {
        match parent {
            Some(folder) => Self::Folder(folder),
            None => Self::TopLevel(owner),
        }
    }

    fn lock_key(self) -> String {
        match self {
            Self::Folder(id) => format!("drive-names:folder:{id}"),
            Self::TopLevel(owner) => format!("drive-names:top:{owner}"),
        }
    }
}

/// A name hash as sent: 64 lowercase hex digits. Every write that names or
/// places an item sends one (docs/plans/drive-unique-names.md), as Proton
/// Drive requires its `Hash`: an editor who cannot reach the folder's key (a
/// file shared by itself) sends a random one, as Proton does for a share root.
pub fn require_name_hash(value: Option<&str>) -> AppResult<String> {
    match value {
        Some(hash) if is_hash(hash) => Ok(hash.to_owned()),
        Some(_) => Err(AppError::bad_request("invalid name hash")),
        None => Err(AppError::bad_request("nameHash is required")
            .with_details(serde_json::json!({ "code": "nameNeeded" }))),
    }
}

/// The Drive-root generation a name hash sent for `place` was made under
/// (docs/plans/identity-rotation.md §3). At the top level the hash key comes
/// from the owner's Drive root, so the client names the root's generation
/// (`nameHashGeneration`), which must be the owner's newest: `409
/// driveRootChanged` otherwise, and the client hashes the name again. In a
/// folder the key is the folder's, and there is none.
pub async fn hash_generation(
    tx: &mut Transaction<'_, Postgres>,
    place: Place,
    sent: Option<u32>,
) -> AppResult<Option<i32>> {
    match place {
        Place::Folder(_) => match sent {
            None => Ok(None),
            Some(_) => Err(AppError::bad_request(
                "nameHashGeneration is only for the top level",
            )),
        },
        Place::TopLevel(owner) => {
            let sent = sent.ok_or_else(|| {
                AppError::bad_request("a top-level name hash comes with its nameHashGeneration")
            })?;
            let newest = crate::account_roots::drive_generation(&mut **tx, owner).await?;
            if sent != newest.get() {
                return Err(AppError::conflict(
                    "the account's Drive root has changed: hash the name again",
                )
                .with_details(json!({ "code": "driveRootChanged" })));
            }
            i32::try_from(sent)
                .map(Some)
                .map_err(|_| AppError::bad_request("invalid nameHashGeneration"))
        }
    }
}

/// A content hash as sent, same form.
pub fn parse_content_hash(value: Option<&str>) -> AppResult<Option<String>> {
    match value {
        None => Ok(None),
        Some(hash) if is_hash(hash) => Ok(Some(hash.to_owned())),
        Some(_) => Err(AppError::bad_request("invalid content hash")),
    }
}

pub(crate) fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Holds `place` for the rest of the transaction, so two writes into it
/// cannot both find a name free.
pub async fn lock_place(tx: &mut Transaction<'_, Postgres>, place: Place) -> AppResult<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(place.lock_key())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Refuses `name_hash` in `place` when a file or folder other than `except`
/// holds it outside the trash: `409` with `code = name_taken` and what holds
/// it (kind, id, and a file's content hash, so the client can tell an
/// identical file from a different one). Call after `lock_place`.
pub async fn ensure_name_free(
    tx: &mut Transaction<'_, Postgres>,
    place: Place,
    name_hash: &str,
    except: Option<Uuid>,
) -> AppResult<()> {
    let except = except.unwrap_or(Uuid::nil());
    let holder: Option<(String, Uuid, Option<String>)> = match place {
        Place::Folder(folder) => {
            sqlx::query_as(
                "SELECT 'file', id, content_hash FROM drive_files
                  WHERE collection_id = $1 AND name_hash = $2 AND deleted_at IS NULL AND id <> $3
                 UNION ALL
                 SELECT 'folder', id, NULL FROM drive_collections
                  WHERE parent_collection_id = $1 AND name_hash = $2 AND deleted_at IS NULL AND id <> $3
                 LIMIT 1",
            )
            .bind(folder)
            .bind(name_hash)
            .bind(except)
            .fetch_optional(&mut **tx)
            .await?
        }
        Place::TopLevel(owner) => {
            sqlx::query_as(
                "SELECT 'folder', id, NULL FROM drive_collections
                  WHERE owner_account_id = $1 AND parent_collection_id IS NULL AND name_hash = $2
                    AND deleted_at IS NULL AND id <> $3 AND kind = 'folder'
                 LIMIT 1",
            )
            .bind(owner)
            .bind(name_hash)
            .bind(except)
            .fetch_optional(&mut **tx)
            .await?
        }
    };
    match holder {
        None => Ok(()),
        Some((kind, id, content_hash)) => Err(name_taken(&kind, id, content_hash.as_deref())),
    }
}

/// The 409 for a name already held.
pub fn name_taken(kind: &str, id: Uuid, content_hash: Option<&str>) -> AppError {
    AppError::conflict("an item with this name is already here").with_details(json!({
        "code": "name_taken",
        "holder": { "kind": kind, "id": id.to_string(), "contentHash": content_hash },
    }))
}

/// A unique-index violation that slipped past the check (another server
/// process without the lock, an older row): the same 409, without details.
pub fn map_unique_violation(error: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(db) = &error {
        if let Some(constraint) = db.constraint() {
            if constraint.ends_with("_unique_name")
                || constraint.ends_with("_unique_top_level_name")
            {
                return AppError::conflict("an item with this name is already here")
                    .with_details(json!({ "code": "name_taken" }));
            }
        }
    }
    error.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_64_lowercase_hex_digits() {
        let good = "a".repeat(64);
        assert_eq!(require_name_hash(Some(&good)).unwrap(), good.clone());
        // Required on every write, as Proton's Hash.
        assert!(require_name_hash(None).is_err());
        assert!(require_name_hash(Some(&"A".repeat(64))).is_err());
        assert!(require_name_hash(Some(&"a".repeat(63))).is_err());
        assert!(parse_content_hash(Some("zz")).is_err());
    }
}
