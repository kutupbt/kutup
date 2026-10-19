//! An account's group list (docs/plans/pairwise-groups.md §5): one sealed
//! entry per pairwise group the account is in, so a new device of the account
//! finds its groups. The server keeps the entries opaque. Each entry's id is a
//! keyed hash of the group id under a key only the account's master key
//! derives, so two members' lists can't be matched, and membership stays
//! hidden. Each entry has its own revision, and the account head covers them
//! all (the `chatGroups` scope).
//!
//! Writes are compare-and-swap on the entry's revision: a write names the
//! revision it started from (0 for a new entry) and carries the next one,
//! which must be above it. `409 revision_conflict` with the current revision
//! when another device wrote first.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::account_heads::{self, NextHead};
use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::{revisions, AppState};

/// The most entries one account keeps.
pub const MAX_ENTRIES: i64 = 1024;
/// The largest sealed entry.
pub const MAX_ENVELOPE_BYTES: usize = 4 * 1024;
/// An entry id: 32 bytes, base64url without padding.
const ID_LEN: usize = 43;

/// One sealed entry.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GroupListEntry {
    /// The keyed hash of the group id (base64url, 43 characters).
    pub id: String,
    pub revision: i64,
    /// The sealed entry, canonical base64.
    pub envelope: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GroupList {
    pub entries: Vec<GroupListEntry>,
}

/// A new or changed entry, on top of `baseRevision`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupListWrite {
    /// The revision the change started from; 0 for a new entry.
    pub base_revision: i64,
    /// The new revision: above `baseRevision`.
    pub revision: u64,
    /// The sealed entry, canonical base64, at most 4 KiB.
    pub envelope: String,
    /// The next sealed account head (base64), once the account keeps one.
    #[serde(default)]
    pub head: Option<String>,
}

/// An entry's removal, from the revision it was read at.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupListDelete {
    pub base_revision: i64,
    #[serde(default)]
    pub head: Option<String>,
}

/// The list exists where pairwise groups do (`CHAT_GROUPS` and federation),
/// as the other group routes; elsewhere `404`.
fn enabled(state: &AppState) -> AppResult<()> {
    if state.config.chat_groups && state.federation.is_some() {
        Ok(())
    } else {
        Err(AppError::not_found("not found"))
    }
}

fn entry_id(id: &str) -> AppResult<String> {
    URL_SAFE_NO_PAD
        .decode(id)
        .ok()
        .filter(|bytes| id.len() == ID_LEN && bytes.len() == 32)
        .filter(|bytes| URL_SAFE_NO_PAD.encode(bytes) == id)
        .map(|_| id.to_owned())
        .ok_or_else(|| AppError::not_found("not found"))
}

fn envelope(value: &str) -> AppResult<Vec<u8>> {
    let bytes = STANDARD
        .decode(value)
        .ok()
        .filter(|bytes| STANDARD.encode(bytes) == value)
        .ok_or_else(|| AppError::bad_request("envelope is not canonical base64"))?;
    if bytes.is_empty() || bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(AppError::bad_request("an entry is 1 byte to 4 KiB sealed"));
    }
    Ok(bytes)
}

async fn current_revision(state: &AppState, user_id: uuid::Uuid, id: &str) -> AppResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT revision FROM chat_group_list WHERE user_id = $1 AND id = $2")
            .bind(user_id)
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .unwrap_or(0),
    )
}

/// `GET /api/chat/group-list` — every entry the account keeps.
#[utoipa::path(
    get,
    path = "/api/chat/group-list",
    tag = "chat",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "The account's entries", body = GroupList))
)]
pub async fn list(State(state): State<AppState>, user: AuthUser) -> AppResult<Json<GroupList>> {
    enabled(&state)?;
    let user_id = trusted_uuid(&user.user_id)?;
    let rows: Vec<(String, i64, Vec<u8>)> = sqlx::query_as(
        "SELECT id, revision, envelope FROM chat_group_list WHERE user_id = $1 ORDER BY id",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(GroupList {
        entries: rows
            .into_iter()
            .map(|(id, revision, envelope)| GroupListEntry {
                id,
                revision,
                envelope: STANDARD.encode(envelope),
            })
            .collect(),
    }))
}

/// `PUT /api/chat/group-list/{id}` — stores an entry if the stored one is
/// still `baseRevision` (none yet: 0).
#[utoipa::path(
    put,
    path = "/api/chat/group-list/{id}",
    tag = "chat",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "The entry id (base64url, 43 characters)")),
    request_body = GroupListWrite,
    responses(
        (status = 200, description = "Stored", body = GroupListEntry),
        (status = 400, description = "Not a valid entry, or the list is full"),
        (status = 409, description = "revision_conflict, head_conflict or head_required"),
    )
)]
pub async fn put(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(input): Json<GroupListWrite>,
) -> AppResult<Json<GroupListEntry>> {
    enabled(&state)?;
    let user_id = trusted_uuid(&user.user_id)?;
    let id = entry_id(&id)?;
    let sealed = envelope(&input.envelope)?;
    let revision = revisions::check_follows(input.revision, input.base_revision)?;
    let head = NextHead::parse(input.head.as_deref())?;
    let mut tx = state.pool.begin().await?;
    let locked = account_heads::lock(&mut tx, user_id, user.session.session_id).await?;
    let stored = if input.base_revision == 0 {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM chat_group_list WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&mut *tx)
                .await?;
        if count >= MAX_ENTRIES {
            return Err(AppError::bad_request("the group list is full"));
        }
        sqlx::query(
            "INSERT INTO chat_group_list (user_id, id, revision, envelope)
             VALUES ($1, $2, $3, $4) ON CONFLICT (user_id, id) DO NOTHING",
        )
        .bind(user_id)
        .bind(&id)
        .bind(revision)
        .bind(&sealed)
        .execute(&mut *tx)
        .await?
    } else {
        sqlx::query(
            "UPDATE chat_group_list SET revision = $3, envelope = $4, updated_at = now()
              WHERE user_id = $1 AND id = $2 AND revision = $5",
        )
        .bind(user_id)
        .bind(&id)
        .bind(revision)
        .bind(&sealed)
        .bind(input.base_revision)
        .execute(&mut *tx)
        .await?
    };
    if stored.rows_affected() != 1 {
        drop(tx);
        return Err(revisions::conflict(
            "this entry was changed elsewhere",
            current_revision(&state, user_id, &id).await?,
        ));
    }
    account_heads::advance(&mut tx, &locked, head.as_ref()).await?;
    tx.commit().await?;
    Ok(Json(GroupListEntry {
        id,
        revision,
        envelope: input.envelope,
    }))
}

/// `DELETE /api/chat/group-list/{id}` — removes an entry read at
/// `baseRevision` (an ended group whose chat its person deleted).
#[utoipa::path(
    delete,
    path = "/api/chat/group-list/{id}",
    tag = "chat",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "The entry id (base64url, 43 characters)")),
    request_body = GroupListDelete,
    responses(
        (status = 204, description = "Removed"),
        (status = 404, description = "No such entry"),
        (status = 409, description = "revision_conflict, head_conflict or head_required"),
    )
)]
pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(input): Json<GroupListDelete>,
) -> AppResult<StatusCode> {
    enabled(&state)?;
    let user_id = trusted_uuid(&user.user_id)?;
    let id = entry_id(&id)?;
    let head = NextHead::parse(input.head.as_deref())?;
    let mut tx = state.pool.begin().await?;
    let locked = account_heads::lock(&mut tx, user_id, user.session.session_id).await?;
    let removed =
        sqlx::query("DELETE FROM chat_group_list WHERE user_id = $1 AND id = $2 AND revision = $3")
            .bind(user_id)
            .bind(&id)
            .bind(input.base_revision)
            .execute(&mut *tx)
            .await?;
    if removed.rows_affected() != 1 {
        drop(tx);
        return match current_revision(&state, user_id, &id).await? {
            0 => Err(AppError::not_found("not found")),
            current => Err(revisions::conflict(
                "this entry was changed elsewhere",
                current,
            )),
        };
    }
    account_heads::advance(&mut tx, &locked, head.as_ref()).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_canonical_32_byte_base64url() {
        let id = URL_SAFE_NO_PAD.encode([7u8; 32]);
        assert_eq!(entry_id(&id).unwrap(), id);
        // Padded, standard alphabet, short, or not canonical: no such entry.
        assert!(entry_id(&format!("{id}=")).is_err());
        assert!(entry_id(&STANDARD.encode([0xfbu8; 32])).is_err());
        assert!(entry_id(&URL_SAFE_NO_PAD.encode([7u8; 31])).is_err());
        // 32 zero bytes, with a spare bit set in the last character.
        assert!(entry_id(&format!("{}B", "A".repeat(42))).is_err());
        assert!(entry_id(&"A".repeat(43)).is_ok());
    }

    #[test]
    fn envelopes_are_canonical_and_bounded() {
        assert_eq!(envelope(&STANDARD.encode([1u8; 10])).unwrap(), [1u8; 10]);
        assert!(envelope(&STANDARD.encode([1u8; MAX_ENVELOPE_BYTES])).is_ok());
        assert!(envelope(&STANDARD.encode(vec![1u8; MAX_ENVELOPE_BYTES + 1])).is_err());
        assert!(envelope("").is_err());
        assert!(envelope("AQ").is_err());
    }
}
