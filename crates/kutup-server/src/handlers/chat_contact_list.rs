//! An account's Chat contacts (docs/plans/chat-contacts-sync.md): one sealed
//! entry per person the account accepted, rejected, blocked or asked, so a
//! device that lost everything restores them. Built as the group list
//! ([`super::chat_group_list`]): the server keeps the entries opaque, each
//! entry's id is a keyed hash of the contact's account under a key only the
//! account's master key derives, and the account head covers them all (the
//! `chatContacts` scope).
//!
//! Writes are compare-and-swap on the entry's revision: a write names the
//! revision it started from (0 for a new entry), and the new revision is the
//! one in the sealed entry's authenticated header, which must be above it.
//! `409 revision_conflict` with the current revision when another device
//! wrote first. Unlike the group list, it answers wherever Chat is, with or
//! without pairwise groups.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::account_heads::{self, NextHead};
use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::{revisions, AppState};

/// The most entries one account keeps, as the pin list. The client evicts
/// before it reaches it (the oldest rejections first, never a block).
pub const MAX_ENTRIES: i64 = 10_000;
/// Every sealed entry's size (`kutup_crypto::chat_contact_list`).
pub const ENVELOPE_BYTES: usize = kutup_crypto::chat_contact_list::SEALED_LEN;

/// One sealed entry.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ContactListEntry {
    /// The keyed hash of the contact's account (base64url, 43 characters).
    pub id: String,
    pub revision: i64,
    /// The sealed entry, canonical base64.
    pub envelope: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ContactList {
    pub entries: Vec<ContactListEntry>,
}

/// A new or changed entry, on top of `baseRevision`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContactListWrite {
    /// The revision the change started from; 0 for a new entry.
    pub base_revision: i64,
    /// The sealed entry (`ChatContactEntryV1`), canonical base64, exactly
    /// 2048 bytes; the revision in its authenticated header must be above
    /// `baseRevision`.
    pub envelope: String,
    /// The next sealed account head (base64), once the account keeps one.
    #[serde(default)]
    pub head: Option<String>,
}

/// An entry's removal, from the revision it was read at.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContactListDelete {
    pub base_revision: i64,
    #[serde(default)]
    pub head: Option<String>,
}

/// The route's id: an entry id (a keyed hash of the contact), canonical
/// base64url; anything else is no such entry.
fn entry_id(id: &str) -> AppResult<String> {
    kutup_crypto::chat_contact_list::decode_entry_id(id)
        .map(|_| id.to_owned())
        .map_err(|_| AppError::not_found("not found"))
}

/// A sealed entry and the revision its authenticated header carries; the
/// server reads nothing else of it.
fn envelope(value: &str) -> AppResult<(Vec<u8>, u64)> {
    let bytes = STANDARD
        .decode(value)
        .ok()
        .filter(|bytes| STANDARD.encode(bytes) == value)
        .ok_or_else(|| AppError::bad_request("envelope is not canonical base64"))?;
    let revision = kutup_crypto::chat_contact_list::inspect(&bytes)
        .map_err(|_| AppError::bad_request("not a sealed contact list entry"))?;
    Ok((bytes, revision))
}

async fn current_revision(state: &AppState, user_id: uuid::Uuid, id: &str) -> AppResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT revision FROM chat_contact_list WHERE user_id = $1 AND id = $2")
            .bind(user_id)
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .unwrap_or(0),
    )
}

/// `GET /api/chat/contact-list` — every entry the account keeps.
#[utoipa::path(
    get,
    path = "/api/chat/contact-list",
    tag = "chat",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "The account's entries", body = ContactList))
)]
pub async fn list(State(state): State<AppState>, user: AuthUser) -> AppResult<Json<ContactList>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let rows: Vec<(String, i64, Vec<u8>)> = sqlx::query_as(
        "SELECT id, revision, envelope FROM chat_contact_list WHERE user_id = $1 ORDER BY id",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(ContactList {
        entries: rows
            .into_iter()
            .map(|(id, revision, envelope)| ContactListEntry {
                id,
                revision,
                envelope: STANDARD.encode(envelope),
            })
            .collect(),
    }))
}

/// `PUT /api/chat/contact-list/{id}` — stores an entry if the stored one is
/// still `baseRevision` (none yet: 0).
#[utoipa::path(
    put,
    path = "/api/chat/contact-list/{id}",
    tag = "chat",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "The entry id (base64url, 43 characters)")),
    request_body = ContactListWrite,
    responses(
        (status = 200, description = "Stored", body = ContactListEntry),
        (status = 400, description = "Not a valid entry, or the list is full"),
        (status = 409, description = "revision_conflict, head_conflict or head_required"),
    )
)]
pub async fn put(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(input): Json<ContactListWrite>,
) -> AppResult<Json<ContactListEntry>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = entry_id(&id)?;
    let (sealed, revision) = envelope(&input.envelope)?;
    let revision = revisions::check_follows(revision, input.base_revision)?;
    let head = NextHead::parse(input.head.as_deref())?;
    let mut tx = state.pool.begin().await?;
    let locked = account_heads::lock(&mut tx, user_id, user.session.session_id).await?;
    let stored = if input.base_revision == 0 {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM chat_contact_list WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&mut *tx)
                .await?;
        if count >= MAX_ENTRIES {
            return Err(AppError::bad_request("the contact list is full"));
        }
        sqlx::query(
            "INSERT INTO chat_contact_list (user_id, id, revision, envelope)
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
            "UPDATE chat_contact_list SET revision = $3, envelope = $4, updated_at = now()
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
    Ok(Json(ContactListEntry {
        id,
        revision,
        envelope: input.envelope,
    }))
}

/// `DELETE /api/chat/contact-list/{id}` — removes an entry read at
/// `baseRevision` (one the client evicted).
#[utoipa::path(
    delete,
    path = "/api/chat/contact-list/{id}",
    tag = "chat",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "The entry id (base64url, 43 characters)")),
    request_body = ContactListDelete,
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
    Json(input): Json<ContactListDelete>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = entry_id(&id)?;
    let head = NextHead::parse(input.head.as_deref())?;
    let mut tx = state.pool.begin().await?;
    let locked = account_heads::lock(&mut tx, user_id, user.session.session_id).await?;
    let removed = sqlx::query(
        "DELETE FROM chat_contact_list WHERE user_id = $1 AND id = $2 AND revision = $3",
    )
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
    use kutup_crypto::account_ref::AccountRef;
    use kutup_crypto::chat_contact_list::{encode_entry_id, ContactListKey};

    #[test]
    fn ids_are_entry_ids_and_nothing_else() {
        let id = encode_entry_id(&[7u8; 32]);
        assert_eq!(entry_id(&id).unwrap(), id);
        assert!(entry_id(&format!("{id}=")).is_err());
        assert!(entry_id(&STANDARD.encode([0xfbu8; 32])).is_err());
        assert!(entry_id("short").is_err());
        // 32 zero bytes, with a spare bit set in the last character.
        assert!(entry_id(&format!("{}B", "A".repeat(42))).is_err());
    }

    #[test]
    fn an_envelope_is_a_sealed_entry_and_its_revision_comes_from_its_header() {
        let key = ContactListKey::derive(&[3u8; 32]);
        let id = key
            .entry_id(&AccountRef::new("b.test", "00000000-0000-4000-8000-0000000000b2").unwrap());
        let binding = "00000000-0000-4000-8000-000000000001";
        let sealed = key.seal(binding, &id, 7, b"{}").unwrap();
        assert_eq!(sealed.len(), ENVELOPE_BYTES);
        let (bytes, revision) = envelope(&STANDARD.encode(&sealed)).unwrap();
        assert_eq!((bytes, revision), (sealed.clone(), 7));
        // Any other size, or not one at all, is refused.
        assert!(envelope(&STANDARD.encode(&sealed[..sealed.len() - 1])).is_err());
        assert!(envelope(&STANDARD.encode([1u8; 10])).is_err());
        assert!(envelope("").is_err());
        assert!(envelope("AQ").is_err());
        // A group list entry isn't one.
        let groups = kutup_crypto::chat_group_list::GroupListKey::derive(&[3u8; 32]);
        let group_entry = groups
            .seal(binding, &groups.entry_id(&[5u8; 32]), 7, b"{}")
            .unwrap();
        assert!(envelope(&STANDARD.encode(group_entry)).is_err());
    }
}
