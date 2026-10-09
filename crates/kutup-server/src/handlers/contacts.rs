//! Contacts (docs/plans/contacts.md): one encrypted address book per account,
//! Proton's model. Clients send a summary (canonical JSON, readable: uid,
//! name, emails, groups, pinned keys) signed by the account authority, and a
//! card (the full vCard) sealed under a key only the account holds. The
//! server verifies the summary, indexes its emails for autocomplete and its
//! groups for filtering, and charges both to the storage pool.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::contact_card::{self, ContactSummaryV1};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

/// Contacts one import may carry, all or nothing.
const MAX_IMPORT: usize = 500;
/// Contacts a page may carry.
const MAX_PAGE: i64 = 1000;
/// Contacts one account may keep.
const MAX_CONTACTS: i64 = 50_000;
const MAX_GROUPS: i64 = 200;

/// A contact as stored: verify `summary` with `signature` against your own
/// account authority before trusting it; open `card` with the contacts key.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ContactRow {
    pub id: String,
    /// Canonical summary JSON, exactly as signed.
    pub summary: String,
    pub signature: String,
    /// The sealed vCard, base64.
    pub card: String,
    pub revision: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: time::OffsetDateTime,
}

type Row = (
    Uuid,
    String,
    Vec<u8>,
    Vec<u8>,
    i64,
    time::OffsetDateTime,
    time::OffsetDateTime,
);

fn to_row((id, summary, signature, card, revision, created_at, updated_at): Row) -> ContactRow {
    ContactRow {
        id: id.to_string(),
        summary,
        signature: STANDARD.encode(signature),
        card: STANDARD.encode(card),
        revision,
        created_at,
        updated_at,
    }
}

const ROW_SELECT: &str =
    "SELECT id, summary, signature, card, revision, created_at, updated_at FROM contacts";

/// A contact to write.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContactInput {
    pub summary: String,
    pub signature: String,
    pub card: String,
}

/// What the server checked about an incoming contact.
struct Checked {
    summary: ContactSummaryV1,
    summary_text: String,
    signature: Vec<u8>,
    card: Vec<u8>,
}

impl Checked {
    fn charge(&self) -> i64 {
        (self.summary_text.len() + self.card.len()) as i64
    }
}

/// The caller's account (`username@server`) and authority key.
async fn account_of(state: &AppState, user_id: Uuid) -> AppResult<(String, [u8; 32])> {
    let (username, authority): (Option<String>, String) =
        sqlx::query_as("SELECT username, account_authority_public_key FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&state.pool)
            .await?;
    let username = username
        .ok_or_else(|| AppError::bad_request("choose a username before adding contacts"))?;
    let authority = STANDARD
        .decode(&authority)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| AppError::internal("account authority key is invalid"))?;
    Ok((
        format!("{username}@{}", state.config.chat_server_name),
        authority,
    ))
}

fn check(input: &ContactInput, account: &str, authority: &[u8; 32]) -> AppResult<Checked> {
    let signature = STANDARD
        .decode(&input.signature)
        .map_err(|_| AppError::bad_request("signature must be base64"))?;
    let card = STANDARD
        .decode(&input.card)
        .map_err(|_| AppError::bad_request("card must be base64"))?;
    let summary =
        contact_card::verify_summary(input.summary.as_bytes(), &signature, account, authority)
            .map_err(|error| AppError::bad_request(format!("summary: {error}")))?;
    contact_card::inspect_card(&card).map_err(|error| AppError::bad_request(error.to_string()))?;
    Ok(Checked {
        summary,
        summary_text: input.summary.clone(),
        signature,
        card,
    })
}

/// Writes the email index and group memberships from a checked summary.
async fn write_index(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    contact_id: Uuid,
    summary: &ContactSummaryV1,
) -> AppResult<()> {
    sqlx::query("DELETE FROM contact_emails WHERE contact_id = $1")
        .bind(contact_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM contact_group_members WHERE contact_id = $1")
        .bind(contact_id)
        .execute(&mut **tx)
        .await?;
    for (position, email) in summary.emails.iter().enumerate() {
        sqlx::query("INSERT INTO contact_emails (contact_id, user_id, address, label, position) VALUES ($1, $2, $3, $4, $5)")
            .bind(contact_id)
            .bind(user_id)
            .bind(&email.address)
            .bind(&email.label)
            .bind(position as i32)
            .execute(&mut **tx)
            .await?;
    }
    for group in &summary.groups {
        let group =
            Uuid::parse_str(group).map_err(|_| AppError::bad_request("group id is invalid"))?;
        let inserted = sqlx::query(
            "INSERT INTO contact_group_members (contact_id, group_id)
             SELECT $1, id FROM contact_groups WHERE id = $2 AND user_id = $3",
        )
        .bind(contact_id)
        .bind(group)
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
        if inserted.rows_affected() != 1 {
            return Err(AppError::bad_request(
                "a group in the summary does not exist",
            ));
        }
    }
    Ok(())
}

/// Charges `add` bytes to the pool (refunds when negative), under the user's row lock.
async fn charge(tx: &mut Transaction<'_, Postgres>, user_id: Uuid, add: i64) -> AppResult<()> {
    let pool = crate::storage_pool::lock(tx, user_id, Default::default()).await?;
    if add > 0 && !pool.fits(add, 0) {
        return Err(AppError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "storage quota exceeded",
        ));
    }
    sqlx::query(
        "UPDATE users SET storage_used_bytes = GREATEST(storage_used_bytes + $2, 0) WHERE id = $1",
    )
    .bind(user_id)
    .bind(add)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn insert(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    checked: &Checked,
) -> AppResult<Uuid> {
    let id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO contacts (user_id, uid, name, summary, signature, card)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (user_id, uid) DO NOTHING
         RETURNING id",
    )
    .bind(user_id)
    .bind(&checked.summary.uid)
    .bind(&checked.summary.name)
    .bind(&checked.summary_text)
    .bind(&checked.signature)
    .bind(&checked.card)
    .fetch_optional(&mut **tx)
    .await?;
    let id = id.ok_or_else(|| AppError::conflict("a contact with this UID already exists"))?;
    write_index(tx, user_id, id, &checked.summary).await?;
    Ok(id)
}

async fn room_for(tx: &mut Transaction<'_, Postgres>, user_id: Uuid, more: usize) -> AppResult<()> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM contacts WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&mut **tx)
        .await?;
    if count + more as i64 > MAX_CONTACTS {
        return Err(AppError::bad_request("the address book is full"));
    }
    Ok(())
}

async fn fetch(state: &AppState, user_id: Uuid, id: Uuid) -> AppResult<ContactRow> {
    let row: Option<Row> = sqlx::query_as(&format!("{ROW_SELECT} WHERE id = $1 AND user_id = $2"))
        .bind(id)
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await?;
    row.map(to_row)
        .ok_or_else(|| AppError::not_found("not found"))
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    offset: Option<i64>,
    limit: Option<i64>,
}

/// A page of contacts, ordered by name.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ContactPage {
    pub contacts: Vec<ContactRow>,
    pub total: i64,
}

/// `GET /api/contacts?offset=&limit=` — the caller's contacts, by name.
#[utoipa::path(
    get,
    path = "/api/contacts",
    tag = "contacts",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "A page of contacts", body = ContactPage))
)]
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Query(query): Query<ListQuery>,
) -> AppResult<Json<ContactPage>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let limit = query.limit.unwrap_or(MAX_PAGE).clamp(1, MAX_PAGE);
    let offset = query.offset.unwrap_or(0).max(0);
    let rows: Vec<Row> = sqlx::query_as(&format!(
        "{ROW_SELECT} WHERE user_id = $1 ORDER BY lower(name), id LIMIT $2 OFFSET $3"
    ))
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM contacts WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&state.pool)
        .await?;
    Ok(Json(ContactPage {
        contacts: rows.into_iter().map(to_row).collect(),
        total,
    }))
}

/// `POST /api/contacts` — adds a contact.
#[utoipa::path(
    post,
    path = "/api/contacts",
    tag = "contacts",
    security(("BearerAuth" = [])),
    request_body = ContactInput,
    responses(
        (status = 201, description = "Added", body = ContactRow),
        (status = 400, description = "Not a valid, account-signed contact"),
        (status = 409, description = "A contact with this UID exists"),
        (status = 413, description = "Storage full"),
    )
)]
pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(input): Json<ContactInput>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let (account, authority) = account_of(&state, user_id).await?;
    let checked = check(&input, &account, &authority)?;
    let mut tx = state.pool.begin().await?;
    charge(&mut tx, user_id, checked.charge()).await?;
    room_for(&mut tx, user_id, 1).await?;
    let id = insert(&mut tx, user_id, &checked).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(fetch(&state, user_id, id).await?)).into_response())
}

/// A contact replacing the stored one at `revision`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContactUpdate {
    pub summary: String,
    pub signature: String,
    pub card: String,
    /// The revision the edit started from.
    pub revision: i64,
}

/// `PUT /api/contacts/{id}` — replaces a contact (same UID) if nobody changed
/// it since `revision`.
#[utoipa::path(
    put,
    path = "/api/contacts/{id}",
    tag = "contacts",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Contact id")),
    request_body = ContactUpdate,
    responses(
        (status = 200, description = "Updated", body = ContactRow),
        (status = 409, description = "Changed elsewhere since this revision"),
    )
)]
pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(input): Json<ContactUpdate>,
) -> AppResult<Json<ContactRow>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let (account, authority) = account_of(&state, user_id).await?;
    let checked = check(
        &ContactInput {
            summary: input.summary,
            signature: input.signature,
            card: input.card,
        },
        &account,
        &authority,
    )?;
    let mut tx = state.pool.begin().await?;
    let current: Option<(String, i64, i64)> = sqlx::query_as(
        "SELECT uid, revision, (octet_length(summary) + octet_length(card))::bigint FROM contacts
          WHERE id = $1 AND user_id = $2 FOR UPDATE",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((uid, revision, old_charge)) = current else {
        return Err(AppError::not_found("not found"));
    };
    if uid != checked.summary.uid {
        return Err(AppError::bad_request("a contact keeps its UID"));
    }
    if revision != input.revision {
        return Err(AppError::conflict("this contact was changed elsewhere"));
    }
    charge(&mut tx, user_id, checked.charge() - old_charge).await?;
    sqlx::query(
        "UPDATE contacts SET name = $2, summary = $3, signature = $4, card = $5,
                revision = revision + 1, updated_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .bind(&checked.summary.name)
    .bind(&checked.summary_text)
    .bind(&checked.signature)
    .bind(&checked.card)
    .execute(&mut *tx)
    .await?;
    write_index(&mut tx, user_id, id, &checked.summary).await?;
    tx.commit().await?;
    Ok(Json(fetch(&state, user_id, id).await?))
}

async fn delete_ids(state: &AppState, user_id: Uuid, ids: &[Uuid]) -> AppResult<u64> {
    let mut tx = state.pool.begin().await?;
    let freed: Option<i64> = sqlx::query_scalar(
        "WITH gone AS (DELETE FROM contacts WHERE user_id = $1 AND id = ANY($2)
                       RETURNING (octet_length(summary) + octet_length(card))::bigint AS bytes)
         SELECT SUM(bytes)::bigint FROM gone",
    )
    .bind(user_id)
    .bind(ids)
    .fetch_one(&mut *tx)
    .await?;
    let freed = freed.unwrap_or(0);
    if freed > 0 {
        charge(&mut tx, user_id, -freed).await?;
    }
    tx.commit().await?;
    Ok(freed as u64)
}

/// `DELETE /api/contacts/{id}`.
#[utoipa::path(
    delete,
    path = "/api/contacts/{id}",
    tag = "contacts",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Contact id")),
    responses((status = 204, description = "Deleted"))
)]
pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    delete_ids(&state, user_id, &[id]).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteContacts {
    pub ids: Vec<String>,
}

/// `POST /api/contacts/delete` — deletes several contacts.
#[utoipa::path(
    post,
    path = "/api/contacts/delete",
    tag = "contacts",
    security(("BearerAuth" = [])),
    request_body = DeleteContacts,
    responses((status = 204, description = "Deleted"))
)]
pub async fn delete_many(
    State(state): State<AppState>,
    user: AuthUser,
    Json(input): Json<DeleteContacts>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    if input.ids.len() > MAX_IMPORT {
        return Err(AppError::bad_request("too many contacts at once"));
    }
    let ids = input
        .ids
        .iter()
        .map(|id| Uuid::parse_str(id).map_err(|_| AppError::bad_request("contact id is invalid")))
        .collect::<AppResult<Vec<_>>>()?;
    delete_ids(&state, user_id, &ids).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportContacts {
    pub contacts: Vec<ContactInput>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub imported: usize,
}

/// `POST /api/contacts/import` — adds up to 500 contacts, all or nothing.
#[utoipa::path(
    post,
    path = "/api/contacts/import",
    tag = "contacts",
    security(("BearerAuth" = [])),
    request_body = ImportContacts,
    responses(
        (status = 200, description = "Imported", body = ImportResult),
        (status = 409, description = "One of them has a UID already in the address book"),
    )
)]
pub async fn import(
    State(state): State<AppState>,
    user: AuthUser,
    Json(input): Json<ImportContacts>,
) -> AppResult<Json<ImportResult>> {
    let user_id = trusted_uuid(&user.user_id)?;
    if input.contacts.is_empty() || input.contacts.len() > MAX_IMPORT {
        return Err(AppError::bad_request("import 1 to 500 contacts at once"));
    }
    let (account, authority) = account_of(&state, user_id).await?;
    let checked = input
        .contacts
        .iter()
        .map(|contact| check(contact, &account, &authority))
        .collect::<AppResult<Vec<_>>>()?;
    let total: i64 = checked.iter().map(Checked::charge).sum();
    let mut tx = state.pool.begin().await?;
    charge(&mut tx, user_id, total).await?;
    room_for(&mut tx, user_id, checked.len()).await?;
    for contact in &checked {
        insert(&mut tx, user_id, contact).await?;
    }
    tx.commit().await?;
    Ok(Json(ImportResult {
        imported: checked.len(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct EmailQuery {
    q: Option<String>,
    limit: Option<i64>,
}

/// One address for a picker (Proton's `ContactEmail`).
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ContactEmailRow {
    pub contact_id: String,
    pub name: String,
    pub address: String,
    pub label: Option<String>,
}

/// `GET /api/contacts/emails?q=&limit=` — addresses whose address or name
/// starts with `q` (any word of the name), recently used first; for the
/// recipient, share and invitee pickers.
#[utoipa::path(
    get,
    path = "/api/contacts/emails",
    tag = "contacts",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Matching addresses", body = [ContactEmailRow]))
)]
pub async fn emails(
    State(state): State<AppState>,
    user: AuthUser,
    Query(query): Query<EmailQuery>,
) -> AppResult<Json<Vec<ContactEmailRow>>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let limit = query.limit.unwrap_or(20).clamp(1, 200);
    let q = query.q.unwrap_or_default().trim().to_lowercase();
    let pattern = format!(
        "{}%",
        q.replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
    );
    let word = format!("% {}", pattern);
    let rows: Vec<(Uuid, String, String, Option<String>)> = sqlx::query_as(
        "SELECT c.id, c.name, e.address, e.label
           FROM contact_emails e JOIN contacts c ON c.id = e.contact_id
          WHERE e.user_id = $1
            AND ($2 = '' OR e.address LIKE $3 OR lower(c.name) LIKE $3 OR lower(c.name) LIKE $4)
          ORDER BY e.last_used_at DESC NULLS LAST, lower(c.name), e.position
          LIMIT $5",
    )
    .bind(user_id)
    .bind(&q)
    .bind(&pattern)
    .bind(&word)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(id, name, address, label)| ContactEmailRow {
                contact_id: id.to_string(),
                name,
                address,
                label,
            })
            .collect(),
    ))
}

/// A contact group (Proton's contact label).
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ContactGroupRow {
    pub id: String,
    pub name: String,
    pub color: String,
    pub members: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContactGroupInput {
    pub name: String,
    pub color: String,
}

fn check_group(input: &ContactGroupInput) -> AppResult<(String, String)> {
    let name = input.name.trim();
    if name.is_empty() || name.chars().count() > 100 || name.chars().any(char::is_control) {
        return Err(AppError::bad_request(
            "group name must be 1 to 100 characters",
        ));
    }
    let color = input.color.to_lowercase();
    if color.len() != 7
        || !color.starts_with('#')
        || !color[1..].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(AppError::bad_request("group colour must be #rrggbb"));
    }
    Ok((name.to_owned(), color))
}

/// `GET /api/contacts/groups`.
#[utoipa::path(
    get,
    path = "/api/contacts/groups",
    tag = "contacts",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "The caller's groups", body = [ContactGroupRow]))
)]
pub async fn list_groups(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<ContactGroupRow>>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let rows: Vec<(Uuid, String, String, i64)> = sqlx::query_as(
        "SELECT g.id, g.name, g.color, COUNT(m.contact_id)
           FROM contact_groups g LEFT JOIN contact_group_members m ON m.group_id = g.id
          WHERE g.user_id = $1 GROUP BY g.id ORDER BY lower(g.name), g.id",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(id, name, color, members)| ContactGroupRow {
                id: id.to_string(),
                name,
                color,
                members,
            })
            .collect(),
    ))
}

/// `POST /api/contacts/groups`.
#[utoipa::path(
    post,
    path = "/api/contacts/groups",
    tag = "contacts",
    security(("BearerAuth" = [])),
    request_body = ContactGroupInput,
    responses((status = 201, description = "Created", body = ContactGroupRow))
)]
pub async fn create_group(
    State(state): State<AppState>,
    user: AuthUser,
    Json(input): Json<ContactGroupInput>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let (name, color) = check_group(&input)?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM contact_groups WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&state.pool)
        .await?;
    if count >= MAX_GROUPS {
        return Err(AppError::bad_request("too many groups"));
    }
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO contact_groups (user_id, name, color) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(user_id)
    .bind(&name)
    .bind(&color)
    .fetch_one(&state.pool)
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(ContactGroupRow {
            id: id.to_string(),
            name,
            color,
            members: 0,
        }),
    )
        .into_response())
}

/// `PUT /api/contacts/groups/{id}` — rename or recolour.
#[utoipa::path(
    put,
    path = "/api/contacts/groups/{id}",
    tag = "contacts",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Group id")),
    request_body = ContactGroupInput,
    responses((status = 204, description = "Updated"))
)]
pub async fn update_group(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(input): Json<ContactGroupInput>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let (name, color) = check_group(&input)?;
    let updated = sqlx::query(
        "UPDATE contact_groups SET name = $3, color = $4 WHERE id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(user_id)
    .bind(&name)
    .bind(&color)
    .execute(&state.pool)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(AppError::not_found("not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /api/contacts/groups/{id}` — the group goes; its members stay.
/// Their signed summaries still name it until the client re-signs them, and
/// readers ignore group ids that no longer exist.
#[utoipa::path(
    delete,
    path = "/api/contacts/groups/{id}",
    tag = "contacts",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Group id")),
    responses((status = 204, description = "Deleted"))
)]
pub async fn delete_group(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    sqlx::query("DELETE FROM contact_groups WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
