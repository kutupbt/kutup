//! Calendars (docs/plans/calendar.md, E1): Proton Calendar's model.
//!
//! A calendar is its OpenPGP key (the secret locked with a passphrase), the
//! passphrase sealed per member to the member's address key and signed by
//! the owner, and its name and description sealed to the calendar key.
//! Events are Proton's parts: the server checks the signed ones against the
//! author's address keys and reads its time columns from the shared signed
//! part only, never from the request; it can't open the encrypted ones.
//!
//! Each account's calendar memberships are listed by the account head
//! (`calendars` scope: the calendar id and the member row's revision, which
//! only the member's own writes move), beyond Proton. Events have no head in
//! E1. Everything is charged to the calendar owner's one storage pool.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::calendar::{self as cal, SealedEventV1, SealedMetadataV1};
use kutup_crypto::calendar_event::{EventTime, SharedSigned};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::account_heads::{self, NextHead};
use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::site_settings::{
    CALENDARS_PER_ACCOUNT, CALENDAR_EVENTS_PAGE, CALENDAR_EVENTS_PER_CALENDAR, CALENDAR_SYNC_BATCH,
    CALENDAR_WINDOW_DAYS,
};
use crate::{revisions, AppState};

/// Proton's permission bits (`CALENDAR_PERMISSIONS`).
pub const SUPER_OWNER: i32 = 1;
pub const OWNER: i32 = 2;
pub const ADMIN: i32 = 4;
pub const READ_MEMBER_LIST: i32 = 8;
pub const WRITE: i32 = 16;
pub const READ: i32 = 32;
pub const AVAILABILITY: i32 = 64;
/// Proton's `MEMBER_PERMISSIONS.OWNS`.
pub const OWNS: i32 = SUPER_OWNER | OWNER | ADMIN | READ_MEMBER_LIST | WRITE | READ | AVAILABILITY;

/// Calendar writes per account (`calendar_writes`, 600 a minute at first):
/// calendars made, changed or deleted and event syncs.
pub(crate) static WRITES: std::sync::LazyLock<crate::ratelimit::RateLimiter> =
    std::sync::LazyLock::new(|| {
        crate::ratelimit::RateLimiter::registered(crate::ratelimit::Limit::CalendarWrites)
    });

fn limited(user_id: Uuid) -> AppResult<()> {
    if WRITES.allow(&user_id.to_string()) {
        Ok(())
    } else {
        Err(AppError::too_many_requests("too many calendar changes")
            .with_details(serde_json::json!({ "code": "rateLimited" })))
    }
}

fn b64(value: &str, what: &str) -> AppResult<Vec<u8>> {
    STANDARD
        .decode(value)
        .ok()
        .filter(|bytes| STANDARD.encode(bytes) == value)
        .ok_or_else(|| AppError::bad_request(format!("{what} is not canonical base64")))
}

fn crypto(error: kutup_crypto::error::CryptoError) -> AppError {
    match error {
        kutup_crypto::error::CryptoError::AuthFailed => {
            AppError::bad_request("a signature or key packet does not verify")
        }
        other => AppError::bad_request(other.to_string()),
    }
}

fn color(value: &str) -> AppResult<String> {
    let value = value.to_ascii_lowercase();
    let valid = value.len() == 7
        && value.starts_with('#')
        && value[1..].bytes().all(|b| b.is_ascii_hexdigit());
    if !valid {
        return Err(AppError::bad_request("color is #rrggbb"));
    }
    Ok(value)
}

/// A member's copy of the passphrase.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PassphraseV1 {
    pub data_packet: String,
    pub signature: String,
    pub key_packet: String,
}

/// A calendar as one member sees it.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CalendarView {
    pub id: Uuid,
    /// The owner's address that signed the passphrase and the metadata:
    /// verify against its key list.
    pub owner_address: String,
    pub public_key: String,
    pub fingerprint: String,
    pub locked_secret_key: String,
    pub passphrase: PassphraseV1,
    /// The member's address the passphrase's key packet is to.
    pub address_id: Uuid,
    #[schema(value_type = Object)]
    pub metadata: SealedMetadataV1,
    pub permissions: i32,
    pub color: String,
    pub display: bool,
    /// The member row's revision (the account head's `calendars` scope).
    pub revision: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CalendarList {
    pub calendars: Vec<CalendarView>,
}

#[derive(sqlx::FromRow)]
struct ViewRow {
    id: Uuid,
    owner_address: String,
    public_key: Vec<u8>,
    fingerprint: String,
    locked_secret_key: Vec<u8>,
    passphrase_data_packet: Vec<u8>,
    passphrase_signature: String,
    passphrase_key_packet: Vec<u8>,
    address_id: Uuid,
    metadata_key_packet: Vec<u8>,
    metadata_data_packet: Vec<u8>,
    metadata_signature: String,
    permissions: i32,
    color: String,
    display: bool,
    revision: i64,
    created_at: time::OffsetDateTime,
    updated_at: time::OffsetDateTime,
}

const VIEW: &str =
    "SELECT c.id, oa.address AS owner_address, c.public_key, c.fingerprint, c.locked_secret_key,
        c.passphrase_data_packet, c.passphrase_signature, m.passphrase_key_packet, m.address_id,
        c.metadata_key_packet, c.metadata_data_packet, c.metadata_signature,
        m.permissions, m.color, m.display, m.revision, c.created_at, c.updated_at
   FROM calendar_members m
   JOIN calendars c ON c.id = m.calendar_id
   JOIN calendar_members om ON om.calendar_id = c.id AND om.user_id = c.owner_id
   JOIN mail_addresses oa ON oa.id = om.address_id";

fn view(row: ViewRow) -> CalendarView {
    CalendarView {
        id: row.id,
        owner_address: row.owner_address,
        public_key: STANDARD.encode(row.public_key),
        fingerprint: row.fingerprint,
        locked_secret_key: STANDARD.encode(row.locked_secret_key),
        passphrase: PassphraseV1 {
            data_packet: STANDARD.encode(row.passphrase_data_packet),
            signature: row.passphrase_signature,
            key_packet: STANDARD.encode(row.passphrase_key_packet),
        },
        address_id: row.address_id,
        metadata: SealedMetadataV1 {
            key_packet: STANDARD.encode(row.metadata_key_packet),
            data_packet: STANDARD.encode(row.metadata_data_packet),
            signature: row.metadata_signature,
        },
        permissions: row.permissions,
        color: row.color,
        display: row.display,
        revision: row.revision,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

async fn fetch(state: &AppState, user_id: Uuid, id: Uuid) -> AppResult<CalendarView> {
    let row: Option<ViewRow> = sqlx::query_as(&format!(
        "{VIEW} WHERE m.user_id = $1 AND m.calendar_id = $2"
    ))
    .bind(user_id)
    .bind(id)
    .fetch_optional(&state.pool)
    .await?;
    row.map(view)
        .ok_or_else(|| AppError::not_found("not found"))
}

/// `GET /api/calendar/calendars` — the caller's calendars.
#[utoipa::path(
    get,
    path = "/api/calendar/calendars",
    tag = "calendar",
    security(("BearerAuth" = [])),
    responses((status = 200, body = CalendarList))
)]
pub async fn list(State(state): State<AppState>, user: AuthUser) -> AppResult<Json<CalendarList>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let rows: Vec<ViewRow> = sqlx::query_as(&format!(
        "{VIEW} WHERE m.user_id = $1 ORDER BY c.created_at, c.id"
    ))
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(CalendarList {
        calendars: rows.into_iter().map(view).collect(),
    }))
}

/// The caller's active address `address_id` and its keys that may still
/// verify (Mail's `FLAG_NOT_COMPROMISED`): `(public keys, primary key)`.
async fn address_keys(
    conn: &mut sqlx::PgConnection,
    user_id: Uuid,
    address_id: Uuid,
) -> AppResult<(Vec<Vec<u8>>, Vec<u8>)> {
    let rows: Vec<(Vec<u8>, bool)> = sqlx::query_as(
        "SELECT k.public_key, k.is_primary FROM mail_address_keys k
           JOIN mail_addresses a ON a.id = k.address_id
          WHERE a.id = $1 AND a.user_id = $2 AND a.state = 'active'
            AND (k.flags & $3) <> 0
          ORDER BY k.created_at, k.fingerprint",
    )
    .bind(address_id)
    .bind(user_id)
    .bind(kutup_crypto::mail_key::FLAG_NOT_COMPROMISED as i32)
    .fetch_all(&mut *conn)
    .await?;
    let primary = rows
        .iter()
        .find(|(_, primary)| *primary)
        .map(|(key, _)| key.clone())
        .ok_or_else(|| AppError::bad_request("the address has no key; add one in Mail first"))?;
    Ok((rows.into_iter().map(|(key, _)| key).collect(), primary))
}

async fn charge(tx: &mut Transaction<'_, Postgres>, owner: Uuid, add: i64) -> AppResult<()> {
    let pool = crate::storage_pool::lock(tx, owner, Default::default()).await?;
    if add > 0 && !pool.fits(add, 0) {
        return Err(AppError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "storage quota exceeded",
        ));
    }
    sqlx::query(
        "UPDATE users SET storage_used_bytes = GREATEST(storage_used_bytes + $2, 0) WHERE id = $1",
    )
    .bind(owner)
    .bind(add)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// A new calendar, as `createCalendar` in the browser makes it.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CalendarCreate {
    /// The calendar's id, a fresh UUID v4 the client draws: the account
    /// head's `calendars` scope names it, and the head is made before the
    /// create (as Contacts' UIDs).
    pub id: Uuid,
    /// The owner's address whose key the passphrase is sealed to.
    pub address_id: Uuid,
    pub public_key: String,
    pub locked_secret_key: String,
    pub passphrase: PassphraseV1,
    #[schema(value_type = Object)]
    pub metadata: SealedMetadataV1,
    pub color: String,
    /// The account's next head (the `calendars` scope gains this calendar
    /// at revision 1).
    pub head: Option<String>,
}

/// `POST /api/calendar/calendars` — makes a calendar the caller owns.
#[utoipa::path(
    post,
    path = "/api/calendar/calendars",
    tag = "calendar",
    security(("BearerAuth" = [])),
    request_body = CalendarCreate,
    responses(
        (status = 201, body = CalendarView),
        (status = 400, description = "A key or packet doesn't check"),
        (status = 409, description = "head_conflict, or the calendar limit"),
        (status = 413, description = "Storage quota exceeded"),
    )
)]
pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(input): Json<CalendarCreate>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    limited(user_id)?;
    let head = NextHead::parse(input.head.as_deref())?;
    if input.id.get_version_num() != 4 {
        return Err(AppError::bad_request("a calendar's id is a UUID v4"));
    }
    let public_key = b64(&input.public_key, "public key")?;
    let locked = b64(&input.locked_secret_key, "locked secret key")?;
    let fingerprint = cal::inspect_calendar_public_key(&public_key).map_err(crypto)?;
    cal::inspect_locked_calendar_key(&locked, &public_key).map_err(crypto)?;
    let data_packet = b64(&input.passphrase.data_packet, "passphrase data packet")?;
    let key_packet = b64(&input.passphrase.key_packet, "passphrase key packet")?;
    let metadata = input.metadata.to_sealed().map_err(crypto)?;
    let color = color(&input.color)?;
    if input.passphrase.signature.len() > 4096 || metadata.signature.len() > 4096 {
        return Err(AppError::bad_request("a signature is too large"));
    }
    // The metadata is to the calendar key; the passphrase to the owner's
    // primary address key.
    if cal::key_packet_key_id(&metadata.key_packet).map_err(crypto)?
        != cal::encryption_key_id(&public_key).map_err(crypto)?
    {
        return Err(AppError::bad_request(
            "the metadata is not to the calendar key",
        ));
    }
    let mut tx = state.pool.begin().await?;
    let locked_head = account_heads::lock(&mut tx, user_id, user.session.session_id).await?;
    let (_, primary) = address_keys(&mut tx, user_id, input.address_id).await?;
    if cal::key_packet_key_id(&key_packet).map_err(crypto)?
        != cal::encryption_key_id(&primary).map_err(crypto)?
    {
        return Err(AppError::bad_request(
            "the passphrase is not to the address's primary key",
        ));
    }
    let owned: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM calendars WHERE owner_id = $1")
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
    if owned >= CALENDARS_PER_ACCOUNT.load(&state.pool).await? {
        return Err(AppError::conflict("calendar limit reached")
            .with_details(serde_json::json!({ "code": "calendarLimit" })));
    }
    let bytes = (public_key.len()
        + locked.len()
        + data_packet.len()
        + input.passphrase.signature.len()
        + key_packet.len()
        + metadata.key_packet.len()
        + metadata.data_packet.len()
        + metadata.signature.len()) as i64;
    charge(&mut tx, user_id, bytes).await?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO calendars (id, owner_id, public_key, fingerprint, locked_secret_key,
             passphrase_data_packet, passphrase_signature,
             metadata_key_packet, metadata_data_packet, metadata_signature, bytes)
         VALUES ($11, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         RETURNING id",
    )
    .bind(user_id)
    .bind(&public_key)
    .bind(hex::encode(fingerprint))
    .bind(&locked)
    .bind(&data_packet)
    .bind(&input.passphrase.signature)
    .bind(&metadata.key_packet)
    .bind(&metadata.data_packet)
    .bind(&metadata.signature)
    .bind(bytes)
    .bind(input.id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| match &error {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            AppError::conflict("this calendar id or key is in use")
                .with_details(serde_json::json!({ "code": "calendarExists" }))
        }
        _ => error.into(),
    })?;
    sqlx::query(
        "INSERT INTO calendar_members (calendar_id, user_id, address_id, permissions,
             passphrase_key_packet, color, revision)
         VALUES ($1, $2, $3, $4, $5, $6, 1)",
    )
    .bind(id)
    .bind(user_id)
    .bind(input.address_id)
    .bind(OWNS)
    .bind(&key_packet)
    .bind(&color)
    .execute(&mut *tx)
    .await?;
    account_heads::advance(&mut tx, &locked_head, head.as_ref()).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(fetch(&state, user_id, id).await?)).into_response())
}

/// A change to a calendar: the owner's new name and description, and the
/// member's own colour and visibility.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CalendarUpdate {
    #[schema(value_type = Option<Object>)]
    pub metadata: Option<SealedMetadataV1>,
    pub color: Option<String>,
    pub display: Option<bool>,
    /// The member row's revision the change started from, and its new one.
    pub base_revision: i64,
    pub revision: u64,
    pub head: Option<String>,
}

/// `PUT /api/calendar/calendars/{id}`
#[utoipa::path(
    put,
    path = "/api/calendar/calendars/{id}",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path)),
    request_body = CalendarUpdate,
    responses(
        (status = 200, body = CalendarView),
        (status = 403, description = "Only the owner renames"),
        (status = 409, description = "revision_conflict or head_conflict"),
    )
)]
pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(input): Json<CalendarUpdate>,
) -> AppResult<Json<CalendarView>> {
    let user_id = trusted_uuid(&user.user_id)?;
    limited(user_id)?;
    let head = NextHead::parse(input.head.as_deref())?;
    let revision = revisions::check_follows(input.revision, input.base_revision)?;
    let color = input.color.as_deref().map(color).transpose()?;
    let metadata = input
        .metadata
        .as_ref()
        .map(|metadata| metadata.to_sealed().map_err(crypto))
        .transpose()?;
    let mut tx = state.pool.begin().await?;
    let locked = account_heads::lock(&mut tx, user_id, user.session.session_id).await?;
    let member: Option<(i64, i32, Uuid, Vec<u8>, i64)> = sqlx::query_as(
        "SELECT m.revision, m.permissions, c.owner_id, c.public_key, c.bytes
           FROM calendar_members m JOIN calendars c ON c.id = m.calendar_id
          WHERE m.calendar_id = $1 AND m.user_id = $2
          FOR UPDATE OF m, c",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((current, permissions, owner, public_key, old_bytes)) = member else {
        return Err(AppError::not_found("not found"));
    };
    if current != input.base_revision {
        return Err(revisions::conflict(
            "this calendar was changed elsewhere",
            current,
        ));
    }
    if let Some(metadata) = &metadata {
        if permissions & OWNER == 0 {
            return Err(AppError::forbidden("only the owner renames a calendar"));
        }
        if metadata.signature.len() > 4096
            || cal::key_packet_key_id(&metadata.key_packet).map_err(crypto)?
                != cal::encryption_key_id(&public_key).map_err(crypto)?
        {
            return Err(AppError::bad_request(
                "the metadata is not to the calendar key",
            ));
        }
        let old_metadata: i64 = sqlx::query_scalar(
            "SELECT (octet_length(metadata_key_packet) + octet_length(metadata_data_packet)
                     + octet_length(metadata_signature))::bigint FROM calendars WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        let new_metadata = (metadata.key_packet.len()
            + metadata.data_packet.len()
            + metadata.signature.len()) as i64;
        charge(&mut tx, owner, new_metadata - old_metadata).await?;
        sqlx::query(
            "UPDATE calendars SET metadata_key_packet = $2, metadata_data_packet = $3,
                    metadata_signature = $4, bytes = $5, updated_at = now()
              WHERE id = $1",
        )
        .bind(id)
        .bind(&metadata.key_packet)
        .bind(&metadata.data_packet)
        .bind(&metadata.signature)
        .bind(old_bytes + new_metadata - old_metadata)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "UPDATE calendar_members SET color = COALESCE($3, color), display = COALESCE($4, display),
                revision = $5
          WHERE calendar_id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(user_id)
    .bind(color)
    .bind(input.display)
    .bind(revision)
    .execute(&mut *tx)
    .await?;
    account_heads::advance(&mut tx, &locked, head.as_ref()).await?;
    tx.commit().await?;
    Ok(Json(fetch(&state, user_id, id).await?))
}

/// The account's next head, for a write that only removes a listed value.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CalendarDelete {
    pub head: Option<String>,
}

/// `DELETE /api/calendar/calendars/{id}` — the owner deletes a calendar and
/// every event in it.
#[utoipa::path(
    delete,
    path = "/api/calendar/calendars/{id}",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path)),
    request_body = CalendarDelete,
    responses((status = 204), (status = 403), (status = 404))
)]
pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(input): Json<CalendarDelete>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    limited(user_id)?;
    let head = NextHead::parse(input.head.as_deref())?;
    let mut tx = state.pool.begin().await?;
    let locked = account_heads::lock(&mut tx, user_id, user.session.session_id).await?;
    let found: Option<(i32, Uuid, i64)> = sqlx::query_as(
        "SELECT m.permissions, c.owner_id,
                (c.bytes + COALESCE((SELECT SUM(bytes) FROM calendar_events e WHERE e.calendar_id = c.id), 0))::bigint
           FROM calendar_members m JOIN calendars c ON c.id = m.calendar_id
          WHERE m.calendar_id = $1 AND m.user_id = $2
          FOR UPDATE OF c",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((permissions, owner, bytes)) = found else {
        return Err(AppError::not_found("not found"));
    };
    if permissions & SUPER_OWNER == 0 {
        return Err(AppError::forbidden("only the owner deletes a calendar"));
    }
    sqlx::query("DELETE FROM calendars WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    charge(&mut tx, owner, -bytes).await?;
    account_heads::advance(&mut tx, &locked, head.as_ref()).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ----- events -----

/// An event as stored.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EventView {
    pub id: Uuid,
    pub calendar_id: Uuid,
    pub uid: String,
    /// The author's address: verify the parts against its key list.
    pub author_address: Option<String>,
    #[schema(value_type = Object)]
    pub event: SealedEventV1,
    /// What the server read from the shared signed part.
    #[serde(with = "time::serde::rfc3339")]
    pub start_utc: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub end_utc: time::OffsetDateTime,
    pub full_day: bool,
    pub sequence: i32,
    /// The stored version: a change names it as its `baseRevision`.
    pub revision: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub modified_at: time::OffsetDateTime,
}

/// Where the next page starts: after this event, by (start, id). The client
/// keeps it, so an event deleted or moved meanwhile never ends or skips a
/// page.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EventCursor {
    #[serde(with = "time::serde::rfc3339")]
    pub after_start: time::OffsetDateTime,
    pub after_id: Uuid,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EventPage {
    pub events: Vec<EventView>,
    /// Pass as `afterStart` and `afterId` for the next page; none when this
    /// was the last.
    pub next: Option<EventCursor>,
}

#[derive(sqlx::FromRow)]
struct EventRow {
    id: Uuid,
    calendar_id: Uuid,
    uid: String,
    author_address: Option<String>,
    shared_key_packet: Vec<u8>,
    calendar_key_packet: Vec<u8>,
    shared_signed: String,
    shared_signed_signature: String,
    shared_encrypted: Vec<u8>,
    shared_encrypted_signature: String,
    calendar_signed: String,
    calendar_signed_signature: String,
    calendar_encrypted: Option<Vec<u8>>,
    calendar_encrypted_signature: Option<String>,
    start_utc: time::OffsetDateTime,
    end_utc: time::OffsetDateTime,
    full_day: bool,
    sequence: i32,
    revision: i64,
    modified_at: time::OffsetDateTime,
}

const EVENT_VIEW: &str = "SELECT e.id, e.calendar_id, e.uid, a.address AS author_address,
        e.shared_key_packet, e.calendar_key_packet,
        e.shared_signed, e.shared_signed_signature,
        e.shared_encrypted, e.shared_encrypted_signature,
        e.calendar_signed, e.calendar_signed_signature,
        e.calendar_encrypted, e.calendar_encrypted_signature,
        e.start_utc, e.end_utc, e.full_day, e.sequence, e.revision, e.modified_at
   FROM calendar_events e
   LEFT JOIN mail_addresses a ON a.id = e.author_address_id";

fn event_view(row: EventRow) -> EventView {
    use kutup_crypto::calendar::EventPartV1;
    EventView {
        id: row.id,
        calendar_id: row.calendar_id,
        uid: row.uid,
        author_address: row.author_address,
        event: SealedEventV1 {
            shared_key_packet: STANDARD.encode(row.shared_key_packet),
            calendar_key_packet: STANDARD.encode(row.calendar_key_packet),
            shared_signed: EventPartV1 {
                data: STANDARD.encode(row.shared_signed.as_bytes()),
                signature: row.shared_signed_signature,
            },
            shared_encrypted: EventPartV1 {
                data: STANDARD.encode(row.shared_encrypted),
                signature: row.shared_encrypted_signature,
            },
            calendar_signed: EventPartV1 {
                data: STANDARD.encode(row.calendar_signed.as_bytes()),
                signature: row.calendar_signed_signature,
            },
            calendar_encrypted: row
                .calendar_encrypted
                .zip(row.calendar_encrypted_signature)
                .map(|(data, signature)| EventPartV1 {
                    data: STANDARD.encode(data),
                    signature,
                }),
        },
        start_utc: row.start_utc,
        end_utc: row.end_utc,
        full_day: row.full_day,
        sequence: row.sequence,
        revision: row.revision,
        modified_at: row.modified_at,
    }
}

/// The caller's permissions on a calendar, or 404 (a calendar the caller
/// isn't a member of doesn't exist for it).
async fn member_permissions(
    conn: &mut sqlx::PgConnection,
    user_id: Uuid,
    calendar: Uuid,
) -> AppResult<i32> {
    sqlx::query_scalar(
        "SELECT permissions FROM calendar_members WHERE calendar_id = $1 AND user_id = $2",
    )
    .bind(calendar)
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| AppError::not_found("not found"))
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct EventsQuery {
    /// The window, RFC 3339: events that meet [start, end).
    pub start: String,
    pub end: String,
    /// The `next` of the previous page, both or neither.
    pub after_start: Option<String>,
    pub after_id: Option<Uuid>,
    pub limit: Option<i64>,
}

fn instant(value: &str, what: &str) -> AppResult<time::OffsetDateTime> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map_err(|_| AppError::bad_request(format!("{what} is not an RFC 3339 time")))
}

/// `GET /api/calendar/calendars/{id}/events?start&end` — the events that
/// meet a window, oldest start first, paged.
#[utoipa::path(
    get,
    path = "/api/calendar/calendars/{id}/events",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path), EventsQuery),
    responses((status = 200, body = EventPage), (status = 404))
)]
pub async fn events(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Query(query): Query<EventsQuery>,
) -> AppResult<Json<EventPage>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let (start, end) = (instant(&query.start, "start")?, instant(&query.end, "end")?);
    let window_days = CALENDAR_WINDOW_DAYS.load(&state.pool).await?;
    if end <= start || end - start > time::Duration::days(window_days) {
        return Err(AppError::bad_request(format!(
            "the window is up to {window_days} days, end after start"
        )));
    }
    let after = match (&query.after_start, query.after_id) {
        (Some(at), Some(id)) => Some((instant(at, "afterStart")?, id)),
        (None, None) => None,
        _ => return Err(AppError::bad_request("afterStart and afterId go together")),
    };
    let page = CALENDAR_EVENTS_PAGE.load(&state.pool).await?;
    let limit = query.limit.unwrap_or(page).clamp(1, page);
    let mut conn = state.pool.acquire().await?;
    let permissions = member_permissions(&mut conn, user_id, id).await?;
    if permissions & READ == 0 {
        return Err(AppError::forbidden("this calendar shows busy times only"));
    }
    // An event meets the half-open window [start, end) when it starts before
    // its end and ends (or, repeating, may still recur) after its start; one
    // of no length meets it when it starts in it. A page continues after the
    // client's cursor by (start, id).
    let mut rows: Vec<EventRow> = sqlx::query_as(&format!(
        "{EVENT_VIEW}
          WHERE e.calendar_id = $1 AND e.start_utc < $3
            AND (COALESCE(e.range_end_utc, 'infinity'::timestamptz) > $2 OR e.start_utc >= $2)
            AND ($4::timestamptz IS NULL OR (e.start_utc, e.id) > ($4, $5))
          ORDER BY e.start_utc, e.id
          LIMIT $6"
    ))
    .bind(id)
    .bind(start)
    .bind(end)
    .bind(after.map(|(at, _)| at))
    .bind(after.map(|(_, id)| id))
    .bind(limit + 1)
    .fetch_all(&mut *conn)
    .await?;
    let next = (rows.len() as i64 > limit).then(|| {
        rows.truncate(limit as usize);
        rows.last().map(|row| EventCursor {
            after_start: row.start_utc,
            after_id: row.id,
        })
    });
    Ok(Json(EventPage {
        events: rows.into_iter().map(event_view).collect(),
        next: next.flatten(),
    }))
}

/// `GET /api/calendar/calendars/{id}/events/{eventId}`
#[utoipa::path(
    get,
    path = "/api/calendar/calendars/{id}/events/{eventId}",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path), ("eventId" = Uuid, Path)),
    responses((status = 200, body = EventView), (status = 404))
)]
pub async fn event(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, event_id)): Path<(Uuid, Uuid)>,
) -> AppResult<Json<EventView>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let mut conn = state.pool.acquire().await?;
    if member_permissions(&mut conn, user_id, id).await? & READ == 0 {
        return Err(AppError::forbidden("this calendar shows busy times only"));
    }
    let row: Option<EventRow> = sqlx::query_as(&format!(
        "{EVENT_VIEW} WHERE e.calendar_id = $1 AND e.id = $2"
    ))
    .bind(id)
    .bind(event_id)
    .fetch_optional(&mut *conn)
    .await?;
    row.map(event_view)
        .map(Json)
        .ok_or_else(|| AppError::not_found("not found"))
}

/// One change in an events sync (Proton's `SyncMultipleEvents`):
/// `{"create": event}`, `{"update": {"id", "event"}}` or `{"delete": {"id"}}`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum EventChange {
    Create(SealedEventV1),
    /// `base_revision`: the event's stored revision the change was made
    /// from; another is `409 revision_conflict`.
    #[serde(rename_all = "camelCase")]
    Update {
        id: Uuid,
        base_revision: i64,
        event: SealedEventV1,
    },
    Delete {
        id: Uuid,
    },
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventSync {
    /// The author's address: every part is signed by one of its keys.
    pub address_id: Uuid,
    /// `{"create": event}`, `{"update": {"id", "event"}}`, `{"delete": {"id"}}`.
    #[schema(value_type = Vec<Object>)]
    pub changes: Vec<EventChange>,
}

/// One change's outcome, in the order sent: each is applied alone.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EventResult {
    pub status: u16,
    pub event: Option<EventView>,
    pub error: Option<String>,
    pub code: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EventSyncResults {
    pub results: Vec<EventResult>,
}

/// What the server stores of a checked event: its parts and the columns it
/// read from the shared signed part.
struct Checked {
    event: kutup_crypto::calendar::SealedEvent,
    shared: SharedSigned,
    start: time::OffsetDateTime,
    end: time::OffsetDateTime,
    bytes: i64,
}

/// An event time as the instant it names (`EventTime::instant`, the
/// bundled time zone database).
fn to_time(time: &EventTime) -> AppResult<time::OffsetDateTime> {
    let seconds = time.instant().map_err(crypto)?.as_second();
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|_| AppError::bad_request("a time is out of range"))
}

/// Checks a sealed event for a calendar and its author's keys, and reads
/// its columns. E1 takes single events: no recurrence, exceptions or
/// organizer yet (E2, E4).
fn check_event(
    event: &SealedEventV1,
    calendar_public_key: &[u8],
    author_keys: &[Vec<u8>],
) -> AppResult<Checked> {
    let event = event.to_event().map_err(crypto)?;
    cal::check_sealed_shape(&event, calendar_public_key).map_err(crypto)?;
    let authors: Vec<&[u8]> = author_keys.iter().map(Vec::as_slice).collect();
    let (shared, calendar) = cal::check_signed_parts(&event, &authors).map_err(crypto)?;
    if shared.rrule.is_some()
        || shared.recurrence_id.is_some()
        || !shared.exdates.is_empty()
        || !calendar.exdates.is_empty()
    {
        return Err(AppError::bad_request(
            "repeating events come with recurrence (E2)",
        ));
    }
    if shared.organizer.is_some() {
        return Err(AppError::bad_request("invitations come later (E4)"));
    }
    let start = to_time(&shared.dtstart)?;
    let end = match &shared.dtend {
        Some(end) => to_time(end)?,
        // RFC 5545: a date without an end is one day; a time, no length.
        None if shared.dtstart.is_date() => start + time::Duration::days(1),
        None => start,
    };
    let bytes = (event.shared_key_packet.len()
        + event.calendar_key_packet.len()
        + [
            Some(&event.shared_signed),
            Some(&event.shared_encrypted),
            Some(&event.calendar_signed),
            event.calendar_encrypted.as_ref(),
        ]
        .into_iter()
        .flatten()
        .map(|part| part.data.len() + part.signature.len())
        .sum::<usize>()) as i64;
    Ok(Checked {
        event,
        shared,
        start,
        end,
        bytes,
    })
}

/// `POST /api/calendar/calendars/{id}/events/sync` — creates, changes and
/// deletes events, each alone (Proton's sync): one result per change.
#[utoipa::path(
    post,
    path = "/api/calendar/calendars/{id}/events/sync",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path)),
    request_body = EventSync,
    responses(
        (status = 200, body = EventSyncResults),
        (status = 400, description = "More changes than one sync takes"),
        (status = 403, description = "The caller may not write to this calendar"),
    )
)]
pub async fn sync(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(input): Json<EventSync>,
) -> AppResult<Json<EventSyncResults>> {
    let user_id = trusted_uuid(&user.user_id)?;
    limited(user_id)?;
    let batch = CALENDAR_SYNC_BATCH.load(&state.pool).await?;
    if input.changes.is_empty() || input.changes.len() as i64 > batch {
        return Err(AppError::bad_request(format!(
            "a sync carries 1 to {batch} changes"
        )));
    }
    let (public_key, owner): (Vec<u8>, Uuid) = {
        let mut conn = state.pool.acquire().await?;
        if member_permissions(&mut conn, user_id, id).await? & WRITE == 0 {
            return Err(AppError::forbidden(
                "you may not change this calendar's events",
            ));
        }
        sqlx::query_as("SELECT public_key, owner_id FROM calendars WHERE id = $1")
            .bind(id)
            .fetch_one(&mut *conn)
            .await?
    };
    let author_keys = {
        let mut conn = state.pool.acquire().await?;
        address_keys(&mut conn, user_id, input.address_id).await?.0
    };
    let max_events = CALENDAR_EVENTS_PER_CALENDAR.load(&state.pool).await?;
    let mut results = Vec::with_capacity(input.changes.len());
    for change in &input.changes {
        let outcome = apply(
            &state,
            id,
            owner,
            user_id,
            input.address_id,
            &public_key,
            &author_keys,
            max_events,
            change,
        )
        .await;
        results.push(match outcome {
            Ok(Some(event_id)) => {
                let row: EventRow = sqlx::query_as(&format!("{EVENT_VIEW} WHERE e.id = $1"))
                    .bind(event_id)
                    .fetch_one(&state.pool)
                    .await?;
                EventResult {
                    status: 200,
                    event: Some(event_view(row)),
                    error: None,
                    code: None,
                }
            }
            Ok(None) => EventResult {
                status: 200,
                event: None,
                error: None,
                code: None,
            },
            // A server fault fails the whole sync; a refused change is its
            // own result.
            Err(error) if error.status.is_server_error() => return Err(error),
            Err(error) => EventResult {
                status: error.status.as_u16(),
                event: None,
                code: Some(
                    error
                        .details
                        .as_ref()
                        .and_then(|details| details.get("code"))
                        .and_then(|code| code.as_str())
                        .unwrap_or(crate::error::default_code(error.status))
                        .to_owned(),
                ),
                error: Some(error.message),
            },
        });
    }
    Ok(Json(EventSyncResults { results }))
}

#[allow(clippy::too_many_arguments)]
async fn apply(
    state: &AppState,
    calendar: Uuid,
    owner: Uuid,
    user_id: Uuid,
    address_id: Uuid,
    public_key: &[u8],
    author_keys: &[Vec<u8>],
    max_events: i64,
    change: &EventChange,
) -> AppResult<Option<Uuid>> {
    let mut tx = state.pool.begin().await?;
    // The calendar row orders the calendar's writes (the count, the UID),
    // and under it the caller is still a member who may write: a calendar
    // deleted or a member removed since the sync began is 404 or 403.
    let permissions: Option<i32> = sqlx::query_scalar(
        "SELECT m.permissions FROM calendars c
           JOIN calendar_members m ON m.calendar_id = c.id AND m.user_id = $2
          WHERE c.id = $1
          FOR UPDATE OF c",
    )
    .bind(calendar)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    match permissions {
        None => return Err(AppError::not_found("not found")),
        Some(permissions) if permissions & WRITE == 0 => {
            return Err(AppError::forbidden(
                "you may not change this calendar's events",
            ))
        }
        Some(_) => {}
    }
    let result = match change {
        EventChange::Create(event) => {
            let checked = check_event(event, public_key, author_keys)?;
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM calendar_events WHERE calendar_id = $1")
                    .bind(calendar)
                    .fetch_one(&mut *tx)
                    .await?;
            if count >= max_events {
                return Err(AppError::conflict("this calendar is full")
                    .with_details(serde_json::json!({ "code": "eventLimit" })));
            }
            charge(&mut tx, owner, checked.bytes).await?;
            let id = insert(&mut tx, calendar, user_id, address_id, &checked).await?;
            Some(id)
        }
        EventChange::Update {
            id,
            base_revision,
            event,
        } => {
            let checked = check_event(event, public_key, author_keys)?;
            type Current = (String, i64, time::OffsetDateTime, i64, i32);
            let current: Option<Current> = sqlx::query_as(
                "SELECT uid, bytes, created_at, revision, sequence FROM calendar_events
                  WHERE id = $1 AND calendar_id = $2 FOR UPDATE",
            )
            .bind(id)
            .bind(calendar)
            .fetch_optional(&mut *tx)
            .await?;
            let Some((uid, old_bytes, created_at, revision, sequence)) = current else {
                return Err(AppError::not_found("not found"));
            };
            if uid != checked.shared.uid {
                return Err(AppError::bad_request("an event keeps its UID"));
            }
            // Made from the stored version, never an older one replayed nor
            // over another device's newer save.
            if revision != *base_revision {
                return Err(revisions::conflict(
                    "this event was changed elsewhere",
                    revision,
                ));
            }
            if i64::from(checked.shared.sequence) < i64::from(sequence) {
                return Err(AppError::conflict("an event's SEQUENCE never goes down")
                    .with_details(serde_json::json!({ "code": "sequenceBehind" })));
            }
            charge(&mut tx, owner, checked.bytes - old_bytes).await?;
            sqlx::query("DELETE FROM calendar_events WHERE id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            // Written again whole (its columns all come from the new
            // parts), keeping its id and when it was made.
            insert_as(
                &mut tx,
                Some((*id, created_at, revision + 1)),
                calendar,
                user_id,
                address_id,
                &checked,
            )
            .await?;
            Some(*id)
        }
        EventChange::Delete { id } => {
            let bytes: Option<i64> = sqlx::query_scalar(
                "DELETE FROM calendar_events WHERE id = $1 AND calendar_id = $2 RETURNING bytes",
            )
            .bind(id)
            .bind(calendar)
            .fetch_optional(&mut *tx)
            .await?;
            let bytes = bytes.ok_or_else(|| AppError::not_found("not found"))?;
            charge(&mut tx, owner, -bytes).await?;
            None
        }
    };
    tx.commit().await?;
    Ok(result)
}

async fn insert(
    tx: &mut Transaction<'_, Postgres>,
    calendar: Uuid,
    user_id: Uuid,
    address_id: Uuid,
    checked: &Checked,
) -> AppResult<Uuid> {
    insert_as(tx, None, calendar, user_id, address_id, checked).await
}

/// Inserts a checked event; `kept` is the id and creation time of the
/// version it replaces, and the new version's revision.
async fn insert_as(
    tx: &mut Transaction<'_, Postgres>,
    kept: Option<(Uuid, time::OffsetDateTime, i64)>,
    calendar: Uuid,
    user_id: Uuid,
    address_id: Uuid,
    checked: &Checked,
) -> AppResult<Uuid> {
    let event = &checked.event;
    let text = |data: &[u8]| String::from_utf8(data.to_vec()).expect("checked as text");
    let shared = &checked.shared;
    sqlx::query_scalar(
        "INSERT INTO calendar_events (id, calendar_id, uid, author_address_id, author_user_id,
             shared_key_packet, calendar_key_packet,
             shared_signed, shared_signed_signature, shared_encrypted, shared_encrypted_signature,
             calendar_signed, calendar_signed_signature,
             calendar_encrypted, calendar_encrypted_signature,
             start_utc, end_utc, start_tz, end_tz, full_day, rrule, recurrence_id, range_end_utc,
             sequence, bytes, created_at, revision)
         VALUES (COALESCE($1, gen_random_uuid()), $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                 $13, $14, $15, $16, $17, $18, $19, $20, NULL, NULL, $17, $21, $22,
                 COALESCE($23, now()), COALESCE($24, 1))
         RETURNING id",
    )
    .bind(kept.map(|(id, _, _)| id))
    .bind(calendar)
    .bind(&shared.uid)
    .bind(address_id)
    .bind(user_id)
    .bind(&event.shared_key_packet)
    .bind(&event.calendar_key_packet)
    .bind(text(&event.shared_signed.data))
    .bind(&event.shared_signed.signature)
    .bind(&event.shared_encrypted.data)
    .bind(&event.shared_encrypted.signature)
    .bind(text(&event.calendar_signed.data))
    .bind(&event.calendar_signed.signature)
    .bind(
        event
            .calendar_encrypted
            .as_ref()
            .map(|part| part.data.clone()),
    )
    .bind(
        event
            .calendar_encrypted
            .as_ref()
            .map(|part| part.signature.clone()),
    )
    .bind(checked.start)
    .bind(checked.end)
    .bind(shared.dtstart.tzid())
    .bind(shared.dtend.as_ref().and_then(EventTime::tzid))
    .bind(shared.dtstart.is_date())
    .bind(shared.sequence.min(i32::MAX as u32) as i32)
    .bind(checked.bytes)
    .bind(kept.map(|(_, created_at, _)| created_at))
    .bind(kept.map(|(_, _, revision)| revision))
    .fetch_one(&mut **tx)
    .await
    .map_err(|error| match &error {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            AppError::conflict("an event with this UID is in the calendar")
                .with_details(serde_json::json!({ "code": "uidTaken" }))
        }
        _ => error.into(),
    })
}
