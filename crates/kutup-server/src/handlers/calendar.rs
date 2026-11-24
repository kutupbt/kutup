//! Calendars (docs/plans/calendar.md, E1): Proton Calendar's model.
//!
//! A calendar is its OpenPGP key (the secret locked with a passphrase), the
//! passphrase shared with each member on their account key and signed by
//! the owner's account key (docs/plans/wipe-unification.md, W4: no address
//! in it, so a rename or a removed address orphans no one), and its name and
//! description sealed to the calendar key.
//! Events are Proton's parts: the server checks the signed ones against the
//! author's address keys and reads its time columns from the shared signed
//! part only, never from the request; it can't open the encrypted ones.
//!
//! A member's own colour and display flag are not here: they are a record
//! of the account's `calendarSettings` scope (docs/plans/account-records.md),
//! sealed and under the account head, filed under a hashed id the server
//! can't tie to the calendar. The member row keeps what the server needs:
//! permissions, the passphrase share and the default reminders it fires
//! alarms from. Events have no head in E1. Everything is charged to the
//! calendar owner's one storage pool.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::calendar::{self as cal, SealedEventV1, SealedMetadataV1};
use kutup_crypto::calendar_event::{EventTime, SharedSigned};
use kutup_crypto::calendar_recurrence::{Rule, Series};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthAccount;
use crate::site_settings::{
    CALENDARS_PER_ACCOUNT, CALENDAR_DEFAULT_REMINDERS, CALENDAR_EVENTS_PAGE,
    CALENDAR_EVENTS_PER_CALENDAR, CALENDAR_MAX_COUNT, CALENDAR_REMINDERS_PER_EVENT,
    CALENDAR_SYNC_BATCH, CALENDAR_WINDOW_DAYS,
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

pub(crate) fn limited(user_id: Uuid) -> AppResult<()> {
    if WRITES.allow(&user_id.to_string()) {
        Ok(())
    } else {
        Err(AppError::too_many_requests("too many calendar changes")
            .with_details(serde_json::json!({ "code": "rateLimited" })))
    }
}

pub(crate) fn b64(value: &str, what: &str) -> AppResult<Vec<u8>> {
    STANDARD
        .decode(value)
        .ok()
        .filter(|bytes| STANDARD.encode(bytes) == value)
        .ok_or_else(|| AppError::bad_request(format!("{what} is not canonical base64")))
}

pub(crate) fn crypto(error: kutup_crypto::error::CryptoError) -> AppError {
    match error {
        kutup_crypto::error::CryptoError::AuthFailed => {
            AppError::bad_request("a signature or key packet does not verify")
        }
        other => AppError::bad_request(other.to_string()),
    }
}

/// A calendar as one member sees it.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CalendarView {
    pub id: Uuid,
    /// The owner's account id (on this server): who shared the passphrase.
    pub owner_account_id: Uuid,
    pub public_key: String,
    pub fingerprint: String,
    pub locked_secret_key: String,
    /// The calendar key's generation, which the share names.
    pub key_generation: i32,
    /// The member's share of the passphrase (`CalendarShareEnvelopeV1`,
    /// base64), to their account key and signed by the owner's.
    pub passphrase_share: String,
    #[schema(value_type = Object)]
    pub metadata: SealedMetadataV1,
    pub permissions: i32,
    /// The member's default reminders for the calendar's events (Proton's
    /// DefaultPartDayNotifications and DefaultFullDayNotifications).
    pub default_reminders: DefaultReminders,
    /// This member shows others when they're busy from this calendar
    /// (docs/plans/calendar-e3.md §4).
    pub share_busy: bool,
    /// The owner's: someone who held the key no longer may, and the owner's
    /// app rotates it when it next loads the calendar (always false for a
    /// member).
    pub rotation_due: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: time::OffsetDateTime,
    /// The owner, on a calendar someone else owns: who signed the member's
    /// shares, which the member checks against its pins (E3 §1).
    pub owner: Option<CalendarOwnerView>,
    /// Every key generation the member holds a share of, oldest first (§2):
    /// older events open with their own generation's key.
    pub keys: Vec<CalendarKeyView>,
}

/// A calendar's owner as a member is told: checked against its pins.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CalendarOwnerView {
    pub account_id: Uuid,
    /// Their address now (`username@server`).
    pub address: String,
    /// Their account incarnation (hex).
    pub incarnation_id: String,
    /// Their account signing key (base64), which signs the shares.
    pub signing_public_key: String,
}

/// One key generation with the caller's share of its passphrase.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CalendarKeyView {
    pub key_generation: i32,
    pub public_key: String,
    pub fingerprint: String,
    pub locked_secret_key: String,
    pub passphrase_share: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DefaultReminders {
    pub timed: Vec<crate::calendar_reminders::Reminder>,
    pub all_day: Vec<crate::calendar_reminders::Reminder>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CalendarList {
    pub calendars: Vec<CalendarView>,
}

#[derive(sqlx::FromRow)]
struct ViewRow {
    id: Uuid,
    #[sqlx(rename = "owner_account_id")]
    owner_id: Uuid,
    public_key: Vec<u8>,
    fingerprint: String,
    locked_secret_key: Vec<u8>,
    key_generation: i32,
    passphrase_share: Vec<u8>,
    metadata_key_packet: Vec<u8>,
    metadata_data_packet: Vec<u8>,
    metadata_signature: String,
    permissions: i32,
    default_reminders_timed: serde_json::Value,
    default_reminders_all_day: serde_json::Value,
    share_busy: bool,
    rotation_due: bool,
    created_at: time::OffsetDateTime,
    updated_at: time::OffsetDateTime,
}

/// A calendar as one member sees it: its newest key generation and the
/// member's share of that generation's passphrase.
/// A calendar row's key suite (`calendars.suite`): 1 is the current
/// Ed25519/X25519 calendar key; a post-quantum key is a new value
/// (docs/plans/calendar.md, M2).
pub(crate) const CALENDAR_SUITE: i16 = 1;

const VIEW: &str =
    "SELECT c.id, c.owner_account_id, k.public_key, k.fingerprint, k.locked_secret_key,
        c.key_generation, s.share AS passphrase_share,
        c.metadata_key_packet, c.metadata_data_packet, c.metadata_signature,
        m.permissions, m.default_reminders_timed, m.default_reminders_all_day,
        m.share_busy, c.rotation_due AND m.account_id = c.owner_account_id AS rotation_due,
        c.created_at, c.updated_at
   FROM calendar_members m
   JOIN calendars c ON c.id = m.calendar_id
   JOIN calendar_keys k ON k.calendar_id = c.id AND k.key_generation = c.key_generation
   JOIN calendar_member_shares s
     ON s.calendar_id = c.id AND s.account_id = m.account_id AND s.key_generation = c.key_generation";

fn view(row: ViewRow) -> CalendarView {
    CalendarView {
        share_busy: row.share_busy,
        rotation_due: row.rotation_due,
        owner: None,
        keys: Vec::new(),
        id: row.id,
        owner_account_id: row.owner_id,
        public_key: STANDARD.encode(row.public_key),
        fingerprint: row.fingerprint,
        locked_secret_key: STANDARD.encode(row.locked_secret_key),
        key_generation: row.key_generation,
        passphrase_share: STANDARD.encode(row.passphrase_share),
        metadata: SealedMetadataV1 {
            key_packet: STANDARD.encode(row.metadata_key_packet),
            data_packet: STANDARD.encode(row.metadata_data_packet),
            signature: row.metadata_signature,
        },
        permissions: row.permissions,
        default_reminders: DefaultReminders {
            timed: serde_json::from_value(row.default_reminders_timed).unwrap_or_default(),
            all_day: serde_json::from_value(row.default_reminders_all_day).unwrap_or_default(),
        },
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

async fn fetch(state: &AppState, user_id: Uuid, id: Uuid) -> AppResult<CalendarView> {
    let row: Option<ViewRow> = sqlx::query_as(&format!(
        "{VIEW} WHERE m.account_id = $1 AND m.calendar_id = $2"
    ))
    .bind(user_id)
    .bind(id)
    .fetch_optional(&state.pool)
    .await?;
    let mut view = row
        .map(view)
        .ok_or_else(|| AppError::not_found("not found"))?;
    complete(state, user_id, std::slice::from_mut(&mut view)).await?;
    Ok(view)
}

/// Fills each calendar's key generations (the caller's shares) and, on
/// one someone else owns, its owner.
pub(crate) async fn complete(
    state: &AppState,
    user_id: Uuid,
    views: &mut [CalendarView],
) -> AppResult<()> {
    if views.is_empty() {
        return Ok(());
    }
    let ids: Vec<Uuid> = views.iter().map(|view| view.id).collect();
    let keys = keys_of(&state.pool, user_id, &ids).await?;
    let owners: Vec<Uuid> = views
        .iter()
        .filter(|view| view.owner_account_id != user_id)
        .map(|view| view.owner_account_id)
        .collect();
    let owners = owners_of(state, &owners).await?;
    for view in views {
        view.keys = keys
            .iter()
            .filter(|(calendar, _)| *calendar == view.id)
            .map(|(_, key)| key.clone())
            .collect();
        if view.owner_account_id != user_id {
            view.owner = owners
                .iter()
                .find(|owner| owner.account_id == view.owner_account_id)
                .cloned();
        }
    }
    Ok(())
}

/// The caller's shares of each calendar's key generations, oldest first.
pub(crate) async fn keys_of<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    user_id: Uuid,
    calendars: &[Uuid],
) -> AppResult<Vec<(Uuid, CalendarKeyView)>> {
    type Row = (Uuid, i32, Vec<u8>, String, Vec<u8>, Vec<u8>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT k.calendar_id, k.key_generation, k.public_key, k.fingerprint,
                k.locked_secret_key, s.share
           FROM calendar_keys k
           JOIN calendar_member_shares s
             ON s.calendar_id = k.calendar_id AND s.key_generation = k.key_generation
          WHERE s.account_id = $1 AND k.calendar_id = ANY($2)
          ORDER BY k.calendar_id, k.key_generation",
    )
    .bind(user_id)
    .bind(calendars)
    .fetch_all(executor)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(calendar, generation, public_key, fingerprint, locked, share)| {
                (
                    calendar,
                    CalendarKeyView {
                        key_generation: generation,
                        public_key: STANDARD.encode(public_key),
                        fingerprint,
                        locked_secret_key: STANDARD.encode(locked),
                        passphrase_share: STANDARD.encode(share),
                    },
                )
            },
        )
        .collect())
}

/// Owners as their calendars' members are told about them.
pub(crate) async fn owners_of(
    state: &AppState,
    accounts: &[Uuid],
) -> AppResult<Vec<CalendarOwnerView>> {
    if accounts.is_empty() {
        return Ok(Vec::new());
    }
    let rows: Vec<(Uuid, String, String, String)> = sqlx::query_as(
        "SELECT id, username, encode(account_incarnation_id, 'hex'),
                COALESCE(kutup_b64(drive_signing_public_key), '')
           FROM accounts WHERE id = ANY($1)",
    )
    .bind(accounts)
    .fetch_all(&state.pool)
    .await?;
    let domain = &state.config.chat_server_name;
    Ok(rows
        .into_iter()
        .map(|(id, username, incarnation, signing)| CalendarOwnerView {
            account_id: id,
            address: format!("{username}@{domain}"),
            incarnation_id: incarnation,
            signing_public_key: signing,
        })
        .collect())
}

/// `GET /api/v1/calendar/calendars` — the caller's calendars.
#[utoipa::path(
    get,
    path = "/api/v1/calendar/calendars",
    tag = "calendar",
    security(("BearerAuth" = [])),
    responses((status = 200, body = CalendarList))
)]
pub async fn list(
    State(state): State<AppState>,
    user: AuthAccount,
) -> AppResult<Json<CalendarList>> {
    let user_id = trusted_uuid(&user.account_id)?;
    let rows: Vec<ViewRow> = sqlx::query_as(&format!(
        "{VIEW} WHERE m.account_id = $1 ORDER BY c.created_at, c.id"
    ))
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    let mut calendars: Vec<CalendarView> = rows.into_iter().map(view).collect();
    complete(&state, user_id, &mut calendars).await?;
    Ok(Json(CalendarList { calendars }))
}

/// The longest passphrase share taken, in base64: two accounts on the
/// longest server names (the column holds 2048 bytes).
pub(crate) const MAX_SHARE_B64: usize = 2048 / 3 * 4 + 4;

/// The caller's active address `address_id` and its keys that may still
/// verify (Mail's `FLAG_NOT_COMPROMISED`): what an author's parts are
/// checked against.
pub(crate) async fn address_keys(
    conn: &mut sqlx::PgConnection,
    user_id: Uuid,
    address_id: Uuid,
) -> AppResult<Vec<Vec<u8>>> {
    let rows: Vec<(Vec<u8>, bool)> = sqlx::query_as(
        "SELECT k.public_key, k.is_primary FROM mail_address_keys k
           JOIN mail_addresses a ON a.id = k.address_id
          WHERE a.id = $1 AND a.account_id = $2 AND a.state = 'active'
            AND (k.flags & $3) <> 0
          ORDER BY k.created_at, k.fingerprint",
    )
    .bind(address_id)
    .bind(user_id)
    .bind(kutup_crypto::mail_key::FLAG_NOT_COMPROMISED as i32)
    .fetch_all(&mut *conn)
    .await?;
    if !rows.iter().any(|(_, primary)| *primary) {
        return Err(AppError::bad_request(
            "the address has no key; add one in Mail first",
        ));
    }
    Ok(rows.into_iter().map(|(key, _)| key).collect())
}

/// A new calendar, as `createCalendar` in the browser makes it.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CalendarCreate {
    /// The calendar's id, a fresh UUID v4 the client draws: its settings
    /// record (`calendarSettings`) is filed under it before the create.
    pub id: Uuid,
    pub public_key: String,
    pub locked_secret_key: String,
    /// The owner's own share of the passphrase (`CalendarShareEnvelopeV1`,
    /// base64): from the caller to the caller, at the first key generation.
    pub passphrase_share: String,
    #[schema(value_type = Object)]
    pub metadata: SealedMetadataV1,
}

/// `POST /api/v1/calendar/calendars` — makes a calendar the caller owns.
#[utoipa::path(
    post,
    path = "/api/v1/calendar/calendars",
    tag = "calendar",
    security(("BearerAuth" = [])),
    request_body = CalendarCreate,
    responses(
        (status = 201, body = CalendarView),
        (status = 400, description = "A key or packet doesn't check"),
        (status = 409, description = "The calendar limit, or the id is in use"),
        (status = 413, description = "Storage quota exceeded"),
    )
)]
pub async fn create(
    State(state): State<AppState>,
    user: AuthAccount,
    Json(input): Json<CalendarCreate>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.account_id)?;
    limited(user_id)?;
    if input.id.get_version_num() != 4 {
        return Err(AppError::bad_request("a calendar's id is a UUID v4"));
    }
    let public_key = b64(&input.public_key, "public key")?;
    let locked = b64(&input.locked_secret_key, "locked secret key")?;
    let fingerprint = cal::inspect_calendar_public_key(&public_key).map_err(crypto)?;
    cal::inspect_locked_calendar_key(&locked, &public_key).map_err(crypto)?;
    if input.passphrase_share.len() > MAX_SHARE_B64 {
        return Err(AppError::bad_request("the passphrase share is too large"));
    }
    let share = cal::CalendarShareEnvelopeV1::decode_b64(&input.passphrase_share)
        .map_err(|_| AppError::bad_request("the passphrase share does not parse"))?;
    let metadata = input.metadata.to_sealed().map_err(crypto)?;
    if metadata.signature.len() > 4096 {
        return Err(AppError::bad_request("a signature is too large"));
    }
    // The metadata is to the calendar key.
    if cal::key_packet_key_id(&metadata.key_packet).map_err(crypto)?
        != cal::encryption_key_id(&public_key).map_err(crypto)?
    {
        return Err(AppError::bad_request(
            "the metadata is not to the calendar key",
        ));
    }
    let mut tx = state.pool.begin().await?;
    // The owner's own copy: from the caller's account, as it is now, to
    // itself, for this calendar's first key, signed by its account key.
    let (incarnation, signing): (String, String) = sqlx::query_as(
        "SELECT encode(account_incarnation_id, 'hex'), kutup_b64(drive_signing_public_key) FROM accounts WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    let signing = STANDARD
        .decode(&signing)
        .map_err(|_| AppError::conflict("account identity is unavailable"))?;
    let me = crate::account_ids::local(&state.config.chat_server_name, user_id)?;
    share
        .verify_binding_and_signature(
            &input.id.to_string(),
            cal::FIRST_KEY_GENERATION,
            &me,
            &incarnation,
            &signing,
            &me,
            &incarnation,
        )
        .map_err(|_| {
            AppError::bad_request("the passphrase share is not the owner's own, for this calendar")
        })?;
    let share = share.encode().map_err(crypto)?;
    let owned: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM calendars WHERE owner_account_id = $1")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
    if owned >= CALENDARS_PER_ACCOUNT.load_for(&state.pool, user_id).await? {
        return Err(AppError::conflict("calendar limit reached")
            .with_details(serde_json::json!({ "code": "calendarLimit" })));
    }
    let bytes = (public_key.len()
        + locked.len()
        + share.len()
        + metadata.key_packet.len()
        + metadata.data_packet.len()
        + metadata.signature.len()) as i64;
    crate::storage_pool::charge_within_quota(&mut tx, user_id, bytes).await?;
    let taken = |error: sqlx::Error| match &error {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            AppError::conflict("this calendar id or key is in use")
                .with_details(serde_json::json!({ "code": "calendarExists" }))
        }
        _ => error.into(),
    };
    let generation = cal::FIRST_KEY_GENERATION as i32;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO calendars (id, owner_account_id, suite, key_generation,
             metadata_key_packet, metadata_data_packet, metadata_signature, bytes)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING id",
    )
    .bind(input.id)
    .bind(user_id)
    .bind(CALENDAR_SUITE)
    .bind(generation)
    .bind(&metadata.key_packet)
    .bind(&metadata.data_packet)
    .bind(&metadata.signature)
    .bind(bytes)
    .fetch_one(&mut *tx)
    .await
    .map_err(taken)?;
    // The first key generation, the owner as a member, and the owner's
    // share of that generation's passphrase.
    sqlx::query(
        "INSERT INTO calendar_keys (calendar_id, key_generation, public_key, fingerprint, locked_secret_key)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(generation)
    .bind(&public_key)
    .bind(hex::encode(fingerprint))
    .bind(&locked)
    .execute(&mut *tx)
    .await
    .map_err(taken)?;
    sqlx::query(
        "INSERT INTO calendar_members (calendar_id, account_id, permissions) VALUES ($1, $2, $3)",
    )
    .bind(id)
    .bind(user_id)
    .bind(OWNS)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO calendar_member_shares (calendar_id, account_id, key_generation, share)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(user_id)
    .bind(generation)
    .bind(&share)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(fetch(&state, user_id, id).await?)).into_response())
}

/// A change to a calendar: the owner's new name and description, and the
/// member's own default reminders (its colour and visibility are its
/// `calendarSettings` record).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CalendarUpdate {
    #[schema(value_type = Option<Object>)]
    pub metadata: Option<SealedMetadataV1>,
    /// The member's own default reminders.
    pub default_reminders: Option<DefaultReminders>,
    /// Show others when this member is busy from this calendar (times only).
    pub share_busy: Option<bool>,
}

/// `PUT /api/v1/calendar/calendars/{id}`
#[utoipa::path(
    put,
    path = "/api/v1/calendar/calendars/{id}",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path)),
    request_body = CalendarUpdate,
    responses(
        (status = 200, body = CalendarView),
        (status = 403, description = "Only the owner renames"),
    )
)]
pub async fn update(
    State(state): State<AppState>,
    user: AuthAccount,
    Path(id): Path<Uuid>,
    Json(input): Json<CalendarUpdate>,
) -> AppResult<Json<CalendarView>> {
    let user_id = trusted_uuid(&user.account_id)?;
    limited(user_id)?;
    if let Some(defaults) = &input.default_reminders {
        let most =
            usize::try_from(CALENDAR_DEFAULT_REMINDERS.load(&state.pool).await?).unwrap_or(5);
        crate::calendar_reminders::check(&defaults.timed, false, most)
            .and_then(|()| crate::calendar_reminders::check(&defaults.all_day, true, most))
            .map_err(|reason| coded(AppError::bad_request(reason), "invalidReminders"))?;
    }
    let metadata = input
        .metadata
        .as_ref()
        .map(|metadata| metadata.to_sealed().map_err(crypto))
        .transpose()?;
    let mut tx = state.pool.begin().await?;
    // The calendar's row first, as every other change locks it (a sync, a
    // sharing change): never the member's before it.
    sqlx::query("SELECT id FROM calendars WHERE id = $1 FOR UPDATE")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let member: Option<(i32, Uuid, Vec<u8>, i64)> = sqlx::query_as(
        "SELECT m.permissions, c.owner_account_id, k.public_key, c.bytes
           FROM calendar_members m JOIN calendars c ON c.id = m.calendar_id
           JOIN calendar_keys k ON k.calendar_id = c.id AND k.key_generation = c.key_generation
          WHERE m.calendar_id = $1 AND m.account_id = $2
          FOR UPDATE OF m",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((permissions, owner, public_key, old_bytes)) = member else {
        return Err(AppError::not_found("not found"));
    };
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
        crate::storage_pool::charge_within_quota(&mut tx, owner, new_metadata - old_metadata)
            .await?;
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
    if let Some(defaults) = &input.default_reminders {
        sqlx::query(
            "UPDATE calendar_members SET default_reminders_timed = $3, default_reminders_all_day = $4
              WHERE calendar_id = $1 AND account_id = $2",
        )
        .bind(id)
        .bind(user_id)
        .bind(serde_json::to_value(&defaults.timed).expect("reminders serialize"))
        .bind(serde_json::to_value(&defaults.all_day).expect("reminders serialize"))
        .execute(&mut *tx)
        .await?;
        // The member's alarms follow, recomputed by the job (a calendar
        // may hold many events).
        crate::calendar_alarms::queue_recompute(&mut tx, user_id, Some(id))
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
    }
    if let Some(share_busy) = input.share_busy {
        // Busy times are answered from the calendars a person owns: a
        // member can't show the owner's (docs/plans/calendar-e3.md §4).
        if permissions & SUPER_OWNER == 0 {
            return Err(coded(
                AppError::forbidden("only a calendar's owner shows its busy times"),
                "notOwner",
            ));
        }
        sqlx::query(
            "UPDATE calendar_members SET share_busy = $3 WHERE calendar_id = $1 AND account_id = $2",
        )
        .bind(id)
        .bind(user_id)
        .bind(share_busy)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(Json(fetch(&state, user_id, id).await?))
}

/// `DELETE /api/v1/calendar/calendars/{id}` — the owner deletes a calendar and
/// every event in it.
#[utoipa::path(
    delete,
    path = "/api/v1/calendar/calendars/{id}",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path)),
    responses((status = 204), (status = 403), (status = 404))
)]
pub async fn delete(
    State(state): State<AppState>,
    user: AuthAccount,
    Path(id): Path<Uuid>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.account_id)?;
    limited(user_id)?;
    let mut tx = state.pool.begin().await?;
    let found: Option<(i32, Uuid, i64)> = sqlx::query_as(
        "SELECT m.permissions, c.owner_account_id,
                (c.bytes
                 + COALESCE((SELECT SUM(bytes) FROM calendar_events e WHERE e.calendar_id = c.id), 0)
                 + COALESCE((SELECT SUM(bytes) FROM calendar_shared_events se
                              WHERE se.home_calendar_id = c.id), 0))::bigint
           FROM calendar_members m JOIN calendars c ON c.id = m.calendar_id
          WHERE m.calendar_id = $1 AND m.account_id = $2
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
    // Every other member is told, once (docs/plans/calendar-e3.md §1).
    sqlx::query(
        "INSERT INTO calendar_member_tombstones (calendar_id, account_id, reason)
         SELECT calendar_id, account_id, 'deleted' FROM calendar_members
          WHERE calendar_id = $1 AND account_id <> $2
         ON CONFLICT (calendar_id, account_id)
            DO UPDATE SET reason = EXCLUDED.reason, created_at = now()",
    )
    .bind(id)
    .bind(owner)
    .execute(&mut *tx)
    .await?;
    // Attendees' copies of its invitations go first, each given back.
    crate::handlers::calendar_invitations::refund_copies_homed_in(&mut tx, &[id]).await?;
    sqlx::query("DELETE FROM calendars WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    crate::storage_pool::charge(&mut *tx, crate::storage_pool::Payer::Account(owner), -bytes)
        .await?;
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
    /// A repeating event's last end, as the server expanded it from both
    /// parts (absent for one without end); a client checks it against its
    /// own expansion, as it checks the start.
    #[serde(with = "time::serde::rfc3339::option")]
    pub range_end_utc: Option<time::OffsetDateTime>,
    pub sequence: i32,
    /// The stored version: a change names it as its `baseRevision`.
    pub revision: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub modified_at: time::OffsetDateTime,
    /// The caller's own reminders for it; null: their calendar's defaults.
    #[schema(value_type = Option<Vec<crate::calendar_reminders::Reminder>>)]
    pub reminders: Option<Vec<crate::calendar_reminders::Reminder>>,
    /// The shared row (Proton's `SharedEventID`): what answers name.
    pub shared_event_id: Uuid,
    /// This calendar is the event's home (the organizer's, or an event
    /// without one); otherwise an attendee's own copy of an invitation.
    pub home: bool,
    /// Who signed the calendar parts when not the author: an attendee's
    /// own copy is signed by the attendee (docs/plans/calendar-e4.md §6).
    pub calendar_author_address: Option<String>,
    /// The attendee part, when the event is an invitation (sealed under
    /// the shared session key).
    #[schema(value_type = Option<Object>)]
    pub attendees: Option<cal::EventPartV1>,
    /// Each attendee's row: their keyed token, optional, and their sealed
    /// answer once given.
    pub attendee_rows: Vec<crate::handlers::calendar_invitations::AttendeeRowView>,
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
pub(crate) struct EventRow {
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
    range_end_utc: Option<time::OffsetDateTime>,
    sequence: i32,
    revision: i64,
    modified_at: time::OffsetDateTime,
    reminders: Option<serde_json::Value>,
    shared_event_id: Uuid,
    home: bool,
    calendar_author_address: Option<String>,
    attendees_encrypted: Option<Vec<u8>>,
    attendees_encrypted_signature: Option<String>,
    attendee_rows: serde_json::Value,
}

/// The events as their caller sees them, with the caller's own reminders:
/// the caller's id is bind parameter `$caller`.
pub(crate) fn event_view_sql(caller: u8) -> String {
    format!(
        "SELECT e.id, e.calendar_id, se.uid, a.address AS author_address,
        e.shared_key_packet, e.calendar_key_packet,
        se.shared_signed, se.shared_signed_signature,
        se.shared_encrypted, se.shared_encrypted_signature,
        e.calendar_signed, e.calendar_signed_signature,
        e.calendar_encrypted, e.calendar_encrypted_signature,
        se.start_utc, se.end_utc, se.full_day, se.range_end_utc, se.sequence, e.revision,
        GREATEST(e.modified_at, se.modified_at) AS modified_at, r.reminders,
        se.id AS shared_event_id, se.home_calendar_id = e.calendar_id AS home,
        ca.address AS calendar_author_address,
        se.attendees_encrypted, se.attendees_encrypted_signature,
        {} AS attendee_rows
   FROM calendar_events e
   JOIN calendar_shared_events se ON se.id = e.shared_event_id
   LEFT JOIN mail_addresses a ON a.id = se.author_address_id
   LEFT JOIN mail_addresses ca ON ca.id = e.author_address_id
   LEFT JOIN calendar_event_reminders r ON r.event_id = e.id AND r.account_id = ${caller}",
        crate::handlers::calendar_invitations::ATTENDEE_ROWS_SQL
    )
}

pub(crate) fn event_view(row: EventRow) -> EventView {
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
        range_end_utc: row.range_end_utc,
        sequence: row.sequence,
        revision: row.revision,
        modified_at: row.modified_at,
        // Stored as checked; one that no longer reads shows as the defaults.
        reminders: row
            .reminders
            .and_then(|list| serde_json::from_value(list).ok()),
        shared_event_id: row.shared_event_id,
        home: row.home,
        calendar_author_address: row.calendar_author_address,
        attendees: row
            .attendees_encrypted
            .zip(row.attendees_encrypted_signature)
            .map(|(data, signature)| cal::EventPartV1 {
                data: STANDARD.encode(data),
                signature,
            }),
        attendee_rows: crate::handlers::calendar_invitations::attendee_rows(row.attendee_rows),
    }
}

/// The caller's permissions on a calendar, or 404 (a calendar the caller
/// isn't a member of doesn't exist for it).
pub(crate) async fn member_permissions(
    conn: &mut sqlx::PgConnection,
    user_id: Uuid,
    calendar: Uuid,
) -> AppResult<i32> {
    sqlx::query_scalar(
        "SELECT permissions FROM calendar_members WHERE calendar_id = $1 AND account_id = $2",
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

/// Whether an event meets the window `[$2, $3)`: it starts before its end
/// and ends (or, repeating, may still recur) after its start; or it is a
/// changed occurrence (a `RECURRENCE-ID`) of a series whose occurrence it
/// replaces meets the window, wherever it was moved to, so a client drawing
/// the series there knows the series no longer occurs at that instant
/// (Proton's `recurrenceInstances`). The occurrence replaced lasts what the
/// series' first does, a day more for zone offsets; a client keeps what
/// meets the window.
pub(crate) const MEETS_WINDOW: &str = "((se.start_utc < $3
            AND COALESCE(se.range_end_utc, 'infinity'::timestamptz) >= $2)
         OR (se.recurrence_id IS NOT NULL AND se.recurrence_id < $3
            AND se.recurrence_id + interval '1 day' + COALESCE(
                (SELECT max(p.end_utc - p.start_utc) FROM calendar_events pe
                   JOIN calendar_shared_events p ON p.id = pe.shared_event_id
                  WHERE pe.calendar_id = e.calendar_id AND p.uid = se.uid
                    AND p.recurrence_id IS NULL), interval '0') >= $2))";

pub(crate) fn instant(value: &str, what: &str) -> AppResult<time::OffsetDateTime> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map_err(|_| AppError::bad_request(format!("{what} is not an RFC 3339 time")))
}

/// `GET /api/v1/calendar/calendars/{id}/events?start&end` — the events that
/// meet a window, oldest start first, paged.
#[utoipa::path(
    get,
    path = "/api/v1/calendar/calendars/{id}/events",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path), EventsQuery),
    responses((status = 200, body = EventPage), (status = 404))
)]
pub async fn events(
    State(state): State<AppState>,
    user: AuthAccount,
    Path(id): Path<Uuid>,
    Query(query): Query<EventsQuery>,
) -> AppResult<Json<EventPage>> {
    let user_id = trusted_uuid(&user.account_id)?;
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
    // of no length meets it when it starts in it, so an event (or a series'
    // last occurrence) ending at the window's start is listed too (the
    // client keeps what meets the window). A page continues after the
    // client's cursor by (start, id).
    let mut rows: Vec<EventRow> = sqlx::query_as(&format!(
        "{}
          WHERE e.calendar_id = $1 AND {}
            AND ($4::timestamptz IS NULL OR (se.start_utc, e.id) > ($4, $5))
          ORDER BY se.start_utc, e.id
          LIMIT $6",
        event_view_sql(7),
        MEETS_WINDOW
    ))
    .bind(id)
    .bind(start)
    .bind(end)
    .bind(after.map(|(at, _)| at))
    .bind(after.map(|(_, id)| id))
    .bind(limit + 1)
    .bind(user_id)
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

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct SeriesQuery {
    /// The series' UID.
    pub uid: String,
    /// The `next` of the previous page, both or neither.
    pub after_start: Option<String>,
    pub after_id: Option<Uuid>,
}

/// `GET /api/v1/calendar/calendars/{id}/events/by-uid?uid` — every event
/// of a calendar with one UID: a series and its changed occurrences,
/// wherever they are (Proton's `queryEvents({ UID })`, read before a
/// series is changed or deleted), oldest start first, paged.
#[utoipa::path(
    get,
    path = "/api/v1/calendar/calendars/{id}/events/by-uid",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path), SeriesQuery),
    responses((status = 200, body = EventPage), (status = 404))
)]
pub async fn events_by_uid(
    State(state): State<AppState>,
    user: AuthAccount,
    Path(id): Path<Uuid>,
    Query(query): Query<SeriesQuery>,
) -> AppResult<Json<EventPage>> {
    let user_id = trusted_uuid(&user.account_id)?;
    if query.uid.is_empty() || query.uid.chars().count() > kutup_crypto::calendar_event::MAX_UID_LEN
    {
        return Err(AppError::bad_request("uid is 1 to 255 characters"));
    }
    let after = match (&query.after_start, query.after_id) {
        (Some(at), Some(id)) => Some((instant(at, "afterStart")?, id)),
        (None, None) => None,
        _ => return Err(AppError::bad_request("afterStart and afterId go together")),
    };
    let limit = CALENDAR_EVENTS_PAGE.load(&state.pool).await?;
    let mut conn = state.pool.acquire().await?;
    let permissions = member_permissions(&mut conn, user_id, id).await?;
    if permissions & READ == 0 {
        return Err(AppError::forbidden("this calendar shows busy times only"));
    }
    let mut rows: Vec<EventRow> = sqlx::query_as(&format!(
        "{}
          WHERE e.calendar_id = $1 AND se.uid = $2
            AND ($3::timestamptz IS NULL OR (se.start_utc, e.id) > ($3, $4))
          ORDER BY se.start_utc, e.id
          LIMIT $5",
        event_view_sql(6)
    ))
    .bind(id)
    .bind(&query.uid)
    .bind(after.map(|(at, _)| at))
    .bind(after.map(|(_, id)| id))
    .bind(limit + 1)
    .bind(user_id)
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

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct AllEventsQuery {
    /// The `next` of the previous page.
    pub after_id: Option<Uuid>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AllEventsPage {
    pub events: Vec<EventView>,
    /// Pass as `afterId` for the next page; none when this was the last.
    pub next: Option<Uuid>,
}

/// `GET /api/v1/calendar/calendars/{id}/events/all` — every event of a
/// calendar, paged by id, whenever it is: what an export opens and writes
/// (docs/plans/calendar.md, E2 §6).
#[utoipa::path(
    get,
    path = "/api/v1/calendar/calendars/{id}/events/all",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path), AllEventsQuery),
    responses((status = 200, body = AllEventsPage), (status = 403), (status = 404))
)]
pub async fn all_events(
    State(state): State<AppState>,
    user: AuthAccount,
    Path(id): Path<Uuid>,
    Query(query): Query<AllEventsQuery>,
) -> AppResult<Json<AllEventsPage>> {
    let user_id = trusted_uuid(&user.account_id)?;
    let page = CALENDAR_EVENTS_PAGE.load(&state.pool).await?;
    let limit = query.limit.unwrap_or(page).clamp(1, page);
    let mut conn = state.pool.acquire().await?;
    let permissions = member_permissions(&mut conn, user_id, id).await?;
    if permissions & READ == 0 {
        return Err(AppError::forbidden("this calendar shows busy times only"));
    }
    let mut rows: Vec<EventRow> = sqlx::query_as(&format!(
        "{}
          WHERE e.calendar_id = $1 AND ($2::uuid IS NULL OR e.id > $2)
          ORDER BY e.id
          LIMIT $3",
        event_view_sql(4)
    ))
    .bind(id)
    .bind(query.after_id)
    .bind(limit + 1)
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await?;
    let next = (rows.len() as i64 > limit).then(|| {
        rows.truncate(limit as usize);
        rows.last().map(|row| row.id)
    });
    Ok(Json(AllEventsPage {
        events: rows.into_iter().map(event_view).collect(),
        next: next.flatten(),
    }))
}

/// `GET /api/v1/calendar/calendars/{id}/events/{eventId}`
#[utoipa::path(
    get,
    path = "/api/v1/calendar/calendars/{id}/events/{eventId}",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path), ("eventId" = Uuid, Path)),
    responses((status = 200, body = EventView), (status = 404))
)]
pub async fn event(
    State(state): State<AppState>,
    user: AuthAccount,
    Path((id, event_id)): Path<(Uuid, Uuid)>,
) -> AppResult<Json<EventView>> {
    let user_id = trusted_uuid(&user.account_id)?;
    let mut conn = state.pool.acquire().await?;
    if member_permissions(&mut conn, user_id, id).await? & READ == 0 {
        return Err(AppError::forbidden("this calendar shows busy times only"));
    }
    let row: Option<EventRow> = sqlx::query_as(&format!(
        "{} WHERE e.calendar_id = $1 AND e.id = $2",
        event_view_sql(3)
    ))
    .bind(id)
    .bind(event_id)
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await?;
    row.map(event_view)
        .map(Json)
        .ok_or_else(|| AppError::not_found("not found"))
}

/// One change in an events sync (Proton's `SyncMultipleEvents`):
/// `{"create": {"id", "event"}}`, `{"update": {"id", "baseRevision",
/// "event"}}` or `{"delete": {"id", "baseRevision"}}`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum EventChange {
    /// `id`: drawn by the client (a UUID v4), so a create retried after it
    /// landed answers the stored event instead of making a second one.
    #[serde(rename_all = "camelCase")]
    Create {
        id: Uuid,
        event: SealedEventV1,
        /// The caller's own reminders for it; absent: their calendar's defaults.
        #[serde(default)]
        reminders: Option<Vec<crate::calendar_reminders::Reminder>>,
        /// An import's (Proton's `Overwrite: 1`): an event of this calendar
        /// with the same UID and RECURRENCE-ID is written over, keeping its
        /// id, unless its SEQUENCE is ahead (`sequenceBehind`).
        #[serde(default)]
        overwrite: bool,
        /// An event with an ORGANIZER: its attendees (docs/plans/calendar-e4.md).
        #[serde(default)]
        invitation: Option<crate::handlers::calendar_invitations::InvitationIn>,
    },
    /// `base_revision`: the event's stored revision the change was made
    /// from; another is `409 revisionConflict`.
    #[serde(rename_all = "camelCase")]
    Update {
        id: Uuid,
        base_revision: i64,
        event: SealedEventV1,
        /// The caller's reminders: absent keeps them, null goes back to the
        /// calendar's defaults, a list replaces them.
        #[serde(default, deserialize_with = "present")]
        reminders: Option<Option<Vec<crate::calendar_reminders::Reminder>>>,
        /// An event with an ORGANIZER: its whole attendee list again.
        #[serde(default)]
        invitation: Option<crate::handlers::calendar_invitations::InvitationIn>,
    },
    /// Names the revision it was made from, as an update does, so a delete
    /// never removes a change another device just saved.
    #[serde(rename_all = "camelCase")]
    Delete { id: Uuid, base_revision: i64 },
}

/// A field that was sent, null or not (`None` only when absent).
fn present<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

/// What a sync change does to the caller's reminders for its event.
enum RemindersChange<'a> {
    Keep,
    Defaults,
    Own(&'a [crate::calendar_reminders::Reminder]),
}

/// Checks and applies the caller's reminders for an event, then recomputes
/// its alarms (every member's: the event changed).
async fn reminders_then_alarms(
    tx: &mut Transaction<'_, Postgres>,
    event: Uuid,
    user_id: Uuid,
    change: RemindersChange<'_>,
) -> AppResult<()> {
    match change {
        RemindersChange::Keep => {}
        RemindersChange::Defaults => {
            sqlx::query(
                "DELETE FROM calendar_event_reminders WHERE event_id = $1 AND account_id = $2",
            )
            .bind(event)
            .bind(user_id)
            .execute(&mut **tx)
            .await?;
        }
        RemindersChange::Own(list) => {
            sqlx::query(
                "INSERT INTO calendar_event_reminders (event_id, account_id, reminders)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (event_id, account_id) DO UPDATE SET reminders = EXCLUDED.reminders",
            )
            .bind(event)
            .bind(user_id)
            .bind(serde_json::to_value(list).expect("reminders serialize"))
            .execute(&mut **tx)
            .await?;
        }
    }
    crate::calendar_alarms::recompute(tx, event)
        .await
        .map_err(|error| AppError::internal(error.to_string()))
}

/// A changed occurrence made or changed: its series' alarms skip the
/// occurrence it replaces (or, its `RECURRENCE-ID` the same, still do).
async fn series_alarms(
    tx: &mut Transaction<'_, Postgres>,
    calendar: Uuid,
    checked: &Checked,
) -> AppResult<()> {
    if checked.recurrence_id.is_none() {
        return Ok(());
    }
    crate::calendar_alarms::recompute_series(tx, calendar, &checked.shared.uid)
        .await
        .map_err(|error| AppError::internal(error.to_string()))
}

fn check_reminders(
    list: Option<&[crate::calendar_reminders::Reminder]>,
    checked: &Checked,
    most: usize,
) -> AppResult<()> {
    if let Some(list) = list {
        crate::calendar_reminders::check(list, checked.shared.dtstart.is_date(), most)
            .map_err(|reason| coded(AppError::bad_request(reason), "invalidReminders"))?;
    }
    Ok(())
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
    /// ORGANIZER is the address that signed the event (the organizer's own
    /// invitation); `Some(false)`: an outside organizer's invitation kept as
    /// its attendee's own event; `None`: no organizer.
    organized_by_author: Option<bool>,
    shared: SharedSigned,
    start: time::OffsetDateTime,
    end: time::OffsetDateTime,
    /// The last occurrence's end as this calendar shows the series; `None`
    /// for one without end.
    range_end: Option<time::OffsetDateTime>,
    /// A changed occurrence: the instant it replaces.
    recurrence_id: Option<time::OffsetDateTime>,
    /// What the shared row holds (the shared parts) and the calendar's own
    /// row (its key packets and its parts); `bytes` is both.
    shared_bytes: i64,
    own_bytes: i64,
    bytes: i64,
}

/// An event time as the instant it names (`EventTime::instant`, the
/// bundled time zone database).
fn to_time(time: &EventTime) -> AppResult<time::OffsetDateTime> {
    let seconds = time.instant().map_err(crypto)?.as_second();
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|_| AppError::bad_request("a time is out of range"))
}

pub(crate) fn coded(error: AppError, code: &str) -> AppError {
    error.with_details(serde_json::json!({ "code": code }))
}

fn from_seconds(seconds: i64) -> AppResult<time::OffsetDateTime> {
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|_| AppError::bad_request("a time is out of range"))
}

/// Checks a sealed event for a calendar and its author's keys, and reads
/// its columns, the series expanded once for its range end (bounded: the
/// format's 1970–2037 range and 500 EXDATEs). An organizer is the author's
/// own address (E4).
fn check_event(
    event: &SealedEventV1,
    calendar_public_key: &[u8],
    author_keys: &[Vec<u8>],
    author_address: &str,
    max_count: i64,
) -> AppResult<Checked> {
    let event = event.to_event().map_err(crypto)?;
    // Written under the newest key generation only: one under an older key
    // is a member's client that missed a rotation (or a removed member's).
    if cal::event_key_id(&event).map_err(crypto)?
        != cal::encryption_key_id(calendar_public_key).map_err(crypto)?
    {
        return Err(coded(
            AppError::conflict("the event is not to the calendar's newest key; reload it"),
            "keyRotated",
        ));
    }
    cal::check_sealed_shape(&event, calendar_public_key).map_err(crypto)?;
    let authors: Vec<&[u8]> = author_keys.iter().map(Vec::as_slice).collect();
    let (shared, calendar) = cal::check_signed_parts(&event, &authors).map_err(crypto)?;
    let organized_by_author = shared.organizer.as_deref().map(|organizer| {
        kutup_crypto::calendar_event::canonical_email(organizer)
            == kutup_crypto::calendar_event::canonical_email(author_address)
    });
    // This calendar's own EXDATEs (Proton's calendar part) remove
    // occurrences of the shared series, and only those: each is one of its
    // occurrences, in its form; together with the shared ones at least one
    // occurrence is left (docs/plans/calendar.md, E2b item 3).
    let rule = shared
        .rrule
        .as_deref()
        .map(Rule::parse)
        .transpose()
        .map_err(crypto)?;
    if rule
        .as_ref()
        .and_then(|rule| rule.count)
        .is_some_and(|count| i64::from(count) > max_count)
    {
        return Err(coded(
            AppError::bad_request(format!(
                "a series repeats at most {max_count} times by COUNT"
            )),
            "countTooLarge",
        ));
    }
    if !calendar.exdates.is_empty() {
        let Some(rule) = rule.as_ref() else {
            return Err(coded(
                AppError::bad_request("an EXDATE removes an occurrence of a repeating event"),
                "exdateNotAnOccurrence",
            ));
        };
        let bare =
            Series::new(&shared.dtstart, shared.dtend.as_ref(), Some(rule), &[]).map_err(crypto)?;
        if !bare.occurs_at_all(&calendar.exdates).map_err(crypto)? {
            return Err(coded(
                AppError::bad_request("an EXDATE is not an occurrence of the series"),
                "exdateNotAnOccurrence",
            ));
        }
    }
    let mut exdates = shared.exdates.clone();
    for exdate in &calendar.exdates {
        if !exdates.contains(exdate) {
            exdates.push(exdate.clone());
        }
    }
    let series = Series::new(
        &shared.dtstart,
        shared.dtend.as_ref(),
        rule.as_ref(),
        &exdates,
    )
    .map_err(crypto)?;
    let range_end = series
        .range_end()
        .map_err(crypto)?
        .map(|at| from_seconds(at.as_second()))
        .transpose()?;
    let recurrence_id = shared.recurrence_id.as_ref().map(to_time).transpose()?;
    let start = to_time(&shared.dtstart)?;
    let end = match &shared.dtend {
        Some(end) => to_time(end)?,
        // RFC 5545: a date without an end is one day; a time, no length.
        None if shared.dtstart.is_date() => start + time::Duration::days(1),
        None => start,
    };
    let size = |parts: &[Option<&cal::EventPart>]| -> usize {
        parts
            .iter()
            .flatten()
            .map(|part| part.data.len() + part.signature.len())
            .sum()
    };
    let shared_bytes = size(&[Some(&event.shared_signed), Some(&event.shared_encrypted)]) as i64;
    let own_bytes = (event.shared_key_packet.len()
        + event.calendar_key_packet.len()
        + size(&[
            Some(&event.calendar_signed),
            event.calendar_encrypted.as_ref(),
        ])) as i64;
    let bytes = shared_bytes + own_bytes;
    Ok(Checked {
        event,
        organized_by_author,
        shared,
        start,
        end,
        range_end,
        recurrence_id,
        shared_bytes,
        own_bytes,
        bytes,
    })
}

/// [`check_event`] on a blocking thread: a series' checks are CPU work, kept
/// off the server's async threads and done before the calendar is locked.
async fn check_event_blocking(
    event: &SealedEventV1,
    calendar_public_key: &[u8],
    author_keys: &[Vec<u8>],
    author_address: &str,
    max_count: i64,
) -> AppResult<Checked> {
    let (event, public_key, author_keys, address) = (
        event.clone(),
        calendar_public_key.to_vec(),
        author_keys.to_vec(),
        author_address.to_owned(),
    );
    tokio::task::spawn_blocking(move || {
        check_event(&event, &public_key, &author_keys, &address, max_count)
    })
    .await
    .map_err(|error| AppError::internal(error.to_string()))?
}

/// `POST /api/v1/calendar/calendars/{id}/events/sync` — creates, changes and
/// deletes events, each alone (Proton's sync): one result per change.
#[utoipa::path(
    post,
    path = "/api/v1/calendar/calendars/{id}/events/sync",
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
    user: AuthAccount,
    Path(id): Path<Uuid>,
    Json(input): Json<EventSync>,
) -> AppResult<Json<EventSyncResults>> {
    let user_id = trusted_uuid(&user.account_id)?;
    limited(user_id)?;
    let batch = CALENDAR_SYNC_BATCH.load(&state.pool).await?;
    if input.changes.is_empty() || input.changes.len() as i64 > batch {
        return Err(AppError::bad_request(format!(
            "a sync carries 1 to {batch} changes"
        )));
    }
    // The newest key generation: an event is written under it only, so a
    // removed member's stale client can't keep writing under an old key
    // (docs/plans/calendar-e3.md, "Decisions").
    let (public_key, owner, generation): (Vec<u8>, Uuid, i32) = {
        let mut conn = state.pool.acquire().await?;
        if member_permissions(&mut conn, user_id, id).await? & WRITE == 0 {
            return Err(AppError::forbidden(
                "you may not change this calendar's events",
            ));
        }
        sqlx::query_as(
            "SELECT k.public_key, c.owner_account_id, c.key_generation FROM calendars c
               JOIN calendar_keys k ON k.calendar_id = c.id AND k.key_generation = c.key_generation
              WHERE c.id = $1",
        )
        .bind(id)
        .fetch_one(&mut *conn)
        .await?
    };
    let (author_keys, author_address) = {
        let mut conn = state.pool.acquire().await?;
        let keys = address_keys(&mut conn, user_id, input.address_id).await?;
        let address: String =
            sqlx::query_scalar("SELECT address FROM mail_addresses WHERE id = $1")
                .bind(input.address_id)
                .fetch_one(&mut *conn)
                .await?;
        (keys, address)
    };
    let max_events = CALENDAR_EVENTS_PER_CALENDAR.load(&state.pool).await?;
    let max_count = CALENDAR_MAX_COUNT.load(&state.pool).await?;
    let most_reminders =
        usize::try_from(CALENDAR_REMINDERS_PER_EVENT.load(&state.pool).await?).unwrap_or(10);
    let mut results = Vec::with_capacity(input.changes.len());
    for change in &input.changes {
        let outcome = apply(
            &state,
            id,
            owner,
            user_id,
            input.address_id,
            (&public_key, generation),
            (&author_keys, &author_address),
            max_events,
            max_count,
            most_reminders,
            change,
        )
        .await;
        results.push(match outcome {
            Ok(Some(event_id)) => {
                let row: EventRow =
                    sqlx::query_as(&format!("{} WHERE e.id = $1", event_view_sql(2)))
                        .bind(event_id)
                        .bind(user_id)
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
    (public_key, generation): (&[u8], i32),
    (author_keys, author_address): (&[Vec<u8>], &str),
    max_events: i64,
    max_count: i64,
    most_reminders: usize,
    change: &EventChange,
) -> AppResult<Option<Uuid>> {
    use crate::handlers::calendar_invitations as invitations;
    // The parts checked first, before the calendar is locked.
    let checked = match change {
        EventChange::Create { id, .. } if id.get_version_num() != 4 => {
            return Err(AppError::bad_request("an event's id is a UUID v4"));
        }
        EventChange::Create { event, .. } | EventChange::Update { event, .. } => Some(
            check_event_blocking(event, public_key, author_keys, author_address, max_count).await?,
        ),
        EventChange::Delete { .. } => None,
    };
    // An event with an ORGANIZER carries its attendees, and only one does;
    // only the calendar's owner invites (never from a calendar shared with
    // them, as Proton's).
    let invitation = match (change, &checked) {
        (
            EventChange::Create { invitation, .. } | EventChange::Update { invitation, .. },
            Some(checked),
        ) => match (checked.shared.organizer.is_some(), invitation) {
            (false, None) => None,
            (true, Some(_)) | (false, Some(_)) if owner != user_id => {
                return Err(coded(
                    AppError::forbidden("invitations are sent from your own calendars"),
                    "notOwnCalendar",
                ))
            }
            (true, Some(invitation)) => {
                // Kutup attendees get the event at once only from the
                // organizer itself: an attendee's own copy of an outside
                // invitation (ORGANIZER someone else) reaches no one.
                if checked.organized_by_author != Some(true) && !invitation.invitees.is_empty() {
                    return Err(coded(
                        AppError::bad_request("only the organizer's own event reaches invitees"),
                        "organizerNotAuthor",
                    ));
                }
                Some(invitations::check_invitation(state, user_id, invitation).await?)
            }
            (true, None) | (false, Some(_)) => {
                return Err(coded(
                    AppError::bad_request("an event with an organizer carries its attendees"),
                    "invitationMismatch",
                ))
            }
        },
        _ => None,
    };
    let mut tx = state.pool.begin().await?;
    // The calendar row orders the calendar's writes (the count, the UID),
    // and under it the caller is still a member who may write: a calendar
    // deleted or a member removed since the sync began is 404 or 403.
    let permissions: Option<(i32, i32)> = sqlx::query_as(
        "SELECT m.permissions, c.key_generation FROM calendars c
           JOIN calendar_members m ON m.calendar_id = c.id AND m.account_id = $2
          WHERE c.id = $1
          FOR UPDATE OF c",
    )
    .bind(calendar)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    match permissions {
        None => return Err(AppError::not_found("not found")),
        Some((permissions, _)) if permissions & WRITE == 0 => {
            return Err(AppError::forbidden(
                "you may not change this calendar's events",
            ))
        }
        // The key rotated since the parts were checked: they are to an old
        // generation's key.
        Some((_, newest)) if checked.is_some() && newest != generation => {
            return Err(coded(
                AppError::conflict("the calendar's key changed; reload it"),
                "keyRotated",
            ))
        }
        Some(_) => {}
    }
    let result = match change {
        EventChange::Create {
            id,
            reminders,
            overwrite,
            ..
        } => {
            let checked = checked.expect("checked above");
            check_reminders(reminders.as_deref(), &checked, most_reminders)?;
            // A create retried after it landed: the same id and parts are
            // the stored event; the id holding anything else is taken. Only
            // this calendar's events are read; an id another calendar holds
            // is taken all the same (the insert says so).
            type Stored = (String, String, String, String, Vec<u8>);
            let stored: Option<Stored> = sqlx::query_as(
                "SELECT se.shared_signed, se.shared_signed_signature,
                        e.calendar_signed, e.calendar_signed_signature, se.shared_encrypted
                   FROM calendar_events e JOIN calendar_shared_events se ON se.id = e.shared_event_id
                  WHERE e.id = $1 AND e.calendar_id = $2",
            )
            .bind(id)
            .bind(calendar)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some((shared, shared_signature, own, own_signature, encrypted)) = stored {
                let event = &checked.event;
                let same = shared.as_bytes() == event.shared_signed.data.as_slice()
                    && shared_signature == event.shared_signed.signature
                    && own.as_bytes() == event.calendar_signed.data.as_slice()
                    && own_signature == event.calendar_signed.signature
                    && encrypted == event.shared_encrypted.data;
                if same {
                    return Ok(Some(*id));
                }
                return Err(coded(
                    AppError::conflict("another event has this id"),
                    "eventIdTaken",
                ));
            }
            let change = match reminders {
                Some(list) => RemindersChange::Own(list),
                None => RemindersChange::Keep,
            };
            if *overwrite {
                let same: Option<Uuid> = sqlx::query_scalar(
                    "SELECT e.id FROM calendar_events e
                       JOIN calendar_shared_events se ON se.id = e.shared_event_id
                      WHERE e.calendar_id = $1 AND se.home_calendar_id = $1 AND se.uid = $2
                        AND se.recurrence_id IS NOT DISTINCT FROM $3",
                )
                .bind(calendar)
                .bind(&checked.shared.uid)
                .bind(checked.recurrence_id)
                .fetch_optional(&mut *tx)
                .await?;
                if let Some(same) = same {
                    rewrite(
                        &mut tx,
                        (calendar, owner, user_id, address_id),
                        same,
                        None,
                        &checked,
                        None,
                    )
                    .await?;
                    reminders_then_alarms(&mut tx, same, user_id, change).await?;
                    tx.commit().await?;
                    return Ok(Some(same));
                }
            }
            check_parent(&mut tx, calendar, &checked, false).await?;
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM calendar_events WHERE calendar_id = $1")
                    .bind(calendar)
                    .fetch_one(&mut *tx)
                    .await?;
            if count >= max_events {
                return Err(AppError::conflict("this calendar is full")
                    .with_details(serde_json::json!({ "code": "eventLimit" })));
            }
            let invitation_bytes = invitation.as_ref().map_or(0, |i| i.bytes());
            crate::storage_pool::charge_within_quota(
                &mut tx,
                owner,
                checked.bytes + invitation_bytes,
            )
            .await?;
            let id = insert(&mut tx, *id, calendar, user_id, address_id, &checked).await?;
            if invitation.is_some() {
                invitations::write_invitation(&mut tx, id, invitation.as_ref()).await?;
                sqlx::query("UPDATE calendar_shared_events SET bytes = bytes + $2 WHERE id = $1")
                    .bind(id)
                    .bind(invitation_bytes)
                    .execute(&mut *tx)
                    .await?;
            }
            reminders_then_alarms(&mut tx, id, user_id, change).await?;
            series_alarms(&mut tx, calendar, &checked).await?;
            Some(id)
        }
        EventChange::Update {
            id,
            base_revision,
            reminders,
            ..
        } => {
            let checked = checked.expect("checked above");
            check_reminders(
                reminders.as_ref().and_then(|r| r.as_deref()),
                &checked,
                most_reminders,
            )?;
            rewrite(
                &mut tx,
                (calendar, owner, user_id, address_id),
                *id,
                Some(*base_revision),
                &checked,
                invitation.as_ref(),
            )
            .await?;
            let change = match reminders {
                None => RemindersChange::Keep,
                Some(None) => RemindersChange::Defaults,
                Some(Some(list)) => RemindersChange::Own(list),
            };
            reminders_then_alarms(&mut tx, *id, user_id, change).await?;
            series_alarms(&mut tx, calendar, &checked).await?;
            Some(*id)
        }
        EventChange::Delete { id, base_revision } => {
            debug_assert!(checked.is_none());
            type Current = (i64, i64, Uuid, i64, bool, String, bool);
            let current: Option<Current> = sqlx::query_as(
                "SELECT e.revision, e.bytes, se.id, se.bytes, se.home_calendar_id = e.calendar_id,
                        se.uid, se.recurrence_id IS NOT NULL
                   FROM calendar_events e JOIN calendar_shared_events se ON se.id = e.shared_event_id
                  WHERE e.id = $1 AND e.calendar_id = $2
                  FOR UPDATE OF e, se",
            )
            .bind(id)
            .bind(calendar)
            .fetch_optional(&mut *tx)
            .await?;
            let Some((revision, own_bytes, shared_id, shared_bytes, home, uid, changed)) = current
            else {
                return Err(AppError::not_found("not found"));
            };
            if revision != *base_revision {
                return Err(revisions::conflict(
                    "this event was changed elsewhere",
                    revision,
                ));
            }
            // Deleted in its home calendar, the shared row goes (with every
            // calendar's copy: their owners get back what each held);
            // elsewhere only this calendar's copy (an attendee's own).
            let bytes = if home {
                invitations::refund_copies(&mut tx, shared_id).await?;
                sqlx::query("DELETE FROM calendar_shared_events WHERE id = $1")
                    .bind(shared_id)
                    .execute(&mut *tx)
                    .await?;
                own_bytes + shared_bytes
            } else {
                sqlx::query("DELETE FROM calendar_events WHERE id = $1")
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
                own_bytes
            };
            crate::storage_pool::charge(
                &mut *tx,
                crate::storage_pool::Payer::Account(owner),
                -bytes,
            )
            .await?;
            // A changed occurrence gone: the series reminds of it again.
            if changed {
                crate::calendar_alarms::recompute_series(&mut tx, calendar, &uid)
                    .await
                    .map_err(|error| AppError::internal(error.to_string()))?;
            }
            None
        }
    };
    tx.commit().await?;
    Ok(result)
}

/// Writes a checked event over the stored event `id` this calendar is home
/// to, in place: its ids, creation time and every member's reminders stay,
/// and so do the rows that hang off its shared row (an invitation's
/// attendees, their answers, and the attendees' own copies, docs/plans/
/// calendar-e4.md §6). An update made from `base_revision`, or (none) an
/// import overwriting the event with its UID (Proton's `Overwrite`).
async fn rewrite(
    tx: &mut Transaction<'_, Postgres>,
    (calendar, owner, user_id, address_id): (Uuid, Uuid, Uuid, Uuid),
    id: Uuid,
    base_revision: Option<i64>,
    checked: &Checked,
    invitation: Option<&crate::handlers::calendar_invitations::CheckedInvitation>,
) -> AppResult<()> {
    type Current = (
        Uuid,
        String,
        i64,
        i64,
        i32,
        Option<time::OffsetDateTime>,
        Option<Uuid>,
        bool,
    );
    // Only an event this calendar is home to is changed here; an
    // attendee's copy is the organizer's to change.
    let current: Option<Current> = sqlx::query_as(
        "SELECT se.id, se.uid, (e.bytes + se.bytes)::bigint, e.revision,
                se.sequence, se.recurrence_id, se.author_account_id,
                se.attendees_encrypted IS NOT NULL
           FROM calendar_events e JOIN calendar_shared_events se ON se.id = e.shared_event_id
          WHERE e.id = $1 AND e.calendar_id = $2 AND se.home_calendar_id = $2
          FOR UPDATE OF e, se",
    )
    .bind(id)
    .bind(calendar)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((shared_id, uid, old_bytes, revision, sequence, recurrence_id, author, invited)) =
        current
    else {
        return Err(AppError::not_found("not found"));
    };
    // An invitation is its organizer's (the owner who sent it) to change:
    // a member writing to the calendar can't rewrite what attendees got.
    if invited && (author != Some(user_id) || owner != user_id) {
        return Err(coded(
            AppError::forbidden("only the organizer changes an invitation"),
            "notOrganizer",
        ));
    }
    if uid != checked.shared.uid {
        return Err(AppError::bad_request("an event keeps its UID"));
    }
    // A series stays a series and a changed occurrence the one it
    // changes (Proton's): never one turned into the other.
    if recurrence_id != checked.recurrence_id {
        return Err(coded(
            AppError::bad_request("an event keeps its RECURRENCE-ID"),
            "recurrenceIdChanged",
        ));
    }
    // A changed occurrence whose series is gone stays a single
    // event, and can still be changed.
    check_parent(tx, calendar, checked, true).await?;
    // Made from the stored version, never an older one replayed nor
    // over another device's newer save.
    if base_revision.is_some_and(|base| base != revision) {
        return Err(revisions::conflict(
            "this event was changed elsewhere",
            revision,
        ));
    }
    if i64::from(checked.shared.sequence) < i64::from(sequence) {
        return Err(AppError::conflict("an event's SEQUENCE never goes down")
            .with_details(serde_json::json!({ "code": "sequenceBehind" })));
    }
    let invitation_bytes = invitation.map_or(0, |i| i.bytes());
    crate::storage_pool::charge_within_quota(
        tx,
        owner,
        checked.bytes + invitation_bytes - old_bytes,
    )
    .await?;
    let event = &checked.event;
    let text = |data: &[u8]| String::from_utf8(data.to_vec()).expect("checked as text");
    let shared = &checked.shared;
    sqlx::query(
        "UPDATE calendar_shared_events SET author_address_id = $2, author_account_id = $3,
                shared_signed = $4, shared_signed_signature = $5,
                shared_encrypted = $6, shared_encrypted_signature = $7,
                start_utc = $8, end_utc = $9, start_tz = $10, end_tz = $11, full_day = $12,
                rrule = $13, range_end_utc = $14, sequence = $15, revision = revision + 1,
                bytes = $16, modified_at = now()
          WHERE id = $1",
    )
    .bind(shared_id)
    .bind(address_id)
    .bind(user_id)
    .bind(text(&event.shared_signed.data))
    .bind(&event.shared_signed.signature)
    .bind(&event.shared_encrypted.data)
    .bind(&event.shared_encrypted.signature)
    .bind(checked.start)
    .bind(checked.end)
    .bind(shared.dtstart.tzid())
    .bind(shared.dtend.as_ref().and_then(EventTime::tzid))
    .bind(shared.dtstart.is_date())
    .bind(&shared.rrule)
    .bind(checked.range_end)
    .bind(shared.sequence.min(i32::MAX as u32) as i32)
    .bind(checked.shared_bytes + invitation_bytes)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE calendar_events SET shared_key_packet = $2, calendar_key_packet = $3,
                calendar_signed = $4, calendar_signed_signature = $5,
                calendar_encrypted = $6, calendar_encrypted_signature = $7,
                revision = $8, bytes = $9, modified_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .bind(&event.shared_key_packet)
    .bind(&event.calendar_key_packet)
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
    .bind(revision + 1)
    .bind(checked.own_bytes)
    .execute(&mut **tx)
    .await?;
    crate::handlers::calendar_invitations::write_invitation(tx, shared_id, invitation).await?;
    // The attendees' copies follow the new times.
    crate::handlers::calendar_invitations::recompute_copies(tx, shared_id).await?;
    Ok(())
}

/// A changed occurrence (Proton's single edit) belongs to a series in the
/// calendar: the same UID, no RECURRENCE-ID, a rule; its RECURRENCE-ID is
/// one of the series' occurrences (an excluded one too: the change replaces
/// it); and its SEQUENCE is not behind the series'. A series deleted later
/// leaves its changes as single events: `orphan_ok` (a change of an existing
/// one) lets them be changed still.
async fn check_parent(
    tx: &mut Transaction<'_, Postgres>,
    calendar: Uuid,
    checked: &Checked,
    orphan_ok: bool,
) -> AppResult<()> {
    let Some(recurrence_id) = checked.shared.recurrence_id.clone() else {
        return Ok(());
    };
    let parent: Option<String> = sqlx::query_scalar(
        "SELECT se.shared_signed FROM calendar_events e
           JOIN calendar_shared_events se ON se.id = e.shared_event_id
          WHERE e.calendar_id = $1 AND se.uid = $2 AND se.recurrence_id IS NULL
            AND se.rrule IS NOT NULL",
    )
    .bind(calendar)
    .bind(&checked.shared.uid)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(parent) = parent else {
        if orphan_ok {
            return Ok(());
        }
        return Err(coded(
            AppError::bad_request("a changed occurrence needs its series in the calendar"),
            "parentMissing",
        ));
    };
    let stored = || AppError::internal("a stored series doesn't parse");
    let parent = SharedSigned::parse(&parent).map_err(|_| stored())?;
    let rule = parent
        .rrule
        .as_deref()
        .map(Rule::parse)
        .transpose()
        .map_err(|_| stored())?;
    if checked.shared.sequence < parent.sequence {
        return Err(AppError::conflict(
            "a changed occurrence's SEQUENCE is not behind its series'",
        )
        .with_details(serde_json::json!({ "code": "sequenceBehind" })));
    }
    let bare = Series::new(&parent.dtstart, parent.dtend.as_ref(), rule.as_ref(), &[])
        .map_err(|_| stored())?;
    // Off the async thread, as the event's own checks.
    let occurs = tokio::task::spawn_blocking(move || {
        bare.occurs_at_all(std::slice::from_ref(&recurrence_id))
    })
    .await
    .map_err(|error| AppError::internal(error.to_string()))?
    .map_err(crypto)?;
    if !occurs {
        return Err(coded(
            AppError::bad_request("RECURRENCE-ID is not an occurrence of the series"),
            "notAnOccurrence",
        ));
    }
    Ok(())
}

/// The ids, creation time and next revision of an event written again.
struct Kept {
    id: Uuid,
    shared_id: Uuid,
    created_at: time::OffsetDateTime,
    revision: i64,
}

async fn insert(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    calendar: Uuid,
    user_id: Uuid,
    address_id: Uuid,
    checked: &Checked,
) -> AppResult<Uuid> {
    // A new event's shared row takes its id: the calendar is its home.
    let kept = Kept {
        id,
        shared_id: id,
        created_at: time::OffsetDateTime::now_utc(),
        revision: 1,
    };
    insert_as(tx, kept, calendar, user_id, address_id, checked).await
}

/// Inserts a checked event in the calendar it is home to: its shared row,
/// then the calendar's own.
async fn insert_as(
    tx: &mut Transaction<'_, Postgres>,
    kept: Kept,
    calendar: Uuid,
    user_id: Uuid,
    address_id: Uuid,
    checked: &Checked,
) -> AppResult<Uuid> {
    let event = &checked.event;
    let text = |data: &[u8]| String::from_utf8(data.to_vec()).expect("checked as text");
    let shared = &checked.shared;
    let taken = |error: sqlx::Error| match &error {
        // The id is another calendar's event's.
        sqlx::Error::Database(db)
            if db.is_unique_violation()
                && matches!(
                    db.constraint(),
                    Some("calendar_shared_events_pkey" | "calendar_events_pkey")
                ) =>
        {
            coded(
                AppError::conflict("another event has this id"),
                "eventIdTaken",
            )
        }
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            AppError::conflict("an event with this UID is in the calendar")
                .with_details(serde_json::json!({ "code": "uidTaken" }))
        }
        _ => error.into(),
    };
    sqlx::query(
        "INSERT INTO calendar_shared_events (id, home_calendar_id, uid, author_address_id,
             author_account_id, shared_signed, shared_signed_signature,
             shared_encrypted, shared_encrypted_signature,
             start_utc, end_utc, start_tz, end_tz, full_day, rrule, recurrence_id, range_end_utc,
             sequence, revision, bytes, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                 $18, $19, $20, $21)",
    )
    .bind(kept.shared_id)
    .bind(calendar)
    .bind(&shared.uid)
    .bind(address_id)
    .bind(user_id)
    .bind(text(&event.shared_signed.data))
    .bind(&event.shared_signed.signature)
    .bind(&event.shared_encrypted.data)
    .bind(&event.shared_encrypted.signature)
    .bind(checked.start)
    .bind(checked.end)
    .bind(shared.dtstart.tzid())
    .bind(shared.dtend.as_ref().and_then(EventTime::tzid))
    .bind(shared.dtstart.is_date())
    .bind(&shared.rrule)
    .bind(checked.recurrence_id)
    .bind(checked.range_end)
    .bind(shared.sequence.min(i32::MAX as u32) as i32)
    .bind(kept.revision)
    .bind(checked.shared_bytes)
    .bind(kept.created_at)
    .execute(&mut **tx)
    .await
    .map_err(taken)?;
    sqlx::query_scalar(
        "INSERT INTO calendar_events (id, calendar_id, shared_event_id,
             shared_key_packet, calendar_key_packet,
             calendar_signed, calendar_signed_signature,
             calendar_encrypted, calendar_encrypted_signature,
             revision, bytes, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
         RETURNING id",
    )
    .bind(kept.id)
    .bind(calendar)
    .bind(kept.shared_id)
    .bind(&event.shared_key_packet)
    .bind(&event.calendar_key_packet)
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
    .bind(kept.revision)
    .bind(checked.own_bytes)
    .bind(kept.created_at)
    .fetch_one(&mut **tx)
    .await
    .map_err(taken)
}
