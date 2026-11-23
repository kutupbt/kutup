//! One device list per account (docs/plans/one-device-list.md): the
//! account's `account_devices` rows against its signed V3 manifest. Every device of
//! every kind (a Chat app, an editing app, the CLI) is a row with a server
//! issued id and credential, and an entry in the manifest the account
//! authority signs; a row is live while it is listed.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use kutup_chat_proto::{
    device_session_hash, AccountDeviceV1, AccountManifestV3, DeviceKind, DeviceTicketResponse,
    RegisterDeviceRequestV1, RegisterDeviceResponseV1,
};
use kutup_crypto::account_ref::AccountRef;
use kutup_crypto::primitives::{hash, Suite};
use serde::Serialize;
use sqlx::{PgConnection, PgExecutor};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::handlers::chat_identity::{self, DeviceKinds};

use crate::error::{AppError, AppResult};
use crate::middleware::AuthAccount;
use crate::AppState;

/// The device's root sign-in: an app session's parent (the account sign-in
/// it was opened under), or the session itself (the CLI, a native app, the
/// Account app). Its devices group, and end, with it.
pub(crate) async fn root_session_id<'e>(
    executor: impl PgExecutor<'e>,
    session_id: Uuid,
) -> AppResult<Uuid> {
    let root: Option<Uuid> = sqlx::query_scalar(
        "SELECT COALESCE(parent_session_id, id) FROM auth_sessions WHERE id = $1",
    )
    .bind(session_id)
    .fetch_optional(executor)
    .await?;
    root.ok_or_else(|| AppError::unauthorized("session not found"))
}

/// What a manifest entry of a device of this sign-in carries as `session`.
pub(crate) fn session_hash(root_session_id: Uuid) -> String {
    device_session_hash(root_session_id.as_bytes())
}

/// `GET /api/v1/account/devices/session`'s answer.
pub use kutup_chat_proto::DeviceSessionResponseV1 as DeviceSessionResponse;

/// `GET /api/v1/account/devices/session` — the `session` hash a device of this sign-in
/// lists in its manifest entry, and the account's device counter. A device
/// asks before it signs its own entry (a re-registration, or adding itself
/// after a link).
#[utoipa::path(
    get,
    path = "/api/v1/account/devices/session",
    tag = "account",
    operation_id = "getDeviceSession",
    responses(
        (status = 200, description = "This sign-in's session hash", body = DeviceSessionResponse),
        (status = 401, description = "Not signed in"),
    ),
    security(("bearerAuth" = []))
)]
pub async fn get_device_session(
    State(state): State<AppState>,
    auth: AuthAccount,
) -> AppResult<Json<DeviceSessionResponse>> {
    let user_id = crate::handlers::trusted_uuid(&auth.account_id)?;
    let root = root_session_id(&state.pool, auth.session.session_id).await?;
    Ok(Json(DeviceSessionResponse {
        session: session_hash(root),
        next_device_id: device_counter(&state.pool, user_id).await?,
    }))
}

/// Which listed entries [`check_listed_rows`] compares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChatKeys {
    /// Every listed Chat device's registration id and suite are its row's.
    Match,
    /// The caller sets them from this request (an identity distribution).
    Set,
}

/// Which rows back a listed entry in [`check_listed_rows`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Backing {
    /// A live row: what a device publishes.
    Live,
    /// Any row, expired ones too: a re-registration carries the head's other
    /// devices over, and may not know which of them idled out (the next
    /// manifest drops those).
    Present,
}

/// Every entry `manifest` lists, except `except` (a device the caller
/// inserts after, in the same transaction), is a row of the account (live,
/// or by `backing`)
/// with the entry's kind, sign-in, frame key, and Chat keys (by `chat`): an
/// entry the server can't back, or one naming another sign-in than its row's,
/// is refused (`409`). Run under the account's lock.
pub(crate) async fn check_listed_rows(
    conn: &mut PgConnection,
    user_id: Uuid,
    manifest: &AccountManifestV3,
    except: Option<u32>,
    chat: ChatKeys,
    backing: Backing,
) -> AppResult<()> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(i32, String, Uuid, Option<Vec<u8>>, Option<i16>, Option<i64>)> = sqlx::query_as(
        "SELECT device_id, kind, session_id, frame_key, suite, registration_id
               FROM account_devices WHERE account_id = $1 AND ($2 OR expired_at IS NULL)
              ORDER BY device_id FOR SHARE",
    )
    .bind(user_id)
    .bind(backing == Backing::Present)
    .fetch_all(&mut *conn)
    .await?;
    for listed in &manifest.devices {
        if Some(listed.device_id) == except {
            continue;
        }
        let row = rows
            .iter()
            .find(|(device_id, ..)| *device_id as u32 == listed.device_id);
        let Some((_, kind, session_id, frame_key, suite, registration_id)) = row else {
            return Err(devices_conflict());
        };
        let frame_key_listed = listed
            .frame_key
            .as_deref()
            .map(kutup_chat_proto::decode_frame_key)
            .transpose()
            .map_err(AppError::bad_request)?;
        let chat_holds = match (&listed.chat, suite, registration_id) {
            (None, None, None) => true,
            (Some(keys), Some(suite), Some(registration_id)) => match chat {
                ChatKeys::Match => {
                    keys.direct_chat_suite.as_u16() == *suite as u16
                        && i64::from(keys.registration_id) == *registration_id
                }
                ChatKeys::Set => true,
            },
            _ => false,
        };
        if DeviceKind::parse(kind).ok().as_ref() != Some(&listed.kind)
            || session_hash(*session_id) != listed.session
            || frame_key_listed.as_ref().map(|key| key.as_slice()) != frame_key.as_deref()
            || !chat_holds
        {
            return Err(devices_conflict());
        }
    }
    Ok(())
}

/// The manifest lists no more devices than the account may have
/// ([`crate::site_settings::DEVICES_PER_ACCOUNT`]), or no more than `head`
/// did: a cap lowered below an account's count still lets it publish one
/// that removes devices. `409 deviceLimit` otherwise.
pub(crate) async fn check_device_cap<'e>(
    executor: impl PgExecutor<'e>,
    user_id: Uuid,
    manifest: &AccountManifestV3,
    head: Option<&AccountManifestV3>,
) -> AppResult<()> {
    let listed = manifest.devices.len();
    if head.is_some_and(|head| listed <= head.devices.len()) {
        return Ok(());
    }
    let most = crate::site_settings::DEVICES_PER_ACCOUNT
        .load_for(executor, user_id)
        .await?;
    if listed as i64 > most {
        return Err(device_limit());
    }
    Ok(())
}

/// The account's next device id (docs/plans/one-device-list.md, "Device
/// ids"): the first id at or after `accounts.next_device_id` that no row in
/// `taken` holds and no head entry lists (its row gone, revoked or ended with
/// its sign-in, until the next manifest drops it), wrapping from 127 to 1;
/// the counter then moves past it. So an id comes back only after every
/// other free id has had its turn, never at once as the lowest free id did;
/// ids are libsignal's 1..=127, so reuse itself stays, as in Signal.
///
/// An id freed less than `hold_seconds` ago (`account_device_releases`, kept
/// by a trigger on every deletion of a row) is passed over too while another
/// is free: a sender certificate its earlier holder was issued names the id,
/// and could otherwise be taken for the new holder's. When only such ids are
/// free, the counter's choice among them is taken all the same: the device
/// cap holds, never a lockout below it.
///
/// What the id's earlier holder left under it goes in the same transaction,
/// as Signal's `AccountsManager.addDevice` clears the id's prekeys and
/// messages: its send records (a deterministic `sendId` of the new holder's
/// would otherwise be answered as a duplicate). Prekeys, mailbox, tickets,
/// push subscriptions, multi-send ids and link tokens go with the row
/// (`ON DELETE CASCADE`).
///
/// Run under the account's lock (`accounts … FOR UPDATE`), which serializes
/// concurrent registrations: each reads the counter the last one left.
/// `409 deviceLimit` when every id is held (the cap is below 127, so only
/// with stale entries the next manifest drops).
pub(crate) async fn take_device_id(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    taken: &[i32],
    hold_seconds: i64,
) -> AppResult<i32> {
    let next: i16 =
        sqlx::query_scalar("SELECT next_device_id FROM accounts WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_one(&mut **tx)
            .await?;
    let mut held: Vec<u32> = taken.iter().map(|id| *id as u32).collect();
    let entries: Vec<i32> = sqlx::query_scalar(
        "SELECT (listed ->> 'deviceId')::int
           FROM chat_device_manifests m, jsonb_array_elements(m.manifest -> 'devices') listed
          WHERE m.account_id = $1",
    )
    .bind(user_id)
    .fetch_all(&mut **tx)
    .await?;
    held.extend(entries.into_iter().map(|id| id as u32));
    let recent: Vec<i32> = sqlx::query_scalar(
        "SELECT device_id FROM account_device_releases
          WHERE account_id = $1 AND released_at > now() - ($2 * interval '1 second')",
    )
    .bind(user_id)
    .bind(hold_seconds)
    .fetch_all(&mut **tx)
    .await?;
    let mut held_longer = held.clone();
    held_longer.extend(recent.into_iter().map(|id| id as u32));
    let id = kutup_chat_proto::next_device_id(next as u32, &held_longer)
        .or_else(|| kutup_chat_proto::next_device_id(next as u32, &held))
        .ok_or_else(device_limit)?;
    claim_device_id(tx, user_id, id as i32).await?;
    sqlx::query(
        "DELETE FROM account_device_releases
          WHERE account_id = $1 AND released_at <= now() - ($2 * interval '1 second')",
    )
    .bind(user_id)
    .bind(hold_seconds)
    .execute(&mut **tx)
    .await?;
    Ok(id as i32)
}

/// Moves the account's counter past `id` and clears what an earlier holder
/// of `id` left that doesn't go with its row ([`take_device_id`]). A
/// re-registration, whose manifest names the id, calls it directly.
pub(crate) async fn claim_device_id(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    id: i32,
) -> AppResult<()> {
    sqlx::query("UPDATE accounts SET next_device_id = $2 WHERE id = $1")
        .bind(user_id)
        .bind(kutup_chat_proto::device_id_after(id as u32) as i16)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM chat_sends WHERE sender_account_id = $1 AND sender_device_id = $2")
        .bind(user_id)
        .bind(id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM account_device_releases WHERE account_id = $1 AND device_id = $2")
        .bind(user_id)
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// How long a freed device id is passed over ([`take_device_id`]): the reach
/// of a sender certificate, when this server issues them.
pub(crate) fn id_hold_seconds(state: &AppState) -> i64 {
    state
        .sealed_sender
        .as_ref()
        .map_or(0, |service| service.certificate_reach_seconds())
}

/// The account's device counter, for a re-registration to name the id the
/// server will require ([`kutup_chat_proto::next_device_id`]).
pub(crate) async fn device_counter<'e>(
    executor: impl PgExecutor<'e>,
    user_id: Uuid,
) -> AppResult<u32> {
    let next: i16 = sqlx::query_scalar("SELECT next_device_id FROM accounts WHERE id = $1")
        .bind(user_id)
        .fetch_one(executor)
        .await?;
    Ok(next as u32)
}

/// `409 deviceLimit`: the account has as many devices as it may.
pub(crate) fn device_limit() -> AppError {
    AppError::conflict("the account's device limit is reached")
        .with_details(serde_json::json!({ "code": "deviceLimit" }))
}

fn devices_conflict() -> AppError {
    AppError::conflict("manifest devices do not match the account's registered devices")
        .with_details(serde_json::json!({ "code": "devicesMismatch" }))
}

// ---------------------------------------------------------------------------
// Editor and CLI devices (slice 2)
// ---------------------------------------------------------------------------

/// `POST /api/v1/account/devices` — an editor or CLI device of the caller's account:
/// a row under the caller's sign-in with the account's next device id
/// ([`take_device_id`]), within
/// [`crate::site_settings::DEVICES_PER_ACCOUNT`]. The device then lists
/// itself in the account's manifest (`POST /api/v1/chat/manifest`); until it
/// does, its frames are refused, and a publication by another device after
/// `deviceListingGraceSeconds` drops the row. A retry with the same
/// credential answers the row it made.
#[utoipa::path(
    post,
    path = "/api/v1/account/devices",
    tag = "account",
    operation_id = "registerDevice",
    request_body = RegisterDeviceRequestV1,
    responses(
        (status = 200, description = "Registered", body = RegisterDeviceResponseV1),
        (status = 400, description = "Malformed kind, frame key or credential"),
        (status = 409, description = "deviceLimit: the account has as many devices as it may"),
    ),
    security(("bearerAuth" = []))
)]
pub async fn register_device(
    State(state): State<AppState>,
    auth: AuthAccount,
    Json(request): Json<RegisterDeviceRequestV1>,
) -> AppResult<Json<RegisterDeviceResponseV1>> {
    request.validate().map_err(AppError::bad_request)?;
    let user_id = crate::handlers::trusted_uuid(&auth.account_id)?;
    if !crate::ratelimit::DEVICE_REGISTRATIONS.allow(&user_id.to_string()) {
        return Err(AppError::too_many_requests("too many requests")
            .with_details(serde_json::json!({ "code": "rateLimited" })));
    }
    let frame_key =
        kutup_chat_proto::decode_frame_key(&request.frame_key).map_err(AppError::bad_request)?;
    let credential = kutup_chat_proto::decode_device_credential(&request.credential)
        .map_err(AppError::bad_request)?;
    let mut tx = state.pool.begin().await?;
    let root = root_session_id(&mut *tx, auth.session.session_id).await?;
    sqlx::query("SELECT id FROM accounts WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    let stale = prune_stale_unlisted(&mut tx, user_id).await?;
    let rows: Vec<(i32, Vec<u8>, Vec<u8>, bool)> = sqlx::query_as(
        "SELECT device_id, credential_salt, credential_hash, expired_at IS NOT NULL
           FROM account_devices WHERE account_id = $1 ORDER BY device_id",
    )
    .bind(user_id)
    .fetch_all(&mut *tx)
    .await?;
    let answer = |device_id: i32| RegisterDeviceResponseV1 {
        device_id: device_id as u32,
        session: session_hash(root),
    };
    if let Some((device_id, ..)) = rows.iter().find(|(_, salt, hash, expired)| {
        !expired
            && kutup_crypto::primitives::ct_eq(
                &chat_identity::credential_hash(salt, &credential),
                hash,
            )
    }) {
        tx.commit().await?;
        for id in stale {
            close_device(&state, user_id, id);
        }
        return Ok(Json(answer(*device_id)));
    }
    let live = rows.iter().filter(|(.., expired)| !expired).count() as i64;
    let most = crate::site_settings::DEVICES_PER_ACCOUNT
        .load_for(&mut *tx, user_id)
        .await?;
    if live >= most {
        return Err(device_limit());
    }
    let taken: Vec<i32> = rows.iter().map(|(id, ..)| *id).collect();
    let device_id = take_device_id(&mut tx, user_id, &taken, id_hold_seconds(&state)).await?;
    let (salt, credential_hash) = chat_identity::new_credential(&credential);
    sqlx::query(
        "INSERT INTO account_devices (account_id, device_id, kind, session_id, frame_key, name,
             credential_salt, credential_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(user_id)
    .bind(device_id)
    .bind(request.kind.as_str())
    .bind(root)
    .bind(&frame_key[..])
    // An unnamed device has no name (NULL), not ''.
    .bind((!request.name.is_empty()).then_some(&request.name))
    .bind(&salt[..])
    .bind(&credential_hash[..])
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    for id in stale {
        close_device(&state, user_id, id);
    }
    Ok(Json(answer(device_id)))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AccountDevicesResponse {
    pub devices: Vec<AccountDeviceV1>,
}

/// `GET /api/v1/account/devices` — every device of the caller's account, of every
/// kind, with whether the account's manifest lists it and whether it is of
/// the caller's sign-in.
#[utoipa::path(
    get,
    path = "/api/v1/account/devices",
    tag = "account",
    operation_id = "listDevices",
    responses((status = 200, description = "The account's devices", body = AccountDevicesResponse)),
    security(("bearerAuth" = []))
)]
pub async fn list_devices(
    State(state): State<AppState>,
    auth: AuthAccount,
) -> AppResult<Json<AccountDevicesResponse>> {
    let user_id = crate::handlers::trusted_uuid(&auth.account_id)?;
    let root = root_session_id(&state.pool, auth.session.session_id).await?;
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        i32,
        String,
        Option<String>,
        Uuid,
        bool,
        OffsetDateTime,
        Option<OffsetDateTime>,
    )> = sqlx::query_as(
        "SELECT device_id, kind, name, session_id, expired_at IS NOT NULL, created_at,
                    last_seen_at
               FROM account_devices WHERE account_id = $1 ORDER BY device_id",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    let head = crate::handlers::chat::stored_manifest(&state.pool, user_id).await?;
    let format = |at: OffsetDateTime| at.format(&Rfc3339).unwrap_or_default();
    let devices = rows
        .into_iter()
        .filter_map(
            |(device_id, kind, name, session_id, expired, created, seen)| {
                Some(AccountDeviceV1 {
                    device_id: device_id as u32,
                    kind: DeviceKind::parse(&kind).ok()?,
                    name: name.unwrap_or_default(),
                    session: session_hash(session_id),
                    this_sign_in: session_id == root,
                    listed: head
                        .as_ref()
                        .is_some_and(|head| head.device(device_id as u32).is_some()),
                    expired,
                    created_at: format(created),
                    last_seen_at: seen.map(format),
                })
            },
        )
        .collect();
    Ok(Json(AccountDevicesResponse { devices }))
}

// ---------------------------------------------------------------------------
// Socket tickets
// ---------------------------------------------------------------------------

/// How long a socket ticket stays usable, in seconds.
const TICKET_TTL_SECONDS: i64 = 60;

fn ticket_hash(ticket: &str) -> String {
    hex::encode(hash(Suite::V1, ticket.as_bytes()))
}

/// `POST /api/v1/account/devices/tickets` — a single-use, short-lived WebSocket
/// credential for the device `X-Kutup-Device` names (browsers can't set
/// headers on a socket): the Chat socket takes one of a Chat device, the
/// collab sockets one of a device with a frame key. Only its hash is kept.
#[utoipa::path(
    post,
    path = "/api/v1/account/devices/tickets",
    tag = "account",
    operation_id = "createDeviceTicket",
    responses(
        (status = 200, description = "One-time ticket", body = DeviceTicketResponse),
        (status = 401, description = "deviceCredential"),
    ),
    security(("bearerAuth" = []))
)]
pub async fn create_device_ticket(
    State(state): State<AppState>,
    auth: AuthAccount,
    headers: HeaderMap,
) -> AppResult<Json<DeviceTicketResponse>> {
    let user_id = crate::handlers::trusted_uuid(&auth.account_id)?;
    let device_id =
        chat_identity::authenticated_device_of(&state.pool, &headers, user_id, DeviceKinds::Any)
            .await?;
    let ticket = crate::handlers::random_token(32);
    let expires_at: OffsetDateTime = sqlx::query_scalar(
        "INSERT INTO account_device_tickets (token_hash, account_id, device_id, expires_at)
         VALUES ($1, $2, $3, now() + ($4 * interval '1 second'))
         RETURNING expires_at",
    )
    .bind(ticket_hash(&ticket))
    .bind(user_id)
    .bind(device_id)
    .bind(TICKET_TTL_SECONDS)
    .fetch_one(&state.pool)
    .await?;
    Ok(Json(DeviceTicketResponse {
        ticket,
        expires_at: expires_at.format(&Rfc3339).unwrap_or_default(),
    }))
}

/// The account and device a ticket was minted for, consumed.
pub(crate) async fn consume_ticket(state: &AppState, ticket: &str) -> AppResult<(Uuid, i32)> {
    if ticket.is_empty() || ticket.len() > 128 {
        return Err(AppError::unauthorized("invalid WebSocket ticket"));
    }
    sqlx::query_as(
        "DELETE FROM account_device_tickets
         WHERE token_hash = $1 AND expires_at > now()
         RETURNING account_id, device_id",
    )
    .bind(ticket_hash(ticket))
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::unauthorized("invalid or expired WebSocket ticket"))
}

// ---------------------------------------------------------------------------
// Devices that sign collab frames
// ---------------------------------------------------------------------------

/// A device whose collab frames count: a live row with a frame key, of a
/// live sign-in, that the account's head manifest lists with that key.
#[derive(Clone, Debug)]
pub(crate) struct FrameDevice {
    pub account_id: Uuid,
    pub device_id: u32,
    pub account: AccountRef,
    pub frame_key: [u8; 32],
    /// The device's root sign-in, rechecked while its sockets are open.
    pub session_id: Uuid,
    /// The head manifest's sequence: a frame naming a later one is refused.
    pub manifest_sequence: u64,
}

/// `user_id`'s device `device_id`, if its frames count now; `403
/// deviceNotAuthorized` otherwise (the client registers again).
pub(crate) async fn frame_device(
    state: &AppState,
    user_id: Uuid,
    device_id: i32,
) -> AppResult<FrameDevice> {
    let row: Option<(Vec<u8>, Uuid, i64)> = sqlx::query_as(
        "SELECT d.frame_key, d.session_id, m.version
           FROM account_devices d
           JOIN chat_device_manifests m ON m.account_id = d.account_id
           JOIN LATERAL jsonb_array_elements(m.manifest -> 'devices') listed ON true
          WHERE d.account_id = $1 AND d.device_id = $2 AND d.expired_at IS NULL
            AND d.frame_key IS NOT NULL
            AND (listed ->> 'deviceId')::int = d.device_id
            AND listed ->> 'frameKey' = kutup_b64(d.frame_key)
            AND EXISTS (SELECT 1 FROM auth_sessions s
                         WHERE s.id = d.session_id AND s.revoked_at IS NULL
                           AND s.expires_at > now())",
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_optional(&state.pool)
    .await?;
    let not_authorized = || {
        AppError::forbidden("this device is not listed, or its sign-in ended")
            .with_details(serde_json::json!({ "code": "deviceNotAuthorized" }))
    };
    let (frame_key, session_id, sequence) = row.ok_or_else(not_authorized)?;
    Ok(FrameDevice {
        account_id: user_id,
        device_id: device_id as u32,
        account: crate::account_ids::local(&state.config.chat_server_name, user_id)?,
        frame_key: frame_key.try_into().map_err(|_| not_authorized())?,
        session_id,
        manifest_sequence: sequence as u64,
    })
}

/// Drops the account's rows its head manifest doesn't list that are older
/// than the listing grace (`deviceListingGraceSeconds`): registrations that
/// never listed themselves. A registration runs this first, under the
/// account's row lock, so such rows hold neither the cap nor an id (a stolen
/// access token can't fill the account with them); only listed rows and
/// rows still within their grace count. Their ids, for [`close_device`]
/// once the transaction commits.
pub(crate) async fn prune_stale_unlisted(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> AppResult<Vec<i32>> {
    let grace = crate::site_settings::DEVICE_LISTING_GRACE_SECONDS
        .load(&mut **tx)
        .await?;
    Ok(sqlx::query_scalar(
        "DELETE FROM account_devices d
          WHERE d.account_id = $1
            AND d.created_at < now() - ($2 * interval '1 second')
            AND NOT EXISTS (
                SELECT 1 FROM chat_device_manifests m,
                       jsonb_array_elements(m.manifest -> 'devices') listed
                 WHERE m.account_id = d.account_id
                   AND (listed ->> 'deviceId')::int = d.device_id)
         RETURNING d.device_id",
    )
    .bind(user_id)
    .bind(grace)
    .fetch_all(&mut **tx)
    .await?)
}

/// Whether `device`'s frames still count as they did when its socket
/// connected, for the socket's periodic recheck: `Some(false)` on a definite
/// no (its row, its listing or its sign-in gone, or its id now another
/// key's), `None` when that can't be told now (tried again at the next tick).
/// A removal also closes the socket at once ([`close_device`]); this catches
/// a close that socket missed.
pub(crate) async fn still_counts(state: &AppState, device: &FrameDevice) -> Option<bool> {
    match frame_device(state, device.account_id, device.device_id as i32).await {
        Ok(now) => Some(now.frame_key == device.frame_key && now.session_id == device.session_id),
        Err(error) if error.status == axum::http::StatusCode::FORBIDDEN => Some(false),
        Err(_) => None,
    }
}

/// The frame device `X-Kutup-Device` names, beside the JWT of `headers`
/// (the collab routes over HTTP).
pub(crate) async fn frame_device_of_request(
    state: &AppState,
    headers: &HeaderMap,
) -> AppResult<FrameDevice> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty())
        .ok_or_else(|| AppError::unauthorized("missing token"))?;
    let auth = crate::middleware::authenticate_access_token(state, token)
        .await
        .map_err(|_| AppError::unauthorized("invalid token"))?;
    let user_id = crate::handlers::trusted_uuid(&auth.account_id)?;
    let device_id =
        chat_identity::authenticated_device_of(&state.pool, headers, user_id, DeviceKinds::Any)
            .await?;
    frame_device(state, user_id, device_id).await
}

/// Closes every socket of a device the account's manifest dropped: its Chat
/// socket and its collab rooms.
pub(crate) fn close_device(state: &AppState, user_id: Uuid, device_id: i32) {
    state.chat_hub.close_device(user_id, device_id);
    state
        .hub
        .close_device(&user_id.to_string(), device_id as u32);
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    /// A day, as a sender certificate's reach.
    const HOLD: i64 = 24 * 60 * 60;

    async fn pool() -> Option<sqlx::PgPool> {
        let Ok(url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return None;
        };
        Some(
            PgPoolOptions::new()
                .max_connections(10)
                .connect(&url)
                .await
                .unwrap(),
        )
    }

    async fn account(pool: &sqlx::PgPool) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO accounts (id, username, identity_suite, drive_key_binding_epoch,
                 master_key_generation)
             VALUES ($1, $2, 2, 1, 1)",
        )
        .bind(id)
        .bind(format!("dev{}", &id.simple().to_string()[..12]))
        .execute(pool)
        .await
        .unwrap();
        id
    }

    /// What a registration does: under the account's lock, the next id over
    /// the account's rows, and its row.
    async fn register(pool: &sqlx::PgPool, user_id: Uuid) -> AppResult<i32> {
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT id FROM accounts WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        let taken: Vec<i32> =
            sqlx::query_scalar("SELECT device_id FROM account_devices WHERE account_id = $1")
                .bind(user_id)
                .fetch_all(&mut *tx)
                .await?;
        let id = take_device_id(&mut tx, user_id, &taken, HOLD).await?;
        sqlx::query(
            "INSERT INTO account_devices (account_id, device_id, kind, session_id, frame_key,
                 credential_salt, credential_hash)
             VALUES ($1, $2, 'editor', $3, $4, $5, $6)",
        )
        .bind(user_id)
        .bind(id)
        .bind(Uuid::new_v4())
        .bind(&[id as u8; 32][..])
        .bind(&[0u8; 16][..])
        .bind(&[0u8; 32][..])
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    async fn remove(pool: &sqlx::PgPool, user_id: Uuid, id: i32) {
        sqlx::query("DELETE FROM account_devices WHERE account_id = $1 AND device_id = $2")
            .bind(user_id)
            .bind(id)
            .execute(pool)
            .await
            .unwrap();
    }

    /// A removed device's id goes to no new device while another is free,
    /// nor within its hold; what its holder left under the id (send records)
    /// goes when it does.
    #[tokio::test]
    async fn live_a_removed_id_comes_back_last() {
        let Some(pool) = pool().await else { return };
        let user_id = account(&pool).await;
        assert_eq!(register(&pool, user_id).await.unwrap(), 1);
        assert_eq!(register(&pool, user_id).await.unwrap(), 2);
        remove(&pool, user_id, 2).await;
        assert_eq!(register(&pool, user_id).await.unwrap(), 3);
        remove(&pool, user_id, 1).await;
        assert_eq!(register(&pool, user_id).await.unwrap(), 4);

        // An id the head manifest still lists, its row gone, is held too.
        sqlx::query(
            "INSERT INTO chat_device_manifests (account_id, version, manifest_hash,
                 authority_key_id, manifest)
             VALUES ($1, 1, decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'),
                     '{\"devices\": [{\"deviceId\": 5}]}'::jsonb)",
        )
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(register(&pool, user_id).await.unwrap(), 6);

        // Past 127 the counter wraps to the lowest free id from 1, passing
        // over ids freed within the hold (1 and 2, a sender certificate of
        // their earlier holders may still be taken).
        sqlx::query("UPDATE accounts SET next_device_id = 127 WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(register(&pool, user_id).await.unwrap(), 127);
        assert_eq!(register(&pool, user_id).await.unwrap(), 7);
        // Once the hold is over, 1 comes back, and the send records its
        // earlier holder left go with the claim.
        sqlx::query(
            "UPDATE account_device_releases SET released_at = now() - interval '2 days'
              WHERE account_id = $1",
        )
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE accounts SET next_device_id = 1 WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO chat_sends (sender_account_id, sender_device_id, send_id)
             VALUES ($1, 1, 'left-by-the-earlier-device-1')",
        )
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(register(&pool, user_id).await.unwrap(), 1);
        let sends: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM chat_sends WHERE sender_account_id = $1 AND sender_device_id = 1",
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(sends, 0, "the earlier holder's send records went");
        assert_eq!(device_counter(&pool, user_id).await.unwrap(), 2);
        let releases: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM account_device_releases WHERE account_id = $1",
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(releases, 0, "releases past the hold are dropped");

        // Only an id within its hold free: taken all the same (no lockout
        // below the cap).
        sqlx::query(
            "INSERT INTO account_devices (account_id, device_id, kind, session_id, frame_key,
                 credential_salt, credential_hash)
             SELECT $1, n, 'editor', gen_random_uuid(), decode(repeat('00', 32), 'hex'),
                    decode(repeat('00', 16), 'hex'), decode(repeat('00', 32), 'hex')
               FROM generate_series(1, 127) n
             ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
        remove(&pool, user_id, 40).await;
        assert_eq!(register(&pool, user_id).await.unwrap(), 40);

        // Every id held: refused (`deviceLimit`), never a held id.
        let refused = register(&pool, user_id).await.unwrap_err();
        assert_eq!(refused.status, axum::http::StatusCode::CONFLICT);

        // An account going away takes its rows with it: its devices leave no
        // releases behind (the trigger skips an account being deleted).
        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
        let left: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM account_device_releases WHERE account_id = $1",
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(left, 0);
    }

    /// Registrations at once each take their own id, in order: the account's
    /// lock serializes the counter.
    #[tokio::test]
    async fn live_concurrent_registrations_take_distinct_ids() {
        let Some(pool) = pool().await else { return };
        let user_id = account(&pool).await;
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let pool = pool.clone();
                tokio::spawn(async move { register(&pool, user_id).await.unwrap() })
            })
            .collect();
        let mut ids = Vec::new();
        for task in tasks {
            ids.push(task.await.unwrap());
        }
        ids.sort_unstable();
        assert_eq!(ids, (1..=8).collect::<Vec<i32>>());
        assert_eq!(device_counter(&pool, user_id).await.unwrap(), 9);
    }
}
