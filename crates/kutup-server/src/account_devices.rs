//! One device list per account (docs/plans/one-device-list.md): the
//! account's `devices` rows against its signed V3 manifest. Every device of
//! every kind (a Chat app, an editing app, the CLI) is a row with a server
//! issued id and credential, and an entry in the manifest the account
//! authority signs; a row is live while it is listed.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use kutup_chat_proto::{
    device_session_hash, AccountDeviceV1, AccountManifestV3, DeviceKind, DeviceTicketResponse,
    RegisterDeviceRequestV1, RegisterDeviceResponseV1, MAX_ACCOUNT_MANIFEST_DEVICES,
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
use crate::middleware::AuthUser;
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

#[derive(Debug, Serialize, ToSchema)]
pub struct DeviceSessionResponse {
    /// Lowercase hex: [`kutup_chat_proto::device_session_hash`] of the
    /// caller's root sign-in.
    pub session: String,
}

/// `GET /api/device-session` — the `session` hash a device of this sign-in
/// lists in its manifest entry. A device asks before it signs its own entry
/// (a re-registration, or adding itself after a link).
#[utoipa::path(
    get,
    path = "/api/device-session",
    tag = "devices",
    operation_id = "getDeviceSession",
    responses(
        (status = 200, description = "This sign-in's session hash", body = DeviceSessionResponse),
        (status = 401, description = "Not signed in"),
    ),
    security(("bearerAuth" = []))
)]
pub async fn get_device_session(
    State(state): State<AppState>,
    auth: AuthUser,
) -> AppResult<Json<DeviceSessionResponse>> {
    let root = root_session_id(&state.pool, auth.session.session_id).await?;
    Ok(Json(DeviceSessionResponse {
        session: session_hash(root),
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
               FROM devices WHERE user_id = $1 AND ($2 OR expired_at IS NULL)
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
        if DeviceKind::parse(kind).ok() != Some(listed.kind)
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

/// `POST /api/devices` — an editor or CLI device of the caller's account:
/// a row under the caller's sign-in with the lowest id no row holds, within
/// [`crate::site_settings::DEVICES_PER_ACCOUNT`]. The device then lists
/// itself in the account's manifest (`POST /api/chat/manifest`); until it
/// does, its frames are refused, and a publication by another device after
/// `deviceListingGraceSeconds` drops the row. A retry with the same
/// credential answers the row it made.
#[utoipa::path(
    post,
    path = "/api/devices",
    tag = "devices",
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
    auth: AuthUser,
    Json(request): Json<RegisterDeviceRequestV1>,
) -> AppResult<Json<RegisterDeviceResponseV1>> {
    request.validate().map_err(AppError::bad_request)?;
    let user_id = crate::handlers::trusted_uuid(&auth.user_id)?;
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
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    let rows: Vec<(i32, Vec<u8>, Vec<u8>, bool)> = sqlx::query_as(
        "SELECT device_id, credential_salt, credential_hash, expired_at IS NOT NULL
           FROM devices WHERE user_id = $1 ORDER BY device_id",
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
        return Ok(Json(answer(*device_id)));
    }
    let live = rows.iter().filter(|(.., expired)| !expired).count() as i64;
    let most = crate::site_settings::DEVICES_PER_ACCOUNT
        .load_for(&mut *tx, user_id)
        .await?;
    if live >= most {
        return Err(device_limit());
    }
    let device_id = (1..=MAX_ACCOUNT_MANIFEST_DEVICES as i32)
        .find(|id| !rows.iter().any(|(taken, ..)| taken == id))
        .ok_or_else(device_limit)?;
    let (salt, credential_hash) = chat_identity::new_credential(&credential);
    sqlx::query(
        "INSERT INTO devices (user_id, device_id, kind, session_id, frame_key, name,
             credential_salt, credential_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(user_id)
    .bind(device_id)
    .bind(request.kind.as_str())
    .bind(root)
    .bind(&frame_key[..])
    .bind(&request.name)
    .bind(&salt[..])
    .bind(&credential_hash[..])
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(answer(device_id)))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AccountDevicesResponse {
    pub devices: Vec<AccountDeviceV1>,
}

/// `GET /api/devices` — every device of the caller's account, of every
/// kind, with whether the account's manifest lists it and whether it is of
/// the caller's sign-in.
#[utoipa::path(
    get,
    path = "/api/devices",
    tag = "devices",
    operation_id = "listDevices",
    responses((status = 200, description = "The account's devices", body = AccountDevicesResponse)),
    security(("bearerAuth" = []))
)]
pub async fn list_devices(
    State(state): State<AppState>,
    auth: AuthUser,
) -> AppResult<Json<AccountDevicesResponse>> {
    let user_id = crate::handlers::trusted_uuid(&auth.user_id)?;
    let root = root_session_id(&state.pool, auth.session.session_id).await?;
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        i32,
        String,
        String,
        Uuid,
        bool,
        OffsetDateTime,
        Option<OffsetDateTime>,
    )> = sqlx::query_as(
        "SELECT device_id, kind, name, session_id, expired_at IS NOT NULL, created_at,
                    last_seen_at
               FROM devices WHERE user_id = $1 ORDER BY device_id",
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
                    name,
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

/// `POST /api/device-ticket` — a single-use, short-lived WebSocket
/// credential for the device `X-Kutup-Device` names (browsers can't set
/// headers on a socket): the Chat socket takes one of a Chat device, the
/// collab sockets one of a device with a frame key. Only its hash is kept.
#[utoipa::path(
    post,
    path = "/api/device-ticket",
    tag = "devices",
    operation_id = "createDeviceTicket",
    responses(
        (status = 200, description = "One-time ticket", body = DeviceTicketResponse),
        (status = 401, description = "deviceCredential"),
    ),
    security(("bearerAuth" = []))
)]
pub async fn create_device_ticket(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: HeaderMap,
) -> AppResult<Json<DeviceTicketResponse>> {
    let user_id = crate::handlers::trusted_uuid(&auth.user_id)?;
    let device_id =
        chat_identity::authenticated_device_of(&state.pool, &headers, user_id, DeviceKinds::Any)
            .await?;
    let ticket = crate::handlers::random_token(32);
    let expires_at: OffsetDateTime = sqlx::query_scalar(
        "INSERT INTO device_tickets (token_hash, user_id, device_id, expires_at)
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
        "DELETE FROM device_tickets
         WHERE token_hash = $1 AND expires_at > now()
         RETURNING user_id, device_id",
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
    pub user_id: Uuid,
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
           FROM devices d
           JOIN chat_device_manifests m ON m.user_id = d.user_id
           JOIN LATERAL jsonb_array_elements(m.manifest -> 'devices') listed ON true
          WHERE d.user_id = $1 AND d.device_id = $2 AND d.expired_at IS NULL
            AND d.frame_key IS NOT NULL
            AND (listed ->> 'deviceId')::int = d.device_id
            AND listed ->> 'frameKey' = encode(d.frame_key, 'base64')
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
        user_id,
        device_id: device_id as u32,
        account: crate::account_ids::local(&state.config.chat_server_name, user_id)?,
        frame_key: frame_key.try_into().map_err(|_| not_authorized())?,
        session_id,
        manifest_sequence: sequence as u64,
    })
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
    let user_id = crate::handlers::trusted_uuid(&auth.user_id)?;
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
