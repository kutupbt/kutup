//! One device list per account (docs/plans/one-device-list.md): the
//! account's `devices` rows against its signed V3 manifest. Every device of
//! every kind (a Chat app, an editing app, the CLI) is a row with a server
//! issued id and credential, and an entry in the manifest the account
//! authority signs; a row is live while it is listed.

use axum::extract::State;
use axum::Json;
use kutup_chat_proto::{device_session_hash, AccountManifestV3, DeviceKind};
use serde::Serialize;
use sqlx::{PgConnection, PgExecutor};
use utoipa::ToSchema;
use uuid::Uuid;

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

/// Every entry `manifest` lists, except `except` (a device the caller
/// inserts after, in the same transaction), is a live row of the account
/// with the entry's kind, sign-in, frame key, and Chat keys (by `chat`): an
/// entry the server can't back, or one naming another sign-in than its row's,
/// is refused (`409`). Run under the account's lock.
pub(crate) async fn check_listed_rows(
    conn: &mut PgConnection,
    user_id: Uuid,
    manifest: &AccountManifestV3,
    except: Option<u32>,
    chat: ChatKeys,
) -> AppResult<()> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(i32, String, Uuid, Option<Vec<u8>>, Option<i16>, Option<i64>)> = sqlx::query_as(
        "SELECT device_id, kind, session_id, frame_key, suite, registration_id
               FROM devices WHERE user_id = $1 AND expired_at IS NULL
              ORDER BY device_id FOR SHARE",
    )
    .bind(user_id)
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
/// ([`crate::site_settings::DEVICES_PER_ACCOUNT`]): `409 deviceLimit`.
pub(crate) async fn check_device_cap<'e>(
    executor: impl PgExecutor<'e>,
    manifest: &AccountManifestV3,
) -> AppResult<()> {
    let most = crate::site_settings::DEVICES_PER_ACCOUNT
        .load(executor)
        .await?;
    if manifest.devices.len() as i64 > most {
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
