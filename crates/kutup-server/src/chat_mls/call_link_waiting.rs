//! A meeting's waiting room (docs/chat-calls.md, "The waiting room").
//!
//! With it on, holding the link no longer gets anyone into the meeting. This
//! server is where that is enforced, because it mints the SFU tokens:
//!
//! - a joiner **knocks** (the access token, a random identity, their sealed
//!   name) and gets a ticket only they hold;
//! - the meeting's **owner**, who alone can derive the host token, lists the
//!   people waiting and admits or turns away each one;
//! - the joiner asks how the knock went with their ticket, and an admitted
//!   one receives the SFU token.
//!
//! A knock whose joiner stopped asking is gone: it is no longer listed, and
//! old ones are removed. The owner reads the names (sealed under a key from
//! the link); this server cannot.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use super::call_link_moderation::{claim_seat, host, sfu_room, tend, Entry, HostCredentials};
use super::call_links::{
    admitted, base64_exact, hex32, owner, require_sfu, room_token, seat_hash, vouched_account,
    SEALED_NAME_BYTES,
};
use crate::error::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::AppState;

/// People who can wait at one meeting at a time.
const MAX_WAITING: i64 = 50;
/// A knocker who has not asked for this long has gone.
const PRESENT_SECONDS: i64 = 20;
/// Knocks are forgotten this long after the knocker last asked.
const FORGET_SECONDS: i64 = 10 * 60;

const WAITING: i16 = 0;
const ADMITTED: i16 = 1;
const TURNED_AWAY: i16 = 2;

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetWaitingRoomRequest {
    pub enabled: bool,
    /// SHA-256 of the owner's host token (standard base64, 32 bytes).
    pub host_token_hash: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KnockRequest {
    pub room_id: String,
    /// The link's access token (standard base64, 32 bytes).
    pub access_token: String,
    /// The joining browser's random identity (32 lowercase hex characters).
    pub participant_id: String,
    /// The joiner's chosen name, sealed (standard base64, 168 bytes).
    pub label: String,
    /// The secret of this identity's seat (standard base64, 32 bytes), as
    /// for a token.
    pub seat: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct KnockResponse {
    pub knock_id: Uuid,
    /// Only the knocker holds it (standard base64, 32 bytes): it asks how
    /// the knock went and collects the SFU token.
    pub ticket: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KnockStatusRequest {
    pub room_id: String,
    pub access_token: String,
    pub knock_id: Uuid,
    pub ticket: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct KnockStatusResponse {
    /// `waiting`, `admitted` or `turnedAway`.
    pub status: &'static str,
    /// With `admitted`: the SFU's WebSocket URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// With `admitted`: a LiveKit token for the meeting's room.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WaitingKnock {
    pub knock_id: Uuid,
    /// The knocker's sealed name.
    pub label: String,
    /// The account address this server vouches for, when the knocker is
    /// signed in here and chose to show it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String)]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WaitingKnocks {
    pub knocks: Vec<WaitingKnock>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DecideKnockRequest {
    pub room_id: String,
    pub access_token: String,
    /// The owner's host token, or
    #[serde(default)]
    pub host_token: Option<String>,
    /// a co-host's own SFU token.
    #[serde(default)]
    pub sfu_token: Option<String>,
    pub knock_id: Uuid,
    pub admit: bool,
}

/// Turn a meeting's waiting room on or off. Turning it off lets everyone
/// still waiting in.
#[utoipa::path(
    put,
    path = "/api/chat/call-links/{roomId}/waiting-room",
    tag = "chat",
    operation_id = "setChatCallLinkWaitingRoom",
    params(("roomId" = String, Path, description = "The link's room id")),
    request_body = SetWaitingRoomRequest,
    responses(
        (status = 204, description = "Set"),
        (status = 404, description = "No such link of this account"),
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn set_waiting_room(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    Json(request): Json<SetWaitingRoomRequest>,
) -> AppResult<StatusCode> {
    hex32("roomId", &room_id)?;
    let host_token_hash = base64_exact("hostTokenHash", &request.host_token_hash, 32)?;
    let mut tx = state.pool.begin().await?;
    let updated = sqlx::query(
        "UPDATE chat_call_links SET waiting_room = $3, host_token_hash = $4
         WHERE room_id = $1 AND owner_user_id = $2",
    )
    .bind(&room_id)
    .bind(owner(&auth)?)
    .bind(request.enabled)
    .bind(&host_token_hash)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if updated == 0 {
        return Err(AppError::not_found("call link not found"));
    }
    if !request.enabled {
        sqlx::query(
            "UPDATE chat_call_link_knocks SET status = $2 WHERE room_id = $1 AND status = $3",
        )
        .bind(&room_id)
        .bind(ADMITTED)
        .bind(WAITING)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Ask to be let into a meeting with a waiting room. No account.
#[utoipa::path(
    post,
    path = "/api/chat/call-links/knock",
    tag = "chat",
    operation_id = "knockChatCallLink",
    request_body = KnockRequest,
    responses(
        (status = 201, description = "Waiting to be admitted", body = KnockResponse),
        (status = 404, description = "No such link, or the wrong access token"),
        (status = 409, description = "The meeting has no waiting room: ask for a token"),
        (status = 423, description = "A host locked the meeting"),
        (status = 429, description = "Too many requests, or the waiting room is full"),
    )
)]
pub(crate) async fn knock(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<KnockRequest>,
) -> AppResult<(StatusCode, Json<KnockResponse>)> {
    require_sfu(&state)?;
    hex32("participantId", &request.participant_id)?;
    let label = base64_exact("label", &request.label, SEALED_NAME_BYTES)?;
    let seat_hash = seat_hash(&request.seat)?;
    let meeting = admitted(&state, &request.room_id, &request.access_token).await?;
    if !meeting.waiting_room {
        return Err(AppError::conflict("this meeting has no waiting room"));
    }
    if meeting.locked {
        return Err(AppError::new(
            StatusCode::LOCKED,
            "a host locked this meeting",
        ));
    }
    let account = vouched_account(&state, &headers).await;
    let mut ticket = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut ticket);
    let ticket_hash: [u8; 32] = Sha256::digest(ticket).into();

    let mut tx = state.pool.begin().await?;
    // One meeting's knocks in turn, so the count below holds.
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('chat_call_link_knocks:' || $1, 0))",
    )
    .bind(&request.room_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "DELETE FROM chat_call_link_knocks
         WHERE room_id = $1 AND last_seen_at < NOW() - make_interval(secs => $2)",
    )
    .bind(&request.room_id)
    .bind(FORGET_SECONDS as f64)
    .execute(&mut *tx)
    .await?;
    let waiting: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chat_call_link_knocks
         WHERE room_id = $1 AND status = $2 AND last_seen_at > NOW() - make_interval(secs => $3)",
    )
    .bind(&request.room_id)
    .bind(WAITING)
    .bind(PRESENT_SECONDS as f64)
    .fetch_one(&mut *tx)
    .await?;
    if waiting >= MAX_WAITING {
        return Err(AppError::too_many_requests("the waiting room is full"));
    }
    let knock_id: Uuid = sqlx::query_scalar(
        "INSERT INTO chat_call_link_knocks
            (room_id, participant_id, label, ticket_hash, seat_hash, account)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(&request.room_id)
    .bind(&request.participant_id)
    .bind(&label)
    .bind(ticket_hash.as_slice())
    .bind(seat_hash.as_slice())
    .bind(&account)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(KnockResponse {
            knock_id,
            ticket: STANDARD.encode(ticket),
        }),
    ))
}

/// How a knock went, for the knocker (who holds its ticket). An admitted one
/// receives the SFU token. Asking also says the knocker is still there.
#[utoipa::path(
    post,
    path = "/api/chat/call-links/knock/status",
    tag = "chat",
    operation_id = "getChatCallLinkKnockStatus",
    request_body = KnockStatusRequest,
    responses(
        (status = 200, description = "The knock's state", body = KnockStatusResponse),
        (status = 404, description = "No such link or knock, or the wrong access token or ticket"),
        (status = 429, description = "Too many requests"),
    )
)]
pub(crate) async fn knock_status(
    State(state): State<AppState>,
    Json(request): Json<KnockStatusRequest>,
) -> AppResult<Json<KnockStatusResponse>> {
    require_sfu(&state)?;
    let presented: [u8; 32] = Sha256::digest(base64_exact("ticket", &request.ticket, 32)?).into();
    let meeting = admitted(&state, &request.room_id, &request.access_token).await?;
    // ticket_hash, status, participant_id, label, seat_hash, account
    type Row = (Vec<u8>, i16, String, Vec<u8>, Vec<u8>, Option<String>);
    let row: Option<Row> = sqlx::query_as(
        "UPDATE chat_call_link_knocks SET last_seen_at = NOW()
         WHERE id = $1 AND room_id = $2
         RETURNING ticket_hash, status, participant_id, label, seat_hash, account",
    )
    .bind(request.knock_id)
    .bind(&request.room_id)
    .fetch_optional(&state.pool)
    .await?;
    let stored: [u8; 32] = row
        .as_ref()
        .and_then(|(hash, ..)| hash.as_slice().try_into().ok())
        .unwrap_or([0u8; 32]);
    let matches = kutup_chat_proto::constant_time_capability_hash_eq(&presented, &stored);
    let Some((_, status, participant_id, label, seat_hash, account)) = row.filter(|_| matches)
    else {
        return Err(AppError::not_found("this knock is gone"));
    };
    Ok(Json(match status {
        ADMITTED => {
            // Let in: the knock becomes their seat.
            let seat_hash: [u8; 32] = seat_hash
                .as_slice()
                .try_into()
                .map_err(|_| AppError::internal("a knock without a seat"))?;
            let seat = claim_seat(
                &state,
                &meeting,
                &request.room_id,
                &participant_id,
                &seat_hash,
                Entry::Admitted,
                account.as_deref(),
            )
            .await?;
            let token = room_token(
                &state,
                &sfu_room(&request.room_id, meeting.sitting),
                &participant_id,
                &STANDARD.encode(label),
                &seat,
                account.as_deref(),
            )?;
            KnockStatusResponse {
                status: "admitted",
                url: Some(token.url),
                token: Some(token.token),
            }
        }
        TURNED_AWAY => KnockStatusResponse {
            status: "turnedAway",
            url: None,
            token: None,
        },
        _ => KnockStatusResponse {
            status: "waiting",
            url: None,
            token: None,
        },
    }))
}

/// Who is waiting to be let in, oldest first, for the meeting's hosts.
#[utoipa::path(
    post,
    path = "/api/chat/call-links/knocks",
    tag = "chat",
    operation_id = "listChatCallLinkKnocks",
    request_body = HostCredentials,
    responses(
        (status = 200, description = "The people waiting", body = WaitingKnocks),
        (status = 404, description = "No such link, or the wrong access or host token"),
        (status = 429, description = "Too many requests"),
    )
)]
pub(crate) async fn knocks(
    State(state): State<AppState>,
    Json(request): Json<HostCredentials>,
) -> AppResult<Json<WaitingKnocks>> {
    let (meeting, _) = host(&state, &request).await?;
    // A host looks here every few seconds: a good moment to look after the
    // meeting (call_link_moderation::tend).
    tend(&state, &request.room_id, &meeting).await;
    let rows: Vec<(Uuid, Vec<u8>, OffsetDateTime, Option<String>)> = sqlx::query_as(
        "SELECT id, label, created_at, account FROM chat_call_link_knocks
         WHERE room_id = $1 AND status = $2 AND last_seen_at > NOW() - make_interval(secs => $3)
         ORDER BY created_at, id",
    )
    .bind(&request.room_id)
    .bind(WAITING)
    .bind(PRESENT_SECONDS as f64)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(WaitingKnocks {
        knocks: rows
            .into_iter()
            .map(|(knock_id, label, created_at, account)| WaitingKnock {
                knock_id,
                label: STANDARD.encode(label),
                account,
                created_at,
            })
            .collect(),
    }))
}

/// Admit or turn away one person waiting, as a host.
#[utoipa::path(
    post,
    path = "/api/chat/call-links/knocks/decide",
    tag = "chat",
    operation_id = "decideChatCallLinkKnock",
    request_body = DecideKnockRequest,
    responses(
        (status = 204, description = "Decided"),
        (status = 404, description = "No such link or waiting knock, or the wrong access or host token"),
        (status = 429, description = "Too many requests"),
    )
)]
pub(crate) async fn decide(
    State(state): State<AppState>,
    Json(request): Json<DecideKnockRequest>,
) -> AppResult<StatusCode> {
    host(
        &state,
        &HostCredentials {
            room_id: request.room_id.clone(),
            access_token: request.access_token.clone(),
            host_token: request.host_token.clone(),
            sfu_token: request.sfu_token.clone(),
        },
    )
    .await?;
    let decided = sqlx::query(
        "UPDATE chat_call_link_knocks SET status = $3
         WHERE id = $1 AND room_id = $2 AND status = $4",
    )
    .bind(request.knock_id)
    .bind(&request.room_id)
    .bind(if request.admit { ADMITTED } else { TURNED_AWAY })
    .bind(WAITING)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if decided == 0 {
        return Err(AppError::not_found("nobody is waiting under that knock"));
    }
    Ok(StatusCode::NO_CONTENT)
}
