//! Call links (docs/chat-calls.md): calls anyone holding a link can join,
//! with or without an account, on this server's SFU.
//!
//! A link's secret lives in its URL fragment and never reaches a server. From
//! it every holder derives the room id, an access token, the media frame key
//! and a key for participants' names. This server keeps, per link, the room
//! id, the SHA-256 of the access token and its owner, which is enough to:
//!
//! - admit a joiner: whoever presents the access token gets an SFU token for
//!   that one room (no account needed, so the routes are rate-limited by
//!   address and the SFU is never open to rooms nobody registered);
//! - show a joiner what the meeting is called and when it is: the owner's
//!   sealed info, handed to whoever presents the access token;
//! - let the owner list, retitle, reschedule and delete their links. Deleting
//!   stops new joins.
//!
//! It never learns the secret, the frame key, the title or time, or who is
//! in a call: the participant identity is random, and the name a participant
//! chose arrives sealed under a key from the link.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use super::call_link_moderation::{
    claim_seat, delete_sfu_room, sfu_room, Entry, Seat, TOKEN_SOURCES_WITHOUT_SCREEN,
};
use super::group_calls::{
    hosts_group_calls, livekit_token_with, GroupCallTokenResponse, TokenExtras,
};
use crate::error::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::AppState;

/// Links one account may keep at a time.
const MAX_LINKS_PER_ACCOUNT: i64 = 50;
/// A sealed participant name: nonce (24) + padded name (128) + tag (16), as
/// `kutup-chat-core` `call_link.rs` makes it.
pub(super) const SEALED_NAME_BYTES: usize = 168;
/// A sealed meeting info: nonce (24) + padded info (512) + tag (16).
const SEALED_INFO_BYTES: usize = 552;

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateCallLinkRequest {
    /// The SFU room: 32 lowercase hex characters, derived from the link's secret.
    pub room_id: String,
    /// Public and random (32 lowercase hex characters): the owner's devices
    /// derive the link's secret again from it.
    pub nonce: String,
    /// SHA-256 of the link's access token (standard base64, 32 bytes).
    pub access_token_hash: String,
    /// The meeting's title and time, sealed under the link's info key
    /// (standard base64, 552 bytes).
    pub info: String,
    /// SHA-256 of the owner's host token (standard base64, 32 bytes), which
    /// only the owner's account can derive. Needed for a waiting room.
    #[serde(default)]
    pub host_token_hash: Option<String>,
    /// Joiners wait until the owner admits them.
    #[serde(default)]
    pub waiting_room: bool,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateCallLinkInfoRequest {
    /// The new sealed info (standard base64, 552 bytes).
    pub info: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CallLinkInfoRequest {
    pub room_id: String,
    /// The link's access token (standard base64, 32 bytes).
    pub access_token: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CallLinkInfoResponse {
    /// The owner's sealed info (standard base64, 552 bytes).
    pub info: String,
    /// Joiners knock and wait for the owner to admit them.
    pub waiting_room: bool,
    /// A host locked the meeting: nobody new comes in for now.
    pub locked: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CallLink {
    pub room_id: String,
    pub nonce: String,
    /// Sealed; only holders of the link open it.
    pub info: String,
    pub waiting_room: bool,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String)]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CallLinkList {
    pub links: Vec<CallLink>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CallLinkTokenRequest {
    pub room_id: String,
    /// The link's access token (standard base64, 32 bytes).
    pub access_token: String,
    /// The joining browser's random identity (32 lowercase hex characters).
    pub participant_id: String,
    /// The joiner's chosen name, sealed under the link's name key (standard
    /// base64, 168 bytes). The SFU hands it to the other participants, who
    /// open it; this server and the SFU cannot.
    pub label: String,
    /// The secret of this identity's seat (standard base64, 32 bytes), which
    /// only the joining browser holds: a token for an identity is minted
    /// only to whoever first asked with it.
    pub seat: String,
    /// The owner's host token (standard base64, 32 bytes): joins a meeting
    /// with a waiting room without waiting.
    #[serde(default)]
    pub host_token: Option<String>,
}

/// The SHA-256 of a seat secret.
pub(super) fn seat_hash(seat: &str) -> AppResult<[u8; 32]> {
    Ok(Sha256::digest(base64_exact("seat", seat, 32)?).into())
}

/// The account address this server vouches for, when the request carries a
/// signed-in account's access token: the joiner chose to show the others
/// who they are. Without one, or with one that does not hold, nobody is
/// vouched for.
pub(super) async fn vouched_account(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?;
    let user = crate::middleware::authenticate_access_token(state, token)
        .await
        .ok()?;
    let user_id = Uuid::parse_str(&user.user_id).ok()?;
    let username: String = sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await
        .ok()??;
    Some(format!("{username}@{}", state.config.chat_server_name))
}

pub(super) fn hex32(name: &str, value: &str) -> AppResult<()> {
    kutup_chat_proto::validate_room_id(value)
        .map_err(|_| AppError::bad_request(format!("{name} is 32 lowercase hex characters")))
}

pub(super) fn base64_exact(name: &str, value: &str, bytes: usize) -> AppResult<Vec<u8>> {
    let decoded = STANDARD
        .decode(value)
        .ok()
        .filter(|decoded| decoded.len() == bytes && STANDARD.encode(decoded) == value);
    decoded.ok_or_else(|| AppError::bad_request(format!("{name} is {bytes} bytes of base64")))
}

pub(super) fn owner(auth: &AuthUser) -> AppResult<Uuid> {
    Uuid::parse_str(&auth.user_id).map_err(|_| AppError::internal("invalid user id"))
}

pub(super) fn require_sfu(state: &AppState) -> AppResult<()> {
    if hosts_group_calls(state) {
        Ok(())
    } else {
        Err(AppError::not_found("this server does not host calls"))
    }
}

#[utoipa::path(
    post,
    path = "/api/chat/call-links",
    tag = "chat",
    operation_id = "createChatCallLink",
    request_body = CreateCallLinkRequest,
    responses(
        (status = 201, description = "The link is registered", body = CallLink),
        (status = 404, description = "This server does not host calls"),
        (status = 409, description = "The link exists, or the account has too many"),
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn create(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(request): Json<CreateCallLinkRequest>,
) -> AppResult<(StatusCode, Json<CallLink>)> {
    require_sfu(&state)?;
    hex32("roomId", &request.room_id)?;
    hex32("nonce", &request.nonce)?;
    let hash = base64_exact("accessTokenHash", &request.access_token_hash, 32)?;
    let info = base64_exact("info", &request.info, SEALED_INFO_BYTES)?;
    let host_token_hash = request
        .host_token_hash
        .as_deref()
        .map(|hash| base64_exact("hostTokenHash", hash, 32))
        .transpose()?;
    if request.waiting_room && host_token_hash.is_none() {
        return Err(AppError::bad_request("a waiting room needs hostTokenHash"));
    }
    let owner = owner(&auth)?;
    let mut tx = state.pool.begin().await?;
    // One account's creations in turn, so the count below holds.
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('chat_call_links:' || $1::text, 0))",
    )
    .bind(owner)
    .execute(&mut *tx)
    .await?;
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM chat_call_links WHERE owner_user_id = $1")
            .bind(owner)
            .fetch_one(&mut *tx)
            .await?;
    if count >= MAX_LINKS_PER_ACCOUNT {
        return Err(AppError::conflict(
            "this account has as many call links as it can keep; delete one first",
        ));
    }
    let created: Option<OffsetDateTime> = sqlx::query_scalar(
        "INSERT INTO chat_call_links
            (room_id, owner_user_id, nonce, access_token_hash, info, host_token_hash, waiting_room)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT DO NOTHING
         RETURNING created_at",
    )
    .bind(&request.room_id)
    .bind(owner)
    .bind(&request.nonce)
    .bind(&hash)
    .bind(&info)
    .bind(&host_token_hash)
    .bind(request.waiting_room)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(created_at) = created else {
        return Err(AppError::conflict("this call link already exists"));
    };
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(CallLink {
            room_id: request.room_id,
            nonce: request.nonce,
            info: request.info,
            waiting_room: request.waiting_room,
            created_at,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/chat/call-links",
    tag = "chat",
    operation_id = "listChatCallLinks",
    responses((status = 200, description = "This account's call links, newest first", body = CallLinkList)),
    security(("bearerAuth" = []))
)]
pub(crate) async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
) -> AppResult<Json<CallLinkList>> {
    let rows: Vec<(String, String, Vec<u8>, bool, OffsetDateTime)> = sqlx::query_as(
        "SELECT room_id, nonce, info, waiting_room, created_at FROM chat_call_links
         WHERE owner_user_id = $1 ORDER BY created_at DESC, room_id",
    )
    .bind(owner(&auth)?)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(CallLinkList {
        links: rows
            .into_iter()
            .map(
                |(room_id, nonce, info, waiting_room, created_at)| CallLink {
                    room_id,
                    nonce,
                    info: STANDARD.encode(info),
                    waiting_room,
                    created_at,
                },
            )
            .collect(),
    }))
}

#[utoipa::path(
    delete,
    path = "/api/chat/call-links/{roomId}",
    tag = "chat",
    operation_id = "deleteChatCallLink",
    params(("roomId" = String, Path, description = "The link's room id")),
    responses(
        (status = 204, description = "Deleted: nobody can join through it any more, and whoever is in it is disconnected"),
        (status = 404, description = "No such link of this account"),
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn delete(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
) -> AppResult<StatusCode> {
    hex32("roomId", &room_id)?;
    let sitting: Option<i64> = sqlx::query_scalar(
        "DELETE FROM chat_call_links WHERE room_id = $1 AND owner_user_id = $2 RETURNING sitting",
    )
    .bind(&room_id)
    .bind(owner(&auth)?)
    .fetch_optional(&state.pool)
    .await?;
    let Some(sitting) = sitting else {
        return Err(AppError::not_found("call link not found"));
    };
    // A meeting that is on ends with its link. The link is gone either way,
    // so an SFU that cannot be reached now does not fail the deletion.
    if hosts_group_calls(&state) {
        if let Err(error) = delete_sfu_room(&state, &sfu_room(&room_id, sitting)).await {
            tracing::warn!(?error, "a deleted meeting's SFU room could not be closed");
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    put,
    path = "/api/chat/call-links/{roomId}/info",
    tag = "chat",
    operation_id = "updateChatCallLinkInfo",
    params(("roomId" = String, Path, description = "The link's room id")),
    request_body = UpdateCallLinkInfoRequest,
    responses(
        (status = 204, description = "The meeting's sealed title and time are replaced"),
        (status = 404, description = "No such link of this account"),
    ),
    security(("bearerAuth" = []))
)]
pub(crate) async fn update_info(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    Json(request): Json<UpdateCallLinkInfoRequest>,
) -> AppResult<StatusCode> {
    hex32("roomId", &room_id)?;
    let info = base64_exact("info", &request.info, SEALED_INFO_BYTES)?;
    let updated = sqlx::query(
        "UPDATE chat_call_links SET info = $3 WHERE room_id = $1 AND owner_user_id = $2",
    )
    .bind(&room_id)
    .bind(owner(&auth)?)
    .bind(&info)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if updated == 0 {
        return Err(AppError::not_found("call link not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// What this server holds of a meeting, for someone who presented its
/// access token.
pub(super) struct Admitted {
    pub info: Vec<u8>,
    pub waiting_room: bool,
    /// Nobody new comes in.
    pub locked: bool,
    /// How many times the meeting was ended for everyone: its SFU room is
    /// named after it (`call_link_moderation::sfu_room`).
    pub sitting: i64,
    /// Since when the meeting has been on without a host in it.
    pub hostless_since: Option<OffsetDateTime>,
    host_token_hash: Option<Vec<u8>>,
}

impl Admitted {
    /// Whether `host_token` is the owner's (compared in constant time).
    pub fn is_host(&self, host_token: Option<&str>) -> AppResult<bool> {
        let Some(token) = host_token else {
            return Ok(false);
        };
        let presented: [u8; 32] = Sha256::digest(base64_exact("hostToken", token, 32)?).into();
        let stored: [u8; 32] = self
            .host_token_hash
            .as_deref()
            .and_then(|hash| hash.try_into().ok())
            .unwrap_or([0u8; 32]);
        Ok(self.host_token_hash.is_some()
            && kutup_chat_proto::constant_time_capability_hash_eq(&presented, &stored))
    }
}

/// The meeting whose access token was presented. A wrong token and an
/// unknown room are answered alike, and take alike.
pub(super) async fn admitted(
    state: &AppState,
    room_id: &str,
    access_token: &str,
) -> AppResult<Admitted> {
    hex32("roomId", room_id)?;
    let presented = base64_exact("accessToken", access_token, 32)?;
    // access_token_hash, info, waiting_room, host_token_hash, locked,
    // sitting, hostless_since
    type Row = (
        Vec<u8>,
        Vec<u8>,
        bool,
        Option<Vec<u8>>,
        bool,
        i64,
        Option<OffsetDateTime>,
    );
    let stored: Option<Row> = sqlx::query_as(
        "SELECT access_token_hash, info, waiting_room, host_token_hash, locked, sitting,
                hostless_since
         FROM chat_call_links WHERE room_id = $1",
    )
    .bind(room_id)
    .fetch_optional(&state.pool)
    .await?;
    let presented_hash: [u8; 32] = Sha256::digest(&presented).into();
    let stored_hash: [u8; 32] = stored
        .as_ref()
        .and_then(|(hash, ..)| hash.as_slice().try_into().ok())
        .unwrap_or([0u8; 32]);
    let matches = kutup_chat_proto::constant_time_capability_hash_eq(&presented_hash, &stored_hash);
    match stored {
        Some((_, info, waiting_room, host_token_hash, locked, sitting, hostless_since))
            if matches =>
        {
            Ok(Admitted {
                info,
                waiting_room,
                locked,
                sitting,
                hostless_since,
                host_token_hash,
            })
        }
        _ => Err(AppError::not_found("this call link does not work")),
    }
}

/// What the meeting is called and when it is, sealed, for whoever holds the
/// link. No account (`middleware::rate_limit_call_link`).
#[utoipa::path(
    post,
    path = "/api/chat/call-links/info",
    tag = "chat",
    operation_id = "getChatCallLinkInfo",
    request_body = CallLinkInfoRequest,
    responses(
        (status = 200, description = "The link's sealed info", body = CallLinkInfoResponse),
        (status = 404, description = "No such link, or the wrong access token"),
        (status = 429, description = "Too many requests"),
    )
)]
pub(crate) async fn info(
    State(state): State<AppState>,
    Json(request): Json<CallLinkInfoRequest>,
) -> AppResult<Json<CallLinkInfoResponse>> {
    let meeting = admitted(&state, &request.room_id, &request.access_token).await?;
    Ok(Json(CallLinkInfoResponse {
        info: STANDARD.encode(meeting.info),
        waiting_room: meeting.waiting_room,
        locked: meeting.locked,
    }))
}

/// An SFU token for whoever holds the link. No account is needed: the route
/// is rate-limited by address (`middleware::rate_limit_call_link`), and a
/// wrong token and an unknown room are answered alike. A signed-in joiner
/// who wants the others to see who they are sends their access token too.
#[utoipa::path(
    post,
    path = "/api/chat/call-links/token",
    tag = "chat",
    operation_id = "getChatCallLinkToken",
    request_body = CallLinkTokenRequest,
    responses(
        (status = 200, description = "An SFU token for the link's room", body = GroupCallTokenResponse),
        (status = 403, description = "The meeting has a waiting room: knock instead"),
        (status = 404, description = "No such link (deleted, or not this server's), or the wrong access token"),
        (status = 409, description = "That identity is someone else's seat"),
        (status = 410, description = "A host removed this participant"),
        (status = 423, description = "A host locked the meeting"),
        (status = 429, description = "Too many requests"),
    )
)]
pub(crate) async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CallLinkTokenRequest>,
) -> AppResult<Json<GroupCallTokenResponse>> {
    require_sfu(&state)?;
    hex32("participantId", &request.participant_id)?;
    base64_exact("label", &request.label, SEALED_NAME_BYTES)?;
    let seat_hash = seat_hash(&request.seat)?;
    let meeting = admitted(&state, &request.room_id, &request.access_token).await?;
    // The owner always comes in, and is recorded as the owner so the others
    // can be shown who the host is. With a waiting room, holding the link is
    // not enough for anyone else: they knock (call_link_waiting.rs), unless
    // they are coming back to a seat they were already let into.
    let entry = if meeting.is_host(request.host_token.as_deref())? {
        Entry::Owner
    } else if meeting.waiting_room {
        Entry::Returning
    } else {
        Entry::Open
    };
    let account = vouched_account(&state, &headers).await;
    let seat = claim_seat(
        &state,
        &meeting,
        &request.room_id,
        &request.participant_id,
        &seat_hash,
        entry,
        account.as_deref(),
    )
    .await?;
    Ok(Json(room_token(
        &state,
        &sfu_room(&request.room_id, meeting.sitting),
        &request.participant_id,
        &request.label,
        &seat,
        account.as_deref(),
    )?))
}

/// An SFU token for one sitting of a meeting, carrying the joiner's sealed
/// name, the account this server vouches for (if any), and what their seat
/// lets them publish.
pub(super) fn room_token(
    state: &AppState,
    sfu_room: &str,
    participant_id: &str,
    label: &str,
    seat: &Seat,
    account: Option<&str>,
) -> AppResult<GroupCallTokenResponse> {
    let config = &state.config;
    Ok(GroupCallTokenResponse {
        url: config.chat_sfu_url.clone(),
        token: livekit_token_with(
            &config.chat_sfu_api_key,
            &config.chat_sfu_api_secret,
            sfu_room,
            participant_id,
            &TokenExtras {
                metadata: Some(label),
                name: account,
                publish_sources: seat.no_screen.then_some(TOKEN_SOURCES_WITHOUT_SCREEN),
            },
            OffsetDateTime::now_utc().unix_timestamp(),
        )?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_are_exact_canonical_base64() {
        let token = STANDARD.encode([7u8; 32]);
        assert_eq!(base64_exact("t", &token, 32).unwrap(), vec![7u8; 32]);
        assert!(base64_exact("t", &STANDARD.encode([7u8; 31]), 32).is_err());
        assert!(base64_exact("t", "not base64", 32).is_err());
        // The same bytes written non-canonically (without padding) are refused.
        assert!(base64_exact("t", token.trim_end_matches('='), 32).is_err());
        assert!(base64_exact(
            "l",
            &STANDARD.encode([1u8; SEALED_NAME_BYTES]),
            SEALED_NAME_BYTES
        )
        .is_ok());
    }

    #[test]
    fn ids_are_32_lowercase_hex() {
        assert!(hex32("roomId", &"ab".repeat(16)).is_ok());
        assert!(hex32("roomId", &"AB".repeat(16)).is_err());
        assert!(hex32("roomId", "abc").is_err());
    }
}
