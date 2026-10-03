//! Call links (docs/chat-calls.md): calls anyone holding a link can join,
//! with or without an account, on this server's SFU.
//!
//! A link's secret lives in its URL fragment and never reaches a server. From
//! it every holder derives the room id, an access token, the media frame key
//! and a key for participants' names. This server keeps, per link, the room
//! id, the SHA-256 of the access token and its owner, which is enough to:
//!
//! - admit a joiner: whoever presents the access token gets an SFU token for
//!   that one room (no account needed, so the route is rate-limited by
//!   address and the SFU is never open to rooms nobody registered);
//! - let the owner list and delete their links. Deleting stops new joins.
//!
//! It never learns the secret, the frame key, or who is in a call: the
//! participant identity is random, and the name a participant chose arrives
//! sealed under a key from the link.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use super::group_calls::{hosts_group_calls, livekit_token, GroupCallTokenResponse};
use crate::error::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::AppState;

/// Links one account may keep at a time.
const MAX_LINKS_PER_ACCOUNT: i64 = 50;
/// A sealed participant name: nonce (24) + padded name (128) + tag (16), as
/// `kutup-chat-core` `call_link.rs` makes it.
const SEALED_NAME_BYTES: usize = 168;

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
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CallLink {
    pub room_id: String,
    pub nonce: String,
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
}

fn hex32(name: &str, value: &str) -> AppResult<()> {
    kutup_chat_proto::validate_room_id(value)
        .map_err(|_| AppError::bad_request(format!("{name} is 32 lowercase hex characters")))
}

fn base64_exact(name: &str, value: &str, bytes: usize) -> AppResult<Vec<u8>> {
    let decoded = STANDARD
        .decode(value)
        .ok()
        .filter(|decoded| decoded.len() == bytes && STANDARD.encode(decoded) == value);
    decoded.ok_or_else(|| AppError::bad_request(format!("{name} is {bytes} bytes of base64")))
}

fn owner(auth: &AuthUser) -> AppResult<Uuid> {
    Uuid::parse_str(&auth.user_id).map_err(|_| AppError::internal("invalid user id"))
}

fn require_sfu(state: &AppState) -> AppResult<()> {
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
        "INSERT INTO chat_call_links (room_id, owner_user_id, nonce, access_token_hash)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT DO NOTHING
         RETURNING created_at",
    )
    .bind(&request.room_id)
    .bind(owner)
    .bind(&request.nonce)
    .bind(&hash)
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
    let rows: Vec<(String, String, OffsetDateTime)> = sqlx::query_as(
        "SELECT room_id, nonce, created_at FROM chat_call_links
         WHERE owner_user_id = $1 ORDER BY created_at DESC, room_id",
    )
    .bind(owner(&auth)?)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(CallLinkList {
        links: rows
            .into_iter()
            .map(|(room_id, nonce, created_at)| CallLink {
                room_id,
                nonce,
                created_at,
            })
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
        (status = 204, description = "Deleted: nobody can join through it any more"),
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
    let deleted =
        sqlx::query("DELETE FROM chat_call_links WHERE room_id = $1 AND owner_user_id = $2")
            .bind(&room_id)
            .bind(owner(&auth)?)
            .execute(&state.pool)
            .await?
            .rows_affected();
    if deleted == 0 {
        return Err(AppError::not_found("call link not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// An SFU token for whoever holds the link. No account: the route is
/// rate-limited by address (`middleware::rate_limit_call_link`), and a wrong
/// token and an unknown room are answered alike.
#[utoipa::path(
    post,
    path = "/api/chat/call-links/token",
    tag = "chat",
    operation_id = "getChatCallLinkToken",
    request_body = CallLinkTokenRequest,
    responses(
        (status = 200, description = "An SFU token for the link's room", body = GroupCallTokenResponse),
        (status = 404, description = "No such link (deleted, or not this server's), or the wrong access token"),
        (status = 429, description = "Too many requests"),
    )
)]
pub(crate) async fn token(
    State(state): State<AppState>,
    Json(request): Json<CallLinkTokenRequest>,
) -> AppResult<Json<GroupCallTokenResponse>> {
    require_sfu(&state)?;
    hex32("roomId", &request.room_id)?;
    hex32("participantId", &request.participant_id)?;
    let presented = base64_exact("accessToken", &request.access_token, 32)?;
    base64_exact("label", &request.label, SEALED_NAME_BYTES)?;
    let stored: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT access_token_hash FROM chat_call_links WHERE room_id = $1")
            .bind(&request.room_id)
            .fetch_optional(&state.pool)
            .await?;
    let presented_hash: [u8; 32] = Sha256::digest(&presented).into();
    // Compared even when the room is unknown, so both cases take alike.
    let stored_hash: [u8; 32] = stored
        .as_deref()
        .and_then(|hash| hash.try_into().ok())
        .unwrap_or([0u8; 32]);
    let matches = kutup_chat_proto::constant_time_capability_hash_eq(&presented_hash, &stored_hash);
    if stored.is_none() || !matches {
        return Err(AppError::not_found("this call link does not work"));
    }
    let config = &state.config;
    Ok(Json(GroupCallTokenResponse {
        url: config.chat_sfu_url.clone(),
        token: livekit_token(
            &config.chat_sfu_api_key,
            &config.chat_sfu_api_secret,
            &request.room_id,
            &request.participant_id,
            Some(&request.label),
            OffsetDateTime::now_utc().unix_timestamp(),
        )?,
    }))
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
