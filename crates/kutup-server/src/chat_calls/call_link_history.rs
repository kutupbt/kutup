//! The meetings an account joined (docs/chat-calls.md, "History").
//!
//! Joining a meeting needs no account, and this server keeps no record of
//! who joined what. An account that wants its list on all of its devices
//! keeps it here itself: each stay is a record its browser sealed under a
//! key from the account master key. This server stores the records and
//! hands them back; it learns how many there are and when each was added,
//! not which meeting any of them is.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::call_links::{base64_exact, hex32, owner};
use crate::error::AppResult;
use crate::middleware::AuthUser;
use crate::AppState;

/// Stays one account keeps; older ones drop off.
const MAX_JOINED_MEETINGS: i64 = 100;
/// A sealed record: nonce (24) + padded record (1024) + tag (16), as
/// `kutup-chat-core` `call_link.rs` makes it.
const SEALED_JOINED_BYTES: usize = 1064;

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JoinedMeeting {
    /// 32 lowercase hex characters, chosen by the browser that recorded it.
    pub id: String,
    /// The stay, sealed under a key from the account master key (standard
    /// base64, 1064 bytes).
    pub entry: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct JoinedMeetingList {
    pub entries: Vec<JoinedMeeting>,
}

/// The account's joined meetings, most recently added first.
#[utoipa::path(
    get,
    path = "/api/chat/joined-meetings",
    tag = "chat",
    operation_id = "listChatJoinedMeetings",
    security(("bearerAuth" = [])),
    responses((status = 200, description = "The account's sealed records", body = JoinedMeetingList))
)]
pub(crate) async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
) -> AppResult<Json<JoinedMeetingList>> {
    let rows: Vec<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT id, entry FROM chat_joined_meetings
         WHERE user_id = $1 ORDER BY created_at DESC, id LIMIT $2",
    )
    .bind(owner(&auth)?)
    .bind(MAX_JOINED_MEETINGS)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(JoinedMeetingList {
        entries: rows
            .into_iter()
            .map(|(id, entry)| JoinedMeeting {
                id,
                entry: STANDARD.encode(entry),
            })
            .collect(),
    }))
}

/// Record one stay. Recording the same id again changes nothing.
#[utoipa::path(
    post,
    path = "/api/chat/joined-meetings",
    tag = "chat",
    operation_id = "addChatJoinedMeeting",
    security(("bearerAuth" = [])),
    request_body = JoinedMeeting,
    responses(
        (status = 204, description = "Recorded"),
        (status = 400, description = "Not a sealed record"),
    )
)]
pub(crate) async fn add(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(request): Json<JoinedMeeting>,
) -> AppResult<StatusCode> {
    hex32("id", &request.id)?;
    let entry = base64_exact("entry", &request.entry, SEALED_JOINED_BYTES)?;
    let user_id = owner(&auth)?;
    sqlx::query(
        "INSERT INTO chat_joined_meetings (user_id, id, entry) VALUES ($1, $2, $3)
         ON CONFLICT (user_id, id) DO NOTHING",
    )
    .bind(user_id)
    .bind(&request.id)
    .bind(entry)
    .execute(&state.pool)
    .await?;
    sqlx::query(
        "DELETE FROM chat_joined_meetings WHERE user_id = $1 AND id IN (
             SELECT id FROM chat_joined_meetings WHERE user_id = $1
             ORDER BY created_at DESC, id OFFSET $2)",
    )
    .bind(user_id)
    .bind(MAX_JOINED_MEETINGS)
    .execute(&state.pool)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Take one stay off the list.
#[utoipa::path(
    delete,
    path = "/api/chat/joined-meetings/{id}",
    tag = "chat",
    operation_id = "deleteChatJoinedMeeting",
    security(("bearerAuth" = [])),
    params(("id" = String, Path, description = "The record's id")),
    responses((status = 204, description = "Gone"))
)]
pub(crate) async fn remove(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    hex32("id", &id)?;
    sqlx::query("DELETE FROM chat_joined_meetings WHERE user_id = $1 AND id = $2")
        .bind(owner(&auth)?)
        .bind(&id)
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Clear the account's list.
#[utoipa::path(
    delete,
    path = "/api/chat/joined-meetings",
    tag = "chat",
    operation_id = "clearChatJoinedMeetings",
    security(("bearerAuth" = [])),
    responses((status = 204, description = "Cleared"))
)]
pub(crate) async fn clear(State(state): State<AppState>, auth: AuthUser) -> AppResult<StatusCode> {
    sqlx::query("DELETE FROM chat_joined_meetings WHERE user_id = $1")
        .bind(owner(&auth)?)
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
