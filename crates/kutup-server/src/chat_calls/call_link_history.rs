//! The meetings an account joined (docs/chat-calls.md, "History").
//!
//! Joining a meeting needs no account, and this server keeps no record of
//! who joined what. An account that wants its list on all of its devices
//! keeps it here itself: each stay is an account record its browser sealed
//! under the account master key (docs/plans/w1-account-record.md), bound to
//! the account and to the row's id. This server checks each record's header,
//! stores the records and hands them back; it learns how many there are and
//! when each was added, not which meeting any of them is.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::call_links::{base64_exact, hex32, owner};
use crate::error::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::AppState;

/// Stays one account keeps; older ones drop off.
const MAX_JOINED_MEETINGS: i64 = 100;
/// A sealed record: every one has this exact length (its stay is padded).
const SEALED_JOINED_BYTES: usize = kutup_crypto::chat_call_link::JOINED_MEETING_SEALED_BYTES;

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JoinedMeeting {
    /// 32 lowercase hex characters, chosen by the browser that recorded it.
    pub id: String,
    /// The stay, an account record sealed under the account master key for
    /// this id (standard base64, `JOINED_MEETING_SEALED_BYTES` bytes).
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

/// This account's record, filed under this id: another account's, or one
/// moved from another id, is refused.
fn record(value: &str, binding: &str, id: &str) -> AppResult<Vec<u8>> {
    let entry = base64_exact("entry", value, SEALED_JOINED_BYTES)?;
    kutup_crypto::chat_call_link::validate_joined_meeting(&entry, binding, id)
        .map_err(|_| AppError::bad_request("not this account's sealed joined meeting"))?;
    Ok(entry)
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
    let user_id = owner(&auth)?;
    let binding = crate::revisions::key_binding(&state.pool, user_id).await?;
    let entry = record(&request.entry, &binding, &request.id)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use kutup_crypto::account_record::MasterKeyGeneration;
    use kutup_crypto::chat_call_link::{call_link_fragment, seal_joined_meeting, JoinedMeetingV1};

    #[test]
    fn a_record_is_this_accounts_stay_under_this_id() {
        let master = STANDARD.encode([3u8; 32]);
        let binding = "00000000-0000-4000-8000-000000000001";
        let id = "00112233445566778899aabbccddeeff";
        let entry = JoinedMeetingV1 {
            fragment: call_link_fragment(&STANDARD.encode([5u8; 32])).unwrap(),
            title: "Standup".into(),
            joined_at_ms: 1,
            seconds: 60,
        };
        let sealed =
            seal_joined_meeting(&master, MasterKeyGeneration::FIRST, binding, id, &entry).unwrap();
        assert_eq!(
            record(&sealed, binding, id).unwrap().len(),
            SEALED_JOINED_BYTES
        );
        // Another id, another account, cut, or not one at all: refused.
        assert!(record(&sealed, binding, &"ab".repeat(16)).is_err());
        assert!(record(&sealed, "00000000-0000-4000-8000-000000000002", id).is_err());
        let bytes = STANDARD.decode(&sealed).unwrap();
        assert!(record(&STANDARD.encode(&bytes[..bytes.len() - 1]), binding, id).is_err());
        assert!(record("AQ", binding, id).is_err());
    }
}
