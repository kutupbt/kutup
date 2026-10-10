//! Reading stored mail (docs/plans/mail.md). The list carries the readable
//! fields; the content is the message as stored, an OpenPGP message the
//! client opens with its address key and parses itself.

use axum::extract::{Path, Query, State};
use axum::response::Response;
use axum::Json;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::{octet_stream_response, trusted_uuid};
use crate::middleware::AuthUser;
use crate::AppState;

const FOLDERS: [&str; 6] = ["inbox", "drafts", "sent", "archive", "spam", "trash"];
const DEFAULT_PAGE: i64 = 50;
const MAX_PAGE: i64 = 200;

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailMailbox {
    pub address: String,
    pub name: String,
}

/// One message's readable fields.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailMessage {
    pub id: String,
    pub thread_id: String,
    pub folder: String,
    pub seen: bool,
    pub starred: bool,
    /// `zero_access` (encrypted on arrival) or `end_to_end`.
    pub protection: String,
    /// Stored (encrypted) size in bytes.
    pub size: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub received_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub sent_at: Option<OffsetDateTime>,
    pub subject: String,
    pub from: Option<MailMailbox>,
    #[schema(value_type = Vec<MailMailbox>)]
    pub to: serde_json::Value,
    #[schema(value_type = Vec<MailMailbox>)]
    pub cc: serde_json::Value,
    #[schema(value_type = Vec<MailMailbox>)]
    pub reply_to: serde_json::Value,
    pub message_id: Option<String>,
    pub attachment_count: i32,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailMessagePage {
    pub messages: Vec<MailMessage>,
    /// Pass as `before` for the next, older page; absent on the last.
    pub next: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct MailListQuery {
    /// One of inbox, drafts, sent, archive, spam, trash.
    pub folder: String,
    /// The `next` of the previous page.
    pub before: Option<String>,
    pub limit: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct Row {
    id: Uuid,
    thread_id: Uuid,
    folder: String,
    seen: bool,
    starred: bool,
    protection: String,
    size_bytes: i64,
    received_at: OffsetDateTime,
    sent_at: Option<OffsetDateTime>,
    subject: String,
    from_address: String,
    from_name: String,
    to_list: serde_json::Value,
    cc_list: serde_json::Value,
    reply_to: serde_json::Value,
    message_id: Option<String>,
    attachment_count: i32,
}

impl From<Row> for MailMessage {
    fn from(row: Row) -> Self {
        MailMessage {
            id: row.id.to_string(),
            thread_id: row.thread_id.to_string(),
            folder: row.folder,
            seen: row.seen,
            starred: row.starred,
            protection: row.protection,
            size: row.size_bytes,
            received_at: row.received_at,
            sent_at: row.sent_at,
            subject: row.subject,
            from: (!row.from_address.is_empty()).then_some(MailMailbox {
                address: row.from_address,
                name: row.from_name,
            }),
            to: row.to_list,
            cc: row.cc_list,
            reply_to: row.reply_to,
            message_id: row.message_id,
            attachment_count: row.attachment_count,
        }
    }
}

/// A page cursor: the last message's arrival time and id.
fn cursor(received_at: OffsetDateTime, id: Uuid) -> String {
    format!("{}_{id}", received_at.unix_timestamp_nanos())
}

fn parse_cursor(value: &str) -> AppResult<(OffsetDateTime, Uuid)> {
    let bad = || AppError::bad_request("before is not a cursor");
    let (nanos, id) = value.split_once('_').ok_or_else(bad)?;
    let nanos: i128 = nanos.parse().map_err(|_| bad())?;
    Ok((
        OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|_| bad())?,
        Uuid::parse_str(id).map_err(|_| bad())?,
    ))
}

/// `GET /api/mail/messages?folder=&before=&limit=` — one folder, newest
/// first.
#[utoipa::path(
    get,
    path = "/api/mail/messages",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(MailListQuery),
    responses(
        (status = 200, description = "A page of the folder", body = MailMessagePage),
        (status = 400, description = "Unknown folder or cursor"),
    )
)]
pub async fn list_messages(
    State(state): State<AppState>,
    user: AuthUser,
    Query(query): Query<MailListQuery>,
) -> AppResult<Json<MailMessagePage>> {
    let user_id = trusted_uuid(&user.user_id)?;
    if !FOLDERS.contains(&query.folder.as_str()) {
        return Err(AppError::bad_request("unknown folder"));
    }
    let limit = query.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
    let before = query.before.as_deref().map(parse_cursor).transpose()?;
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, thread_id, folder, seen, starred, protection, size_bytes, received_at, sent_at,
                subject, from_address, from_name, to_list, cc_list, reply_to, message_id,
                attachment_count
           FROM mail_messages
          WHERE user_id = $1 AND folder = $2
            AND ($3::timestamptz IS NULL OR (received_at, id) < ($3, $4))
          ORDER BY received_at DESC, id DESC
          LIMIT $5",
    )
    .bind(user_id)
    .bind(&query.folder)
    .bind(before.map(|(at, _)| at))
    .bind(before.map(|(_, id)| id))
    .bind(limit + 1)
    .fetch_all(&state.pool)
    .await?;
    let more = rows.len() as i64 > limit;
    let messages: Vec<MailMessage> = rows
        .into_iter()
        .take(limit as usize)
        .map(MailMessage::from)
        .collect();
    let next = more
        .then(|| messages.last())
        .flatten()
        .map(|last| cursor(last.received_at, Uuid::parse_str(&last.id).expect("own id")));
    Ok(Json(MailMessagePage { messages, next }))
}

/// `GET /api/mail/messages/{id}/content` — the stored message: a binary
/// OpenPGP message encrypted to the address key.
#[utoipa::path(
    get,
    path = "/api/mail/messages/{id}/content",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Message id")),
    responses(
        (status = 200, description = "The encrypted message", content_type = "application/octet-stream"),
        (status = 404, description = "No such message of yours"),
    )
)]
pub async fn message_content(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    // Each message is written once under its own key, so the plain key is
    // always the stored version.
    let key: Option<String> =
        sqlx::query_scalar("SELECT object_key FROM mail_messages WHERE id = $1 AND user_id = $2")
            .bind(id)
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await?;
    let key = key.ok_or_else(|| AppError::not_found("not found"))?;
    let (body, size) = state
        .storage
        .get_object(&key)
        .await
        .map_err(|_| AppError::internal("storage"))?;
    Ok(octet_stream_response(body, size, &[]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursors_round_trip() {
        let at = OffsetDateTime::from_unix_timestamp_nanos(1_791_529_200_123_456_789).unwrap();
        let id = Uuid::new_v4();
        assert_eq!(parse_cursor(&cursor(at, id)).unwrap(), (at, id));
        assert!(parse_cursor("nope").is_err());
        assert!(parse_cursor("1_notauuid").is_err());
    }
}
