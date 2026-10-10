//! Reading and filing stored mail (docs/plans/mail.md). The list carries
//! the readable fields; the content is the message as stored, an OpenPGP
//! message the client opens with its address key and parses itself.
//! Drafts and sending are in `mail_send`.

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

pub(crate) const FOLDERS: [&str; 6] = ["inbox", "drafts", "sent", "archive", "spam", "trash"];
/// Messages one request may file or delete.
const MAX_BATCH: usize = 500;
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
    /// `inbound` (received) or `outbound` (sent, or a draft).
    pub direction: String,
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
    /// Your own sent copies only.
    #[schema(value_type = Vec<MailMailbox>)]
    pub bcc: serde_json::Value,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
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
    /// One of inbox, drafts, sent, archive, spam, trash; or `starred`, or
    /// `all` (everything but Spam and Trash).
    pub folder: String,
    /// Searches subjects and addresses.
    pub q: Option<String>,
    /// The `next` of the previous page.
    pub before: Option<String>,
    pub limit: Option<i64>,
}

#[derive(sqlx::FromRow)]
pub(crate) struct Row {
    id: Uuid,
    thread_id: Uuid,
    direction: String,
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
    bcc_list: serde_json::Value,
    message_id: Option<String>,
    in_reply_to: Option<String>,
    references_list: Vec<String>,
    attachment_count: i32,
}

/// The columns a [`Row`] reads.
pub(crate) const ROW_COLUMNS: &str = "id, thread_id, direction, folder, seen, starred, protection,
    size_bytes, received_at, sent_at, subject, from_address, from_name, to_list, cc_list,
    reply_to, bcc_list, message_id, in_reply_to, references_list, attachment_count";

impl From<Row> for MailMessage {
    fn from(row: Row) -> Self {
        MailMessage {
            id: row.id.to_string(),
            thread_id: row.thread_id.to_string(),
            direction: row.direction,
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
            bcc: row.bcc_list,
            message_id: row.message_id,
            in_reply_to: row.in_reply_to,
            references: row.references_list,
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

/// `GET /api/mail/messages?folder=&q=&before=&limit=` — one folder (or
/// Starred, or all mail), newest first, optionally searched.
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
    let folder = query.folder.as_str();
    if !FOLDERS.contains(&folder) && folder != "starred" && folder != "all" {
        return Err(AppError::bad_request("unknown folder"));
    }
    let limit = query.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
    let before = query.before.as_deref().map(parse_cursor).transpose()?;
    let search = query
        .q
        .as_deref()
        .map(str::trim)
        .filter(|q| !q.is_empty())
        .map(|q| {
            let escaped: String = q
                .chars()
                .take(200)
                .flat_map(|c| match c {
                    '%' | '_' | '\\' => vec!['\\', c],
                    c => vec![c],
                })
                .collect();
            format!("%{escaped}%")
        });
    let rows: Vec<Row> = sqlx::query_as(&format!(
        "SELECT {ROW_COLUMNS}
           FROM mail_messages
          WHERE user_id = $1
            AND CASE $2
                  WHEN 'starred' THEN starred AND folder NOT IN ('spam', 'trash')
                  WHEN 'all' THEN folder NOT IN ('spam', 'trash')
                  ELSE folder = $2
                END
            AND ($3::timestamptz IS NULL OR (received_at, id) < ($3, $4))
            AND ($6::text IS NULL OR subject ILIKE $6 OR from_address ILIKE $6
                 OR from_name ILIKE $6 OR to_list::text ILIKE $6 OR cc_list::text ILIKE $6)
          ORDER BY received_at DESC, id DESC
          LIMIT $5"
    ))
    .bind(user_id)
    .bind(folder)
    .bind(before.map(|(at, _)| at))
    .bind(before.map(|(_, id)| id))
    .bind(limit + 1)
    .bind(search)
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
    let row: Option<(String, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT object_key, key_packet FROM mail_messages WHERE id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;
    let (key, key_packet) = row.ok_or_else(|| AppError::not_found("not found"))?;
    let (body, size) = state
        .storage
        .get_object(&key)
        .await
        .map_err(|_| AppError::internal("storage"))?;
    let Some(key_packet) = key_packet else {
        return Ok(octet_stream_response(body, size, &[]));
    };
    // A distribution-list copy: the member's key packet, then the list's
    // shared data packet, which together are one OpenPGP message.
    use futures_util::StreamExt as _;
    let length = size + key_packet.len() as i64;
    let stream = futures_util::stream::once(async move {
        Ok::<_, std::io::Error>(axum::body::Bytes::from(key_packet))
    })
    .chain(tokio_util::io::ReaderStream::new(body.into_async_read()));
    Response::builder()
        .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
        .header(axum::http::header::CONTENT_LENGTH, length)
        .body(axum::body::Body::from_stream(stream))
        .map_err(|_| AppError::internal("response"))
}

fn parse_ids(ids: &[String]) -> AppResult<Vec<Uuid>> {
    if ids.is_empty() || ids.len() > MAX_BATCH {
        return Err(AppError::bad_request("1 to 500 message ids"));
    }
    ids.iter()
        .map(|id| Uuid::parse_str(id).map_err(|_| AppError::bad_request("not a message id")))
        .collect()
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateMailMessages {
    pub ids: Vec<String>,
    pub seen: Option<bool>,
    pub starred: Option<bool>,
    /// inbox, archive, spam or trash for received mail; sent, archive or
    /// trash for sent mail. Drafts stay in Drafts.
    pub folder: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdatedMailMessages {
    /// Messages changed; ids that are not yours, or a folder a message
    /// cannot go to, are left alone.
    pub updated: u64,
}

/// `PATCH /api/mail/messages` — marks read or unread, stars, or files up
/// to 500 messages at once. Moving to Trash marks them read, as Proton does.
#[utoipa::path(
    patch,
    path = "/api/mail/messages",
    tag = "mail",
    security(("BearerAuth" = [])),
    request_body = UpdateMailMessages,
    responses(
        (status = 200, description = "How many changed", body = UpdatedMailMessages),
        (status = 400, description = "No change asked, unknown folder or too many ids"),
    )
)]
pub async fn update_messages(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<UpdateMailMessages>,
) -> AppResult<Json<UpdatedMailMessages>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let ids = parse_ids(&request.ids)?;
    if request.seen.is_none() && request.starred.is_none() && request.folder.is_none() {
        return Err(AppError::bad_request("nothing to change"));
    }
    if let Some(folder) = request.folder.as_deref() {
        if !["inbox", "archive", "spam", "trash", "sent"].contains(&folder) {
            return Err(AppError::bad_request("cannot move messages there"));
        }
    }
    let updated = sqlx::query(
        "UPDATE mail_messages SET
             seen = CASE WHEN $5::text = 'trash' THEN true ELSE COALESCE($3, seen) END,
             starred = COALESCE($4, starred),
             folder = COALESCE($5, folder)
          WHERE user_id = $1 AND id = ANY($2)
            AND ($5::text IS NULL OR (
                  folder <> 'drafts' AND (
                    (direction = 'inbound' AND $5 IN ('inbox', 'archive', 'spam', 'trash'))
                 OR (direction = 'outbound' AND $5 IN ('sent', 'archive', 'trash')))))",
    )
    .bind(user_id)
    .bind(&ids)
    .bind(request.seen)
    .bind(request.starred)
    .bind(request.folder.as_deref())
    .execute(&state.pool)
    .await?
    .rows_affected();
    Ok(Json(UpdatedMailMessages { updated }))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteMailMessages {
    pub ids: Vec<String>,
}

/// `POST /api/mail/messages/delete` — deletes messages for good, only from
/// Trash, Spam and Drafts (elsewhere the client moves to Trash first, as
/// Proton does). Frees their storage at once.
#[utoipa::path(
    post,
    path = "/api/mail/messages/delete",
    tag = "mail",
    security(("BearerAuth" = [])),
    request_body = DeleteMailMessages,
    responses((status = 200, description = "How many were deleted", body = UpdatedMailMessages))
)]
pub async fn delete_messages(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<DeleteMailMessages>,
) -> AppResult<Json<UpdatedMailMessages>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let ids = parse_ids(&request.ids)?;
    let deleted = delete_for_good(&state, user_id, &ids, &["trash", "spam", "drafts"]).await?;
    Ok(Json(UpdatedMailMessages { updated: deleted }))
}

/// Deletes `ids` of `user_id` that sit in one of `folders`, with their draft
/// attachments, refunds the pool and then removes the objects.
pub(crate) async fn delete_for_good(
    state: &AppState,
    user_id: Uuid,
    ids: &[Uuid],
    folders: &[&str],
) -> AppResult<u64> {
    let mut tx = state.pool.begin().await?;
    crate::storage_pool::lock(&mut tx, user_id, Default::default()).await?;
    let attachments: Vec<(String, i64)> = sqlx::query_as(
        "SELECT a.object_key, a.size_bytes FROM mail_draft_attachments a
           JOIN mail_messages m ON m.id = a.message_id
          WHERE m.user_id = $1 AND m.id = ANY($2) AND m.folder = ANY($3)",
    )
    .bind(user_id)
    .bind(ids)
    .bind(folders)
    .fetch_all(&mut *tx)
    .await?;
    // A distribution-list copy only drops the member's row: the shared data
    // packet is the group's, released once nobody holds it.
    let deleted: Vec<(String, String, i64, bool)> = sqlx::query_as(
        "DELETE FROM mail_messages WHERE user_id = $1 AND id = ANY($2) AND folder = ANY($3)
         RETURNING object_key, object_version, size_bytes, key_packet IS NOT NULL",
    )
    .bind(user_id)
    .bind(ids)
    .bind(folders)
    .fetch_all(&mut *tx)
    .await?;
    let list_copies = deleted.iter().filter(|(_, _, _, shared)| *shared).count();
    let messages: Vec<(String, String, i64)> = deleted
        .iter()
        .filter(|(_, _, _, shared)| !*shared)
        .map(|(key, version, size, _)| (key.clone(), version.clone(), *size))
        .collect();
    let freed: i64 = messages.iter().map(|(_, _, size)| size).sum::<i64>()
        + attachments.iter().map(|(_, size)| size).sum::<i64>();
    sqlx::query(
        "UPDATE users SET storage_used_bytes = GREATEST(storage_used_bytes - $2, 0) WHERE id = $1",
    )
    .bind(user_id)
    .bind(freed)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    // The rows are gone; a failed object delete leaves work for the sweep.
    for (key, version) in messages
        .iter()
        .map(|(key, version, _)| (key.as_str(), version.as_str()))
        .chain(attachments.iter().map(|(key, _)| (key.as_str(), "")))
    {
        if let Err(error) = state.storage.delete_stored(key, version).await {
            tracing::warn!(error = %error, "mail: deleted message object left for the sweep");
        }
    }
    if list_copies > 0 {
        if let Err(error) =
            crate::mail::groups::release_unreferenced(&state.pool, &state.storage).await
        {
            tracing::warn!(error = %error, "mail: group objects left for the next release");
        }
    }
    Ok(deleted.len() as u64)
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailFolderCount {
    pub folder: String,
    pub unread: i64,
    pub total: i64,
}

/// `GET /api/mail/counts` — unread and total per folder, and for Starred.
#[utoipa::path(
    get,
    path = "/api/mail/counts",
    tag = "mail",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Per folder", body = [MailFolderCount]))
)]
pub async fn counts(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<MailFolderCount>>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT folder, COUNT(*) FILTER (WHERE NOT seen), COUNT(*)
           FROM mail_messages WHERE user_id = $1 GROUP BY folder
         UNION ALL
         SELECT 'starred', COUNT(*) FILTER (WHERE NOT seen), COUNT(*)
           FROM mail_messages
          WHERE user_id = $1 AND starred AND folder NOT IN ('spam', 'trash')",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(folder, unread, total)| MailFolderCount {
                folder,
                unread,
                total,
            })
            .collect(),
    ))
}

/// `GET /api/mail/threads/{id}` — every message of one of your threads,
/// oldest first.
#[utoipa::path(
    get,
    path = "/api/mail/threads/{id}",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Thread id")),
    responses(
        (status = 200, description = "The thread", body = [MailMessage]),
        (status = 404, description = "No such thread of yours"),
    )
)]
pub async fn thread(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<MailMessage>>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let rows: Vec<Row> = sqlx::query_as(&format!(
        "SELECT {ROW_COLUMNS} FROM mail_messages
          WHERE user_id = $1 AND thread_id = $2
          ORDER BY received_at, id
          LIMIT 500"
    ))
    .bind(user_id)
    .bind(id)
    .fetch_all(&state.pool)
    .await?;
    if rows.is_empty() {
        return Err(AppError::not_found("not found"));
    }
    Ok(Json(rows.into_iter().map(MailMessage::from).collect()))
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
