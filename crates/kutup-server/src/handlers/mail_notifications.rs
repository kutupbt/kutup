//! `GET /api/mail/notifications` — new mail to tell the reader about
//! (docs/plans/mail-parity.md, P6), as Proton's `useNewEmailNotification`:
//! unread mail that arrived, or snoozed mail that came back, in the Inbox,
//! Starred, or a folder with notifications on (never Spam or Trash). Mail
//! open in a tab asks on its poll with the `now` of its last answer, and
//! shows a desktop notification for each. The answer looks a minute
//! further back than `after`, so mail whose arrival committed just after the
//! last answer is not missed; the reader skips what it already showed.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

/// At most this many in one answer; the reader then sees one grouped notice.
const MAX_NEW: i64 = 20;

#[derive(Debug, Deserialize, IntoParams)]
pub struct NotificationsQuery {
    /// The `now` of the last answer (RFC 3339); without it, only `now`.
    pub after: Option<String>,
}

#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct NewMail {
    pub id: String,
    pub thread_id: String,
    /// `inbox`, or `custom` with `custom_folder`.
    pub folder: String,
    pub custom_folder: Option<String>,
    pub subject: String,
    pub from_address: String,
    pub from_name: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NewMailPage {
    /// The next `after`.
    pub now: String,
    /// Oldest first.
    pub messages: Vec<NewMail>,
    /// More arrived than are listed.
    pub more: bool,
}

#[utoipa::path(
    get,
    path = "/api/mail/notifications",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(NotificationsQuery),
    responses(
        (status = 200, description = "New mail since `after`", body = NewMailPage),
        (status = 400, description = "`after` is not an RFC 3339 time"),
    )
)]
pub async fn new_mail(
    State(state): State<AppState>,
    user: AuthUser,
    Query(query): Query<NotificationsQuery>,
) -> AppResult<Json<NewMailPage>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let now: OffsetDateTime = sqlx::query_scalar("SELECT now()")
        .fetch_one(&state.pool)
        .await?;
    let now_text = now
        .format(&Rfc3339)
        .map_err(|_| AppError::internal("time"))?;
    let Some(after) = query
        .after
        .as_deref()
        .map(str::trim)
        .filter(|a| !a.is_empty())
    else {
        return Ok(Json(NewMailPage {
            now: now_text,
            messages: Vec::new(),
            more: false,
        }));
    };
    let after = OffsetDateTime::parse(after, &Rfc3339)
        .map_err(|_| AppError::bad_request("after is an RFC 3339 time"))?;
    let mut messages: Vec<NewMail> = sqlx::query_as(
        "SELECT m.id::text, m.thread_id::text, m.folder, m.custom_folder::text, m.subject,
                m.from_address, m.from_name
           FROM mail_messages m
          WHERE m.owner = $1 AND m.user_id = $1
            AND m.notify_at > $2 - interval '1 minute' AND m.notify_at <= $3
            AND m.direction = 'inbound' AND NOT m.seen
            AND (m.folder = 'inbox'
                 OR (m.starred AND m.folder NOT IN ('spam', 'trash'))
                 OR (m.folder = 'custom' AND EXISTS (
                        SELECT 1 FROM mail_folders f
                         WHERE f.user_id = m.user_id AND f.id = m.custom_folder AND f.notify)))
          ORDER BY m.notify_at, m.id
          LIMIT $4",
    )
    .bind(user_id)
    .bind(after)
    .bind(now)
    .bind(MAX_NEW + 1)
    .fetch_all(&state.pool)
    .await?;
    let more = messages.len() as i64 > MAX_NEW;
    messages.truncate(MAX_NEW as usize);
    Ok(Json(NewMailPage {
        now: now_text,
        messages,
        more,
    }))
}
