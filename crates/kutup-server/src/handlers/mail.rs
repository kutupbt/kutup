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

pub(crate) const FOLDERS: [&str; 8] = [
    "inbox",
    "drafts",
    "scheduled",
    "snoozed",
    "sent",
    "archive",
    "spam",
    "trash",
];
/// Messages one request may file or delete.
const MAX_BATCH: usize = 500;
const DEFAULT_PAGE: i64 = 50;
const MAX_PAGE: i64 = 200;

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq, Eq)]
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
    /// A fixed folder, or `custom` with `custom_folder`.
    pub folder: String,
    /// The account's own folder the message is in (`folder` is `custom`).
    pub custom_folder: Option<String>,
    /// The account's labels on the message.
    pub labels: Vec<String>,
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
    /// From a mailing list the reader unsubscribed from (Proton's banner then says so).
    pub unsubscribed: bool,
    /// From a list that offers a way out (List-Unsubscribe, noted on arrival):
    /// moving it to Spam may unsubscribe (Proton's SpamAction).
    pub unsubscribable: bool,
    /// The reader sent the read receipt its sender asked for (Proton's
    /// "Read receipt sent").
    pub receipt_sent: bool,
    /// Its attached files (Proton's AttachmentsMetadata), for the list.
    pub attachments: Vec<crate::mail::headers::AttachmentMeta>,
    /// A scheduled message (folder `scheduled`): when it is sent, and its
    /// held send, to take it back with `POST /api/mail/outbox/{id}/cancel`.
    #[serde(with = "time::serde::rfc3339::option")]
    pub scheduled_at: Option<OffsetDateTime>,
    pub outbox_id: Option<String>,
    /// Snoozed (folder `snoozed`): when it comes back to the Inbox.
    #[serde(with = "time::serde::rfc3339::option")]
    pub snoozed_until: Option<OffsetDateTime>,
    /// The distribution list or shared mailbox it came through.
    pub group_address: Option<String>,
    /// A shared mailbox's sent mail: the member who sent it.
    pub sent_by: Option<String>,
    /// Listed by conversation: the thread this message is the newest of, in
    /// the place listed (Proton's conversation grouping).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation: Option<MailConversation>,
}

/// A conversation in one place: its messages there, as Proton's
/// `ContextNumMessages` and `ContextNumUnread`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailConversation {
    /// Its messages here, oldest first: what an action on the row acts on.
    pub members: Vec<ConversationMember>,
    pub unread: i64,
    /// Any of them starred.
    pub starred: bool,
    /// Who wrote them, each once, in the order they first wrote.
    pub senders: Vec<MailMailbox>,
    /// Attachments across them.
    pub attachment_count: i64,
    /// Their attached files, oldest message first (Proton's
    /// AttachmentsMetadata for a conversation).
    pub attachments: Vec<crate::mail::headers::AttachmentMeta>,
}

/// What moving or marking one message of a conversation needs.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConversationMember {
    pub id: String,
    pub folder: String,
    pub direction: String,
    pub custom_folder: Option<String>,
    #[serde(default)]
    pub unsubscribable: bool,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailMessagePage {
    pub messages: Vec<MailMessage>,
    /// Pass as `before` for the next, older page; absent on the last.
    pub next: Option<String>,
    /// With `page`: how many messages (or conversations) the place holds
    /// with these filters, for Proton's "page N of M".
    pub total: Option<i64>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct MailListQuery {
    /// One of inbox, drafts, sent, archive, spam, trash; or `starred`, or
    /// `all` (everything but Spam and Trash); or `folder:<id>` for one of the
    /// account's folders, or `label:<id>` for a label (outside Spam and Trash).
    pub folder: String,
    /// Searches subjects and addresses.
    pub q: Option<String>,
    /// The `next` of the previous page.
    pub before: Option<String>,
    /// Page number from 0, `limit` to a page (Proton's paging), instead of
    /// `before`; the answer then carries `total`.
    pub page: Option<i64>,
    pub limit: Option<i64>,
    /// A shared mailbox (its group id) instead of your own.
    pub group: Option<String>,
    /// One row per conversation, its newest message here (Proton's
    /// conversation grouping); the cursor then pages conversations.
    #[serde(default)]
    pub conversations: bool,
    /// `true`: unread only; `false`: read only (Proton's Unread and Read
    /// filters); by conversation, one with any unread message counts as
    /// unread.
    pub unread: Option<bool>,
    /// Only messages (or conversations) with attachments.
    #[serde(default)]
    pub attachments: bool,
    /// `newest` (the default), `oldest`, `largest` or `smallest` (Proton's
    /// sort options); the cursor follows it.
    pub sort: Option<String>,
}

/// How a page is ordered, as Proton's sort options.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sort {
    Newest,
    Oldest,
    Largest,
    Smallest,
}

impl Sort {
    fn parse(value: Option<&str>) -> AppResult<Self> {
        Ok(match value.unwrap_or("newest") {
            "newest" => Sort::Newest,
            "oldest" => Sort::Oldest,
            "largest" => Sort::Largest,
            "smallest" => Sort::Smallest,
            _ => {
                return Err(AppError::bad_request(
                    "sort is newest, oldest, largest or smallest",
                ))
            }
        })
    }

    fn by_size(self) -> bool {
        matches!(self, Sort::Largest | Sort::Smallest)
    }

    fn descending(self) -> bool {
        matches!(self, Sort::Newest | Sort::Largest)
    }

    /// `ORDER BY` for `time` and `size` columns (and `id`).
    fn order(self, time: &str, size: &str, id: &str) -> String {
        let column = if self.by_size() { size } else { time };
        let direction = if self.descending() { "DESC" } else { "ASC" };
        format!("{column} {direction}, {id} {direction}")
    }

    /// The page's start: past the cursor in the sort's direction ($3 time,
    /// $9 size, $4 id).
    fn after(self, time: &str, size: &str, id: &str) -> String {
        let op = if self.descending() { "<" } else { ">" };
        if self.by_size() {
            format!("($9::bigint IS NULL OR ({size}, {id}) {op} ($9, $4))")
        } else {
            format!("($3::timestamptz IS NULL OR ({time}, {id}) {op} ($3, $4))")
        }
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct Row {
    id: Uuid,
    thread_id: Uuid,
    direction: String,
    folder: String,
    custom_folder: Option<Uuid>,
    labels: Vec<Uuid>,
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
    unsubscribed: bool,
    unsubscribable: bool,
    receipt_sent: bool,
    attachments: sqlx::types::Json<Vec<crate::mail::headers::AttachmentMeta>>,
    scheduled_at: Option<OffsetDateTime>,
    outbox_id: Option<Uuid>,
    snoozed_until: Option<OffsetDateTime>,
    group_address: Option<String>,
    sent_by_name: Option<String>,
}

/// The columns a [`Row`] reads.
pub(crate) const ROW_COLUMNS: &str = "id, thread_id, direction, folder, custom_folder,
    ARRAY(SELECT l.label_id FROM mail_message_labels l WHERE l.message_id = mail_messages.id) AS labels,
    seen, starred, protection,
    size_bytes, received_at, sent_at, subject, from_address, from_name, to_list, cc_list,
    reply_to, bcc_list, message_id, in_reply_to, references_list, attachment_count, unsubscribed,
    unsubscribable, receipt_sent, attachments,
    (SELECT o.deliver_at FROM mail_outbox o WHERE o.draft_id = mail_messages.id AND o.scheduled
        AND o.state = 'pending') AS scheduled_at,
    (SELECT o.id FROM mail_outbox o WHERE o.draft_id = mail_messages.id AND o.scheduled
        AND o.state = 'pending') AS outbox_id,
    snoozed_until,
    (SELECT g.address FROM mail_groups g WHERE g.id = mail_messages.group_id) AS group_address,
    (SELECT u.username FROM users u WHERE u.id = mail_messages.sent_by) AS sent_by_name";

impl From<Row> for MailMessage {
    fn from(row: Row) -> Self {
        MailMessage {
            id: row.id.to_string(),
            thread_id: row.thread_id.to_string(),
            direction: row.direction,
            folder: row.folder,
            custom_folder: row.custom_folder.map(|id| id.to_string()),
            labels: row.labels.iter().map(Uuid::to_string).collect(),
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
            unsubscribed: row.unsubscribed,
            unsubscribable: row.unsubscribable,
            receipt_sent: row.receipt_sent,
            attachments: row.attachments.0,
            scheduled_at: row.scheduled_at,
            outbox_id: row.outbox_id.map(|id| id.to_string()),
            snoozed_until: row.snoozed_until,
            group_address: row.group_address,
            sent_by: row.sent_by_name,
            conversation: None,
        }
    }
}

/// Whose mailbox a request is about: the caller's own, or a shared mailbox
/// (docs/plans/mail-groups.md) they are a member of. Rows are scoped by
/// `mail_messages.owner`, the account or the group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mailbox {
    Own(Uuid),
    Shared(Uuid),
}

impl Mailbox {
    pub(crate) fn owner(self) -> Uuid {
        match self {
            Mailbox::Own(id) | Mailbox::Shared(id) => id,
        }
    }
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct MailboxQuery {
    /// A shared mailbox (its group id) instead of your own.
    pub group: Option<String>,
}

/// The mailbox `group` names for `user_id`; not a member (or not a shared
/// mailbox) is "not found", as for someone else's message.
pub(crate) async fn mailbox(
    state: &AppState,
    user_id: Uuid,
    group: Option<&str>,
) -> AppResult<Mailbox> {
    let Some(group) = group else {
        return Ok(Mailbox::Own(user_id));
    };
    let group = Uuid::parse_str(group).map_err(|_| AppError::not_found("not found"))?;
    let member: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM mail_group_members m JOIN mail_groups g ON g.id = m.group_id
                         WHERE m.group_id = $1 AND m.user_id = $2 AND g.kind = 'shared')",
    )
    .bind(group)
    .bind(user_id)
    .fetch_one(&state.pool)
    .await?;
    if !member {
        return Err(AppError::not_found("not found"));
    }
    Ok(Mailbox::Shared(group))
}

/// A page cursor: the last row's sort key (arrival time in nanoseconds, or
/// size in bytes) and id.
fn cursor(key: i128, id: Uuid) -> String {
    format!("{key}_{id}")
}

/// Where a page starts: an arrival time or a size, with the id after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cursor {
    time: Option<OffsetDateTime>,
    size: Option<i64>,
    id: Uuid,
}

fn parse_cursor(value: &str, sort: Sort) -> AppResult<Cursor> {
    let bad = || AppError::bad_request("before is not a cursor");
    let (key, id) = value.split_once('_').ok_or_else(bad)?;
    let key: i128 = key.parse().map_err(|_| bad())?;
    let id = Uuid::parse_str(id).map_err(|_| bad())?;
    Ok(if sort.by_size() {
        Cursor {
            time: None,
            size: Some(i64::try_from(key).map_err(|_| bad())?),
            id,
        }
    } else {
        Cursor {
            time: Some(OffsetDateTime::from_unix_timestamp_nanos(key).map_err(|_| bad())?),
            size: None,
            id,
        }
    })
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
    let owner = mailbox(&state, user_id, query.group.as_deref())
        .await?
        .owner();
    let folder = query.folder.as_str();
    // One of the account's folders or labels: `folder:<id>`, `label:<id>`.
    let (place, place_id) = match folder.split_once(':') {
        Some((kind @ ("folder" | "label"), id)) => (
            kind,
            Some(Uuid::parse_str(id).map_err(|_| AppError::bad_request("unknown folder"))?),
        ),
        _ if FOLDERS.contains(&folder) || folder == "starred" || folder == "all" => (folder, None),
        _ => return Err(AppError::bad_request("unknown folder")),
    };
    // All mail leaves out Spam and Trash only when the account asks
    // (Proton's "Exclude Spam/Trash from All mail"); a search always does.
    let almost_all = query.q.as_deref().is_some_and(|q| !q.trim().is_empty())
        || crate::handlers::mail_settings::settings_of(&state, user_id)
            .await?
            .almost_all_mail;
    let limit = query.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
    let sort = Sort::parse(query.sort.as_deref())?;
    let before = query
        .before
        .as_deref()
        .map(|value| parse_cursor(value, sort))
        .transpose()?;
    let page = match (query.page, &before) {
        (Some(_), Some(_)) => return Err(AppError::bad_request("page or before, not both")),
        (Some(page), None) if !(0..=MAX_PAGE_NUMBER).contains(&page) => {
            return Err(AppError::bad_request("page is out of range"))
        }
        (page, _) => page,
    };
    let filters = Filters {
        unread: query.unread,
        attachments: query.attachments,
        sort,
    };
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
    let listing = Listing {
        owner,
        place,
        place_id,
        almost_all,
        search,
        before,
        filters,
        place_filter: PLACE_WHERE,
    };
    if query.conversations {
        return list_conversations(&state, &listing, limit, page).await;
    }
    let (mut rows, mut total) = message_rows(&state, &listing, limit, page.unwrap_or(0)).await?;
    // Past the end (mail moved away since): the total still answers.
    if rows.is_empty() && page.is_some_and(|p| p > 0) {
        total = message_rows(&state, &listing, 1, 0).await?.1;
    }
    let more = rows.len() as i64 > limit;
    if page.is_some() {
        rows.truncate(limit as usize);
    }
    let messages: Vec<MailMessage> = rows
        .into_iter()
        .take(limit as usize)
        .map(MailMessage::from)
        .collect();
    let next = more.then(|| messages.last()).flatten().map(|last| {
        let key = if sort.by_size() {
            i128::from(last.size)
        } else {
            last.received_at.unix_timestamp_nanos()
        };
        cursor(key, Uuid::parse_str(&last.id).expect("own id"))
    });
    Ok(Json(MailMessagePage {
        messages,
        next,
        total: page.map(|_| total),
    }))
}

/// Pages past this are refused (`page × limit` stays small for `OFFSET`).
const MAX_PAGE_NUMBER: i64 = 10_000;

/// What a listing asks for, beyond its page.
struct Listing<'a> {
    owner: Uuid,
    place: &'a str,
    place_id: Option<Uuid>,
    almost_all: bool,
    search: Option<String>,
    before: Option<Cursor>,
    filters: Filters,
    /// The place and the search, as SQL over `mail_messages`.
    place_filter: &'a str,
}

#[derive(sqlx::FromRow)]
struct CountedRow {
    #[sqlx(flatten)]
    row: Row,
    full_count: i64,
}

/// One page of messages (one more than `limit`, to tell whether more
/// follow), skipping `page` pages, and how many there are in all.
async fn message_rows(
    state: &AppState,
    listing: &Listing<'_>,
    limit: i64,
    page: i64,
) -> AppResult<(Vec<Row>, i64)> {
    let sort = listing.filters.sort;
    let after = sort.after("received_at", "size_bytes", "id");
    let order = sort.order("received_at", "size_bytes", "id");
    let place_filter = listing.place_filter;
    let rows: Vec<CountedRow> = sqlx::query_as(&format!(
        "SELECT {ROW_COLUMNS}, count(*) OVER () AS full_count
           FROM mail_messages
          WHERE {place_filter}
            AND ($10::bool IS NULL OR seen <> $10)
            AND (NOT $11 OR attachment_count > 0)
            AND {after}
          ORDER BY {order}
          LIMIT $5 OFFSET $12"
    ))
    .bind(listing.owner)
    .bind(listing.place)
    .bind(listing.before.and_then(|c| c.time))
    .bind(listing.before.map(|c| c.id))
    .bind(limit + 1)
    .bind(listing.search.as_deref())
    .bind(listing.place_id)
    .bind(listing.almost_all)
    .bind(listing.before.and_then(|c| c.size))
    .bind(listing.filters.unread)
    .bind(listing.filters.attachments)
    .bind(page * limit)
    .fetch_all(&state.pool)
    .await?;
    let total = rows.first().map_or(0, |r| r.full_count);
    Ok((rows.into_iter().map(|r| r.row).collect(), total))
}

/// The place and the search, shared by the listings and batch changes: $1
/// owner, $2 place, $6 search, $7 the folder or label, $8 almost all mail.
const PLACE_WHERE: &str = "owner = $1
        AND CASE $2
              WHEN 'starred' THEN starred AND folder NOT IN ('spam', 'trash')
              WHEN 'all' THEN (NOT $8 OR folder NOT IN ('spam', 'trash'))
              WHEN 'folder' THEN custom_folder = $7
              WHEN 'label' THEN folder NOT IN ('spam', 'trash') AND EXISTS (
                  SELECT 1 FROM mail_message_labels l
                   WHERE l.message_id = mail_messages.id AND l.label_id = $7)
              ELSE folder = $2
            END
        AND ($6::text IS NULL OR subject ILIKE $6 OR from_address ILIKE $6
             OR from_name ILIKE $6 OR to_list::text ILIKE $6 OR cc_list::text ILIKE $6)";

/// The list's filters and order beyond the place and the search.
#[derive(Clone, Copy, Debug)]
struct Filters {
    unread: Option<bool>,
    attachments: bool,
    sort: Sort,
}

type ConversationRow = (
    Uuid,
    OffsetDateTime,
    sqlx::types::Json<Vec<ConversationMember>>,
    i64,
    bool,
    sqlx::types::Json<Vec<MailMailbox>>,
    i64,
    i64,
    i64,
    sqlx::types::Json<Vec<crate::mail::headers::AttachmentMeta>>,
);

/// [`list_messages`] by conversation: each thread's newest message in the
/// place, in the sort's order (by its newest arrival, or by its messages'
/// size together, as Proton sorts conversations), with what the row stands
/// for.
async fn list_conversations(
    state: &AppState,
    listing: &Listing<'_>,
    limit: i64,
    page: Option<i64>,
) -> AppResult<Json<MailMessagePage>> {
    let owner = listing.owner;
    let sort = listing.filters.sort;
    let (mut threads, mut total) =
        conversation_rows(state, listing, limit, page.unwrap_or(0)).await?;
    if threads.is_empty() && page.is_some_and(|p| p > 0) {
        total = conversation_rows(state, listing, 1, 0).await?.1;
    }
    let more = threads.len() as i64 > limit;
    threads.truncate(limit as usize);
    let latest: Vec<Uuid> = threads.iter().map(|t| t.0).collect();
    let rows: Vec<Row> = sqlx::query_as(&format!(
        "SELECT {ROW_COLUMNS} FROM mail_messages WHERE owner = $1 AND id = ANY($2)"
    ))
    .bind(owner)
    .bind(&latest)
    .fetch_all(&state.pool)
    .await?;
    let mut by_id: std::collections::HashMap<Uuid, Row> =
        rows.into_iter().map(|r| (r.id, r)).collect();
    let next = more.then(|| threads.last()).flatten().map(|row| {
        let key = if sort.by_size() {
            i128::from(row.7)
        } else {
            row.1.unix_timestamp_nanos()
        };
        cursor(key, row.0)
    });
    let messages = threads
        .into_iter()
        .filter_map(
            |(id, _, members, unread, starred, senders, attachments, _, _, files)| {
                // Moved or deleted between the two reads: left for the next refresh.
                let mut message = MailMessage::from(by_id.remove(&id)?);
                message.conversation = Some(MailConversation {
                    members: members.0,
                    unread,
                    starred,
                    senders: senders.0,
                    attachment_count: attachments,
                    attachments: files.0,
                });
                Some(message)
            },
        )
        .collect();
    Ok(Json(MailMessagePage {
        messages,
        next,
        total: page.map(|_| total),
    }))
}

/// One page of conversations (one more than `limit`), skipping `page`
/// pages, and how many there are in all.
async fn conversation_rows(
    state: &AppState,
    listing: &Listing<'_>,
    limit: i64,
    page: i64,
) -> AppResult<(Vec<ConversationRow>, i64)> {
    let sort = listing.filters.sort;
    let place_filter = listing.place_filter;
    let after = sort.after("t.last_at", "t.total_size", "t.latest");
    let order = sort.order("t.last_at", "t.total_size", "t.latest");
    let threads: Vec<ConversationRow> = sqlx::query_as(&format!(
        "WITH here AS (
             SELECT id, thread_id, folder, direction, custom_folder, received_at, seen, starred,
                    from_address, from_name, attachment_count, size_bytes, unsubscribable,
                    attachments
               FROM mail_messages
              WHERE {place_filter}
         ), threads AS (
             SELECT thread_id,
                    (array_agg(id ORDER BY received_at DESC, id DESC))[1] AS latest,
                    max(received_at) AS last_at,
                    jsonb_agg(jsonb_build_object('id', id, 'folder', folder, 'direction', direction,
                                                 'customFolder', custom_folder,
                                                 'unsubscribable', unsubscribable)
                              ORDER BY received_at, id) AS members,
                    count(*) FILTER (WHERE NOT seen) AS unread,
                    bool_or(starred) AS starred,
                    sum(attachment_count)::bigint AS attachments,
                    sum(size_bytes)::bigint AS total_size
               FROM here GROUP BY thread_id
         )
         SELECT t.latest, t.last_at, t.members, t.unread, t.starred,
                COALESCE((SELECT jsonb_agg(jsonb_build_object('address', s.from_address, 'name', s.from_name)
                                           ORDER BY s.first_at)
                            FROM (SELECT from_address, (array_agg(from_name ORDER BY received_at))[1] AS from_name,
                                         min(received_at) AS first_at
                                    FROM here h WHERE h.thread_id = t.thread_id AND h.from_address <> ''
                                   GROUP BY from_address) s), '[]'::jsonb),
                t.attachments, t.total_size, count(*) OVER (),
                COALESCE((SELECT jsonb_agg(e.a || jsonb_build_object('message', h.id) ORDER BY h.received_at, h.id, e.n)
                            FROM here h, jsonb_array_elements(h.attachments) WITH ORDINALITY AS e(a, n)
                           WHERE h.thread_id = t.thread_id), '[]'::jsonb)
           FROM threads t
          WHERE ($10::bool IS NULL OR (t.unread > 0) = $10)
            AND (NOT $11 OR t.attachments > 0)
            AND {after}
          ORDER BY {order}
          LIMIT $5 OFFSET $12"
    ))
    .bind(listing.owner)
    .bind(listing.place)
    .bind(listing.before.and_then(|c| c.time))
    .bind(listing.before.map(|c| c.id))
    .bind(limit + 1)
    .bind(listing.search.as_deref())
    .bind(listing.place_id)
    .bind(listing.almost_all)
    .bind(listing.before.and_then(|c| c.size))
    .bind(listing.filters.unread)
    .bind(listing.filters.attachments)
    .bind(page * limit)
    .fetch_all(&state.pool)
    .await?;
    let total = threads.first().map_or(0, |t| t.8);
    Ok((threads, total))
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailReceiptSent {
    /// A shared mailbox (its group id) instead of your own.
    pub group: Option<String>,
}

/// `POST /api/mail/messages/{id}/receipt` — notes that the reader sent the
/// read receipt the message asked for (Proton's "Send read receipt"). The
/// client sends the receipt itself, as mail (RFC 8098), so its contents
/// stay end to end where the original was.
#[utoipa::path(
    post,
    path = "/api/mail/messages/{id}/receipt",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Message id")),
    request_body = MailReceiptSent,
    responses(
        (status = 204, description = "Noted"),
        (status = 404, description = "Not a received message of yours"),
    )
)]
pub async fn receipt_sent(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(request): Json<MailReceiptSent>,
) -> AppResult<axum::http::StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let owner = mailbox(&state, user_id, request.group.as_deref())
        .await?
        .owner();
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let marked = sqlx::query(
        "UPDATE mail_messages SET receipt_sent = true
          WHERE id = $1 AND owner = $2 AND direction = 'inbound'",
    )
    .bind(id)
    .bind(owner)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if marked == 0 {
        return Err(AppError::not_found("not found"));
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnsubscribeMailList {
    /// The message's https `List-Unsubscribe` URL when it also has
    /// `List-Unsubscribe-Post: List-Unsubscribe=One-Click` (RFC 8058): the
    /// server sends the request. Absent when the reader unsubscribed
    /// another way (a web page, an email).
    pub one_click_url: Option<String>,
    /// A shared mailbox (its group id) instead of your own.
    pub group: Option<String>,
}

/// `POST /api/mail/messages/{id}/unsubscribe` — unsubscribes from the
/// message's mailing list (Proton's one-click unsubscribe), or records that
/// the reader did, so the message says "Unsubscribed".
#[utoipa::path(
    post,
    path = "/api/mail/messages/{id}/unsubscribe",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Message id")),
    request_body = UnsubscribeMailList,
    responses(
        (status = 204, description = "Unsubscribed"),
        (status = 404, description = "No such message of yours"),
        (status = 502, description = "The list did not take the request"),
    )
)]
pub async fn unsubscribe(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(request): Json<UnsubscribeMailList>,
) -> AppResult<axum::http::StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let owner = mailbox(&state, user_id, request.group.as_deref())
        .await?
        .owner();
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM mail_messages WHERE id = $1 AND owner = $2 AND direction = 'inbound')",
    )
    .bind(id)
    .bind(owner)
    .fetch_one(&state.pool)
    .await?;
    if !exists {
        return Err(AppError::not_found("not found"));
    }
    if let Some(url) = request.one_click_url.as_deref() {
        crate::mail::unsubscribe::one_click(&state, url)
            .await
            .map_err(|_| {
                AppError::new(
                    axum::http::StatusCode::BAD_GATEWAY,
                    "the mailing list did not take the request",
                )
            })?;
    }
    sqlx::query("UPDATE mail_messages SET unsubscribed = true WHERE id = $1 AND owner = $2")
        .bind(id)
        .bind(owner)
        .execute(&state.pool)
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// `GET /api/mail/messages/{id}/content` — the stored message: a binary
/// OpenPGP message encrypted to the address key.
#[utoipa::path(
    get,
    path = "/api/mail/messages/{id}/content",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Message id"), MailboxQuery),
    responses(
        (status = 200, description = "The encrypted message", content_type = "application/octet-stream"),
        (status = 404, description = "No such message of yours"),
    )
)]
pub async fn message_content(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(scope): Query<MailboxQuery>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let owner = mailbox(&state, user_id, scope.group.as_deref())
        .await?
        .owner();
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    // Each message is written once under its own key, so the plain key is
    // always the stored version.
    let row: Option<(String, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT object_key, key_packet FROM mail_messages WHERE id = $1 AND owner = $2",
    )
    .bind(id)
    .bind(owner)
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

fn parse_place(id: &str) -> AppResult<Uuid> {
    Uuid::parse_str(id).map_err(|_| AppError::bad_request("not a folder or label id"))
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
    /// trash for sent mail; `custom` with `customFolder` for either. Drafts
    /// stay in Drafts.
    pub folder: Option<String>,
    /// One of the account's folders, with `folder: "custom"`.
    pub custom_folder: Option<String>,
    /// Labels of the account to add or remove (drafts included).
    #[serde(default)]
    pub add_labels: Vec<String>,
    #[serde(default)]
    pub remove_labels: Vec<String>,
    /// A shared mailbox (its group id) instead of your own.
    pub group: Option<String>,
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
    let owner = mailbox(&state, user_id, request.group.as_deref())
        .await?
        .owner();
    let ids = parse_ids(&request.ids)?;
    let updated = update_ids(&state, user_id, owner, &ids, &request).await?;
    Ok(Json(UpdatedMailMessages { updated }))
}

/// [`update_messages`]' change, on `ids` of `owner`'s mailbox (any number:
/// a batch over a whole place passes them all).
async fn update_ids(
    state: &AppState,
    user_id: Uuid,
    owner: Uuid,
    ids: &[Uuid],
    request: &UpdateMailMessages,
) -> AppResult<u64> {
    let add: Vec<Uuid> = request
        .add_labels
        .iter()
        .map(|id| parse_place(id))
        .collect::<AppResult<_>>()?;
    let remove: Vec<Uuid> = request
        .remove_labels
        .iter()
        .map(|id| parse_place(id))
        .collect::<AppResult<_>>()?;
    if request.seen.is_none()
        && request.starred.is_none()
        && request.folder.is_none()
        && add.is_empty()
        && remove.is_empty()
    {
        return Err(AppError::bad_request("nothing to change"));
    }
    if add.len() > 50 || remove.len() > 50 {
        return Err(AppError::bad_request("50 labels at most"));
    }
    let custom = match (request.folder.as_deref(), request.custom_folder.as_deref()) {
        (Some("custom"), Some(id)) => Some(parse_place(id)?),
        (Some(folder), None) if ["inbox", "archive", "spam", "trash", "sent"].contains(&folder) => {
            None
        }
        (None, None) => None,
        _ => return Err(AppError::bad_request("cannot move messages there")),
    };
    if request.group.is_some() && (custom.is_some() || !add.is_empty() || !remove.is_empty()) {
        // A shared mailbox has no folders or labels of its own yet
        // (docs/plans/mail-filters.md), and yours are yours alone.
        return Err(AppError::bad_request(
            "folders and labels belong to your own mailbox",
        ));
    }
    let mut tx = state.pool.begin().await?;
    if let Some(custom) = custom {
        let mine: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM mail_folders WHERE user_id = $1 AND id = $2)",
        )
        .bind(user_id)
        .bind(custom)
        .fetch_one(&mut *tx)
        .await?;
        if !mine {
            return Err(AppError::bad_request("no such folder"));
        }
    }
    let labels: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mail_labels WHERE user_id = $1 AND id = ANY($2)")
            .bind(user_id)
            .bind(add.iter().chain(&remove).copied().collect::<Vec<_>>())
            .fetch_one(&mut *tx)
            .await?;
    let mut wanted: Vec<Uuid> = add.iter().chain(&remove).copied().collect();
    wanted.sort();
    wanted.dedup();
    if labels != wanted.len() as i64 {
        return Err(AppError::bad_request("no such label"));
    }
    let updated = if request.seen.is_some() || request.starred.is_some() || request.folder.is_some()
    {
        sqlx::query(
            "UPDATE mail_messages SET
                 seen = CASE WHEN $5::text = 'trash' THEN true ELSE COALESCE($3, seen) END,
                 starred = COALESCE($4, starred),
                 folder = COALESCE($5, folder),
                 custom_folder = CASE WHEN $5::text IS NULL THEN custom_folder ELSE $6 END,
                 -- Moved out of Snoozed: no longer waiting to come back.
                 snoozed_until = CASE WHEN $5::text IS NULL THEN snoozed_until ELSE NULL END
              WHERE owner = $1 AND id = ANY($2)
                AND ($5::text IS NULL OR (
                      folder NOT IN ('drafts', 'scheduled') AND (
                        $5 = 'custom'
                     OR (direction = 'inbound' AND $5 IN ('inbox', 'archive', 'spam', 'trash'))
                     OR (direction = 'outbound' AND $5 IN ('sent', 'archive', 'trash')))))",
        )
        .bind(owner)
        .bind(ids)
        .bind(request.seen)
        .bind(request.starred)
        .bind(request.folder.as_deref())
        .bind(custom)
        .execute(&mut *tx)
        .await?
        .rows_affected()
    } else {
        // Labels only: every message of yours among the ids counts.
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM mail_messages WHERE owner = $1 AND id = ANY($2)",
        )
        .bind(owner)
        .bind(ids)
        .fetch_one(&mut *tx)
        .await? as u64
    };
    if !add.is_empty() {
        sqlx::query(
            "INSERT INTO mail_message_labels (message_id, label_id)
             SELECT m.id, l FROM mail_messages m, UNNEST($3::uuid[]) l
              WHERE m.user_id = $1 AND m.id = ANY($2)
             ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(ids)
        .bind(&add)
        .execute(&mut *tx)
        .await?;
    }
    if !remove.is_empty() {
        sqlx::query(
            "DELETE FROM mail_message_labels l USING mail_messages m
              WHERE l.message_id = m.id AND m.user_id = $1 AND m.id = ANY($2) AND l.label_id = ANY($3)",
        )
        .bind(user_id)
        .bind(ids)
        .bind(&remove)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(updated)
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnoozeMailMessages {
    pub ids: Vec<String>,
    /// When they come back to the Inbox (a minute to a year ahead); absent
    /// or null: back now (Unsnooze).
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub until: Option<OffsetDateTime>,
    /// A shared mailbox (its group id) instead of your own.
    pub group: Option<String>,
}

/// `POST /api/mail/messages/snooze` — Proton's Snooze: Inbox messages wait
/// in Snoozed until `until`, then come back unread; without `until`,
/// snoozed messages come back now.
#[utoipa::path(
    post,
    path = "/api/mail/messages/snooze",
    tag = "mail",
    security(("BearerAuth" = [])),
    request_body = SnoozeMailMessages,
    responses(
        (status = 200, description = "How many changed", body = UpdatedMailMessages),
        (status = 400, description = "A time outside a minute to a year ahead, or bad ids"),
    )
)]
pub async fn snooze_messages(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<SnoozeMailMessages>,
) -> AppResult<Json<UpdatedMailMessages>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let owner = mailbox(&state, user_id, request.group.as_deref())
        .await?
        .owner();
    let ids = parse_ids(&request.ids)?;
    let updated = match request.until {
        Some(until) => {
            let now = OffsetDateTime::now_utc();
            if until < now + time::Duration::minutes(1) || until > now + time::Duration::days(366) {
                return Err(AppError::bad_request(
                    "snooze from a minute to a year ahead",
                ));
            }
            sqlx::query(
                "UPDATE mail_messages SET folder = 'snoozed', snoozed_until = $3
                  WHERE owner = $1 AND id = ANY($2) AND folder IN ('inbox', 'snoozed')
                    AND direction = 'inbound'",
            )
            .bind(owner)
            .bind(&ids)
            .bind(until)
            .execute(&state.pool)
            .await?
            .rows_affected()
        }
        None => sqlx::query(
            "UPDATE mail_messages SET folder = 'inbox', snoozed_until = NULL
              WHERE owner = $1 AND id = ANY($2) AND folder = 'snoozed'",
        )
        .bind(owner)
        .bind(&ids)
        .execute(&state.pool)
        .await?
        .rows_affected(),
    };
    Ok(Json(UpdatedMailMessages { updated }))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchMailMessages {
    /// Every message here: one of inbox, drafts, sent, archive, spam, trash,
    /// `starred`, `folder:<id>` or `label:<id>`, as the list's `folder`.
    /// All mail is not one (Proton's select all leaves it out).
    pub place: String,
    pub seen: Option<bool>,
    /// As in `PATCH /api/mail/messages`.
    pub folder: Option<String>,
    pub custom_folder: Option<String>,
    #[serde(default)]
    pub add_labels: Vec<String>,
    #[serde(default)]
    pub remove_labels: Vec<String>,
    /// A shared mailbox (its group id) instead of your own.
    pub group: Option<String>,
}

/// `POST /api/mail/messages/batch` — Proton's select all: marks read or
/// unread, files or labels every message in a place at once, past the
/// loaded page; the same rules as `PATCH /api/mail/messages`.
#[utoipa::path(
    post,
    path = "/api/mail/messages/batch",
    tag = "mail",
    security(("BearerAuth" = [])),
    request_body = BatchMailMessages,
    responses(
        (status = 200, description = "How many changed", body = UpdatedMailMessages),
        (status = 400, description = "No change asked, All mail, an unknown place or folder"),
    )
)]
pub async fn batch_messages(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<BatchMailMessages>,
) -> AppResult<Json<UpdatedMailMessages>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let owner = mailbox(&state, user_id, request.group.as_deref())
        .await?
        .owner();
    let (place, place_id) = match request.place.split_once(':') {
        Some((kind @ ("folder" | "label"), id)) => (
            kind,
            Some(Uuid::parse_str(id).map_err(|_| AppError::bad_request("unknown place"))?),
        ),
        _ if FOLDERS.contains(&request.place.as_str()) || request.place == "starred" => {
            (request.place.as_str(), None)
        }
        _ => return Err(AppError::bad_request("unknown place")),
    };
    // $6 search, $7 place id, $8 almost all, renumbered for this query.
    let place_filter = PLACE_WHERE
        .replace("$6", "$3")
        .replace("$7", "$4")
        .replace("$8", "$5");
    let ids: Vec<Uuid> = sqlx::query_scalar(&format!(
        "SELECT id FROM mail_messages WHERE {place_filter}"
    ))
    .bind(owner)
    .bind(place)
    .bind(None::<String>)
    .bind(place_id)
    .bind(true)
    .fetch_all(&state.pool)
    .await?;
    let change = UpdateMailMessages {
        ids: Vec::new(),
        seen: request.seen,
        starred: None,
        folder: request.folder,
        custom_folder: request.custom_folder,
        add_labels: request.add_labels,
        remove_labels: request.remove_labels,
        group: request.group,
    };
    // In chunks, each its own transaction: a large mailbox never holds one
    // long row lock or one long statement. A failure part way leaves the
    // chunks before it done, as Proton's background tasks do.
    let mut updated = 0;
    for chunk in ids.chunks(state.config.mail_batch_chunk) {
        updated += update_ids(&state, user_id, owner, chunk, &change).await?;
    }
    if ids.is_empty() {
        // Still checks the change (nothing to change, unknown folder or label).
        update_ids(&state, user_id, owner, &[], &change).await?;
    }
    Ok(Json(UpdatedMailMessages { updated }))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteMailMessages {
    pub ids: Vec<String>,
    /// A shared mailbox (its group id) instead of your own.
    pub group: Option<String>,
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
    let mailbox = mailbox(&state, user_id, request.group.as_deref()).await?;
    let deleted = delete_for_good(&state, mailbox, &ids, &["trash", "spam", "drafts"]).await?;
    Ok(Json(UpdatedMailMessages { updated: deleted }))
}

/// Deletes `ids` of a mailbox that sit in one of `folders`, with their draft
/// attachments, refunds its storage (the account's, or a shared mailbox's
/// group) and then removes the objects.
pub(crate) async fn delete_for_good(
    state: &AppState,
    mailbox: Mailbox,
    ids: &[Uuid],
    folders: &[&str],
) -> AppResult<u64> {
    let owner = mailbox.owner();
    let mut tx = state.pool.begin().await?;
    match mailbox {
        Mailbox::Own(user_id) => {
            crate::storage_pool::lock(&mut tx, user_id, Default::default()).await?;
        }
        Mailbox::Shared(group_id) => {
            crate::mail::groups::lock(&mut tx, group_id).await?;
        }
    }
    let attachments: Vec<(String, i64)> = sqlx::query_as(
        "SELECT a.object_key, a.size_bytes FROM mail_draft_attachments a
           JOIN mail_messages m ON m.id = a.message_id
          WHERE m.owner = $1 AND m.id = ANY($2) AND m.folder = ANY($3)",
    )
    .bind(owner)
    .bind(ids)
    .bind(folders)
    .fetch_all(&mut *tx)
    .await?;
    // A distribution-list copy only drops the member's row: the shared data
    // packet is the group's, released once nobody holds it.
    let deleted: Vec<(String, String, i64, bool)> = sqlx::query_as(
        "DELETE FROM mail_messages WHERE owner = $1 AND id = ANY($2) AND folder = ANY($3)
         RETURNING object_key, object_version, size_bytes, key_packet IS NOT NULL",
    )
    .bind(owner)
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
    sqlx::query(match mailbox {
        Mailbox::Own(_) => {
            "UPDATE users SET storage_used_bytes = GREATEST(storage_used_bytes - $2, 0) WHERE id = $1"
        }
        Mailbox::Shared(_) => {
            "UPDATE mail_groups SET storage_used_bytes = GREATEST(storage_used_bytes - $2, 0) WHERE id = $1"
        }
    })
    .bind(owner)
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

#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct MailCountsQuery {
    /// A shared mailbox (its group id) instead of your own.
    pub group: Option<String>,
    /// Count conversations, not messages (Proton's conversation grouping).
    #[serde(default)]
    pub conversations: bool,
}

/// `GET /api/mail/counts` — unread and total per folder, for Starred, and
/// for each of the account's folders (`folder:<id>`) and labels
/// (`label:<id>`, outside Spam and Trash); by conversation when asked.
#[utoipa::path(
    get,
    path = "/api/mail/counts",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(MailCountsQuery),
    responses((status = 200, description = "Per folder", body = [MailFolderCount]))
)]
pub async fn counts(
    State(state): State<AppState>,
    user: AuthUser,
    Query(scope): Query<MailCountsQuery>,
) -> AppResult<Json<Vec<MailFolderCount>>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let owner = mailbox(&state, user_id, scope.group.as_deref())
        .await?
        .owner();
    // What one counts: a message, or a conversation with any message there.
    let (unread, total) = if scope.conversations {
        (
            "COUNT(DISTINCT m.thread_id) FILTER (WHERE NOT m.seen)",
            "COUNT(DISTINCT m.thread_id)",
        )
    } else {
        ("COUNT(*) FILTER (WHERE NOT m.seen)", "COUNT(*)")
    };
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(&format!(
        "SELECT m.folder, {unread}, {total}
           FROM mail_messages m WHERE m.owner = $1 AND m.folder <> 'custom' GROUP BY m.folder
         UNION ALL
         SELECT 'starred', {unread}, {total}
           FROM mail_messages m
          WHERE m.owner = $1 AND m.starred AND m.folder NOT IN ('spam', 'trash')
         UNION ALL
         SELECT 'folder:' || m.custom_folder, {unread}, {total}
           FROM mail_messages m WHERE m.owner = $1 AND m.folder = 'custom' GROUP BY m.custom_folder
         UNION ALL
         SELECT 'label:' || l.label_id, {unread}, {total}
           FROM mail_message_labels l JOIN mail_messages m ON m.id = l.message_id
          WHERE m.owner = $1 AND m.folder NOT IN ('spam', 'trash') GROUP BY l.label_id"
    ))
    .bind(owner)
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
    params(("id" = String, Path, description = "Thread id"), MailboxQuery),
    responses(
        (status = 200, description = "The thread", body = [MailMessage]),
        (status = 404, description = "No such thread of yours"),
    )
)]
pub async fn thread(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(scope): Query<MailboxQuery>,
) -> AppResult<Json<Vec<MailMessage>>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let owner = mailbox(&state, user_id, scope.group.as_deref())
        .await?
        .owner();
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let rows: Vec<Row> = sqlx::query_as(&format!(
        "SELECT {ROW_COLUMNS} FROM mail_messages
          WHERE owner = $1 AND thread_id = $2
          ORDER BY received_at, id
          LIMIT 500"
    ))
    .bind(owner)
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
        let by_time = parse_cursor(&cursor(at.unix_timestamp_nanos(), id), Sort::Newest).unwrap();
        assert_eq!(
            (by_time.time, by_time.size, by_time.id),
            (Some(at), None, id)
        );
        let by_size = parse_cursor(&cursor(4096, id), Sort::Smallest).unwrap();
        assert_eq!(
            (by_size.time, by_size.size, by_size.id),
            (None, Some(4096), id)
        );
        assert!(parse_cursor("nope", Sort::Newest).is_err());
        assert!(parse_cursor("1_notauuid", Sort::Oldest).is_err());
    }

    #[test]
    fn sorts_order_and_page_both_ways() {
        assert_eq!(Sort::parse(None).unwrap(), Sort::Newest);
        assert!(Sort::parse(Some("random")).is_err());
        assert_eq!(Sort::Oldest.order("t", "s", "id"), "t ASC, id ASC");
        assert_eq!(Sort::Largest.order("t", "s", "id"), "s DESC, id DESC");
        assert!(Sort::Smallest
            .after("t", "s", "id")
            .contains("(s, id) > ($9, $4)"));
        assert!(Sort::Newest
            .after("t", "s", "id")
            .contains("(t, id) < ($3, $4)"));
    }
}
