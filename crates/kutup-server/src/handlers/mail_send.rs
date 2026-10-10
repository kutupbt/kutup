//! Drafts and sending (docs/plans/mail.md, C2). The browser builds each
//! message, signs it and encrypts it once (`mail_key::encrypt_split`): a
//! data packet plus a key packet per Kutup recipient and one for the
//! sender's copy. The server stores `key packet || data packet` per
//! recipient after checking each key packet names that recipient's current
//! key, and hands mail for outside recipients, which the browser also sends
//! as plaintext, to Stalwart.

use std::collections::BTreeMap;

use aws_sdk_s3::primitives::ByteStream;
use axum::extract::{Multipart, Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::mail_key;
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::mail::{delete_for_good, MailMessage, Row, ROW_COLUMNS};
use crate::handlers::{octet_stream_response, trusted_uuid};
use crate::mail::headers::{self, Mailbox, Readable};
use crate::mail::{insert_message, NewMessage};
use crate::middleware::AuthUser;
use crate::AppState;

/// The largest message, attachments included (Proton's limit).
pub const MAX_MESSAGE_BYTES: usize = 25 * 1024 * 1024;
/// OpenPGP adds packet headers, a signature and the session key wrapping.
const MAX_ENCRYPTED_BYTES: usize = MAX_MESSAGE_BYTES + 64 * 1024;
/// A draft's text, without its attachments.
const MAX_DRAFT_BODY_BYTES: usize = 4 * 1024 * 1024;
/// A PGP/MIME message: the encrypted message armored (4/3), its line breaks
/// and the MIME wrapper.
const MAX_PGP_MESSAGE_BYTES: usize = MAX_ENCRYPTED_BYTES / 3 * 4 + 1024 * 1024;
/// The body limit of the send route: the data packet, the plaintext for
/// outside recipients without keys, and PGP messages for those with keys
/// (four of the largest; smaller messages fit many more).
pub const SEND_BODY_LIMIT: usize =
    2 * MAX_ENCRYPTED_BYTES + 4 * MAX_PGP_MESSAGE_BYTES + 1024 * 1024;
const MAX_RECIPIENTS: usize = 100;
const MAX_REFERENCES: usize = 50;

fn too_large() -> AppError {
    AppError::new(StatusCode::PAYLOAD_TOO_LARGE, "message too large")
}

fn quota_exceeded() -> AppError {
    AppError::new(StatusCode::PAYLOAD_TOO_LARGE, "storage quota exceeded")
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailboxInput {
    pub address: String,
    #[serde(default)]
    pub name: String,
}

/// What the server may read of a draft or a message being sent.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailMeta {
    #[serde(default)]
    pub subject: String,
    /// The sender's display name.
    #[serde(default)]
    pub from_name: String,
    #[serde(default)]
    pub to: Vec<MailboxInput>,
    #[serde(default)]
    pub cc: Vec<MailboxInput>,
    #[serde(default)]
    pub bcc: Vec<MailboxInput>,
    /// The Message-ID the browser gave the message, `<…@server name>`
    /// without the brackets.
    pub message_id: String,
    pub in_reply_to: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub attachment_count: i32,
    /// The thread a reply belongs to, when the browser knows it.
    pub thread_id: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SendMeta {
    #[serde(flatten)]
    pub mail: MailMeta,
    /// The draft this message was written in; deleted once sent.
    pub draft_id: Option<String>,
    /// Base64 key packets: `self` for the sender's copy, and one per Kutup
    /// recipient address.
    pub key_packets: BTreeMap<String, String>,
    /// Ready-made PGP/MIME messages for outside recipients with keys
    /// (docs/plans/mail.md, C3), in parts `pgp0`, `pgp1`, …: To and Cc in
    /// one, each Bcc recipient in their own. Outside recipients in none get
    /// `mime`.
    #[serde(default)]
    pub pgp: Vec<PgpPackage>,
}

/// One PGP/MIME message and whom it goes to.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PgpPackage {
    pub recipients: Vec<String>,
}

/// The sender's address and current primary key.
struct Sender {
    address_id: Uuid,
    address: String,
    key_id: [u8; 8],
}

async fn sender(state: &AppState, user_id: Uuid) -> AppResult<Sender> {
    let row: Option<(Uuid, String, Vec<u8>)> = sqlx::query_as(
        "SELECT a.id, a.address, k.public_key
           FROM mail_addresses a
           JOIN mail_address_keys k ON k.address_id = a.id AND k.is_primary
          WHERE a.user_id = $1
          ORDER BY a.created_at LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;
    let (address_id, address, public_key) = row.ok_or_else(|| {
        AppError::conflict("this account has no mail address key yet")
            .with_details(json!({ "code": "noAddressKey" }))
    })?;
    let key_id = mail_key::encryption_key_id(&public_key)
        .map_err(|_| AppError::internal("stored address key does not parse"))?;
    Ok(Sender {
        address_id,
        address,
        key_id,
    })
}

fn mailbox(input: &MailboxInput) -> AppResult<Mailbox> {
    let address = input.address.trim().to_lowercase();
    let valid = address.len() <= 320
        && address.matches('@').count() == 1
        && !address.starts_with('@')
        && !address.ends_with('@')
        && !address
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "<>(),;:\"[]\\".contains(c));
    if !valid {
        return Err(AppError::bad_request(format!(
            "not an email address: {}",
            headers::clip(&input.address, 80)
        ))
        .with_details(json!({ "code": "invalidAddress" })));
    }
    Ok(Mailbox {
        address,
        name: headers::clip(headers::single_line(&input.name).trim(), 400),
    })
}

fn mailboxes(inputs: &[MailboxInput]) -> AppResult<Vec<Mailbox>> {
    inputs.iter().map(mailbox).collect()
}

/// Checked readable fields: the recipients (To, Cc, Bcc) and the row's
/// readable part, with From always the sender.
struct Checked {
    readable: Readable,
    bcc: Vec<Mailbox>,
}

fn check_meta(meta: &MailMeta, sender: &Sender, server_name: &str) -> AppResult<Checked> {
    let to = mailboxes(&meta.to)?;
    let cc = mailboxes(&meta.cc)?;
    let bcc = mailboxes(&meta.bcc)?;
    if to.len() + cc.len() + bcc.len() > MAX_RECIPIENTS {
        return Err(AppError::bad_request("at most 100 recipients"));
    }
    let message_id = headers::message_id(&meta.message_id)
        .filter(|id| {
            id.rsplit_once('@')
                .is_some_and(|(_, domain)| domain.eq_ignore_ascii_case(server_name))
        })
        .ok_or_else(|| AppError::bad_request("messageId must be <…@server name>"))?;
    let in_reply_to = match meta.in_reply_to.as_deref() {
        Some(id) => {
            Some(headers::message_id(id).ok_or_else(|| AppError::bad_request("bad inReplyTo"))?)
        }
        None => None,
    };
    if meta.references.len() > MAX_REFERENCES {
        return Err(AppError::bad_request("at most 50 references"));
    }
    let references = meta
        .references
        .iter()
        .map(|id| headers::message_id(id).ok_or_else(|| AppError::bad_request("bad reference")))
        .collect::<AppResult<Vec<_>>>()?;
    if !(0..=100).contains(&meta.attachment_count) {
        return Err(AppError::bad_request("attachmentCount out of range"));
    }
    Ok(Checked {
        readable: Readable {
            subject: headers::clip(headers::single_line(&meta.subject).trim(), 1000),
            from: Some(Mailbox {
                address: sender.address.clone(),
                name: headers::clip(headers::single_line(&meta.from_name).trim(), 400),
            }),
            to,
            cc,
            reply_to: Vec::new(),
            sent_at: Some(time::OffsetDateTime::now_utc().unix_timestamp()),
            message_id: Some(message_id),
            in_reply_to,
            references,
            attachment_count: meta.attachment_count,
            spam: false,
            bounce: None,
            pgp_encrypted: false,
        },
        bcc,
    })
}

/// A thread id from the browser, if it is one of the caller's threads.
async fn own_thread(
    state: &AppState,
    user_id: Uuid,
    thread: Option<&str>,
) -> AppResult<Option<Uuid>> {
    let Some(thread) = thread.and_then(|t| Uuid::parse_str(t).ok()) else {
        return Ok(None);
    };
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM mail_messages WHERE user_id = $1 AND thread_id = $2)",
    )
    .bind(user_id)
    .bind(thread)
    .fetch_one(&state.pool)
    .await?;
    Ok(exists.then_some(thread))
}

/// The parts of a multipart form, each read whole within its limit.
async fn read_parts(
    multipart: &mut Multipart,
    limits: &[(&str, usize)],
) -> AppResult<BTreeMap<String, Vec<u8>>> {
    let mut parts = BTreeMap::new();
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::bad_request("invalid multipart form"))?
    {
        let name = field.name().unwrap_or_default().to_string();
        let Some(&(_, limit)) = limits.iter().find(|(part, _)| *part == name) else {
            return Err(AppError::bad_request(format!("unexpected part {name}")));
        };
        if parts.contains_key(&name) {
            return Err(AppError::bad_request(format!("duplicate part {name}")));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = field
            .chunk()
            .await
            .map_err(|_| AppError::bad_request("invalid multipart form"))?
        {
            if bytes.len() + chunk.len() > limit {
                return Err(too_large());
            }
            bytes.extend_from_slice(&chunk);
        }
        parts.insert(name, bytes);
    }
    Ok(parts)
}

fn meta_part<T: serde::de::DeserializeOwned>(parts: &BTreeMap<String, Vec<u8>>) -> AppResult<T> {
    let bytes = parts
        .get("meta")
        .ok_or_else(|| AppError::bad_request("missing meta"))?;
    serde_json::from_slice(bytes).map_err(|error| AppError::bad_request(format!("meta: {error}")))
}

/// Checks a message the sender encrypted to themself (a draft, a draft
/// attachment): it must start with a key packet for their current key.
fn check_own(message: &[u8], sender: &Sender) -> AppResult<()> {
    match mail_key::message_key_id(message) {
        Ok(id) if id == sender.key_id => Ok(()),
        _ => Err(
            AppError::bad_request("not encrypted to your current address key")
                .with_details(json!({ "code": "keyChanged" })),
        ),
    }
}

async fn put(state: &AppState, key: &str, bytes: Vec<u8>) -> AppResult<String> {
    let size = bytes.len() as i64;
    state
        .storage
        .put_object_versioned(key, ByteStream::from(bytes), size)
        .await
        .map_err(|_| AppError::internal("storage"))
}

async fn remove_objects(state: &AppState, objects: &[(String, String)]) {
    for (key, version) in objects {
        if let Err(error) = state.storage.delete_stored(key, version).await {
            tracing::warn!(error = %error, "mail: unrecorded object left for the sweep");
        }
    }
}

async fn row(state: &AppState, user_id: Uuid, id: Uuid) -> AppResult<MailMessage> {
    let row: Row = sqlx::query_as(&format!(
        "SELECT {ROW_COLUMNS} FROM mail_messages WHERE user_id = $1 AND id = $2"
    ))
    .bind(user_id)
    .bind(id)
    .fetch_one(&state.pool)
    .await?;
    Ok(MailMessage::from(row))
}

/// `POST /api/mail/drafts` — a new draft: multipart `meta` (JSON, the
/// readable fields) and `body` (the message without attachments, encrypted
/// to your own address key).
#[utoipa::path(
    post,
    path = "/api/mail/drafts",
    tag = "mail",
    security(("BearerAuth" = [])),
    request_body(content = Vec<u8>, content_type = "multipart/form-data", description = "meta and body"),
    responses(
        (status = 200, description = "The draft", body = MailMessage),
        (status = 413, description = "Too large, or storage quota exceeded"),
    )
)]
pub async fn create_draft(
    State(state): State<AppState>,
    user: AuthUser,
    mut multipart: Multipart,
) -> AppResult<Json<MailMessage>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let parts = read_parts(
        &mut multipart,
        &[("meta", 256 * 1024), ("body", MAX_DRAFT_BODY_BYTES)],
    )
    .await?;
    let meta: MailMeta = meta_part(&parts)?;
    let sender = sender(&state, user_id).await?;
    let checked = check_meta(&meta, &sender, &state.config.chat_server_name)?;
    let body = parts
        .get("body")
        .cloned()
        .ok_or_else(|| AppError::bad_request("missing body"))?;
    check_own(&body, &sender)?;
    let thread = own_thread(&state, user_id, meta.thread_id.as_deref()).await?;
    let id = Uuid::new_v4();
    let key = crate::mail::object_key(user_id, Uuid::new_v4());
    let size = body.len() as i64;
    let version = put(&state, &key, body).await?;
    let stored = async {
        let mut tx = state.pool.begin().await?;
        let pool = crate::storage_pool::lock(&mut tx, user_id, Default::default()).await?;
        if !pool.fits(size, 0) {
            return Err(quota_exceeded());
        }
        insert_message(
            &mut tx,
            NewMessage {
                id,
                user_id,
                address_id: sender.address_id,
                thread_id: thread,
                direction: "outbound",
                folder: "drafts",
                protection: "end_to_end",
                seen: true,
                object_key: &key,
                object_version: &version,
                size,
                readable: &checked.readable,
                bcc: &checked.bcc,
                external_recipients: 0,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    .await;
    if let Err(error) = stored {
        remove_objects(&state, &[(key, version)]).await;
        return Err(error);
    }
    Ok(Json(row(&state, user_id, id).await?))
}

/// `PUT /api/mail/drafts/{id}` — replaces a draft's readable fields and
/// body (multipart, as for creating). Attachments stay.
#[utoipa::path(
    put,
    path = "/api/mail/drafts/{id}",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Draft id")),
    request_body(content = Vec<u8>, content_type = "multipart/form-data", description = "meta and body"),
    responses(
        (status = 200, description = "The draft", body = MailMessage),
        (status = 404, description = "No such draft of yours"),
        (status = 413, description = "Too large, or storage quota exceeded"),
    )
)]
pub async fn update_draft(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    mut multipart: Multipart,
) -> AppResult<Json<MailMessage>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let parts = read_parts(
        &mut multipart,
        &[("meta", 256 * 1024), ("body", MAX_DRAFT_BODY_BYTES)],
    )
    .await?;
    let meta: MailMeta = meta_part(&parts)?;
    let sender = sender(&state, user_id).await?;
    let checked = check_meta(&meta, &sender, &state.config.chat_server_name)?;
    let body = parts
        .get("body")
        .cloned()
        .ok_or_else(|| AppError::bad_request("missing body"))?;
    check_own(&body, &sender)?;
    let key = crate::mail::object_key(user_id, Uuid::new_v4());
    let size = body.len() as i64;
    let version = put(&state, &key, body).await?;
    let replaced = async {
        let mut tx = state.pool.begin().await?;
        let pool = crate::storage_pool::lock(&mut tx, user_id, Default::default()).await?;
        let old: Option<(String, String, i64)> = sqlx::query_as(
            "SELECT object_key, object_version, size_bytes FROM mail_messages
              WHERE id = $1 AND user_id = $2 AND folder = 'drafts' FOR UPDATE",
        )
        .bind(id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (old_key, old_version, old_size) = old.ok_or_else(|| AppError::not_found("not found"))?;
        if !pool.fits(size - old_size, 0) {
            return Err(quota_exceeded());
        }
        let readable = &checked.readable;
        let (from_address, from_name) = readable
            .from
            .as_ref()
            .map(|m| (m.address.clone(), m.name.clone()))
            .unwrap_or_default();
        sqlx::query(
            "UPDATE mail_messages SET object_key = $3, object_version = $4, size_bytes = $5,
                    subject = $6, from_address = $7, from_name = $8, to_list = $9, cc_list = $10,
                    bcc_list = $11, message_id = $12, in_reply_to = $13, references_list = $14,
                    attachment_count = $15, sent_at = now(), received_at = now()
              WHERE id = $1 AND user_id = $2",
        )
        .bind(id)
        .bind(user_id)
        .bind(&key)
        .bind(&version)
        .bind(size)
        .bind(&readable.subject)
        .bind(from_address)
        .bind(from_name)
        .bind(json!(readable.to))
        .bind(json!(readable.cc))
        .bind(json!(checked.bcc))
        .bind(&readable.message_id)
        .bind(&readable.in_reply_to)
        .bind(&readable.references)
        .bind(readable.attachment_count)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE users SET storage_used_bytes = GREATEST(storage_used_bytes + $2, 0) WHERE id = $1",
        )
        .bind(user_id)
        .bind(size - old_size)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok((old_key, old_version))
    }
    .await;
    match replaced {
        Ok(old) => remove_objects(&state, &[old]).await,
        Err(error) => {
            remove_objects(&state, &[(key, version)]).await;
            return Err(error);
        }
    }
    Ok(Json(row(&state, user_id, id).await?))
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DraftAttachment {
    pub id: String,
    pub size: i64,
}

async fn own_draft(state: &AppState, user_id: Uuid, id: &str) -> AppResult<Uuid> {
    let id = Uuid::parse_str(id).map_err(|_| AppError::not_found("not found"))?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM mail_messages WHERE id = $1 AND user_id = $2 AND folder = 'drafts')",
    )
    .bind(id)
    .bind(user_id)
    .fetch_one(&state.pool)
    .await?;
    exists
        .then_some(id)
        .ok_or_else(|| AppError::not_found("not found"))
}

/// `POST /api/mail/drafts/{id}/attachments` — one attachment, multipart
/// `part`: the MIME part as it will be sent, encrypted to your own key.
#[utoipa::path(
    post,
    path = "/api/mail/drafts/{id}/attachments",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Draft id")),
    request_body(content = Vec<u8>, content_type = "multipart/form-data", description = "part"),
    responses(
        (status = 200, description = "The attachment", body = DraftAttachment),
        (status = 413, description = "Attachments over 25 MB, or storage quota exceeded"),
    )
)]
pub async fn add_draft_attachment(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    mut multipart: Multipart,
) -> AppResult<Json<DraftAttachment>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let draft = own_draft(&state, user_id, &id).await?;
    let parts = read_parts(&mut multipart, &[("part", MAX_ENCRYPTED_BYTES)]).await?;
    let part = parts
        .get("part")
        .cloned()
        .ok_or_else(|| AppError::bad_request("missing part"))?;
    check_own(&part, &sender(&state, user_id).await?)?;
    let attachment = Uuid::new_v4();
    let key = format!("{}att-{attachment}", crate::mail::object_prefix(user_id));
    let size = part.len() as i64;
    let version = put(&state, &key, part).await?;
    let stored = async {
        let mut tx = state.pool.begin().await?;
        let pool = crate::storage_pool::lock(&mut tx, user_id, Default::default()).await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(size_bytes), 0)::bigint FROM mail_draft_attachments WHERE message_id = $1",
        )
        .bind(draft)
        .fetch_one(&mut *tx)
        .await?;
        if total + size > MAX_ENCRYPTED_BYTES as i64 {
            return Err(too_large());
        }
        if !pool.fits(size, 0) {
            return Err(quota_exceeded());
        }
        sqlx::query(
            "INSERT INTO mail_draft_attachments (id, message_id, user_id, object_key, size_bytes)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(attachment)
        .bind(draft)
        .bind(user_id)
        .bind(&key)
        .bind(size)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE users SET storage_used_bytes = storage_used_bytes + $2 WHERE id = $1")
            .bind(user_id)
            .bind(size)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
    .await;
    if let Err(error) = stored {
        remove_objects(&state, &[(key, version)]).await;
        return Err(error);
    }
    Ok(Json(DraftAttachment {
        id: attachment.to_string(),
        size,
    }))
}

/// `GET /api/mail/drafts/{id}/attachments` — a draft's attachments, in the
/// order they were added.
#[utoipa::path(
    get,
    path = "/api/mail/drafts/{id}/attachments",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Draft id")),
    responses((status = 200, description = "The attachments", body = [DraftAttachment]))
)]
pub async fn list_draft_attachments(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<DraftAttachment>>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let draft = own_draft(&state, user_id, &id).await?;
    let rows: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT id, size_bytes FROM mail_draft_attachments WHERE message_id = $1 ORDER BY created_at, id",
    )
    .bind(draft)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(id, size)| DraftAttachment {
                id: id.to_string(),
                size,
            })
            .collect(),
    ))
}

/// `GET /api/mail/drafts/{id}/attachments/{attachment}` — the encrypted part.
#[utoipa::path(
    get,
    path = "/api/mail/drafts/{id}/attachments/{attachment}",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(
        ("id" = String, Path, description = "Draft id"),
        ("attachment" = String, Path, description = "Attachment id"),
    ),
    responses((status = 200, description = "The encrypted part", content_type = "application/octet-stream"))
)]
pub async fn draft_attachment_content(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, attachment)): Path<(String, String)>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let draft = own_draft(&state, user_id, &id).await?;
    let attachment = Uuid::parse_str(&attachment).map_err(|_| AppError::not_found("not found"))?;
    let key: String = sqlx::query_scalar(
        "SELECT object_key FROM mail_draft_attachments WHERE id = $1 AND message_id = $2",
    )
    .bind(attachment)
    .bind(draft)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("not found"))?;
    let (body, size) = state
        .storage
        .get_object(&key)
        .await
        .map_err(|_| AppError::internal("storage"))?;
    Ok(octet_stream_response(body, size, &[]))
}

/// `DELETE /api/mail/drafts/{id}/attachments/{attachment}`.
#[utoipa::path(
    delete,
    path = "/api/mail/drafts/{id}/attachments/{attachment}",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(
        ("id" = String, Path, description = "Draft id"),
        ("attachment" = String, Path, description = "Attachment id"),
    ),
    responses((status = 204, description = "Removed"))
)]
pub async fn delete_draft_attachment(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, attachment)): Path<(String, String)>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let draft = own_draft(&state, user_id, &id).await?;
    let attachment = Uuid::parse_str(&attachment).map_err(|_| AppError::not_found("not found"))?;
    let mut tx = state.pool.begin().await?;
    crate::storage_pool::lock(&mut tx, user_id, Default::default()).await?;
    let removed: Option<(String, i64)> = sqlx::query_as(
        "DELETE FROM mail_draft_attachments WHERE id = $1 AND message_id = $2
         RETURNING object_key, size_bytes",
    )
    .bind(attachment)
    .bind(draft)
    .fetch_optional(&mut *tx)
    .await?;
    let (key, size) = removed.ok_or_else(|| AppError::not_found("not found"))?;
    sqlx::query(
        "UPDATE users SET storage_used_bytes = GREATEST(storage_used_bytes - $2, 0) WHERE id = $1",
    )
    .bind(user_id)
    .bind(size)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    remove_objects(&state, &[(key, String::new())]).await;
    Ok(StatusCode::NO_CONTENT)
}

/// How one recipient fared.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SendRecipient {
    pub address: String,
    /// `delivered` (a Kutup user, end to end), `sent` (handed to the outside
    /// world), `full` (a Kutup user whose storage is full: not delivered), or
    /// `failed` (refused by the mail server after mail to others had already
    /// gone out).
    pub status: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SendResult {
    /// Your sent copy.
    pub message: MailMessage,
    pub recipients: Vec<SendRecipient>,
}

/// A Kutup recipient with their copy.
struct LocalCopy {
    address: String,
    recipient: crate::mail::Recipient,
    key: String,
    version: String,
    size: i64,
}

/// `POST /api/mail/send` — sends a message. Multipart: `meta` (JSON:
/// readable fields, `keyPackets`, optional `draftId` and `pgp`), `data` (the
/// shared data packet), `pgp0`, `pgp1`, … (PGP/MIME messages for outside
/// recipients with keys, as `pgp` lists them) and, when other outside
/// recipients remain, `mime` (the message in plaintext, for Stalwart).
#[utoipa::path(
    post,
    path = "/api/mail/send",
    tag = "mail",
    security(("BearerAuth" = [])),
    request_body(content = Vec<u8>, content_type = "multipart/form-data", description = "meta, data, pgp0… and mime"),
    responses(
        (status = 200, description = "Sent", body = SendResult),
        (status = 409, description = "A recipient's key changed (code keyChanged, address)"),
        (status = 403, description = "Outside sending is off on this server (code outsideSendingOff), or paused for you (code sendingPaused)"),
        (status = 413, description = "Too large, or your storage quota exceeded"),
        (status = 422, description = "No such Kutup address (code unknownRecipient), or refused outside"),
        (status = 429, description = "Sending limit reached"),
    )
)]
pub async fn send(
    State(state): State<AppState>,
    user: AuthUser,
    mut multipart: Multipart,
) -> AppResult<Json<SendResult>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let pgp_parts: Vec<String> = (0..MAX_RECIPIENTS).map(|i| format!("pgp{i}")).collect();
    let mut limits = vec![
        ("meta", 512 * 1024),
        ("data", MAX_ENCRYPTED_BYTES),
        ("mime", MAX_MESSAGE_BYTES + 1024 * 1024),
    ];
    limits.extend(
        pgp_parts
            .iter()
            .map(|name| (name.as_str(), MAX_PGP_MESSAGE_BYTES)),
    );
    let parts = read_parts(&mut multipart, &limits).await?;
    let meta: SendMeta = meta_part(&parts)?;
    let data = parts
        .get("data")
        .ok_or_else(|| AppError::bad_request("missing data"))?;
    let sender = sender(&state, user_id).await?;
    let server_name = state.config.chat_server_name.as_str();
    let checked = check_meta(&meta.mail, &sender, server_name)?;
    let readable = &checked.readable;
    let all: Vec<&Mailbox> = readable
        .to
        .iter()
        .chain(&readable.cc)
        .chain(&checked.bcc)
        .collect();
    if all.is_empty() {
        return Err(AppError::bad_request("no recipients"));
    }
    let key_packet = |name: &str| -> AppResult<Vec<u8>> {
        let encoded = meta
            .key_packets
            .get(name)
            .ok_or_else(|| AppError::bad_request(format!("missing key packet for {name}")))?;
        STANDARD
            .decode(encoded)
            .map_err(|_| AppError::bad_request("key packets must be base64"))
    };

    // The sender's own copy.
    let own_packet = key_packet("self")?;
    if mail_key::key_packet_key_id(&own_packet).ok() != Some(sender.key_id) {
        return Err(AppError::conflict("your address key changed; reload")
            .with_details(json!({ "code": "keyChanged", "address": sender.address })));
    }

    // Kutup recipients, each with a key packet for their current key.
    let mut seen = std::collections::BTreeSet::new();
    let mut local = Vec::new();
    let mut external = Vec::new();
    for mailbox in &all {
        if !seen.insert(mailbox.address.clone()) {
            continue;
        }
        let domain = mailbox
            .address
            .rsplit_once('@')
            .map(|(_, d)| d)
            .unwrap_or_default();
        if !domain.eq_ignore_ascii_case(server_name) {
            external.push(mailbox.address.clone());
            continue;
        }
        let recipient = match crate::mail::resolve(&state, &mailbox.address).await {
            Ok(recipient) => Some(recipient),
            Err(reply) if reply.code == 452 => {
                // Full pool: not delivered, the rest still are. Look the
                // account up without the room check.
                None
            }
            Err(_) => {
                return Err(AppError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "no such Kutup address",
                )
                .with_details(json!({ "code": "unknownRecipient", "address": mailbox.address })));
            }
        };
        let packet = key_packet(&mailbox.address)?;
        local.push((mailbox.address.clone(), recipient, packet));
    }
    for (address, recipient, packet) in &local {
        if let Some(recipient) = recipient {
            let expected = mail_key::encryption_key_id(&recipient.public_key)
                .map_err(|_| AppError::internal("stored address key does not parse"))?;
            if mail_key::key_packet_key_id(packet).ok() != Some(expected) {
                return Err(AppError::conflict("a recipient's key changed; try again")
                    .with_details(json!({ "code": "keyChanged", "address": address })));
            }
        }
    }

    // Outside recipients: PGP messages for those with keys, the plaintext
    // for the rest, each checked; then the sending limits.
    let bcc: Vec<&str> = checked.bcc.iter().map(|m| m.address.as_str()).collect();
    let packages = pgp_packages(
        &meta.pgp,
        &parts,
        &external,
        &bcc,
        &sender.address,
        readable,
    )?;
    let plain: Vec<String> = external
        .iter()
        .filter(|address| !packages.iter().any(|(to, _)| to.contains(address)))
        .cloned()
        .collect();
    let mime = match (plain.is_empty(), parts.get("mime")) {
        (true, None) => None,
        (true, Some(_)) => {
            return Err(AppError::bad_request(
                "no plaintext: every outside recipient has a PGP message",
            ))
        }
        (false, None) => return Err(AppError::bad_request("missing mime for outside recipients")),
        (false, Some(mime)) => {
            if !same_message(mime, &sender.address, readable) {
                return Err(AppError::bad_request(
                    "mime must be the same message: From you, the same Message-ID, no Bcc header",
                ));
            }
            Some(mime)
        }
    };
    if !external.is_empty() {
        if !state.config.mail_outside_sending.allows(user.is_admin) {
            return Err(AppError::forbidden(
                "this server does not send mail to outside addresses yet",
            )
            .with_details(json!({ "code": "outsideSendingOff" })));
        }
        crate::mail::safety::check_send(&state, user_id, external.len() as i64).await?;
    }

    // Store every copy, then record them under the pool locks.
    let own_key = crate::mail::object_key(user_id, Uuid::new_v4());
    let own_copy = [own_packet.as_slice(), data].concat();
    let own_size = own_copy.len() as i64;
    let own_version = put(&state, &own_key, own_copy).await?;
    let mut objects = vec![(own_key.clone(), own_version.clone())];
    let mut copies = Vec::new();
    let mut statuses = Vec::new();
    for (address, recipient, packet) in local {
        let Some(recipient) = recipient else {
            statuses.push(SendRecipient {
                address,
                status: "full".into(),
            });
            continue;
        };
        let key = crate::mail::object_key(recipient.user_id, Uuid::new_v4());
        let copy = [packet.as_slice(), data].concat();
        let size = copy.len() as i64;
        let version = match put(&state, &key, copy).await {
            Ok(version) => version,
            Err(error) => {
                remove_objects(&state, &objects).await;
                return Err(error);
            }
        };
        objects.push((key.clone(), version.clone()));
        copies.push(LocalCopy {
            address,
            recipient,
            key,
            version,
            size,
        });
    }

    let id = Uuid::new_v4();
    let thread = own_thread(&state, user_id, meta.mail.thread_id.as_deref()).await?;
    let mut spam_refused = false;
    let recorded: AppResult<Vec<SendRecipient>> = async {
        let mut tx = state.pool.begin().await?;
        // Lock every account in one order, so two sends cannot deadlock.
        let mut accounts: Vec<Uuid> = copies.iter().map(|c| c.recipient.user_id).collect();
        accounts.push(user_id);
        accounts.sort();
        accounts.dedup();
        let mut pools = BTreeMap::new();
        for account in accounts {
            pools.insert(
                account,
                crate::storage_pool::lock(&mut tx, account, Default::default()).await?,
            );
        }
        if !pools[&user_id].fits(own_size, 0) {
            return Err(quota_exceeded());
        }
        insert_message(
            &mut tx,
            NewMessage {
                id,
                user_id,
                address_id: sender.address_id,
                thread_id: thread,
                direction: "outbound",
                folder: "sent",
                // End to end when nobody got the plaintext.
                protection: if plain.is_empty() {
                    "end_to_end"
                } else {
                    "zero_access"
                },
                seen: true,
                object_key: &own_key,
                object_version: &own_version,
                size: own_size,
                readable,
                bcc: &checked.bcc,
                external_recipients: external.len() as i32,
            },
        )
        .await?;
        let mut results = Vec::new();
        for copy in &copies {
            let pool = pools.get_mut(&copy.recipient.user_id).expect("locked");
            if !pool.fits(copy.size, 0) {
                results.push(SendRecipient {
                    address: copy.address.clone(),
                    status: "full".into(),
                });
                continue;
            }
            insert_message(
                &mut tx,
                NewMessage {
                    id: Uuid::new_v4(),
                    user_id: copy.recipient.user_id,
                    address_id: copy.recipient.address_id,
                    thread_id: None,
                    direction: "inbound",
                    folder: "inbox",
                    protection: "end_to_end",
                    seen: false,
                    object_key: &copy.key,
                    object_version: &copy.version,
                    size: copy.size,
                    readable,
                    bcc: &[],
                    external_recipients: 0,
                },
            )
            .await?;
            pool.used += copy.size;
            results.push(SendRecipient {
                address: copy.address.clone(),
                status: "delivered".into(),
            });
        }
        // Outside mail goes last: once Stalwart has it, it is sent. The
        // plaintext first, the likeliest to be refused: a refusal of the
        // first submission fails the whole send; a later one fails only its
        // recipients, since the others' mail is already on its way.
        let submissions = mime
            .map(|mime| (plain.as_slice(), mime.as_slice()))
            .into_iter()
            .chain(
                packages
                    .iter()
                    .map(|(to, message)| (to.as_slice(), message.as_slice())),
            );
        let mut handed = false;
        for (recipients, message) in submissions {
            let submitted = crate::mail::submit::submit(
                &state.config.mail_submission_addr,
                &format!("kutup@{server_name}"),
                &state.config.mail_inbound_token,
                crate::mail::submit::Envelope {
                    from: &sender.address,
                    recipients,
                    message,
                },
            )
            .await;
            let status = match submitted {
                Ok(()) => "sent",
                Err(error) => {
                    if refused_as_spam(&error) {
                        spam_refused = true;
                    }
                    if !handed {
                        return Err(submit_error(error));
                    }
                    tracing::warn!(error = %error, "mail: a later submission failed");
                    "failed"
                }
            };
            handed |= status == "sent";
            results.extend(recipients.iter().map(|address| SendRecipient {
                address: address.clone(),
                status: status.into(),
            }));
        }
        tx.commit().await?;
        Ok(results)
    }
    .await;
    if spam_refused {
        if let Err(error) = crate::mail::safety::record(
            &state.pool,
            user_id,
            crate::mail::safety::Event::SpamRefused,
            1,
        )
        .await
        {
            tracing::warn!(error = %error, "mail: spam refusal not recorded");
        }
    }
    let results = match recorded {
        Ok(results) => results,
        Err(error) => {
            remove_objects(&state, &objects).await;
            return Err(error);
        }
    };
    // Copies a full account could not take.
    let undelivered: Vec<(String, String)> = copies
        .iter()
        .filter(|copy| {
            results
                .iter()
                .any(|r| r.address == copy.address && r.status == "full")
        })
        .map(|copy| (copy.key.clone(), copy.version.clone()))
        .collect();
    remove_objects(&state, &undelivered).await;
    if let Some(draft) = meta
        .draft_id
        .as_deref()
        .and_then(|d| Uuid::parse_str(d).ok())
    {
        delete_for_good(&state, user_id, &[draft], &["drafts"]).await?;
    }
    statuses.extend(results);
    Ok(Json(SendResult {
        message: row(&state, user_id, id).await?,
        recipients: statuses,
    }))
}

/// Whether `message` is the message being sent: From the sender, the same
/// Message-ID, and no Bcc header (Bcc recipients are not named to others).
fn same_message(message: &[u8], sender: &str, readable: &Readable) -> bool {
    let parsed = Readable::parse(message);
    parsed.from.as_ref().map(|m| m.address.as_str()) == Some(sender)
        && parsed.message_id == readable.message_id
        && !has_bcc_header(message)
}

/// The PGP messages `pgp` lists, each checked: the same message (see
/// [`same_message`]), encrypted (RFC 3156 `multipart/encrypted` around an
/// encrypted OpenPGP message), for outside recipients of this message, each
/// in one package only, and a Bcc recipient alone in theirs (key IDs would
/// name them to the others).
fn pgp_packages<'a>(
    pgp: &[PgpPackage],
    parts: &'a BTreeMap<String, Vec<u8>>,
    external: &[String],
    bcc: &[&str],
    sender: &str,
    readable: &Readable,
) -> AppResult<Vec<(Vec<String>, &'a Vec<u8>)>> {
    let bad = |text: &str| Err(AppError::bad_request(format!("pgp: {text}")));
    if pgp.len() > MAX_RECIPIENTS {
        return bad("too many messages");
    }
    for name in parts.keys() {
        if let Some(index) = name.strip_prefix("pgp") {
            if index.parse::<usize>().map_or(true, |i| i >= pgp.len()) {
                return bad(&format!("unexpected part {name}"));
            }
        }
    }
    let mut covered = std::collections::BTreeSet::new();
    let mut packages = Vec::with_capacity(pgp.len());
    for (index, package) in pgp.iter().enumerate() {
        let Some(message) = parts.get(&format!("pgp{index}")) else {
            return bad(&format!("missing part pgp{index}"));
        };
        if package.recipients.is_empty() {
            return bad("a message without recipients");
        }
        let mut recipients = Vec::with_capacity(package.recipients.len());
        for address in &package.recipients {
            let Some(found) = external.iter().find(|e| e.eq_ignore_ascii_case(address)) else {
                return bad(&format!("{address} is not an outside recipient"));
            };
            if !covered.insert(found.to_ascii_lowercase()) {
                return bad(&format!("{address} is in two messages"));
            }
            if package.recipients.len() > 1 && bcc.iter().any(|b| b.eq_ignore_ascii_case(found)) {
                return bad("a Bcc recipient must have a message of their own");
            }
            recipients.push(found.clone());
        }
        if !same_message(message, sender, readable) {
            return bad("must be the same message: From you, the same Message-ID, no Bcc header");
        }
        if !Readable::parse(message).pgp_encrypted || !is_multipart_encrypted(message) {
            return bad("must be PGP/MIME (multipart/encrypted)");
        }
        packages.push((recipients, message));
    }
    Ok(packages)
}

/// Whether the top Content-Type is RFC 3156 `multipart/encrypted` (inline
/// PGP is read on arrival but not sent).
fn is_multipart_encrypted(message: &[u8]) -> bool {
    use mail_parser::MimeHeaders as _;
    mail_parser::MessageParser::default()
        .parse_headers(message)
        .and_then(|parsed| {
            parsed.content_type().map(|kind| {
                kind.ctype().eq_ignore_ascii_case("multipart")
                    && kind
                        .subtype()
                        .is_some_and(|s| s.eq_ignore_ascii_case("encrypted"))
            })
        })
        .unwrap_or(false)
}

/// Whether the message's header block has a Bcc field.
fn has_bcc_header(message: &[u8]) -> bool {
    let end = message
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(message.len());
    message[..end]
        .split(|b| *b == b'\n')
        .any(|line| line.len() >= 4 && line[..4].eq_ignore_ascii_case(b"bcc:"))
}

/// Whether Stalwart refused a submission for its spam score ("550 5.7.1
/// Message rejected due to excessive spam score").
fn refused_as_spam(error: &crate::mail::submit::SubmitError) -> bool {
    matches!(error, crate::mail::submit::SubmitError::Refused { code: 550, text, .. }
        if text.to_ascii_lowercase().contains("spam"))
}

fn submit_error(error: crate::mail::submit::SubmitError) -> AppError {
    use crate::mail::submit::SubmitError;
    if refused_as_spam(&error) {
        return AppError::new(StatusCode::UNPROCESSABLE_ENTITY, "refused as spam")
            .with_details(json!({ "code": "spam" }));
    }
    match error {
        SubmitError::Refused {
            code,
            text,
            recipient,
        } if (500..600).contains(&code) => AppError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "refused by the mail server",
        )
        .with_details(json!({ "code": "refused", "address": recipient, "reason": text })),
        error => {
            tracing::warn!(error = %error, "mail: submission failed");
            AppError::new(StatusCode::SERVICE_UNAVAILABLE, "mail server unavailable")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sender() -> Sender {
        Sender {
            address_id: Uuid::nil(),
            address: "alice@kutup.test".into(),
            key_id: [0; 8],
        }
    }

    fn meta() -> MailMeta {
        MailMeta {
            subject: "Merhaba\ndünya".into(),
            from_name: "Alice".into(),
            to: vec![MailboxInput {
                address: " Bob@Kutup.Test ".into(),
                name: "Bob".into(),
            }],
            cc: Vec::new(),
            bcc: vec![MailboxInput {
                address: "carol@example.org".into(),
                name: String::new(),
            }],
            message_id: "abc@kutup.test".into(),
            in_reply_to: Some("<parent@example.org>".into()),
            references: vec!["root@example.org".into()],
            attachment_count: 1,
            thread_id: None,
        }
    }

    fn pgp_mime(from: &str, message_id: &str, armored: &str) -> Vec<u8> {
        format!(
            "From: {from}\r\nTo: dave@example.org\r\nMessage-ID: <{message_id}>\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"b\"\r\n\r\n\
             --b\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n\
             --b\r\nContent-Type: application/octet-stream\r\n\r\n{armored}\r\n--b--\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn pgp_packages_are_checked() {
        use kutup_crypto::mail_key::{encrypt_armored_signed, generate_address_key};
        let key = generate_address_key("alice@kutup.test", 1_790_000_000).unwrap();
        let armored = encrypt_armored_signed(
            &[&key.public_key],
            &key.secret_key,
            b"Content-Type: text/plain\r\n\r\nhi\r\n",
            1_790_000_100,
        )
        .unwrap()
        .replace('\n', "\r\n");
        let checked = check_meta(&meta(), &sender(), "kutup.test").unwrap();
        let readable = &checked.readable;
        let external = vec![
            "dave@example.org".to_string(),
            "erin@example.org".to_string(),
            "carol@example.org".to_string(),
        ];
        let bcc = ["carol@example.org"];
        let good = pgp_mime("alice@kutup.test", "abc@kutup.test", &armored);
        let package = |to: &[&str]| PgpPackage {
            recipients: to.iter().map(|a| a.to_string()).collect(),
        };
        let parts_of = |messages: &[&[u8]]| {
            messages
                .iter()
                .enumerate()
                .map(|(i, m)| (format!("pgp{i}"), m.to_vec()))
                .collect::<BTreeMap<_, _>>()
        };
        let check = |pgp: &[PgpPackage], parts: &BTreeMap<String, Vec<u8>>| {
            pgp_packages(pgp, parts, &external, &bcc, "alice@kutup.test", readable)
                .map(|packages| packages.into_iter().map(|(to, _)| to).collect::<Vec<_>>())
        };

        // To and Cc together, each Bcc alone.
        let parts = parts_of(&[&good, &good]);
        let packages = check(
            &[
                package(&["Dave@Example.org", "erin@example.org"]),
                package(&["carol@example.org"]),
            ],
            &parts,
        )
        .unwrap();
        assert_eq!(packages[0], vec!["dave@example.org", "erin@example.org"]);
        assert_eq!(packages[1], vec!["carol@example.org"]);

        // A Bcc recipient sharing a message, a recipient twice, a stranger.
        let one = parts_of(&[&good]);
        assert!(check(&[package(&["dave@example.org", "carol@example.org"])], &one).is_err());
        assert!(check(
            &[
                package(&["dave@example.org"]),
                package(&["dave@example.org"])
            ],
            &parts
        )
        .is_err());
        assert!(check(&[package(&["mallory@example.org"])], &one).is_err());
        assert!(check(&[package(&[])], &one).is_err());
        // Parts and the list must agree.
        assert!(check(&[], &one).is_err());
        assert!(check(
            &[
                package(&["dave@example.org"]),
                package(&["erin@example.org"])
            ],
            &one
        )
        .is_err());

        // Not the same message, or not encrypted.
        let other_sender = pgp_mime("eve@kutup.test", "abc@kutup.test", &armored);
        let other_id = pgp_mime("alice@kutup.test", "other@kutup.test", &armored);
        let plaintext = pgp_mime(
            "alice@kutup.test",
            "abc@kutup.test",
            "-----BEGIN PGP MESSAGE-----\r\n\r\nhi\r\n-----END PGP MESSAGE-----",
        );
        let mut with_bcc = b"Bcc: carol@example.org\r\n".to_vec();
        with_bcc.extend_from_slice(&good);
        let inline =
            format!("From: alice@kutup.test\r\nMessage-ID: <abc@kutup.test>\r\n\r\n{armored}\r\n");
        for bad in [
            &other_sender,
            &other_id,
            &plaintext,
            &with_bcc,
            &inline.into_bytes(),
        ] {
            assert!(check(&[package(&["dave@example.org"])], &parts_of(&[bad])).is_err());
        }
    }

    #[test]
    fn meta_is_checked_and_from_is_the_sender() {
        let checked = check_meta(&meta(), &sender(), "kutup.test").unwrap();
        let r = &checked.readable;
        assert_eq!(r.subject, "Merhaba dünya");
        assert_eq!(r.from.as_ref().unwrap().address, "alice@kutup.test");
        assert_eq!(r.to[0].address, "bob@kutup.test");
        assert_eq!(checked.bcc[0].address, "carol@example.org");
        assert_eq!(r.in_reply_to.as_deref(), Some("parent@example.org"));

        let mut foreign = meta();
        foreign.message_id = "abc@elsewhere.org".into();
        assert!(check_meta(&foreign, &sender(), "kutup.test").is_err());
        let mut bad = meta();
        bad.to[0].address = "Bob <bob@kutup.test>".into();
        assert!(check_meta(&bad, &sender(), "kutup.test").is_err());
        let mut many = meta();
        many.cc = (0..100)
            .map(|i| MailboxInput {
                address: format!("u{i}@x.org"),
                name: String::new(),
            })
            .collect();
        assert!(check_meta(&many, &sender(), "kutup.test").is_err());
    }

    #[test]
    fn spam_refusals_are_told_apart() {
        use crate::mail::submit::SubmitError;
        let spam = SubmitError::Refused {
            code: 550,
            text: "5.7.1 Message rejected due to excessive spam score.".into(),
            recipient: None,
        };
        assert!(refused_as_spam(&spam));
        let unknown = SubmitError::Refused {
            code: 550,
            text: "5.1.1 no such user".into(),
            recipient: Some("x@y.org".into()),
        };
        assert!(!refused_as_spam(&unknown));
        assert!(!refused_as_spam(&SubmitError::Unavailable("down".into())));
    }

    #[test]
    fn bcc_headers_are_found_in_the_header_block_only() {
        assert!(has_bcc_header(b"To: a@b\r\nBcc: c@d\r\n\r\nbody"));
        assert!(has_bcc_header(b"BCC: c@d\r\n\r\n"));
        assert!(!has_bcc_header(b"To: a@b\r\n\r\nBcc: in the body\r\n"));
    }
}
