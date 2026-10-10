//! Mail from outside (docs/plans/mail.md, C1). Stalwart, the SMTP edge,
//! asks [`rcpt_hook`] whether each recipient exists and hands accepted mail
//! to the LMTP server here. Each message is encrypted to its address's
//! primary key before it is written anywhere (Proton's "zero-access"), then
//! stored in S3 with its readable fields in `mail_messages`, charged to the
//! account's one storage pool.

pub mod headers;
pub mod lmtp;
pub mod outside_keys;
pub mod submit;

use std::sync::Arc;
use std::time::Duration;

use aws_sdk_s3::primitives::ByteStream;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::AppState;
use headers::Readable;
use lmtp::Reply;

/// The largest message stored: Stalwart takes up to 50 MB and prepends its
/// own headers.
pub const MAX_MESSAGE_BYTES: usize = 52 * 1024 * 1024;

/// Where an account's messages live in the bucket.
pub fn object_prefix(user_id: Uuid) -> String {
    format!("mail/{user_id}/")
}

pub(crate) fn object_key(user_id: Uuid, message_id: Uuid) -> String {
    format!("{}{message_id}", object_prefix(user_id))
}

/// Compares secrets without leaking where they differ or how long they are.
pub(crate) fn secret_matches(given: &[u8], expected: &[u8]) -> bool {
    let (given, expected) = (Sha256::digest(given), Sha256::digest(expected));
    given
        .iter()
        .zip(expected.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// `name@server` (any case, an optional `+tag`) as the stored address, or
/// `None` for an address of another domain.
fn local_address(recipient: &str, server_name: &str) -> Option<String> {
    let (local, domain) = recipient.trim().rsplit_once('@')?;
    if !domain.eq_ignore_ascii_case(server_name) {
        return None;
    }
    let local = local.split_once('+').map_or(local, |(base, _)| base);
    kutup_crypto::mail_key::canonical_address(&format!(
        "{}@{}",
        local.to_ascii_lowercase(),
        server_name.to_ascii_lowercase()
    ))
    .ok()
}

/// An accepted recipient: whose mail it is and the key it is encrypted to.
#[derive(Debug, Clone)]
pub struct Recipient {
    pub(crate) user_id: Uuid,
    pub(crate) address_id: Uuid,
    pub(crate) public_key: Vec<u8>,
}

pub(crate) fn unknown() -> Reply {
    Reply::new(550, "5.1.1", "no such user here")
}

pub(crate) fn full() -> Reply {
    Reply::new(452, "4.2.2", "mailbox full, try again later")
}

fn try_later() -> Reply {
    Reply::new(451, "4.3.0", "temporary failure, try again later")
}

/// Whether `recipient` can receive mail now: a Kutup address on this server
/// with a primary key, on an active account with room in its pool.
pub async fn resolve(state: &AppState, recipient: &str) -> Result<Recipient, Reply> {
    let address = local_address(recipient, &state.config.chat_server_name).ok_or_else(unknown)?;
    let row: Option<(Uuid, Uuid, Vec<u8>, i64, i64)> = sqlx::query_as(
        "SELECT a.id, a.user_id, k.public_key, u.storage_quota_bytes, u.storage_used_bytes
           FROM mail_addresses a
           JOIN users u ON u.id = a.user_id AND u.is_active
           JOIN mail_address_keys k ON k.address_id = a.id AND k.is_primary
          WHERE a.address = $1",
    )
    .bind(&address)
    .fetch_optional(&state.pool)
    .await
    .map_err(|error| {
        tracing::warn!(error = %error, "mail: recipient lookup failed");
        try_later()
    })?;
    let (address_id, user_id, public_key, quota, used) = row.ok_or_else(unknown)?;
    let reserved = crate::storage_pool::reserved(&state.pool, user_id, Default::default())
        .await
        .map_err(|_| try_later())?;
    if used.saturating_add(reserved) >= quota {
        return Err(full());
    }
    Ok(Recipient {
        user_id,
        address_id,
        public_key,
    })
}

/// Stores `raw` for `recipient`: encrypted, then written, then recorded and
/// charged in one transaction. Plaintext stays in this function's memory.
pub async fn store(state: &AppState, recipient: &Recipient, raw: &[u8]) -> Reply {
    match store_inner(state, recipient, raw).await {
        Ok(reply) => reply,
        Err(error) => {
            tracing::warn!(user = %recipient.user_id, error = %error, "mail: storing failed");
            try_later()
        }
    }
}

async fn store_inner(state: &AppState, recipient: &Recipient, raw: &[u8]) -> anyhow::Result<Reply> {
    let owned = raw.to_vec();
    let public_key = recipient.public_key.clone();
    let (readable, ciphertext) = tokio::task::spawn_blocking(move || {
        let readable = Readable::parse(&owned);
        kutup_crypto::mail_key::encrypt_binary(&public_key, &owned).map(|c| (readable, c))
    })
    .await??;

    if let Some(message_id) = &readable.message_id {
        let seen: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM mail_messages
                             WHERE address_id = $1 AND message_id = $2 AND direction = 'inbound')",
        )
        .bind(recipient.address_id)
        .bind(message_id)
        .fetch_one(&state.pool)
        .await?;
        if seen {
            return Ok(Reply::new(250, "2.0.0", "already delivered"));
        }
    }

    let id = Uuid::new_v4();
    let key = object_key(recipient.user_id, id);
    let size = i64::try_from(ciphertext.len())?;
    let version = state
        .storage
        .put_object_versioned(&key, ByteStream::from(ciphertext), size)
        .await?;
    let answer = match record(state, recipient, id, &key, &version, size, &readable).await {
        Ok(Some(stored)) => return Ok(stored),
        Ok(None) => Ok(Reply::new(250, "2.0.0", "already delivered")),
        Err(Recorded::Full) => Ok(full()),
        Err(Recorded::Failed(error)) => Err(error),
    };
    // Nothing points at the object: remove it now rather than leave it to
    // the sweep.
    if let Err(error) = state.storage.delete_stored(&key, &version).await {
        tracing::warn!(error = %error, "mail: unrecorded object left for the sweep");
    }
    answer
}

enum Recorded {
    Full,
    Failed(anyhow::Error),
}

impl From<sqlx::Error> for Recorded {
    fn from(error: sqlx::Error) -> Self {
        Recorded::Failed(error.into())
    }
}

/// Inserts the row and charges the pool under its lock. `Ok(None)` when the
/// same message arrived meanwhile.
async fn record(
    state: &AppState,
    recipient: &Recipient,
    id: Uuid,
    key: &str,
    version: &str,
    size: i64,
    readable: &Readable,
) -> Result<Option<Reply>, Recorded> {
    let mut tx = state.pool.begin().await?;
    let pool = crate::storage_pool::lock(&mut tx, recipient.user_id, Default::default()).await?;
    if !pool.fits(size, 0) {
        return Err(Recorded::Full);
    }
    let inserted = insert_message(
        &mut tx,
        NewMessage {
            id,
            user_id: recipient.user_id,
            address_id: recipient.address_id,
            thread_id: None,
            direction: "inbound",
            folder: if readable.spam { "spam" } else { "inbox" },
            protection: "zero_access",
            seen: false,
            object_key: key,
            object_version: version,
            size,
            readable,
            bcc: &[],
            external_recipients: 0,
        },
    )
    .await?;
    if !inserted {
        return Ok(None);
    }
    tx.commit().await?;
    Ok(Some(Reply::new(250, "2.0.0", "stored")))
}

/// A message row to write (migration 085).
pub(crate) struct NewMessage<'a> {
    pub id: Uuid,
    pub user_id: Uuid,
    pub address_id: Uuid,
    /// The thread, when the caller knows it; otherwise the thread of an
    /// ancestor named in In-Reply-To or References, else a new one.
    pub thread_id: Option<Uuid>,
    pub direction: &'static str,
    pub folder: &'static str,
    pub protection: &'static str,
    pub seen: bool,
    pub object_key: &'a str,
    pub object_version: &'a str,
    pub size: i64,
    pub readable: &'a Readable,
    pub bcc: &'a [headers::Mailbox],
    pub external_recipients: i32,
}

/// The thread of the newest message of `user_id` that `readable` replies to.
pub(crate) async fn ancestor_thread(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    readable: &Readable,
) -> sqlx::Result<Option<Uuid>> {
    let ancestors: Vec<&str> = readable
        .in_reply_to
        .iter()
        .chain(readable.references.iter().rev())
        .map(String::as_str)
        .collect();
    if ancestors.is_empty() {
        return Ok(None);
    }
    sqlx::query_scalar(
        "SELECT thread_id FROM mail_messages
          WHERE user_id = $1 AND message_id = ANY($2)
          ORDER BY received_at DESC LIMIT 1",
    )
    .bind(user_id)
    .bind(&ancestors)
    .fetch_optional(&mut **tx)
    .await
}

/// Inserts `message` and charges its owner's pool; the caller holds the
/// pool lock and has checked the size fits. `false` when the same incoming
/// message was already stored for that address.
pub(crate) async fn insert_message(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    message: NewMessage<'_>,
) -> sqlx::Result<bool> {
    let readable = message.readable;
    let thread = match message.thread_id {
        Some(thread) => Some(thread),
        None => ancestor_thread(tx, message.user_id, readable).await?,
    };
    let sent_at = readable
        .sent_at
        .and_then(|secs| time::OffsetDateTime::from_unix_timestamp(secs).ok());
    let (from_address, from_name) = readable
        .from
        .as_ref()
        .map(|m| (m.address.as_str(), m.name.as_str()))
        .unwrap_or_default();
    let inserted: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO mail_messages
            (id, user_id, address_id, thread_id, direction, folder, seen, protection, object_key,
             object_version, size_bytes, sent_at, subject, from_address, from_name, to_list,
             cc_list, reply_to, bcc_list, message_id, in_reply_to, references_list,
             attachment_count, external_recipients)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                 $18, $19, $20, $21, $22, $23, $24)
         ON CONFLICT (address_id, message_id) WHERE direction = 'inbound' AND message_id IS NOT NULL
         DO NOTHING
         RETURNING id",
    )
    .bind(message.id)
    .bind(message.user_id)
    .bind(message.address_id)
    .bind(thread.unwrap_or(message.id))
    .bind(message.direction)
    .bind(message.folder)
    .bind(message.seen)
    .bind(message.protection)
    .bind(message.object_key)
    .bind(message.object_version)
    .bind(message.size)
    .bind(sent_at)
    .bind(&readable.subject)
    .bind(from_address)
    .bind(from_name)
    .bind(json!(readable.to))
    .bind(json!(readable.cc))
    .bind(json!(readable.reply_to))
    .bind(json!(message.bcc))
    .bind(&readable.message_id)
    .bind(&readable.in_reply_to)
    .bind(&readable.references)
    .bind(readable.attachment_count)
    .bind(message.external_recipients)
    .fetch_optional(&mut **tx)
    .await?;
    if inserted.is_none() {
        return Ok(false);
    }
    sqlx::query("UPDATE users SET storage_used_bytes = storage_used_bytes + $2 WHERE id = $1")
        .bind(message.user_id)
        .bind(message.size)
        .execute(&mut **tx)
        .await?;
    Ok(true)
}

struct Receiver(AppState);

impl lmtp::Delivery for Receiver {
    type Recipient = Recipient;

    async fn check(&self, address: &str) -> Result<Recipient, Reply> {
        resolve(&self.0, address).await
    }

    async fn deliver(&self, recipient: &Recipient, message: &[u8]) -> Reply {
        store(&self.0, recipient, message).await
    }
}

/// Connections served at once; Stalwart opens a few per delivery burst.
const MAX_CONNECTIONS: usize = 16;

/// Binds the LMTP listener, when mail is on, and serves it in the background.
pub async fn spawn_receiver(state: AppState) -> anyhow::Result<()> {
    if state.config.mail_inbound_token.is_empty() {
        return Ok(());
    }
    let listener = tokio::net::TcpListener::bind(&state.config.mail_lmtp_bind).await?;
    tracing::info!(bind = %state.config.mail_lmtp_bind, "mail: LMTP receiver listening");
    let settings = Arc::new(lmtp::Settings {
        hostname: state.config.chat_server_name.clone(),
        secret: state.config.mail_inbound_token.clone(),
        max_message_bytes: MAX_MESSAGE_BYTES,
        max_recipients: 100,
        timeout: Duration::from_secs(300),
    });
    let receiver = Arc::new(Receiver(state));
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    tokio::spawn(async move {
        loop {
            let (socket, _) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::warn!(error = %error, "mail: LMTP accept failed");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            let Ok(slot) = Arc::clone(&slots).acquire_owned().await else {
                return;
            };
            let (settings, receiver) = (Arc::clone(&settings), Arc::clone(&receiver));
            tokio::spawn(async move {
                let _slot = slot;
                let stream = tokio::io::BufReader::new(socket);
                if let Err(error) = lmtp::serve(stream, &settings, receiver.as_ref()).await {
                    tracing::info!(error = %error, "mail: LMTP session ended");
                }
            });
        }
    });
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct HookRequest {
    context: HookContext,
    envelope: Option<HookEnvelope>,
}

#[derive(Debug, Deserialize)]
struct HookContext {
    stage: String,
}

#[derive(Debug, Deserialize)]
struct HookEnvelope {
    to: Vec<HookAddress>,
}

#[derive(Debug, Deserialize)]
struct HookAddress {
    address: String,
}

/// `POST /internal/mail/rcpt`: Stalwart's MTA hook at the RCPT stage. The
/// recipient being checked is the last of `envelope.to`. Not routed by
/// nginx; Stalwart authenticates with the bearer token.
pub async fn rcpt_hook(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<HookRequest>,
) -> Response {
    let token = &state.config.mail_inbound_token;
    if token.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let given = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();
    if !secret_matches(given.as_bytes(), token.as_bytes()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let recipient = request
        .envelope
        .as_ref()
        .and_then(|envelope| envelope.to.last());
    let (true, Some(recipient)) = (request.context.stage == "rcpt", recipient) else {
        return Json(json!({ "action": "accept" })).into_response();
    };
    match resolve(&state, &recipient.address).await {
        Ok(_) => Json(json!({ "action": "accept" })).into_response(),
        Err(reply) => Json(json!({
            "action": "reject",
            "response": {
                "status": reply.code,
                "enhanced_status": reply.status,
                "message": reply.text,
            },
        }))
        .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_addresses() {
        assert_eq!(
            local_address("Alice+news@Kutup.Dev", "kutup.dev").as_deref(),
            Some("alice@kutup.dev")
        );
        assert_eq!(local_address("alice@kutup.dev.evil", "kutup.dev"), None);
        assert_eq!(local_address("alice@other.org", "kutup.dev"), None);
        assert_eq!(local_address("no-at-sign", "kutup.dev"), None);
        assert_eq!(local_address("@kutup.dev", "kutup.dev"), None);
    }

    #[test]
    fn secrets_compare_whole() {
        assert!(secret_matches(b"abc", b"abc"));
        assert!(!secret_matches(b"abc", b"abd"));
        assert!(!secret_matches(b"ab", b"abc"));
        assert!(!secret_matches(b"", b"abc"));
    }
}
