//! Mail from outside (docs/plans/mail.md, C1). Stalwart, the SMTP edge,
//! asks [`rcpt_hook`] whether each recipient exists and hands accepted mail
//! to the LMTP server here. Each message is encrypted to its address's
//! primary key before it is written anywhere (Proton's "zero-access"), then
//! stored in S3 with its readable fields in `mail_messages`, charged to the
//! account's one storage pool.

pub mod auto_reply;
pub mod domains;
pub mod expiry;
pub mod filters;
pub mod forwarding;
pub mod group_keys;
pub mod groups;
pub mod headers;
pub mod lmtp;
pub mod outbox;
pub mod outside_keys;
pub mod retention;
pub mod safety;
pub mod sender_rules;
pub mod snooze;
pub mod submit;
pub mod unsubscribe;

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
    typed_address(&format!("{local}@{server_name}"))
}

/// The form a sender's address is kept and compared in (block, spam and
/// allow lists, image senders, auto-reply records): one of this server's
/// addresses folded, as its names are (any spelling is the one account's,
/// docs/plans/username-renames.md); any other lowercased, as Proton keeps
/// outside senders.
pub(crate) fn sender_key(server_name: &str, address: &str) -> String {
    let lower = address.trim().to_lowercase();
    match lower.rsplit_once('@') {
        Some((_, domain)) if domain.eq_ignore_ascii_case(server_name) => {
            kutup_crypto::names::fold_address(&lower).unwrap_or(lower)
        }
        _ => lower,
    }
}

/// An address as a person types one of this server's: lowercased, its local
/// part any spelling of a name (`.`, `_` and `-` anywhere, which lookups
/// fold away: one account or group per folded name), or `None`.
pub(crate) fn typed_address(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    let (local, domain) = value.split_once('@')?;
    let valid = !local.is_empty()
        && local.len() <= 64
        && local
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        && !kutup_crypto::names::fold(local).is_empty()
        && !domain.is_empty()
        && !domain.contains('@')
        && domain
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b));
    valid.then_some(value)
}

/// Role addresses (RFC 2142) no account may take. All but `mailer-daemon@`
/// are system groups ([`groups`]), which reach their members or, while they
/// have none, every administrator.
pub const RESERVED_LOCAL_PARTS: [&str; 5] = [
    "postmaster",
    "abuse",
    "hostmaster",
    "mailer-daemon",
    "security",
];

/// An accepted recipient: whose mail it is and the key it is encrypted to.
#[derive(Debug, Clone)]
pub struct Recipient {
    pub(crate) user_id: Uuid,
    pub(crate) address_id: Uuid,
    pub(crate) public_key: Vec<u8>,
    /// Taken by a custom domain's catch-all (its domain and the owner's
    /// daily cap): never forwarded outside, so a catch-all can't relay mail
    /// for any name to anywhere, and counted once when stored.
    pub(crate) caught: Option<(Uuid, i64)>,
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

/// Whether `recipient` can receive mail now: a Kutup address on this server,
/// in any spelling (`.`, `_`, `-` and case fold away), that receives (the
/// account's current address, or an old one in its receiving window), with a
/// primary key, on an active account with room in its pool. A closed or freed
/// address is unknown (`5.1.1`); one whose keys are not stored yet is a
/// temporary failure (`4.3.0`), so the sender retries.
pub async fn resolve(state: &AppState, recipient: &str) -> Result<Recipient, Reply> {
    let lookup_failed = |error: sqlx::Error| {
        tracing::warn!(error = %error, "mail: recipient lookup failed");
        try_later()
    };
    let (row, caught) = match local_address(recipient, &state.config.chat_server_name) {
        Some(address) => (
            own_domain_row(state, &address)
                .await
                .map_err(lookup_failed)?,
            None,
        ),
        None => match custom_domain_row(state, recipient)
            .await
            .map_err(lookup_failed)?
        {
            CustomDomain::Address(row) => (row, None),
            CustomDomain::Caught(row, cap) => (row, Some(cap)),
            CustomDomain::OverCap => {
                return Err(Reply::new(452, "4.2.2", "mailbox full, try again later"))
            }
        },
    };
    let (address_id, user_id, public_key, quota, used) = row.ok_or_else(unknown)?;
    // An address whose keys are not stored yet (a new account, or a rename,
    // moments before its client uploads them): try again later, never a
    // permanent refusal.
    let public_key = public_key.ok_or_else(try_later)?;
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
        caught,
    })
}

/// What a custom domain's recipient is.
enum CustomDomain {
    Address(Option<RecipientRow>),
    /// The catch-all took it: its domain and the owner's daily cap.
    Caught(Option<RecipientRow>, (Uuid, i64)),
    /// The catch-all's day is full.
    OverCap,
}

/// A recipient's address id, account, primary key (none yet), quota and use.
type RecipientRow = (Uuid, Uuid, Option<Vec<u8>>, i64, i64);

/// An address on the server's own domain, in any folded spelling.
async fn own_domain_row(
    state: &AppState,
    address: &str,
) -> Result<Option<RecipientRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT a.id, a.user_id, k.public_key, u.storage_quota_bytes, u.storage_used_bytes
           FROM mail_addresses a
           JOIN users u ON u.id = a.user_id AND u.is_active
           LEFT JOIN mail_address_keys k ON k.address_id = a.id AND k.is_primary
          WHERE a.folded = kutup_fold(split_part($1, '@', 1)) || '@' || lower(split_part($1, '@', 2))
            AND (a.state = 'active'
                 OR (a.state = 'receiving' AND a.receive_until > now()))",
    )
    .bind(address)
    .fetch_optional(&state.pool)
    .await
}

/// An address on a custom domain an account holds and may use now
/// (docs/plans/mail-custom-domains.md §5–6), lowercased with its `+tag`
/// stripped; an unknown name there goes to the domain's catch-all, within
/// its daily cap.
async fn custom_domain_row(state: &AppState, recipient: &str) -> Result<CustomDomain, sqlx::Error> {
    let Some((local, domain)) = recipient.trim().rsplit_once('@') else {
        return Ok(CustomDomain::Address(None));
    };
    let local = local
        .split_once('+')
        .map_or(local, |(base, _)| base)
        .to_lowercase();
    let domain = domain.to_lowercase();
    if !domains::sweep::configured(state) {
        return Ok(CustomDomain::Address(None));
    }
    let held: Option<domains::store::Row> = sqlx::query_as(&format!(
        "SELECT {} FROM mail_domains
          WHERE name = $1 AND state IN (1, 2) AND stopped_at IS NULL AND removed_at IS NULL",
        domains::store::COLUMNS
    ))
    .bind(&domain)
    .fetch_optional(&state.pool)
    .await?;
    let Some(held) = held else {
        return Ok(CustomDomain::Address(None));
    };
    // The owner's settings: the site's, with an administrator's overrides
    // for this account (the catch-all among them).
    let settings = domains::settings::Settings::load(&state.pool)
        .await?
        .for_user(&state.pool, held.user_id)
        .await?;
    if !held.usable(&settings) {
        return Ok(CustomDomain::Address(None));
    }
    let (domain_id, catch_all) = (held.id, held.catch_all_address_id);
    const SELECT: &str =
        "SELECT a.id, a.user_id, k.public_key, u.storage_quota_bytes, u.storage_used_bytes
           FROM mail_addresses a
           JOIN users u ON u.id = a.user_id AND u.is_active
           LEFT JOIN mail_address_keys k ON k.address_id = a.id AND k.is_primary";
    let row: Option<RecipientRow> = sqlx::query_as(&format!(
        "{SELECT} WHERE a.folded = $1 AND a.domain_id = $2 AND a.state = 'active'"
    ))
    .bind(format!("{local}@{domain}"))
    .bind(domain_id)
    .fetch_optional(&state.pool)
    .await?;
    if row.is_some() {
        return Ok(CustomDomain::Address(row));
    }
    let Some(catch_all) = catch_all.filter(|_| settings.catch_all) else {
        return Ok(CustomDomain::Address(None));
    };
    if !domains::catch_all_has_room(&state.pool, domain_id, settings.catch_all_per_day).await? {
        return Ok(CustomDomain::OverCap);
    }
    let row: Option<RecipientRow> = sqlx::query_as(&format!(
        "{SELECT} WHERE a.id = $1 AND a.domain_id = $2 AND a.state = 'active'"
    ))
    .bind(catch_all)
    .bind(domain_id)
    .fetch_optional(&state.pool)
    .await?;
    Ok(CustomDomain::Caught(
        row,
        (domain_id, settings.catch_all_per_day),
    ))
}

/// Where mail to an address goes: one account, or a group's receivers.
#[derive(Debug, Clone)]
pub enum Target {
    Person(Recipient),
    Group(groups::Group, Vec<groups::Receiver>),
    /// A shared mailbox: its mail is encrypted to the group's key.
    Shared(groups::Group, Vec<u8>),
    /// A bounce of an outside forward, to its return path: counted on the
    /// forwarding and dropped (docs/plans/mail-forwarding.md).
    ForwardBounce(Uuid),
}

/// [`resolve`], groups included: a group that takes `sender`'s mail, has
/// room and someone to receive it.
pub async fn resolve_target(
    state: &AppState,
    recipient: &str,
    sender: groups::Sender,
) -> Result<Target, Reply> {
    // Our return paths are checked here, at RCPT: a forged or stale one is
    // refused before any data, so nothing becomes backscatter.
    if let Some((local, domain)) = recipient.trim().rsplit_once('@') {
        if domain.eq_ignore_ascii_case(&state.config.chat_server_name)
            && local.to_ascii_lowercase().starts_with("fwd-")
        {
            return forwarding::bounce_forwarding(&state.config.mail_forwarding_keys, local)
                .map(Target::ForwardBounce)
                .ok_or_else(unknown);
        }
    }
    // Groups live on the server's own domain; a custom domain's addresses
    // are people's (docs/plans/mail-custom-domains.md §0).
    let Some(address) = local_address(recipient, &state.config.chat_server_name) else {
        return resolve(state, recipient).await.map(Target::Person);
    };
    let lookup_failed = |error: sqlx::Error| {
        tracing::warn!(error = %error, "mail: group lookup failed");
        try_later()
    };
    let Some(group) = groups::find(&state.pool, &address)
        .await
        .map_err(lookup_failed)?
    else {
        return resolve(state, recipient).await.map(Target::Person);
    };
    if !groups::may_post(&state.pool, &group, sender)
        .await
        .map_err(lookup_failed)?
    {
        return Err(Reply::new(
            550,
            "5.7.1",
            "this group does not take mail from you",
        ));
    }
    if !groups::has_room(&state.pool, group.id)
        .await
        .map_err(lookup_failed)?
    {
        return Err(full());
    }
    if group.kind == "shared" {
        let key = group_keys::primary_public_key(&state.pool, group.id)
            .await
            .map_err(lookup_failed)?
            .ok_or_else(|| Reply::new(451, "4.3.0", "this mailbox has no key yet"))?;
        return Ok(Target::Shared(group, key));
    }
    let receivers = groups::receivers(&state.pool, &group)
        .await
        .map_err(lookup_failed)?;
    if receivers.is_empty() {
        return Err(Reply::new(
            550,
            "5.2.1",
            "this group has nobody to receive mail",
        ));
    }
    Ok(Target::Group(group, receivers))
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
    let authserv = state.config.mail_hostname.clone();
    let (readable, may_answer, ciphertext) = tokio::task::spawn_blocking(move || {
        let mut readable = Readable::parse(&owned);
        readable.from_authenticated = headers::dmarc_passed(&owned, &authserv);
        let may_answer = auto_reply::may_answer(&owned);
        kutup_crypto::mail_key::encrypt_binary(&public_key, &owned)
            .map(|c| (readable, may_answer, c))
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
    // A caught message counts against its catch-all's day once, here; the
    // day may have filled since RCPT on another backend.
    if let Some((domain, per_day)) = recipient.caught {
        if !crate::mail::domains::count_catch_all(&state.pool, domain, per_day).await? {
            return Ok(Reply::new(452, "4.2.2", "mailbox full, try again later"));
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
        Ok(Some(stored)) => {
            // On to the address's forwardings, after its own copy is kept.
            if forwarding::forwards(&state.pool, recipient.address_id).await {
                forwarding::spawn_forward(
                    state,
                    forwarding::Arrived {
                        address_id: recipient.address_id,
                        message_id: id,
                        object_key: key.clone(),
                        object_version: version.clone(),
                        readable: readable.clone(),
                        may_forward: recipient.caught.is_none()
                            && forwarding::may_forward(&state.config.mail_forwarding_keys, raw),
                        plaintext: Some(std::sync::Arc::new(raw.to_vec())),
                    },
                );
            }
            if may_answer && readable.bounce.is_none() {
                auto_reply::spawn(
                    state,
                    auto_reply::Delivered {
                        user_id: recipient.user_id,
                        message: id,
                    },
                );
            }
            // A report of mail this account sent failing: counts towards
            // pausing its sending (only for its own messages).
            if let Some(bounce) = &readable.bounce {
                if let Some(original) = &bounce.original_message_id {
                    if let Err(error) = safety::record_bounce(
                        &state.pool,
                        recipient.user_id,
                        original,
                        bounce.failures,
                    )
                    .await
                    {
                        tracing::warn!(error = %error, "mail: bounce not recorded");
                    }
                }
            }
            return Ok(stored);
        }
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
            user_id: Some(recipient.user_id),
            address_id: recipient.address_id,
            thread_id: None,
            direction: "inbound",
            folder: if readable.spam { "spam" } else { "inbox" },
            // Encrypted by its sender with OpenPGP: end to end; otherwise
            // it came in clear and is encrypted here (zero access).
            protection: if readable.pgp_encrypted {
                "end_to_end"
            } else {
                "zero_access"
            },
            seen: false,
            object_key: key,
            object_version: version,
            size,
            readable,
            bcc: &[],
            external_recipients: 0,
            group_id: None,
            key_packet: None,
            sent_by: None,
            forwarded_from: None,
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
    /// The account whose mailbox it is; none for a shared mailbox's message
    /// (then `group_id` is the mailbox).
    pub user_id: Option<Uuid>,
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
    /// The distribution list the copy came through.
    pub group_id: Option<Uuid>,
    /// A list member's own key packet: the object is the list's shared data
    /// packet, charged to the group, not to this account.
    pub key_packet: Option<&'a [u8]>,
    /// The member who sent it as a shared mailbox.
    pub sent_by: Option<Uuid>,
    /// The address it was forwarded from (docs/plans/mail-forwarding.md):
    /// opened only with the forwarding key, never forwarded again.
    pub forwarded_from: Option<&'a str>,
}

/// The thread of the newest message in the mailbox of `owner` (an account,
/// or a shared mailbox's group) that `readable` replies to.
pub(crate) async fn ancestor_thread(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    owner: Uuid,
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
          WHERE owner = $1 AND message_id = ANY($2)
          ORDER BY received_at DESC LIMIT 1",
    )
    .bind(owner)
    .bind(&ancestors)
    .fetch_optional(&mut **tx)
    .await
}

/// Inserts `message` and charges its owner's pool (a list member's copy is
/// charged to the group by the caller instead); the caller holds the pool
/// lock and has checked the size fits. `false` when the same incoming
/// message was already stored for that address.
pub(crate) async fn insert_message(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    message: NewMessage<'_>,
) -> sqlx::Result<bool> {
    let readable = message.readable;
    let owner = message
        .user_id
        .or(message.group_id)
        .expect("a message belongs to an account or a group");
    let thread = match message.thread_id {
        Some(thread) => Some(thread),
        None => ancestor_thread(tx, owner, readable).await?,
    };
    let sent_at = readable
        .sent_at
        .and_then(|secs| time::OffsetDateTime::from_unix_timestamp(secs).ok());
    let (from_address, from_name) = readable
        .from
        .as_ref()
        .map(|m| (m.address.as_str(), m.name.as_str()))
        .unwrap_or_default();
    // The account's block, spam and allow lists come first
    // (docs/plans/mail-filters.md, F3); a blocked message is not stored.
    let mut folder = message.folder;
    if let (Some(user_id), "inbound", "inbox" | "spam") =
        (message.user_id, message.direction, folder)
    {
        match sender_rules::verdict(tx, user_id, from_address).await? {
            Some(sender_rules::Kind::Block) => return Ok(false),
            Some(sender_rules::Kind::Spam) => folder = "spam",
            Some(sender_rules::Kind::Allow) if readable.from_authenticated => folder = "inbox",
            _ => {}
        }
    }
    let inserted: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO mail_messages
            (id, user_id, address_id, thread_id, direction, folder, seen, protection, object_key,
             object_version, size_bytes, sent_at, subject, from_address, from_name, to_list,
             cc_list, reply_to, bcc_list, message_id, in_reply_to, references_list,
             attachment_count, external_recipients, group_id, key_packet, sent_by, unsubscribable,
             attachments, expires_at, notify_at, forwarded_from)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                 $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30,
                 CASE WHEN $5 = 'inbound' AND NOT $7 THEN now() END, $31)
         ON CONFLICT (address_id, message_id) WHERE direction = 'inbound' AND message_id IS NOT NULL
         DO NOTHING
         RETURNING id",
    )
    .bind(message.id)
    .bind(message.user_id)
    .bind(message.address_id)
    .bind(thread.unwrap_or(message.id))
    .bind(message.direction)
    .bind(folder)
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
    .bind(message.group_id)
    .bind(message.key_packet)
    .bind(message.sent_by)
    .bind(readable.list_unsubscribe)
    .bind(sqlx::types::Json(&readable.attachments))
    .bind(readable.expires_at)
    .bind(message.forwarded_from)
    .fetch_optional(&mut **tx)
    .await?;
    if inserted.is_none() {
        return Ok(false);
    }
    if message.key_packet.is_some() {
        return Ok(true);
    }
    // A shared mailbox's message is charged to its group.
    let charge = match message.user_id {
        Some(_) => "UPDATE users SET storage_used_bytes = storage_used_bytes + $2 WHERE id = $1",
        None => "UPDATE mail_groups SET storage_used_bytes = storage_used_bytes + $2 WHERE id = $1",
    };
    sqlx::query(charge)
        .bind(owner)
        .bind(message.size)
        .execute(&mut **tx)
        .await?;
    // The account's filters, on incoming mail (distribution-list copies
    // included) and its own sent copies; never on drafts, on mail filed as
    // spam, or on a shared mailbox's copy, which has no one owner yet
    // (docs/plans/mail-filters.md).
    if let Some(user_id) = message.user_id.filter(|_| {
        (message.direction == "inbound" && folder == "inbox")
            || (message.direction == "outbound" && folder == "sent")
    }) {
        filters::on_arrival(
            tx,
            user_id,
            message.address_id,
            message.id,
            message.direction,
            readable,
        )
        .await?;
    }
    Ok(true)
}

struct Receiver(AppState);

impl lmtp::Delivery for Receiver {
    type Recipient = Target;

    // Every LMTP delivery comes from outside, through Stalwart.
    async fn check(&self, address: &str) -> Result<Target, Reply> {
        resolve_target(&self.0, address, groups::Sender::Outside).await
    }

    async fn deliver(&self, target: &Target, message: &[u8]) -> Reply {
        match target {
            Target::Person(recipient) => store(&self.0, recipient, message).await,
            Target::Group(group, receivers) => {
                groups::store_from_outside(&self.0, group, receivers, message).await
            }
            Target::Shared(group, key) => groups::store_shared(&self.0, group, key, message).await,
            Target::ForwardBounce(forwarding) => {
                if let Err(error) = forwarding::record_bounce(&self.0.pool, *forwarding).await {
                    tracing::warn!(error = %error, "mail: a forwarding bounce was not counted");
                    return try_later();
                }
                Reply::new(250, "2.0.0", "noted")
            }
        }
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
    match resolve_target(&state, &recipient.address, groups::Sender::Outside).await {
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
    fn this_servers_senders_compare_folded_others_exactly() {
        // Any spelling of one of this server's names is the one sender.
        assert_eq!(
            sender_key("kutup.dev", "Ada.L@Kutup.dev"),
            sender_key("kutup.dev", "ada_l@kutup.dev")
        );
        assert_eq!(sender_key("kutup.dev", "ada-l@kutup.dev"), "adal@kutup.dev");
        // Another server's addresses are only lowercased.
        assert_eq!(
            sender_key("kutup.dev", "J.Doe@Example.org"),
            "j.doe@example.org"
        );
        assert_ne!(
            sender_key("kutup.dev", "j.doe@example.org"),
            sender_key("kutup.dev", "jdoe@example.org")
        );
    }

    #[test]
    fn local_addresses() {
        assert_eq!(
            local_address("Alice+news@Kutup.Dev", "kutup.dev").as_deref(),
            Some("alice@kutup.dev")
        );
        // Any spelling of a name: lookups fold it.
        assert_eq!(
            local_address("Ada.L@kutup.dev", "kutup.dev").as_deref(),
            Some("ada.l@kutup.dev")
        );
        assert_eq!(local_address("...@kutup.dev", "kutup.dev"), None);
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
