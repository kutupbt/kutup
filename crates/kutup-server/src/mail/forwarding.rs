//! Mail forwarding (docs/plans/mail-forwarding.md), as Proton has it.
//!
//! An address forwards end to end to a Kutup address on this server (the
//! server turns each arriving key packet into one for the forwardee with a
//! proxy factor k, reading no message), or outside (re-sent; the address's
//! end-to-end encryption is off while any outside forwarding is on).
//!
//! k with the forwardee's secret key gives the forwarder's, so it is sealed
//! here under `MAIL_FORWARDING_KEYS` (the key's id kept beside it, the AAD
//! bound to the forwarding and both fingerprints), never logged, never
//! returned, and deleted whenever the forwarding can't resume.

use aws_sdk_s3::primitives::ByteStream;
use kutup_crypto::mail_forwarding::{self, ProxyInstance};
use uuid::Uuid;

use super::filters::{self, Condition, Match, Subject};
use super::headers::Readable;
use crate::opaque_setup::OpaqueSetupKeys;
use crate::AppState;

/// Forwardings one address may have, and one account (user decision
/// 2026-10-19).
pub const MAX_PER_ADDRESS: i64 = 10;
pub const MAX_PER_ACCOUNT: i64 = 25;
/// Pending forwardings to one address at a time.
pub const MAX_PENDING_PER_FORWARDEE: i64 = 5;
/// A pending forwarding's activation or confirmation link lives this long.
pub const PENDING_DAYS: i64 = 7;
/// Mail that arrives with more `Received` headers than this is delivered
/// but never forwarded again (a loop through outside providers).
pub const MAX_HOPS: usize = 20;

/// Seals k under the current `MAIL_FORWARDING_KEYS` key:
/// `(key id, sealed)`. `None` without a key: end-to-end forwarding is then
/// unavailable.
pub fn seal(
    keys: &OpaqueSetupKeys,
    forwarding: Uuid,
    instance: &ProxyInstance,
) -> Option<(u16, Vec<u8>)> {
    let (id, key) = keys.current()?;
    mail_forwarding::seal_proxy_parameter(key, id, forwarding.as_bytes(), instance)
        .ok()
        .map(|sealed| (id, sealed))
}

/// Opens a sealed k. `None` when its key is gone from the configuration or
/// it was sealed for another forwarding or subkey: the forwarding is then
/// made Outdated, never an arrival error.
pub fn open(
    keys: &OpaqueSetupKeys,
    key_id: u16,
    forwarding: Uuid,
    forwarder_fingerprint: [u8; 20],
    forwardee_fingerprint: [u8; 20],
    sealed: &[u8],
) -> Option<ProxyInstance> {
    let key = keys.get(key_id)?;
    mail_forwarding::open_proxy_parameter(
        key,
        key_id,
        forwarding.as_bytes(),
        forwarder_fingerprint,
        forwardee_fingerprint,
        sealed,
    )
    .ok()
}

/// The address's end-to-end forwardings were made for a key it no longer
/// receives on: they become Outdated, their proxy factors are deleted (an
/// old k with the forwardee key still opens the old key's mail) and any
/// pending activation goes. Re-enabling makes new material.
pub async fn outdate(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    forwarder_address_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM mail_forwarding_keys
          WHERE forwarding_id IN (SELECT id FROM mail_forwardings
                                   WHERE forwarder_address_id = $1 AND kind = 'end_to_end')",
    )
    .bind(forwarder_address_id)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE mail_forwardings SET state = 'outdated', activation = NULL, expires_at = NULL,
                updated_at = now()
          WHERE forwarder_address_id = $1 AND kind = 'end_to_end' AND state <> 'rejected'",
    )
    .bind(forwarder_address_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// A pending forwarding the forwardee declined, or that lapsed: its proxy
/// factors and activation go, and the forwarder may ask again with new
/// material.
/// After an outside forwarding of `address` ends or is declined: when it
/// was the last, the address owes a key list without EMAIL_NO_ENCRYPT,
/// which only its owner's client can sign (it does at its next Mail
/// sign-in).
pub async fn settle_outside(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    address: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE mail_addresses SET key_list_owed = true
          WHERE id = $1
            AND NOT EXISTS (SELECT 1 FROM mail_forwardings
                             WHERE forwarder_address_id = $1 AND kind = 'outside'
                               AND state <> 'rejected')
            AND EXISTS (SELECT 1 FROM mail_address_keys
                         WHERE address_id = $1 AND NOT is_forwarding AND flags & 4 <> 0)",
    )
    .bind(address)
    .execute(&mut **tx)
    .await
    .map(drop)
}

pub async fn reject(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    forwarding: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM mail_forwarding_keys WHERE forwarding_id = $1")
        .bind(forwarding)
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "UPDATE mail_forwardings SET state = 'rejected', activation = NULL, expires_at = NULL,
                confirmation_hash = NULL, updated_at = now()
          WHERE id = $1",
    )
    .bind(forwarding)
    .execute(&mut **tx)
    .await?;
    let address: Uuid =
        sqlx::query_scalar("SELECT forwarder_address_id FROM mail_forwardings WHERE id = $1")
            .bind(forwarding)
            .fetch_one(&mut **tx)
            .await?;
    settle_outside(tx, address).await
}

/// Pending forwardings past their expiry lapse, as a decline does.
pub async fn sweep_expired(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    // Locked as they are read, so an accept racing the sweep wins or loses
    // whole.
    let mut tx = pool.begin().await?;
    let lapsed: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM mail_forwardings WHERE state = 'pending' AND expires_at <= now()
            FOR UPDATE SKIP LOCKED",
    )
    .fetch_all(&mut *tx)
    .await?;
    for forwarding in lapsed {
        reject(&mut tx, forwarding).await?;
    }
    tx.commit().await
}

/// An outside forwardee address as it may be used, or `None`: a plain
/// RFC 5321 mailbox, lowercased: one `@`; a local part of atext and single
/// dots (no quoting); a domain of at least two labels of letters, digits and
/// inner hyphens. Nothing that could end an SMTP command or a header line
/// gets through (`submit` refuses those again).
pub fn outside_address(value: &str) -> Option<String> {
    if value.chars().any(char::is_control) {
        return None;
    }
    let value = value.trim_matches(' ').to_ascii_lowercase();
    if value.len() > 254 || !value.is_ascii() {
        return None;
    }
    let (local, domain) = value.split_once('@')?;
    let atext = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+/=?^_`{|}~-".contains(c);
    let local_ok = !local.is_empty()
        && local.len() <= 64
        && local
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(atext));
    let labels: Vec<&str> = domain.split('.').collect();
    let domain_ok = domain.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
        && !labels
            .last()
            .is_some_and(|tld| tld.chars().all(|c| c.is_ascii_digit()));
    (local_ok && domain_ok).then_some(value)
}

/// A return path lasts this many days (as SRS0's timestamp).
const RETURN_PATH_DAYS: i64 = 21;
/// A forwarding limit as the database counters compare it: the registry's
/// value (`forwarding_*`, `forwardings_created`; one account's own where it
/// counts per account).
pub fn limit(limit: crate::ratelimit::Limit, account: Option<Uuid>) -> i32 {
    let value = match account {
        Some(account) => crate::ratelimit::value_for(limit, &account.to_string()),
        None => crate::ratelimit::value(limit),
    };
    i32::try_from(value).unwrap_or(i32::MAX)
}

/// What an account spends of its forwarding allowances.
pub enum Charge {
    /// A forwarding made.
    Creation,
    /// A confirmation email sent.
    Confirmation,
    /// A message re-sent outside.
    Forward,
}

/// Charges `charge` to the account's allowances (`mail_forwarding_quota`,
/// apart from the forwardings, so deleting one gives nothing back). `false`
/// when it is spent; nothing is charged then.
pub async fn charge(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account: Uuid,
    charge: Charge,
) -> Result<bool, sqlx::Error> {
    let (created, confirmations, forwards) = match charge {
        Charge::Creation => (1, 0, 0),
        Charge::Confirmation => (0, 1, 0),
        Charge::Forward => (0, 0, 1),
    };
    sqlx::query("INSERT INTO mail_forwarding_quota (user_id) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(account)
        .execute(&mut **tx)
        .await?;
    let charged = sqlx::query(
        "UPDATE mail_forwarding_quota SET
                created_this_hour = CASE WHEN hour = date_trunc('hour', now())
                                         THEN created_this_hour ELSE 0 END + $2,
                hour = date_trunc('hour', now()),
                confirmations_today = CASE WHEN day = current_date
                                           THEN confirmations_today ELSE 0 END + $3,
                forwards_today = CASE WHEN day = current_date
                                      THEN forwards_today ELSE 0 END + $4,
                day = current_date
          WHERE user_id = $1
            AND (CASE WHEN hour = date_trunc('hour', now()) THEN created_this_hour ELSE 0 END)
                + $2 <= $5
            AND (CASE WHEN day = current_date THEN confirmations_today ELSE 0 END) + $3 <= $6
            AND (CASE WHEN day = current_date THEN forwards_today ELSE 0 END) + $4 <= $7",
    )
    .bind(account)
    .bind(created)
    .bind(confirmations)
    .bind(forwards)
    .bind(limit(
        crate::ratelimit::Limit::ForwardingsCreated,
        Some(account),
    ))
    .bind(limit(
        crate::ratelimit::Limit::ForwardingConfirmationsSent,
        Some(account),
    ))
    .bind(limit(
        crate::ratelimit::Limit::ForwardingOutsideAccount,
        Some(account),
    ))
    .execute(&mut **tx)
    .await?;
    Ok(charged.rows_affected() == 1)
}

/// Why an account may not send outside now, under the same rules as Mail's
/// own sending and auto-replies: the server's outside-sending policy
/// (`off`, `admins`, `on`) and the account's sending standing (paused by an
/// administrator, or for bounces or spam). `None` when it may.
pub async fn outside_refusal(
    state: &AppState,
    account: Uuid,
) -> Result<Option<&'static str>, crate::error::AppError> {
    let is_admin: bool = sqlx::query_scalar("SELECT is_admin FROM users WHERE id = $1")
        .bind(account)
        .fetch_one(&state.pool)
        .await?;
    if !crate::site_settings::mail_outside_sending(&state.pool, state.config.mail_outside_sending)
        .await?
        .allows(is_admin)
    {
        return Ok(Some("outsideSendingOff"));
    }
    if super::safety::standing(state, account)
        .await?
        .paused
        .is_some()
    {
        return Ok(Some("sendingPaused"));
    }
    Ok(None)
}

const RETURN_PATH_DOMAIN: &[u8] = b"kutup/mail-forwarding/return-path/v1\0";
const MARKER_DOMAIN: &[u8] = b"kutup/mail-forwarding/marker/v1\0";

/// The loop marker's MAC: its own label, over the forwarding alone.
fn marker_mac(key: &[u8; 32], forwarding: Uuid) -> String {
    use hmac::{Hmac, Mac as _};
    let mut mac = <Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(key).expect("any key length");
    mac.update(MARKER_DOMAIN);
    mac.update(forwarding.as_bytes());
    hex::encode(&mac.finalize().into_bytes()[..8])
}

fn return_path_mac(key: &[u8; 32], forwarding: Uuid, day: i64) -> String {
    use hmac::{Hmac, Mac as _};
    let mut mac = <Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(key).expect("any key length");
    mac.update(RETURN_PATH_DOMAIN);
    mac.update(forwarding.as_bytes());
    mac.update(&day.to_be_bytes());
    hex::encode(&mac.finalize().into_bytes()[..8])
}

fn today() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp() / 86_400
}

/// The envelope sender an outside forward goes out with: our domain (so
/// SPF holds for the hop we make), naming the forwarding and the day under
/// an HMAC, so a bounce comes back to us, is checked at RCPT and counted on
/// its forwarding. SRS's purpose in a VERP form: bounces are counted here,
/// not relayed. `None` without `MAIL_FORWARDING_KEYS`.
pub fn return_path(keys: &OpaqueSetupKeys, server_name: &str, forwarding: Uuid) -> Option<String> {
    let (_, key) = keys.current()?;
    let day = today();
    Some(format!(
        "fwd-{}-{day}-{}@{server_name}",
        forwarding.simple(),
        return_path_mac(key, forwarding, day)
    ))
}

/// The forwarding a bounce's recipient local part names, when it is one of
/// our return paths, its HMAC holds under any configured key and it is no
/// older than [`RETURN_PATH_DAYS`].
pub fn bounce_forwarding(keys: &OpaqueSetupKeys, local: &str) -> Option<Uuid> {
    let rest = local.to_ascii_lowercase();
    let rest = rest.strip_prefix("fwd-")?;
    let mut parts = rest.split('-');
    let (id, day, mac) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || id.len() != 32 || mac.len() != 16 {
        return None;
    }
    let forwarding = Uuid::parse_str(id).ok()?;
    let day: i64 = day.parse().ok()?;
    let age = today() - day;
    if !(0..=RETURN_PATH_DAYS).contains(&age) {
        return None;
    }
    keys.ids()
        .filter_map(|id| keys.get(id))
        .any(|key| {
            let expected = return_path_mac(key, forwarding, day);
            expected.len() == mac.len()
                && expected
                    .bytes()
                    .zip(mac.bytes())
                    .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                    == 0
        })
        .then_some(forwarding)
}

/// A bounce came back for an outside forwarding: counted for the day, and
/// after `forwarding_bounces` bounces the forwarding pauses with a notice.
pub async fn record_bounce(pool: &sqlx::PgPool, forwarding: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE mail_forwardings SET
                bounces_today = CASE WHEN day = current_date THEN bounces_today + 1 ELSE 1 END,
                sent_today = CASE WHEN day = current_date THEN sent_today ELSE 0 END,
                invites_today = CASE WHEN day = current_date THEN invites_today ELSE 0 END,
                day = current_date, updated_at = now()
          WHERE id = $1 AND kind = 'outside'",
    )
    .bind(forwarding)
    .execute(pool)
    .await?;
    sqlx::query(
        "UPDATE mail_forwardings SET state = 'paused', notice = 'bounces'
          WHERE id = $1 AND state = 'active' AND bounces_today >= $2",
    )
    .bind(forwarding)
    .bind(limit(crate::ratelimit::Limit::ForwardingBounces, None))
    .execute(pool)
    .await?;
    Ok(())
}

/// How often [`spawn`]'s loop tidies forwardings.
const TICK: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// Tidies forwardings now and then: pending ones past their expiry lapse,
/// and forwardings whose forwarder or forwardee address no longer receives
/// (closed after a rename hold, or freed) end with their proxy factors.
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(TICK);
        loop {
            tick.tick().await;
            if let Err(error) = tidy(&state.pool).await {
                tracing::warn!(error = %error, "mail: tidying forwardings failed");
            }
        }
    });
}

/// One pass of [`spawn`]'s loop.
pub async fn tidy(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    sweep_expired(pool).await?;
    // A deactivated account's forwardings, either side, keep no proxy
    // factor: they are Outdated, and re-enabled with new material if the
    // account comes back.
    let stopped: Vec<Uuid> = sqlx::query_scalar(
        "SELECT f.id FROM mail_forwardings f
           JOIN users fu ON fu.id = f.user_id
           LEFT JOIN mail_addresses b ON b.id = f.forwardee_address_id
           LEFT JOIN users bu ON bu.id = b.user_id
          WHERE f.kind = 'end_to_end' AND f.state <> 'outdated'
            AND (NOT fu.is_active OR NOT COALESCE(bu.is_active, true))",
    )
    .fetch_all(pool)
    .await?;
    for forwarding in stopped {
        let mut tx = pool.begin().await?;
        sqlx::query("DELETE FROM mail_forwarding_keys WHERE forwarding_id = $1")
            .bind(forwarding)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE mail_forwardings SET state = 'outdated', activation = NULL,
                    expires_at = NULL, updated_at = now()
              WHERE id = $1",
        )
        .bind(forwarding)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }
    sqlx::query(
        "DELETE FROM mail_forwardings f
          USING mail_addresses a
          WHERE a.id IN (f.forwarder_address_id, f.forwardee_address_id)
            AND NOT (a.state = 'active' OR (a.state = 'receiving' AND a.receive_until > now()))",
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// A copy just stored in a forwarder's mailbox, for [`forward_copy`].
pub struct Arrived {
    pub address_id: Uuid,
    /// The copy's message row (its folder after filters decides spam).
    pub message_id: Uuid,
    pub object_key: String,
    pub object_version: String,
    pub readable: Readable,
    /// Whether the message may be forwarded at all: false when it came back
    /// through a forwarding loop (our marker header, our SRS sender, or more
    /// than [`MAX_HOPS`] `Received` headers).
    pub may_forward: bool,
    /// The message as it arrived, when the server read it (mail from
    /// outside, or Kutup mail sent readable): what an outside forwarding
    /// re-sends. `None` for end-to-end Kutup mail, which can't go outside.
    pub plaintext: Option<std::sync::Arc<Vec<u8>>>,
}

/// Whether the address has an active forwarding: the arrival paths ask
/// before copying a message or starting a task for it.
pub async fn forwards(pool: &sqlx::PgPool, address: Uuid) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM mail_forwardings
                         WHERE forwarder_address_id = $1 AND state = 'active')",
    )
    .bind(address)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|error| {
        // Not known: try, rather than drop it unseen; forward_copy finds out
        // and logs what it can't do.
        tracing::warn!(%address, error = %error, "mail: whether the address forwards is unknown");
        true
    })
}

/// Whether arriving mail may be forwarded: not when it carries a marker
/// one of our forwardings set (its HMAC holds under a configured key), or has
/// come through more than [`MAX_HOPS`] hops. A forged marker is ignored. Only
/// header lines count: folded continuation lines are part of the one above.
pub fn may_forward(keys: &OpaqueSetupKeys, raw: &[u8]) -> bool {
    let headers = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .or_else(|| raw.windows(2).position(|window| window == b"\n\n"))
        .map_or(raw, |end| &raw[..end]);
    let text = String::from_utf8_lossy(headers);
    let mut received = 0usize;
    for line in text.lines() {
        if line.starts_with([' ', '\t']) {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.eq_ignore_ascii_case("x-kutup-forwarded") && ours(keys, value.trim()) {
            return false;
        }
        if name.eq_ignore_ascii_case("received") {
            received += 1;
        }
    }
    received <= MAX_HOPS
}

/// Whether a marker value is one of ours: `<forwarding>-<hmac>`.
fn ours(keys: &OpaqueSetupKeys, marker: &str) -> bool {
    let Some((id, mac)) = marker.split_once('-') else {
        return false;
    };
    let Ok(forwarding) = Uuid::parse_str(id) else {
        return false;
    };
    keys.ids().filter_map(|id| keys.get(id)).any(|key| {
        let expected = marker_mac(key, forwarding);
        expected.len() == mac.len()
            && expected
                .bytes()
                .zip(mac.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    })
}

/// Forwards a copy just stored for an address to each of the address's
/// active end-to-end forwardings whose conditions it meets. Runs after the
/// copy's own delivery committed and never fails it: a message that can't
/// be forwarded (its key packet can't be transformed, or the forwardee's
/// mailbox is full) is counted on the forwarding.
pub fn spawn_forward(state: &AppState, arrived: Arrived) {
    let state = state.clone();
    tokio::spawn(async move {
        if let Err(error) = forward_copy(&state, arrived).await {
            tracing::warn!(error = %error, "mail: forwarding failed");
        }
    });
}

/// id, kind, match, conditions, forwardee address and account (end to end),
/// forwardee email, forwarder address, forwarder account.
type Forwarding = (
    Uuid,
    String,
    String,
    serde_json::Value,
    Option<Uuid>,
    Option<Uuid>,
    String,
    String,
    Uuid,
);

async fn forward_copy(state: &AppState, arrived: Arrived) -> anyhow::Result<()> {
    if !arrived.may_forward {
        return Ok(());
    }
    let forwardings: Vec<Forwarding> = sqlx::query_as(
        "SELECT f.id, f.kind, f.match, f.conditions, b.id, b.user_id, f.forwardee_email,
                a.address, f.user_id
           FROM mail_forwardings f
           JOIN mail_addresses a ON a.id = f.forwarder_address_id
           LEFT JOIN mail_addresses b ON b.id = f.forwardee_address_id
           LEFT JOIN users u ON u.id = b.user_id
          WHERE f.forwarder_address_id = $1 AND f.state = 'active'
            AND (f.kind = 'outside' OR (b.state = 'active' AND b.disabled_at IS NULL AND u.is_active))",
    )
    .bind(arrived.address_id)
    .fetch_all(&state.pool)
    .await?;
    if forwardings.is_empty() {
        return Ok(());
    }
    // Spam isn't forwarded, nor what itself came by forwarding.
    let copy: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT folder, forwarded_from FROM mail_messages WHERE id = $1")
            .bind(arrived.message_id)
            .fetch_optional(&state.pool)
            .await?;
    match copy {
        Some((folder, None)) if folder != "spam" => {}
        _ => return Ok(()),
    }
    let readable = &arrived.readable;
    let subject = Subject {
        from: readable.from.as_ref(),
        to: &readable.to,
        cc: &readable.cc,
        address: "",
        subject: &readable.subject,
        attachments: readable.attachment_count,
    };
    let mut message: Option<Vec<u8>> = None;
    for (
        id,
        kind,
        rule,
        conditions,
        forwardee_address,
        forwardee_user,
        forwardee_email,
        forwarder_address,
        forwarder_user,
    ) in forwardings
    {
        let conditions: Vec<Condition> = serde_json::from_value(conditions).unwrap_or_default();
        let rule = if rule == "any" {
            Match::Any
        } else {
            Match::All
        };
        if !conditions.is_empty() && !filters::matches(rule, &conditions, &subject) {
            continue;
        }
        if kind == "outside" {
            let sent = forward_outside(
                state,
                id,
                forwarder_user,
                &forwardee_email,
                readable,
                arrived.plaintext.as_deref(),
            )
            .await?;
            if !sent {
                count_skip(state, id).await?;
            }
            continue;
        }
        let (Some(forwardee_address), Some(forwardee_user)) = (forwardee_address, forwardee_user)
        else {
            continue;
        };
        let Some(instances) = instances(state, id).await? else {
            continue;
        };
        if message.is_none() {
            let (body, _) = state
                .storage
                .get_stored(&arrived.object_key, &arrived.object_version)
                .await?;
            message = Some(body.collect().await?.into_bytes().to_vec());
        }
        let stored = message.as_deref().expect("read above");
        let (forwardee_public_key, instances) = instances;
        let forwarded = {
            let stored = stored.to_vec();
            tokio::task::spawn_blocking(move || {
                mail_forwarding::forward_message(&stored, &forwardee_public_key, &instances)
            })
            .await?
        };
        let delivered = match forwarded {
            Ok(forwarded) => {
                deliver(
                    state,
                    forwardee_user,
                    forwardee_address,
                    &forwarder_address,
                    forwarded,
                    readable,
                )
                .await?
            }
            Err(_) => false,
        };
        if !delivered {
            count_skip(state, id).await?;
        }
    }
    Ok(())
}

async fn count_skip(state: &AppState, forwarding: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE mail_forwardings SET skipped = skipped + 1 WHERE id = $1")
        .bind(forwarding)
        .execute(&state.pool)
        .await
        .map(drop)
}

/// The marker header an outside forward carries, so it is never forwarded
/// again when it comes back (an HMAC of the forwarding, so it names nothing).
fn marker(keys: &OpaqueSetupKeys, forwarding: Uuid) -> Option<String> {
    let (_, key) = keys.current()?;
    Some(format!(
        "X-Kutup-Forwarded: {}-{}\r\n",
        forwarding.simple(),
        marker_mac(key, forwarding)
    ))
}

/// Claims one message of the day's budgets: the forwarding's and its
/// account's. `false` (and the forwarding's notice set) when either is
/// spent; it goes on the next day.
async fn claim_budget(
    state: &AppState,
    forwarding: Uuid,
    account: Uuid,
) -> Result<bool, sqlx::Error> {
    let mut tx = state.pool.begin().await?;
    // Each account's forwards are counted one at a time.
    sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR UPDATE")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    let claimed = sqlx::query(
        "UPDATE mail_forwardings SET
                sent_today = CASE WHEN day = current_date THEN sent_today + 1 ELSE 1 END,
                bounces_today = CASE WHEN day = current_date THEN bounces_today ELSE 0 END,
                invites_today = CASE WHEN day = current_date THEN invites_today ELSE 0 END,
                notice = CASE WHEN day = current_date THEN notice ELSE NULL END,
                day = current_date
          WHERE id = $1 AND (day <> current_date OR sent_today < $2)",
    )
    .bind(forwarding)
    .bind(limit(crate::ratelimit::Limit::ForwardingOutside, None))
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    let account_allows = claimed && charge(&mut tx, account, Charge::Forward).await?;
    if !claimed || !account_allows {
        drop(tx);
        sqlx::query("UPDATE mail_forwardings SET notice = 'budget' WHERE id = $1")
            .bind(forwarding)
            .execute(&state.pool)
            .await?;
        return Ok(false);
    }
    tx.commit().await?;
    Ok(true)
}

/// Re-sends a message to an outside forwardee through Stalwart: unchanged
/// but for our marker header on top, from our return path. `false` when it
/// can't go: the server never read it (end-to-end mail), it arrived
/// PGP-encrypted, the budget is spent, or submission failed.
async fn forward_outside(
    state: &AppState,
    forwarding: Uuid,
    account: Uuid,
    forwardee_email: &str,
    readable: &Readable,
    plaintext: Option<&Vec<u8>>,
) -> anyhow::Result<bool> {
    let keys = &state.config.mail_forwarding_keys;
    let (Some(plaintext), false) = (plaintext, readable.pgp_encrypted) else {
        return Ok(false);
    };
    let (Some(marker), Some(from)) = (
        marker(keys, forwarding),
        return_path(keys, &state.config.chat_server_name, forwarding),
    ) else {
        return Ok(false);
    };
    // Mail's own rules first: outside sending allowed for the account, and
    // its sending not paused.
    if outside_refusal(state, account).await?.is_some() {
        return Ok(false);
    }
    if !claim_budget(state, forwarding, account).await? {
        return Ok(false);
    }
    let message = [marker.as_bytes(), plaintext.as_slice()].concat();
    let submitted = super::submit::submit(
        &state.config.mail_submission_addr,
        &format!("kutup@{}", state.config.chat_server_name),
        &state.config.mail_inbound_token,
        super::submit::Envelope {
            from: &from,
            recipients: &[forwardee_email.to_owned()],
            message: &message,
        },
    )
    .await;
    if let Err(error) = &submitted {
        tracing::warn!(%forwarding, error = %error, "mail: an outside forward was not submitted");
    }
    Ok(submitted.is_ok())
}

/// Forwarder and forwardee fingerprints, the forwardee key, the sealed k and
/// its server key's id.
type SealedRow = (String, String, Vec<u8>, Vec<u8>, i16);

/// A forwarding's forwardee key and opened proxy factors. `None` (and the
/// forwarding made Outdated) when a factor no longer opens: its server key
/// is gone from the configuration.
async fn instances(
    state: &AppState,
    forwarding: Uuid,
) -> anyhow::Result<Option<(Vec<u8>, Vec<ProxyInstance>)>> {
    let rows: Vec<SealedRow> = sqlx::query_as(
        "SELECT forwarder_fingerprint, forwardee_fingerprint, forwardee_public_key,
                proxy_parameter_sealed, secret_version
           FROM mail_forwarding_keys WHERE forwarding_id = $1",
    )
    .bind(forwarding)
    .fetch_all(&state.pool)
    .await?;
    let mut public_key = None;
    let mut opened = Vec::with_capacity(rows.len());
    for (forwarder, forwardee, key, sealed, version) in rows {
        let fingerprint =
            |value: &str| -> Option<[u8; 20]> { hex::decode(value).ok()?.try_into().ok() };
        let instance = match (fingerprint(&forwarder), fingerprint(&forwardee)) {
            (Some(forwarder), Some(forwardee)) => open(
                &state.config.mail_forwarding_keys,
                version as u16,
                forwarding,
                forwarder,
                forwardee,
                &sealed,
            ),
            _ => None,
        };
        let Some(instance) = instance else {
            tracing::warn!(%forwarding, "mail: a forwarding's sealed factor no longer opens; outdated");
            let mut tx = state.pool.begin().await?;
            sqlx::query("DELETE FROM mail_forwarding_keys WHERE forwarding_id = $1")
                .bind(forwarding)
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "UPDATE mail_forwardings SET state = 'outdated', updated_at = now() WHERE id = $1",
            )
            .bind(forwarding)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(None);
        };
        public_key = Some(key);
        opened.push(instance);
    }
    Ok(public_key.map(|key| (key, opened)))
}

/// Stores a forwarded copy in the forwardee's mailbox, charged to them and
/// through their filters, marked as forwarded. `false` when it couldn't be
/// stored (their mailbox is full, or they block the sender).
async fn deliver(
    state: &AppState,
    forwardee_user: Uuid,
    forwardee_address: Uuid,
    forwarder_address: &str,
    forwarded: Vec<u8>,
    readable: &Readable,
) -> anyhow::Result<bool> {
    let id = Uuid::new_v4();
    let key = super::object_key(forwardee_user, id);
    let size = i64::try_from(forwarded.len())?;
    let version = state
        .storage
        .put_object_versioned(&key, ByteStream::from(forwarded), size)
        .await?;
    let stored: anyhow::Result<bool> = async {
        let mut tx = state.pool.begin().await?;
        let pool = crate::storage_pool::lock(&mut tx, forwardee_user, Default::default()).await?;
        if !pool.fits(size, 0) {
            return Ok(false);
        }
        let stored = super::insert_message(
            &mut tx,
            super::NewMessage {
                id,
                user_id: Some(forwardee_user),
                address_id: forwardee_address,
                thread_id: None,
                direction: "inbound",
                folder: "inbox",
                protection: "end_to_end",
                seen: false,
                object_key: &key,
                object_version: &version,
                size,
                readable,
                bcc: &[],
                external_recipients: 0,
                group_id: None,
                key_packet: None,
                sent_by: None,
                forwarded_from: Some(forwarder_address),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(stored)
    }
    .await;
    if !matches!(stored, Ok(true)) {
        if let Err(error) = state.storage.delete_stored(&key, &version).await {
            tracing::warn!(error = %error, "mail: unrecorded forwarded copy left for the sweep");
        }
    }
    stored
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn keys(entries: &str) -> OpaqueSetupKeys {
        OpaqueSetupKeys::parse(entries).unwrap()
    }

    const ONE: &str = "1:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const TWO: &str = "2:AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

    /// A rotated configuration seals with the new key and still opens what
    /// the old one sealed; with the old key gone nothing opens, and nothing
    /// panics.
    #[test]
    fn sealed_proxy_parameters_follow_the_configured_keys() {
        let forwarding = Uuid::new_v4();
        let instance = ProxyInstance {
            forwarder_fingerprint: [1u8; 20],
            forwardee_fingerprint: [2u8; 20],
            proxy_parameter: Zeroizing::new([7u8; 32]),
        };
        let (id, sealed) = seal(&keys(ONE), forwarding, &instance).unwrap();
        assert_eq!(id, 1);
        let both = keys(&format!("{ONE},{TWO}"));
        let opened = open(&both, id, forwarding, [1u8; 20], [2u8; 20], &sealed).unwrap();
        assert_eq!(*opened.proxy_parameter, [7u8; 32]);
        assert_eq!(seal(&both, forwarding, &instance).unwrap().0, 2);
        assert!(open(&keys(TWO), id, forwarding, [1u8; 20], [2u8; 20], &sealed).is_none());
        assert!(seal(&OpaqueSetupKeys::default(), forwarding, &instance).is_none());
    }

    /// A return path names its forwarding under the configured keys and
    /// for a while only; anything else isn't one.
    #[test]
    fn return_paths_check_their_hmac_and_age() {
        let forwarding = Uuid::new_v4();
        let path = return_path(&keys(ONE), "kutup.test", forwarding).unwrap();
        let local = path.split_once('@').unwrap().0;
        assert!(local.len() <= 64);
        assert_eq!(bounce_forwarding(&keys(ONE), local), Some(forwarding));
        assert_eq!(
            bounce_forwarding(&keys(&format!("{ONE},{TWO}")), local),
            Some(forwarding)
        );
        assert_eq!(bounce_forwarding(&keys(TWO), local), None, "another key");
        assert_eq!(
            bounce_forwarding(&keys(ONE), &local.to_uppercase()),
            Some(forwarding)
        );
        let other = local.replace(
            &forwarding.simple().to_string(),
            &Uuid::new_v4().simple().to_string(),
        );
        assert_eq!(
            bounce_forwarding(&keys(ONE), &other),
            None,
            "another forwarding"
        );
        let day = today();
        let old = format!(
            "fwd-{}-{}-{}",
            forwarding.simple(),
            day - RETURN_PATH_DAYS - 1,
            return_path_mac(&[1u8; 32], forwarding, day - RETURN_PATH_DAYS - 1)
        );
        assert_eq!(bounce_forwarding(&keys(ONE), &old), None, "too old");
        assert_eq!(bounce_forwarding(&keys(ONE), "alice"), None);
        assert_eq!(bounce_forwarding(&keys(ONE), "fwd-x-1-y"), None);
    }

    /// Only plain mailboxes: nothing that could carry an SMTP command or a
    /// header line.
    #[test]
    fn outside_addresses_are_plain_mailboxes() {
        assert_eq!(
            outside_address(" Bob.Smith+fwd@Outside.Test "),
            Some("bob.smith+fwd@outside.test".into())
        );
        for bad in [
            "bob@outside.test>\r\nRCPT TO:<eve@evil.test",
            "bob@outside.test\r\nBcc: eve@evil.test",
            "bob@outside.test\n",
            "bob\0@outside.test",
            "bob smith@outside.test",
            "<bob@outside.test>",
            "bob@outside.test>",
            "bob@@outside.test",
            "bob@a@outside.test",
            "\"bob\"@outside.test",
            ".bob@outside.test",
            "bob..smith@outside.test",
            "bob@outside",
            "bob@-outside.test",
            "bob@outside-.test",
            "bob@outside..test",
            "bob@[127.0.0.1]",
            "bob@1.2.3.4",
            "böb@outside.test",
            "@outside.test",
            "bob@",
        ] {
            assert_eq!(outside_address(bad), None, "{bad:?}");
        }
        assert_eq!(
            outside_address(&format!("{}@outside.test", "a".repeat(65))),
            None
        );
    }

    /// Only our own marker stops a forward, and only a real header line
    /// counts as one; hops beyond the cap do too.
    #[test]
    fn our_marker_and_too_many_hops_stop_a_forward() {
        let one = keys(ONE);
        let forwarding = Uuid::new_v4();
        let header = marker(&one, forwarding).unwrap();
        let mail = |headers: &str| format!("{headers}From: a@b.test\r\n\r\nbody\r\n");
        assert!(may_forward(&one, mail("").as_bytes()));
        assert!(!may_forward(&one, mail(&header).as_bytes()));
        assert!(!may_forward(
            &keys(&format!("{ONE},{TWO}")),
            mail(&header).as_bytes()
        ));
        // Forged, for another forwarding, or under a key we don't hold.
        assert!(may_forward(
            &one,
            mail("X-Kutup-Forwarded: 0123456789abcdef\r\n").as_bytes()
        ));
        let other = header.replace(
            &forwarding.simple().to_string(),
            &Uuid::new_v4().simple().to_string(),
        );
        assert!(may_forward(&one, mail(&other).as_bytes()));
        assert!(may_forward(&keys(TWO), mail(&header).as_bytes()));
        // A folded line isn't a header of its own.
        let folded = format!("Subject: hi\r\n {}", header);
        assert!(may_forward(&one, mail(&folded).as_bytes()));
        // In the body, it is nothing.
        assert!(may_forward(
            &one,
            format!("From: a@b.test\r\n\r\n{header}").as_bytes()
        ));
        let hops = |n: usize| {
            (0..n)
                .map(|i| format!("Received: from h{i}\r\n"))
                .collect::<String>()
        };
        assert!(may_forward(&one, mail(&hops(MAX_HOPS)).as_bytes()));
        assert!(!may_forward(&one, mail(&hops(MAX_HOPS + 1)).as_bytes()));
        let folded_hops = (0..MAX_HOPS + 5)
            .map(|_| " Received: folded\r\n")
            .collect::<String>();
        assert!(may_forward(
            &one,
            mail(&format!("X-Long: a\r\n{folded_hops}")).as_bytes()
        ));
    }
}
