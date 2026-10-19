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
    Ok(())
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
}

/// Whether arriving mail may be forwarded: not when it carries our
/// forwarding marker, or has come through more than [`MAX_HOPS`] hops.
pub fn may_forward(raw: &[u8]) -> bool {
    let headers = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .or_else(|| raw.windows(2).position(|window| window == b"\n\n"))
        .map_or(raw, |end| &raw[..end]);
    let text = String::from_utf8_lossy(headers);
    let mut received = 0usize;
    for line in text.lines() {
        let name = line.split_once(':').map(|(name, _)| name.trim());
        match name {
            Some(name) if name.eq_ignore_ascii_case("x-kutup-forwarded") => return false,
            Some(name) if name.eq_ignore_ascii_case("received") => received += 1,
            _ => {}
        }
    }
    received <= MAX_HOPS
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

type Forwarding = (Uuid, String, serde_json::Value, Uuid, Uuid, String);

async fn forward_copy(state: &AppState, arrived: Arrived) -> anyhow::Result<()> {
    if !arrived.may_forward {
        return Ok(());
    }
    let forwardings: Vec<Forwarding> = sqlx::query_as(
        "SELECT f.id, f.match, f.conditions, b.id, b.user_id, a.address
           FROM mail_forwardings f
           JOIN mail_addresses a ON a.id = f.forwarder_address_id
           JOIN mail_addresses b ON b.id = f.forwardee_address_id AND b.state = 'active'
           JOIN users u ON u.id = b.user_id AND u.is_active
          WHERE f.forwarder_address_id = $1 AND f.kind = 'end_to_end' AND f.state = 'active'",
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
    for (id, rule, conditions, forwardee_address, forwardee_user, forwarder_address) in forwardings
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
            sqlx::query("UPDATE mail_forwardings SET skipped = skipped + 1 WHERE id = $1")
                .bind(id)
                .execute(&state.pool)
                .await?;
        }
    }
    Ok(())
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
}
