//! Collaboration devices of people on other servers
//! (docs/plans/device-registration.md, "Remote devices").
//!
//! Frames under a share's capability can only come from that share's
//! recipient. A bridge (the recipient's server) announces each of their
//! devices with the account's signed statement (`DeviceRegistrationV1`); home
//! keeps the device only when the statement verifies under an authority whose
//! hash is the incarnation the share names, for the bridge's own domain, and
//! is less than 30 days old (a lease: the client renews it every two weeks,
//! so a revocation a bridge withholds matters for at most that long). A
//! bridge also forwards its users' signed revocations; a revoked key is never
//! accepted again. Rows are bound to the incarnation, not the name.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use kutup_crypto::device_registration::{self, DeviceStatement, PURPOSE_COLLAB_FRAMES};
use kutup_crypto::envelope::{self, Frame};
use kutup_crypto::primitives::{hash, Suite};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::{AppError, AppResult};

/// How long an announced device's statement holds.
pub const LEASE_MS: i64 = 30 * 24 * 3600 * 1000;
/// How far in the future a statement may be dated (by home's clock).
const MAX_FUTURE_MS: i64 = 24 * 3600 * 1000;
/// Devices and revocations in one announce, together.
pub const MAX_PER_ANNOUNCE: usize = 50;
/// How long a device past its lease is kept before it is swept.
const SWEEP_GRACE_MS: i64 = 7 * 24 * 3600 * 1000;

pub fn now_ms() -> i64 {
    (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64
}

/// One device as a bridge announces it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnnouncedDevice {
    /// The bridge's id for the device (what its frames name).
    pub device_id: i64,
    /// The bridge's id for the account, as the statement signs it.
    pub user_id: String,
    pub authority_public_key: String,
    pub public_signing: String,
    pub challenge: String,
    pub issued_at_ms: i64,
    pub signature: String,
}

/// One revocation as a bridge forwards it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnnouncedRevocation {
    /// The bridge's own order of its revocations (never a clock): home says
    /// back the highest it has processed.
    pub seq: i64,
    pub authority_public_key: String,
    pub public_signing: String,
    /// As the account signed it: data only.
    pub revoked_at_ms: i64,
    pub signature: String,
}

/// Why an announced device was not kept.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Refused {
    pub device_id: i64,
    /// `notRecipient`, `doesNotVerify`, `expired`, `revoked`, `keyInUse`,
    /// `tooManyDevices`.
    pub code: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnnounceOutcome {
    pub accepted: Vec<i64>,
    pub refused: Vec<Refused>,
    /// The highest of the bridge's revocation sequence numbers home has
    /// processed for this account: the bridge sends what comes after it.
    pub revocations_through: i64,
}

fn key32(value: &str) -> Option<[u8; 32]> {
    STANDARD
        .decode(value)
        .ok()
        .filter(|raw| STANDARD.encode(raw) == value)
        .and_then(|raw| raw.try_into().ok())
}

fn key_hash(key: &[u8; 32]) -> Vec<u8> {
    hash(Suite::V1, key).to_vec()
}

/// Takes in an announce for the share's recipient (`incarnation`, and the
/// account name for display) from `domain`.
pub async fn take_announce(
    pool: &sqlx::PgPool,
    domain: &str,
    account: &str,
    incarnation: &str,
    devices: &[AnnouncedDevice],
    revocations: &[AnnouncedRevocation],
) -> AppResult<AnnounceOutcome> {
    if devices.len() + revocations.len() > MAX_PER_ANNOUNCE {
        return Err(AppError::bad_request(format!(
            "at most {MAX_PER_ANNOUNCE} devices and revocations in one announce"
        )));
    }
    let now = now_ms();
    let mut tx = pool.begin().await?;
    // One announce at a time per account here: the cap counts truly.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("remote-devices:{domain}:{incarnation}"))
        .execute(&mut *tx)
        .await?;

    // Revocations first: a device revoked in the same announce stays out.
    // Each is processed for good (kept, or refused as one that can never
    // verify), so the mark passes it either way.
    let mut through_seq: i64 = 0;
    for revocation in revocations {
        if revocation.seq <= 0 {
            return Err(AppError::bad_request("a revocation's seq is positive"));
        }
        through_seq = through_seq.max(revocation.seq);
        let (Some(authority), Some(key)) = (
            key32(&revocation.authority_public_key),
            key32(&revocation.public_signing),
        ) else {
            continue;
        };
        if kutup_crypto::identity::incarnation_id_from_authority_public(&authority) != incarnation
            || device_registration::verify_revocation(
                &authority,
                domain,
                &key,
                revocation.revoked_at_ms,
                &revocation.signature,
            )
            .is_err()
        {
            continue;
        }
        sqlx::query(
            "INSERT INTO remote_revoked_device_keys (key_hash, domain, incarnation_id, revoked_at_ms)
             VALUES ($1, $2, $3, $4) ON CONFLICT (domain, key_hash) DO NOTHING",
        )
        .bind(key_hash(&key))
        .bind(domain)
        .bind(incarnation)
        .bind(revocation.revoked_at_ms)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE remote_collab_devices SET active = false, revoked_at_ms = $3,
                                              revocation_signature = $4
             WHERE domain = $1 AND public_signing = $2 AND revoked_at_ms IS NULL",
        )
        .bind(domain)
        .bind(key.to_vec())
        .bind(revocation.revoked_at_ms)
        .bind(&revocation.signature)
        .execute(&mut *tx)
        .await?;
    }

    let mut outcome = AnnounceOutcome::default();
    for device in devices {
        let refuse = |code: &str| Refused {
            device_id: device.device_id,
            code: code.to_owned(),
        };
        let (Some(authority), Some(key), Some(challenge)) = (
            key32(&device.authority_public_key),
            key32(&device.public_signing),
            key32(&device.challenge),
        ) else {
            outcome.refused.push(refuse("doesNotVerify"));
            continue;
        };
        if kutup_crypto::identity::incarnation_id_from_authority_public(&authority) != incarnation {
            outcome.refused.push(refuse("notRecipient"));
            continue;
        }
        let statement = DeviceStatement {
            server: domain,
            user_id: &device.user_id,
            device_public: &key,
            purpose: PURPOSE_COLLAB_FRAMES,
            challenge: &challenge,
            issued_at_ms: device.issued_at_ms,
        };
        if device_registration::verify(&authority, &statement, &device.signature).is_err() {
            outcome.refused.push(refuse("doesNotVerify"));
            continue;
        }
        // Age by this server's clock; a statement dated ahead would stretch
        // the lease.
        if device.issued_at_ms > now + MAX_FUTURE_MS || device.issued_at_ms <= now - LEASE_MS {
            outcome.refused.push(refuse("expired"));
            continue;
        }
        // Revoked by that server's account (one server's revocation never
        // blocks another's device).
        let revoked: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM remote_revoked_device_keys
                            WHERE domain = $1 AND key_hash = $2)",
        )
        .bind(domain)
        .bind(key_hash(&key))
        .fetch_one(&mut *tx)
        .await?;
        if revoked {
            outcome.refused.push(refuse("revoked"));
            continue;
        }
        let existing: Option<(Vec<u8>, String)> = sqlx::query_as(
            "SELECT public_signing, incarnation_id FROM remote_collab_devices
             WHERE domain = $1 AND device_id = $2",
        )
        .bind(domain)
        .bind(device.device_id)
        .fetch_optional(&mut *tx)
        .await?;
        match existing {
            Some((stored_key, stored_incarnation))
                if stored_key == key && stored_incarnation.trim() == incarnation =>
            {
                // A renewal: keep the newest statement.
                sqlx::query(
                    "UPDATE remote_collab_devices
                     SET registration_challenge = $3, registration_issued_at_ms = $4,
                         registration_signature = $5, account = $6
                     WHERE domain = $1 AND device_id = $2 AND registration_issued_at_ms < $4",
                )
                .bind(domain)
                .bind(device.device_id)
                .bind(challenge.to_vec())
                .bind(device.issued_at_ms)
                .bind(&device.signature)
                .bind(account)
                .execute(&mut *tx)
                .await?;
                outcome.accepted.push(device.device_id);
            }
            Some(_) => outcome.refused.push(refuse("keyInUse")),
            None => {
                // In use, as at home: active and within the lease (devices of
                // ended sign-ins stop renewing and drop out by themselves).
                let active: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM remote_collab_devices
                     WHERE domain = $1 AND incarnation_id = $2 AND active
                       AND registration_issued_at_ms > $3",
                )
                .bind(domain)
                .bind(incarnation)
                .bind(now - LEASE_MS)
                .fetch_one(&mut *tx)
                .await?;
                if active >= crate::handlers::devices::MAX_ACTIVE_DEVICES {
                    outcome.refused.push(refuse("tooManyDevices"));
                    continue;
                }
                let inserted = sqlx::query(
                    "INSERT INTO remote_collab_devices
                        (domain, device_id, incarnation_id, account, user_id, authority_public_key,
                         public_signing, registration_challenge, registration_issued_at_ms,
                         registration_signature)
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
                     ON CONFLICT (domain, public_signing) DO NOTHING",
                )
                .bind(domain)
                .bind(device.device_id)
                .bind(incarnation)
                .bind(account)
                .bind(&device.user_id)
                .bind(&device.authority_public_key)
                .bind(key.to_vec())
                .bind(challenge.to_vec())
                .bind(device.issued_at_ms)
                .bind(&device.signature)
                .execute(&mut *tx)
                .await?;
                if inserted.rows_affected() == 1 {
                    outcome.accepted.push(device.device_id);
                } else {
                    outcome.refused.push(refuse("keyInUse"));
                }
            }
        }
    }
    outcome.revocations_through = sqlx::query_scalar(
        "INSERT INTO remote_revocation_marks (domain, incarnation_id, through_seq)
         VALUES ($1, $2, $3)
         ON CONFLICT (domain, incarnation_id) DO UPDATE
             SET through_seq = GREATEST(remote_revocation_marks.through_seq, EXCLUDED.through_seq)
         RETURNING through_seq",
    )
    .bind(domain)
    .bind(incarnation)
    .bind(through_seq)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(outcome)
}

/// What a frame from a bridge is, by its sender device.
#[derive(Debug, PartialEq, Eq)]
pub enum RemoteSender {
    /// An announced, fresh device of the share's recipient, whose signature
    /// the frame carries.
    Trusted,
    /// Not announced here: the bridge announces it and sends again.
    Unknown,
    /// Announced, but its statement is more than 30 days old: its client
    /// renews it (only it can: it holds the account's keys).
    Expired,
    /// Revoked, another account's, or a signature that does not verify.
    Refused,
}

/// Checks the device behind a frame `domain` sent under a share whose
/// recipient is `incarnation`.
pub async fn check_sender(
    pool: &sqlx::PgPool,
    domain: &str,
    incarnation: &str,
    frame: &Frame,
    raw: &[u8],
) -> AppResult<RemoteSender> {
    let row: Option<(Vec<u8>, String, bool, i64)> = sqlx::query_as(
        "SELECT public_signing, incarnation_id, active, registration_issued_at_ms
         FROM remote_collab_devices WHERE domain = $1 AND device_id = $2",
    )
    .bind(domain)
    .bind(frame.sender_device_id as i64)
    .fetch_optional(pool)
    .await?;
    let Some((key, device_incarnation, active, issued_at_ms)) = row else {
        return Ok(RemoteSender::Unknown);
    };
    if !active || device_incarnation.trim() != incarnation {
        return Ok(RemoteSender::Refused);
    }
    if envelope::verify(raw, &key).is_err() {
        return Ok(RemoteSender::Refused);
    }
    if issued_at_ms <= now_ms() - LEASE_MS {
        return Ok(RemoteSender::Expired);
    }
    Ok(RemoteSender::Trusted)
}

/// Daily: device rows of an account no share here names any more go, with
/// their revoked ones (the key's tombstone stays, so it never comes back).
pub async fn sweep(pool: &sqlx::PgPool) -> sqlx::Result<u64> {
    let gone = sqlx::query(
        "DELETE FROM remote_collab_devices d
         WHERE NOT EXISTS (
             SELECT 1 FROM federated_outgoing_shares s
             WHERE s.recipient_domain = d.domain AND s.recipient_incarnation_id = d.incarnation_id)
           AND NOT EXISTS (
             SELECT 1 FROM federated_outgoing_file_shares s
             WHERE s.recipient_domain = d.domain AND s.recipient_incarnation_id = d.incarnation_id)",
    )
    .execute(pool)
    .await?;
    // Past the lease, and a week more (time for a renewal under way):
    // devices of ended sign-ins never renew. A revoked key stays refused
    // through its tombstone.
    let lapsed =
        sqlx::query("DELETE FROM remote_collab_devices WHERE registration_issued_at_ms < $1")
            .bind(now_ms() - LEASE_MS - SWEEP_GRACE_MS)
            .execute(pool)
            .await?;
    Ok(gone.rows_affected() + lapsed.rows_affected())
}

// --- the bridge's side -------------------------------------------------------

/// What a bridge tells home in one announce: `devices` of the account (the
/// trusted ones among `device_ids`) and its revocations home has not stored
/// yet, oldest first, all within [`MAX_PER_ANNOUNCE`]. `more` when
/// revocations are left for another announce.
pub struct Announce {
    pub devices: Vec<AnnouncedDevice>,
    pub revocations: Vec<AnnouncedRevocation>,
    pub more: bool,
}

pub async fn announce_for(
    pool: &sqlx::PgPool,
    user_id: uuid::Uuid,
    home_domain: &str,
    device_ids: &[i64],
) -> sqlx::Result<Announce> {
    let authority: String =
        sqlx::query_scalar("SELECT account_authority_public_key FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(pool)
            .await?;
    // id, key, challenge, issued at, signature.
    type DeviceRow = (i64, Vec<u8>, Vec<u8>, i64, String);
    let rows: Vec<DeviceRow> = sqlx::query_as(&format!(
        "SELECT d.id, d.public_signing, d.registration_challenge, d.registration_issued_at_ms,
                d.registration_signature
         FROM user_devices d JOIN users u ON u.id = d.user_id
         WHERE d.user_id = $1 AND d.id = ANY($2) AND {}
         ORDER BY d.id LIMIT $3",
        crate::handlers::devices::DEVICE_LIVE
    ))
    .bind(user_id)
    .bind(device_ids)
    .bind(MAX_PER_ANNOUNCE as i64)
    .fetch_all(pool)
    .await?;
    let devices: Vec<AnnouncedDevice> = rows
        .into_iter()
        .map(
            |(id, key, challenge, issued_at_ms, signature)| AnnouncedDevice {
                device_id: id,
                user_id: user_id.to_string(),
                authority_public_key: authority.clone(),
                public_signing: STANDARD.encode(key),
                challenge: STANDARD.encode(challenge),
                issued_at_ms,
                signature,
            },
        )
        .collect();
    let through: i64 = sqlx::query_scalar(
        "SELECT COALESCE((SELECT through_seq FROM collab_revocation_marks
                          WHERE home_domain = $1 AND user_id = $2), 0)",
    )
    .bind(home_domain)
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    let room = (MAX_PER_ANNOUNCE - devices.len()) as i64;
    let revoked: Vec<(i64, Vec<u8>, i64, String)> = sqlx::query_as(
        // This incarnation's only (home takes no others), after the mark, in
        // this server's order: never the signed times, which clients chose.
        "SELECT d.revocation_seq, d.public_signing, d.revoked_at_ms, d.revocation_signature
         FROM user_devices d JOIN users u ON u.id = d.user_id
         WHERE d.user_id = $1 AND d.revocation_seq > $2
           AND d.incarnation_id = u.account_incarnation_id
         ORDER BY d.revocation_seq LIMIT $3",
    )
    .bind(user_id)
    .bind(through)
    .bind(room + 1)
    .fetch_all(pool)
    .await?;
    let more = revoked.len() as i64 > room;
    let revocations = revoked
        .into_iter()
        .take(room as usize)
        .map(|(seq, key, revoked_at_ms, signature)| AnnouncedRevocation {
            seq,
            authority_public_key: authority.clone(),
            public_signing: STANDARD.encode(key),
            revoked_at_ms,
            signature,
        })
        .collect();
    Ok(Announce {
        devices,
        revocations,
        more,
    })
}

/// Home has processed the account's revocations through `through_seq` (its
/// answer, kept as given: lower after a restore of home, which then gets
/// them again).
pub async fn advance_mark(
    pool: &sqlx::PgPool,
    user_id: uuid::Uuid,
    home_domain: &str,
    through_seq: i64,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO collab_revocation_marks (home_domain, user_id, through_seq)
         VALUES ($1, $2, $3)
         ON CONFLICT (home_domain, user_id) DO UPDATE SET through_seq = EXCLUDED.through_seq",
    )
    .bind(home_domain)
    .bind(user_id)
    .bind(through_seq)
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kutup_crypto::identity::AccountIdentityKeysV1;

    const BRIDGE: &str = "bridge.test";

    async fn pool() -> Option<sqlx::PgPool> {
        let url = std::env::var("KUTUP_LIVE_DATABASE_URL").ok()?;
        Some(
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(2)
                .connect(&url)
                .await
                .unwrap(),
        )
    }

    fn identity(seed: u8) -> AccountIdentityKeysV1 {
        AccountIdentityKeysV1::derive(&[seed; 32]).unwrap()
    }

    /// A device of `who` (a remote account), announced as its bridge would.
    fn device(
        who: &AccountIdentityKeysV1,
        id: i64,
        key_seed: u8,
        issued_at_ms: i64,
    ) -> AnnouncedDevice {
        let key = kutup_crypto::primitives::SigningKey::from_seed(
            kutup_crypto::primitives::Suite::V1,
            &[key_seed; 32],
        )
        .verifying_key()
        .to_array::<32>();
        let challenge = [id as u8; 32];
        let user = "33333333-3333-4333-8333-333333333333";
        let statement = DeviceStatement {
            server: BRIDGE,
            user_id: user,
            device_public: &key,
            purpose: PURPOSE_COLLAB_FRAMES,
            challenge: &challenge,
            issued_at_ms,
        };
        AnnouncedDevice {
            device_id: id,
            user_id: user.into(),
            authority_public_key: STANDARD.encode(who.authority_public_key()),
            public_signing: STANDARD.encode(key),
            challenge: STANDARD.encode(challenge),
            issued_at_ms,
            signature: device_registration::sign(who, &statement).unwrap(),
        }
    }

    fn revocation(who: &AccountIdentityKeysV1, key_seed: u8, at: i64) -> AnnouncedRevocation {
        let key = kutup_crypto::primitives::SigningKey::from_seed(
            kutup_crypto::primitives::Suite::V1,
            &[key_seed; 32],
        )
        .verifying_key()
        .to_array::<32>();
        // The bridge's order: one sequence for the tests, as for a server.
        static SEQ: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(1);
        AnnouncedRevocation {
            seq: SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            authority_public_key: STANDARD.encode(who.authority_public_key()),
            public_signing: STANDARD.encode(key),
            revoked_at_ms: at,
            signature: device_registration::sign_revocation(who, BRIDGE, &key, at).unwrap(),
        }
    }

    async fn clean(pool: &sqlx::PgPool, incarnation: &str) {
        sqlx::query("DELETE FROM remote_collab_devices WHERE domain = $1 AND incarnation_id = $2")
            .bind(BRIDGE)
            .bind(incarnation)
            .execute(pool)
            .await
            .unwrap();
        for table in ["remote_revoked_device_keys", "remote_revocation_marks"] {
            sqlx::query(&format!(
                "DELETE FROM {table} WHERE domain = $1 AND incarnation_id = $2"
            ))
            .bind(BRIDGE)
            .bind(incarnation)
            .execute(pool)
            .await
            .unwrap();
        }
    }

    /// (a) unannounced and (b) wrong-account devices, (c) revocation for
    /// good, (d) the cap, and the lease (expired, future-dated).
    #[tokio::test]
    async fn live_remote_devices_are_the_recipients_own_and_fresh() {
        let Some(pool) = pool().await else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let (alice, mallory) = (identity(51), identity(52));
        let incarnation = alice.incarnation_id();
        clean(&pool, &incarnation).await;
        let now = now_ms();
        let account = "alice@bridge.test";

        // A device of the recipient: kept; one signed by another account, or
        // for another server, is not.
        let mut foreign = device(&mallory, 2, 2, now);
        let mut elsewhere = device(&alice, 3, 3, now);
        elsewhere.signature = {
            let key = kutup_crypto::primitives::SigningKey::from_seed(
                kutup_crypto::primitives::Suite::V1,
                &[3; 32],
            )
            .verifying_key()
            .to_array::<32>();
            let challenge = [3u8; 32];
            device_registration::sign(
                &alice,
                &DeviceStatement {
                    server: "other.test",
                    user_id: &elsewhere.user_id,
                    device_public: &key,
                    purpose: PURPOSE_COLLAB_FRAMES,
                    challenge: &challenge,
                    issued_at_ms: now,
                },
            )
            .unwrap()
        };
        foreign.authority_public_key = STANDARD.encode(mallory.authority_public_key());
        let outcome = take_announce(
            &pool,
            BRIDGE,
            account,
            &incarnation,
            &[device(&alice, 1, 1, now), foreign, elsewhere],
            &[],
        )
        .await
        .unwrap();
        assert_eq!(outcome.accepted, vec![1]);
        let codes: Vec<_> = outcome.refused.iter().map(|r| r.code.as_str()).collect();
        assert_eq!(codes, vec!["notRecipient", "doesNotVerify"]);

        // The lease: a statement older than 30 days, or dated ahead, is refused.
        let outcome = take_announce(
            &pool,
            BRIDGE,
            account,
            &incarnation,
            &[
                device(&alice, 4, 4, now - LEASE_MS - 1),
                device(&alice, 5, 5, now + 2 * MAX_FUTURE_MS),
            ],
            &[],
        )
        .await
        .unwrap();
        assert!(
            outcome.refused.iter().all(|r| r.code == "expired"),
            "{outcome:?}"
        );

        // A frame from an unannounced device is unknown; from the announced
        // one, trusted; after its lease, expired.
        let frame_from = |sender: i64, seed: u8| {
            let context = kutup_crypto::envelope::CollabFrameContextV1::new(
                kutup_crypto::envelope::kind::YJS_UPDATE,
                1,
                1,
                "44444444-4444-4444-8444-444444444444",
                sender as u64,
                1,
            )
            .unwrap();
            let packed = envelope::seal_unsigned(b"x", &[9u8; 32], context).unwrap();
            let signed = envelope::sign(&Frame::unpack(&packed).unwrap(), &[seed; 32]).unwrap();
            (Frame::unpack(&signed).unwrap(), signed)
        };
        let (frame, raw) = frame_from(1, 1);
        assert_eq!(
            check_sender(&pool, BRIDGE, &incarnation, &frame, &raw)
                .await
                .unwrap(),
            RemoteSender::Trusted
        );
        let (frame, raw) = frame_from(9, 9);
        assert_eq!(
            check_sender(&pool, BRIDGE, &incarnation, &frame, &raw)
                .await
                .unwrap(),
            RemoteSender::Unknown
        );
        // Signed by another key than the announced one: refused.
        let (frame, raw) = frame_from(1, 8);
        assert_eq!(
            check_sender(&pool, BRIDGE, &incarnation, &frame, &raw)
                .await
                .unwrap(),
            RemoteSender::Refused
        );
        // Under a share whose recipient is another account: refused.
        let (frame, raw) = frame_from(1, 1);
        assert_eq!(
            check_sender(&pool, BRIDGE, &mallory.incarnation_id(), &frame, &raw)
                .await
                .unwrap(),
            RemoteSender::Refused
        );
        sqlx::query("UPDATE remote_collab_devices SET registration_issued_at_ms = $3 WHERE domain = $1 AND device_id = $2")
            .bind(BRIDGE)
            .bind(1_i64)
            .bind(now - LEASE_MS - 1)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            check_sender(&pool, BRIDGE, &incarnation, &frame, &raw)
                .await
                .unwrap(),
            RemoteSender::Expired
        );
        // A renewal (a newer statement) makes it fresh again.
        let outcome = take_announce(
            &pool,
            BRIDGE,
            account,
            &incarnation,
            &[device(&alice, 1, 1, now)],
            &[],
        )
        .await
        .unwrap();
        assert_eq!(outcome.accepted, vec![1]);
        assert_eq!(
            check_sender(&pool, BRIDGE, &incarnation, &frame, &raw)
                .await
                .unwrap(),
            RemoteSender::Trusted
        );

        // A revocation by the account: refused from now on, and never back.
        let revoked = revocation(&alice, 1, now);
        let seq = revoked.seq;
        let outcome = take_announce(&pool, BRIDGE, account, &incarnation, &[], &[revoked])
            .await
            .unwrap();
        assert_eq!(outcome.revocations_through, seq, "home says how far it got");
        assert_eq!(
            check_sender(&pool, BRIDGE, &incarnation, &frame, &raw)
                .await
                .unwrap(),
            RemoteSender::Refused
        );
        let outcome = take_announce(
            &pool,
            BRIDGE,
            account,
            &incarnation,
            &[device(&alice, 1, 1, now + 1)],
            &[],
        )
        .await
        .unwrap();
        assert_eq!(outcome.refused[0].code, "revoked");
        // Another account cannot revoke this one's device.
        take_announce(
            &pool,
            BRIDGE,
            account,
            &incarnation,
            &[device(&alice, 6, 6, now)],
            &[revocation(&mallory, 6, now)],
        )
        .await
        .unwrap();
        let (frame, raw) = frame_from(6, 6);
        assert_eq!(
            check_sender(&pool, BRIDGE, &incarnation, &frame, &raw)
                .await
                .unwrap(),
            RemoteSender::Trusted
        );

        // The cap: at most 20 active devices for the account.
        let many: Vec<AnnouncedDevice> = (100..121)
            .map(|i| device(&alice, i, i as u8, now))
            .collect();
        let first = take_announce(
            &pool,
            BRIDGE,
            account,
            &incarnation,
            &many[..25.min(many.len())],
            &[],
        )
        .await
        .unwrap();
        assert!(
            first.refused.iter().any(|r| r.code == "tooManyDevices"),
            "{first:?}"
        );
        let active: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM remote_collab_devices WHERE domain = $1 AND incarnation_id = $2 AND active",
        )
        .bind(BRIDGE)
        .bind(&incarnation)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(active, crate::handlers::devices::MAX_ACTIVE_DEVICES);
        // At most 50 entries in one announce.
        let too_many: Vec<AnnouncedRevocation> = (0..51)
            .map(|i| revocation(&alice, 200u8.wrapping_add(i), now + i as i64))
            .collect();
        assert!(
            take_announce(&pool, BRIDGE, account, &incarnation, &[], &too_many)
                .await
                .is_err()
        );
        clean(&pool, &incarnation).await;
    }

    /// More than 50 revocations reach home over several announces, none
    /// skipped (the bridge's mark follows what home stored).
    #[tokio::test]
    async fn live_revocations_page_past_fifty() {
        let Some(pool) = pool().await else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let alice = identity(61);
        let incarnation = alice.incarnation_id();
        clean(&pool, &incarnation).await;
        // A local account (the bridge's side) with 65 revoked devices. Their
        // keys (130..195) are none the other test uses: revoked keys are
        // refused whoever announces them, and the tests run at once.
        let user_id = uuid::Uuid::new_v4();
        let username = format!("paging{}", &user_id.simple().to_string()[..12]);
        sqlx::query(
            "INSERT INTO users (id, username, master_key_envelope, recovery_key_envelope,
                drive_private_key_envelope, public_key, account_authority_public_key,
                account_authority_key_id, account_incarnation_id, drive_signing_public_key)
             VALUES ($1, $2, '', '', '', '', $3, $4, $5, '')",
        )
        .bind(user_id)
        .bind(&username)
        .bind(STANDARD.encode(alice.authority_public_key()))
        .bind(alice.authority_key_id())
        .bind(&incarnation)
        .execute(&pool)
        .await
        .unwrap();
        let now = now_ms();
        for i in 0..65_i64 {
            let key = kutup_crypto::primitives::SigningKey::from_seed(
                kutup_crypto::primitives::Suite::V1,
                &[130 + i as u8; 32],
            )
            .verifying_key()
            .to_array::<32>();
            // Clients' clocks: every third from a laptop two hours fast, the
            // rest from one that agrees, all in the same millisecond. The
            // fast ones come first: a mark by time would skip the rest.
            let at = if i % 3 == 0 {
                now + 2 * 3600 * 1000
            } else {
                now
            };
            let signature = device_registration::sign_revocation(&alice, BRIDGE, &key, at).unwrap();
            sqlx::query(
                "INSERT INTO user_devices (user_id, public_signing, incarnation_id, registration_challenge,
                    registration_issued_at_ms, registration_signature, is_active, revoked_at_ms,
                    revocation_signature, revocation_seq)
                 VALUES ($1, $2, $3, $4, $5, 'x', false, $6, $7,
                         nextval('user_devices_revocation_seq'))",
            )
            .bind(user_id)
            .bind(key.to_vec())
            .bind(&incarnation)
            .bind(vec![0u8; 32])
            .bind(now)
            .bind(at)
            .bind(&signature)
            .execute(&pool)
            .await
            .unwrap();
        }
        // The bridge pages; home (take_announce) stores; the mark follows.
        let mut announces = 0;
        loop {
            let announce = announce_for(&pool, user_id, BRIDGE, &[]).await.unwrap();
            assert!(announce.devices.len() + announce.revocations.len() <= MAX_PER_ANNOUNCE);
            let outcome = take_announce(
                &pool,
                BRIDGE,
                "x@bridge.test",
                &incarnation,
                &announce.devices,
                &announce.revocations,
            )
            .await
            .unwrap();
            advance_mark(&pool, user_id, BRIDGE, outcome.revocations_through)
                .await
                .unwrap();
            announces += 1;
            if !announce.more {
                break;
            }
            assert!(announces < 10, "paging does not end");
        }
        assert!(announces >= 2);
        let stored: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM remote_revoked_device_keys WHERE domain = $1 AND incarnation_id = $2",
        )
        .bind(BRIDGE)
        .bind(&incarnation)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(stored, 65, "every revocation reached home");
        // And nothing is sent again.
        let again = announce_for(&pool, user_id, BRIDGE, &[]).await.unwrap();
        assert!(again.revocations.is_empty() && !again.more);
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
        clean(&pool, &incarnation).await;
    }

    /// The cap counts devices in use (within the lease), and a revocation
    /// stays with the server whose account made it.
    #[tokio::test]
    async fn live_the_cap_counts_devices_in_use_and_revocations_stay_per_server() {
        let Some(pool) = pool().await else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let alice = identity(71);
        let incarnation = alice.incarnation_id();
        clean(&pool, &incarnation).await;
        let now = now_ms();
        // 20 devices whose statements lapsed (their sign-ins ended): not in
        // use, so a 21st registers.
        let lapsed: Vec<AnnouncedDevice> = (300..320)
            .map(|i| device(&alice, i, (i - 100) as u8, now))
            .collect();
        take_announce(&pool, BRIDGE, "a@bridge.test", &incarnation, &lapsed, &[])
            .await
            .unwrap();
        sqlx::query(
            "UPDATE remote_collab_devices SET registration_issued_at_ms = $3
             WHERE domain = $1 AND incarnation_id = $2",
        )
        .bind(BRIDGE)
        .bind(&incarnation)
        .bind(now - LEASE_MS - 1)
        .execute(&pool)
        .await
        .unwrap();
        let outcome = take_announce(
            &pool,
            BRIDGE,
            "a@bridge.test",
            &incarnation,
            &[device(&alice, 400, 240, now)],
            &[],
        )
        .await
        .unwrap();
        assert_eq!(outcome.accepted, vec![400], "{outcome:?}");

        // Another server "revoking" the same key under its own account
        // blocks nothing here.
        let mallory = identity(72);
        let key = kutup_crypto::primitives::SigningKey::from_seed(
            kutup_crypto::primitives::Suite::V1,
            &[241; 32],
        )
        .verifying_key()
        .to_array::<32>();
        let at = now;
        let forged = AnnouncedRevocation {
            seq: 1,
            authority_public_key: STANDARD.encode(mallory.authority_public_key()),
            public_signing: STANDARD.encode(key),
            revoked_at_ms: at,
            signature: device_registration::sign_revocation(&mallory, "other.test", &key, at)
                .unwrap(),
        };
        take_announce(
            &pool,
            "other.test",
            "m@other.test",
            &mallory.incarnation_id(),
            &[],
            &[forged],
        )
        .await
        .unwrap();
        let outcome = take_announce(
            &pool,
            BRIDGE,
            "a@bridge.test",
            &incarnation,
            &[device(&alice, 401, 241, now)],
            &[],
        )
        .await
        .unwrap();
        assert_eq!(outcome.accepted, vec![401], "{outcome:?}");
        for table in ["remote_revoked_device_keys", "remote_revocation_marks"] {
            sqlx::query(&format!("DELETE FROM {table} WHERE domain = 'other.test'"))
                .execute(&pool)
                .await
                .unwrap();
        }
        clean(&pool, &incarnation).await;
    }

    /// Two revocations of one account at once are numbered in the order they
    /// commit: the second waits for the first, so a bridge that sent number
    /// n has sent every revocation before it.
    #[tokio::test]
    async fn live_revocations_are_numbered_in_commit_order() {
        let Some(pool) = pool().await else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let alice = identity(81);
        let incarnation = alice.incarnation_id();
        let user_id = uuid::Uuid::new_v4();
        let username = format!("order{}", &user_id.simple().to_string()[..12]);
        sqlx::query(
            "INSERT INTO users (id, username, master_key_envelope, recovery_key_envelope,
                drive_private_key_envelope, public_key, account_authority_public_key,
                account_authority_key_id, account_incarnation_id, drive_signing_public_key)
             VALUES ($1, $2, '', '', '', '', $3, $4, $5, '')",
        )
        .bind(user_id)
        .bind(&username)
        .bind(STANDARD.encode(alice.authority_public_key()))
        .bind(alice.authority_key_id())
        .bind(&incarnation)
        .execute(&pool)
        .await
        .unwrap();
        let now = now_ms();
        let mut ids = Vec::new();
        for seed in [196u8, 197] {
            let key = kutup_crypto::primitives::SigningKey::from_seed(
                kutup_crypto::primitives::Suite::V1,
                &[seed; 32],
            )
            .verifying_key()
            .to_array::<32>();
            let id: i64 = sqlx::query_scalar(
                "INSERT INTO user_devices (user_id, public_signing, incarnation_id, registration_challenge,
                    registration_issued_at_ms, registration_signature)
                 VALUES ($1, $2, $3, $4, $5, 'x') RETURNING id",
            )
            .bind(user_id)
            .bind(key.to_vec())
            .bind(&incarnation)
            .bind(vec![0u8; 32])
            .bind(now)
            .fetch_one(&pool)
            .await
            .unwrap();
            ids.push(id);
        }
        // The first revocation is recorded and held open...
        let mut first = pool.begin().await.unwrap();
        crate::handlers::devices::record_revocation(&mut first, user_id, ids[0], now, "a")
            .await
            .unwrap();
        // ...the second starts meanwhile and must wait for it.
        let second = {
            let pool = pool.clone();
            let id = ids[1];
            tokio::spawn(async move {
                let mut tx = pool.begin().await.unwrap();
                crate::handlers::devices::record_revocation(&mut tx, user_id, id, now, "b")
                    .await
                    .unwrap();
                tx.commit().await.unwrap();
            })
        };
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert!(!second.is_finished(), "the second waits for the first");
        first.commit().await.unwrap();
        second.await.unwrap();
        let seqs: Vec<i64> = sqlx::query_scalar(
            "SELECT revocation_seq FROM user_devices WHERE id = ANY($1) ORDER BY id",
        )
        .bind(&ids)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(seqs[0] < seqs[1], "numbered as committed: {seqs:?}");
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
