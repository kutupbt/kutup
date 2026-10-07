//! Sealed sender a server provisions for itself (docs/self-hosting.md,
//! "Contacts-only sealed sender").
//!
//! With no offline root configured, a server with a federation identity makes
//! its own: a root generated in memory, used once to sign a long-lived online
//! certificate, and dropped. Only the root's public key and the online
//! private key are stored (`sealed_sender_generated_certificates`), so a copy
//! of the database cannot sign another certificate under that root. Before a
//! certificate runs out, the cycle repeats with a new root under the policy's
//! usual rules: the new root and certificate are published first and start
//! issuing a day later, and the old ones leave the policy when they expire.
//!
//! The policy is built from the stored rows, so every instance builds the same
//! one; renewal runs under a database lock, and publishing an unchanged policy
//! is a no-op.

use std::collections::BTreeSet;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::{
    DirectChatSuiteId, SealedSenderRootV1, SealedSenderServerCertificateV1,
    SealedSenderServicePolicyV1, SealedSenderSuiteId,
};
use kutup_federation_proto::FederatedFeaturePolicyTypeV1;
use libsignal_protocol::{KeyPair, PrivateKey, ServerCertificate};
use rand09::rngs::OsRng;
use rand09::{RngCore as _, TryRngCore as _};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;

use crate::federation::{FederationStack, PolicyRotation};
use crate::sealed_sender_service::{ActiveSealedSender, OnlineSigner};

const DAY: i64 = 24 * 60 * 60;
/// How long one online certificate issues for.
const CERTIFICATE_LIFETIME: i64 = 90 * DAY;
/// How long before the current certificate runs out its successor is made.
const RENEW_BEFORE: i64 = 30 * DAY;
const SENDER_CERTIFICATE_LIFETIME: u32 = 24 * 60 * 60;
const MAXIMUM_CLOCK_SKEW: u32 = 5 * 60;
/// How long a successor is published before it issues: the policy's rule
/// for introducing a root (24 hours plus the clock skew), so every server
/// and client has it before a sender certificate signed under it arrives.
const SUCCESSOR_LEAD: i64 = DAY + MAXIMUM_CLOCK_SKEW as i64;
/// libsignal treats this certificate id as revoked.
const LIBSIGNAL_REVOKED_TEST_CERTIFICATE_ID: u32 = 0xDEAD_C357;
const PROVISION_LOCK: i64 = 0x4b55_5455_5353_5052;
pub(crate) const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60 * 60);

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
struct GeneratedCertificate {
    certificate_id: i64,
    root_id: String,
    root_public_key: String,
    certificate: String,
    online_private_key: Option<Vec<u8>>,
    published_at: i64,
    activates_at: i64,
    expires_at: i64,
}

/// When a new certificate should start issuing, if one is due at `now`: at
/// once when nothing can issue, a day after publication when the current
/// one is within [`RENEW_BEFORE`] of running out, otherwise none.
fn successor_activation(rows: &[GeneratedCertificate], now: i64) -> Option<i64> {
    let latest_expiry = rows
        .iter()
        .filter(|row| row.online_private_key.is_some() && row.expires_at > now)
        .map(|row| row.expires_at)
        .max();
    let Some(latest_expiry) = latest_expiry else {
        return Some(now);
    };
    if latest_expiry - now > RENEW_BEFORE {
        return None;
    }
    // A server that was down for most of the window: the current one cannot
    // bridge the lead, so the successor starts at once rather than leaving a
    // gap in which no certificate can be issued.
    let bridges_lead = latest_expiry
        >= now
            + SUCCESSOR_LEAD
            + i64::from(SENDER_CERTIFICATE_LIFETIME)
            + i64::from(MAXIMUM_CLOCK_SKEW);
    Some(if bridges_lead {
        now + SUCCESSOR_LEAD
    } else {
        now
    })
}

/// The published policy: every certificate that has not expired, with its
/// root.
fn build_policy(
    domain: &str,
    rows: &[GeneratedCertificate],
    now: i64,
) -> anyhow::Result<SealedSenderServicePolicyV1> {
    let mut live: Vec<&GeneratedCertificate> =
        rows.iter().filter(|row| row.expires_at > now).collect();
    live.sort_by_key(|row| (row.activates_at, row.certificate_id));
    let policy = SealedSenderServicePolicyV1 {
        policy_version: 1,
        canonical_domain: domain.to_string(),
        suite: SealedSenderSuiteId::LibsignalV2DeliveryCapabilityV1,
        roots: live
            .iter()
            .map(|row| SealedSenderRootV1 {
                root_id: row.root_id.clone(),
                public_key: row.root_public_key.clone(),
                activates_at: row.published_at,
                revokes_at: None,
            })
            .collect(),
        server_certificates: live
            .iter()
            .map(|row| {
                Ok(SealedSenderServerCertificateV1 {
                    certificate_id: u32::try_from(row.certificate_id)?,
                    root_id: row.root_id.clone(),
                    certificate: row.certificate.clone(),
                    activates_at: row.activates_at,
                    expires_at: row.expires_at,
                })
            })
            .collect::<anyhow::Result<_>>()?,
        sender_certificate_lifetime_seconds: SENDER_CERTIFICATE_LIFETIME,
        maximum_clock_skew_seconds: MAXIMUM_CLOCK_SKEW,
        direct_chat_suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
    };
    policy.validate().map_err(anyhow::Error::msg)?;
    Ok(policy)
}

/// A new cycle: a root made here, used to sign one online certificate, and
/// dropped when this returns.
fn generate(
    rows: &[GeneratedCertificate],
    now: i64,
    activates_at: i64,
) -> anyhow::Result<GeneratedCertificate> {
    let mut rng = OsRng.unwrap_err();
    let taken: BTreeSet<i64> = rows.iter().map(|row| row.certificate_id).collect();
    let certificate_id = loop {
        let id = rng.next_u32();
        if id != 0 && id != LIBSIGNAL_REVOKED_TEST_CERTIFICATE_ID && !taken.contains(&i64::from(id))
        {
            break id;
        }
    };
    let root = KeyPair::generate(&mut rng);
    let online = KeyPair::generate(&mut rng);
    let certificate = ServerCertificate::new(
        certificate_id,
        online.public_key,
        &root.private_key,
        &mut rng,
    )?;
    if !certificate.validate(&root.public_key)? {
        anyhow::bail!("generated sealed sender certificate failed root validation");
    }
    let root_public = root.public_key.serialize();
    Ok(GeneratedCertificate {
        certificate_id: i64::from(certificate_id),
        root_id: hex::encode(Sha256::digest(&root_public)),
        root_public_key: STANDARD.encode(&root_public),
        certificate: STANDARD.encode(certificate.serialized()?),
        online_private_key: Some(online.private_key.serialize().to_vec()),
        published_at: now,
        activates_at,
        expires_at: activates_at + CERTIFICATE_LIFETIME,
    })
}

/// Renew when due, publish the policy, and return what this instance issues
/// with. A policy this server did not make (an operator's offline root) is
/// replaced only when the operator allows it.
pub(crate) async fn maintain(
    pool: &sqlx::PgPool,
    federation: &FederationStack,
    rotation: PolicyRotation,
    now: OffsetDateTime,
) -> anyhow::Result<ActiveSealedSender> {
    let now_seconds = now.unix_timestamp();
    let feature = FederatedFeaturePolicyTypeV1::SealedSenderService;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(PROVISION_LOCK)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE sealed_sender_generated_certificates SET online_private_key = NULL
         WHERE expires_at <= $1 AND online_private_key IS NOT NULL",
    )
    .bind(now_seconds)
    .execute(&mut *tx)
    .await?;
    let mut rows: Vec<GeneratedCertificate> = sqlx::query_as(
        "SELECT certificate_id, root_id, root_public_key, certificate, online_private_key,
                published_at, activates_at, expires_at
         FROM sealed_sender_generated_certificates ORDER BY activates_at, certificate_id",
    )
    .fetch_all(&mut *tx)
    .await?;
    if rotation == PolicyRotation::Refuse {
        let persisted = federation
            .feature_policies()
            .local_history(federation.server_name(), feature)
            .await?;
        if let Some(history) = persisted {
            let current = history.verify()?;
            let policy =
                SealedSenderServicePolicyV1::from_canonical_bytes(&current.payload_bytes()?)
                    .map_err(anyhow::Error::msg)?;
            let own: BTreeSet<&str> = rows.iter().map(|row| row.root_id.as_str()).collect();
            if policy
                .roots
                .iter()
                .any(|root| !own.contains(root.root_id.as_str()))
            {
                anyhow::bail!(
                    "the published sealed sender policy uses a root this server did not make (an offline root); \
                     configure it again, or run `kutup-server feature-policy rotate sealed-sender` to let the server provision its own"
                );
            }
        }
    }
    if let Some(activates_at) = successor_activation(&rows, now_seconds) {
        let created = generate(&rows, now_seconds, activates_at)?;
        sqlx::query(
            "INSERT INTO sealed_sender_generated_certificates
                (certificate_id, root_id, root_public_key, certificate, online_private_key,
                 published_at, activates_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(created.certificate_id)
        .bind(&created.root_id)
        .bind(&created.root_public_key)
        .bind(&created.certificate)
        .bind(&created.online_private_key)
        .bind(created.published_at)
        .bind(created.activates_at)
        .bind(created.expires_at)
        .execute(&mut *tx)
        .await?;
        tracing::info!(
            certificate_id = created.certificate_id,
            activates_at = created.activates_at,
            expires_at = created.expires_at,
            "provisioned a sealed sender certificate under a new root"
        );
        rows.push(created);
    }
    tx.commit().await?;

    let policy = build_policy(federation.server_name(), &rows, now_seconds)?;
    federation
        .feature_policies()
        .ensure_local(
            federation,
            feature,
            &policy.canonical_bytes().map_err(anyhow::Error::msg)?,
            if rotation == PolicyRotation::Operator {
                PolicyRotation::Operator
            } else {
                PolicyRotation::Automatic
            },
            now,
        )
        .await?;
    let signers = rows
        .iter()
        .filter(|row| row.expires_at > now_seconds)
        .filter_map(|row| row.online_private_key.as_ref().map(|key| (row, key)))
        .map(|(row, key)| {
            Ok(OnlineSigner {
                certificate_id: u32::try_from(row.certificate_id)?,
                activates_at: row.activates_at,
                expires_at: row.expires_at,
                certificate: ServerCertificate::deserialize(&STANDARD.decode(&row.certificate)?)?,
                private_key: PrivateKey::deserialize(key)?,
            })
        })
        .collect::<anyhow::Result<_>>()?;
    Ok(ActiveSealedSender { policy, signers })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn row(id: i64, activates_at: i64) -> GeneratedCertificate {
        generate(&[], activates_at, activates_at)
            .map(|mut row| {
                row.certificate_id = id;
                row
            })
            .unwrap()
    }

    #[test]
    fn the_first_certificate_issues_at_once() {
        assert_eq!(successor_activation(&[], NOW), Some(NOW));
    }

    #[test]
    fn a_successor_is_made_a_month_before_expiry_and_issues_a_day_later() {
        let current = row(1, NOW);
        assert_eq!(
            successor_activation(std::slice::from_ref(&current), NOW + DAY),
            None
        );
        let renew_at = current.expires_at - RENEW_BEFORE;
        assert_eq!(
            successor_activation(std::slice::from_ref(&current), renew_at - 1),
            None
        );
        assert_eq!(
            successor_activation(std::slice::from_ref(&current), renew_at),
            Some(renew_at + SUCCESSOR_LEAD)
        );
        let successor = row(2, renew_at + SUCCESSOR_LEAD);
        assert_eq!(
            successor_activation(&[current, successor], renew_at + 1),
            None,
            "one successor at a time"
        );
    }

    #[test]
    fn a_server_back_after_a_long_absence_renews_at_once() {
        let current = row(1, NOW);
        assert_eq!(
            successor_activation(std::slice::from_ref(&current), current.expires_at - DAY),
            Some(current.expires_at - DAY)
        );
        let mut wiped = current.clone();
        wiped.online_private_key = None;
        assert_eq!(
            successor_activation(&[wiped], current.expires_at + 10),
            Some(current.expires_at + 10)
        );
    }

    #[test]
    fn the_policy_lists_live_certificates_and_drops_expired_ones() {
        let current = row(1, NOW);
        let renew_at = current.expires_at - RENEW_BEFORE;
        let successor = row(2, renew_at + SUCCESSOR_LEAD);
        let rows = [current.clone(), successor.clone()];
        let both = build_policy("kutup.example", &rows, renew_at + 1).unwrap();
        assert_eq!(both.roots.len(), 2);
        assert_eq!(both.server_certificates.len(), 2);
        let later = build_policy("kutup.example", &rows, current.expires_at).unwrap();
        assert_eq!(later.roots.len(), 1);
        assert_eq!(later.roots[0].root_id, successor.root_id);
        assert_eq!(later.server_certificates[0].certificate_id, 2);
    }

    #[test]
    fn a_generated_certificate_validates_under_its_published_root_only() {
        let made = row(7, NOW);
        let root = libsignal_protocol::PublicKey::deserialize(
            &STANDARD.decode(&made.root_public_key).unwrap(),
        )
        .unwrap();
        let certificate =
            ServerCertificate::deserialize(&STANDARD.decode(&made.certificate).unwrap()).unwrap();
        assert!(certificate.validate(&root).unwrap());
        let other = row(8, NOW);
        let other_root = libsignal_protocol::PublicKey::deserialize(
            &STANDARD.decode(&other.root_public_key).unwrap(),
        )
        .unwrap();
        assert!(!certificate.validate(&other_root).unwrap());
        let online = PrivateKey::deserialize(made.online_private_key.as_ref().unwrap()).unwrap();
        assert_eq!(
            online.public_key().unwrap().serialize(),
            certificate.public_key().unwrap().serialize()
        );
    }
}
