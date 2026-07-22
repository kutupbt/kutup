use std::{fmt, str::FromStr};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_federation_proto::{
    grouped_fingerprint, validate_server_name, verify_identity_chain,
    FederationDiscoveryTransportPolicy, FederationDiscoveryV2, FederationIdentityDocumentV1,
};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

/// Trust applies to the server identity, not to an individual feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerTrustState {
    Tofu,
    Verified,
    Quarantined,
}

impl PeerTrustState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tofu => "tofu",
            Self::Verified => "verified",
            Self::Quarantined => "quarantined",
        }
    }
}

impl fmt::Display for PeerTrustState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for PeerTrustState {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "tofu" => Ok(Self::Tofu),
            "verified" => Ok(Self::Verified),
            "quarantined" => Ok(Self::Quarantined),
            _ => anyhow::bail!("database contains unknown federation trust state {value:?}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FederationPeerObservation {
    FirstPinned {
        sequence: u64,
        fingerprint: String,
    },
    Unchanged {
        sequence: u64,
        trust: PeerTrustState,
    },
    Advanced {
        previous_sequence: u64,
        sequence: u64,
        trust: PeerTrustState,
    },
    Quarantined {
        retained_sequence: u64,
        candidate_sequence: u64,
        reason: String,
    },
    AlreadyQuarantined {
        retained_sequence: u64,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct PinnedFederationPeer {
    pub document_hash: String,
    pub public_key: [u8; 32],
}

#[derive(Clone)]
pub(crate) struct FederationTrustStore {
    pool: PgPool,
}

impl FederationTrustStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Verify a complete candidate chain and its signed discovery document
    /// before touching trust state. Only a self-consistent but conflicting
    /// history quarantines an already-pinned peer; malformed input is rejected.
    #[cfg(test)]
    pub async fn observe_peer(
        &self,
        discovery: &FederationDiscoveryV2,
        candidate_chain: &[FederationIdentityDocumentV1],
        now: OffsetDateTime,
    ) -> anyhow::Result<FederationPeerObservation> {
        self.observe_peer_with_transport_policy(
            discovery,
            candidate_chain,
            now,
            FederationDiscoveryTransportPolicy::HttpsOnly,
        )
        .await
    }

    pub async fn observe_peer_with_transport_policy(
        &self,
        discovery: &FederationDiscoveryV2,
        candidate_chain: &[FederationIdentityDocumentV1],
        now: OffsetDateTime,
        transport_policy: FederationDiscoveryTransportPolicy,
    ) -> anyhow::Result<FederationPeerObservation> {
        let domain = discovery.server.as_str();
        validate_server_name(domain).map_err(anyhow::Error::msg)?;
        verify_identity_chain(domain, candidate_chain).map_err(anyhow::Error::msg)?;
        discovery
            .verify_at_with_transport_policy(domain, now.unix_timestamp(), transport_policy)
            .map_err(anyhow::Error::msg)?;
        let candidate = candidate_chain
            .last()
            .ok_or_else(|| anyhow::anyhow!("federation identity chain is empty"))?;
        let candidate_hash = candidate.document_hash()?;
        if candidate != &discovery.identity || candidate_hash != discovery.identity_document_hash {
            anyhow::bail!(
                "signed discovery does not describe the final document in the supplied identity chain"
            );
        }

        let mut transaction = self.pool.begin().await?;
        lock_domain(&mut transaction, domain).await?;
        let existing = load_peer(&mut transaction, domain).await?;
        let observation = match existing {
            None => {
                insert_peer(
                    &mut transaction,
                    domain,
                    PeerTrustState::Tofu,
                    candidate,
                    &candidate_hash,
                    now,
                )
                .await?;
                insert_identity_documents(
                    &mut transaction,
                    domain,
                    candidate_chain,
                    "accepted",
                    now,
                )
                .await?;
                insert_audit(
                    &mut transaction,
                    None,
                    "federation.identity.pin",
                    json!({
                        "actorType": "system",
                        "domain": domain,
                        "trust": "tofu",
                        "sequence": candidate.sequence,
                        "fingerprint": candidate.key.key_id,
                    }),
                    now,
                )
                .await?;
                FederationPeerObservation::FirstPinned {
                    sequence: candidate.sequence,
                    fingerprint: candidate.key.key_id.clone(),
                }
            }
            Some(existing) => {
                observe_existing(
                    &mut transaction,
                    existing,
                    candidate_chain,
                    candidate,
                    &candidate_hash,
                    now,
                )
                .await?
            }
        };
        transaction.commit().await?;
        Ok(observation)
    }

    /// Load the only key federation traffic may trust. Discovery candidates
    /// never flow directly into request verification.
    pub async fn pinned_peer(&self, domain: &str) -> anyhow::Result<Option<PinnedFederationPeer>> {
        validate_server_name(domain).map_err(anyhow::Error::msg)?;
        type PeerRow = (String, String);
        let row: Option<PeerRow> = sqlx::query_as(
            "SELECT current_document_hash, current_public_key
             FROM federation_peer_identities WHERE domain = $1",
        )
        .bind(domain)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|(document_hash, encoded)| {
            let decoded = STANDARD
                .decode(encoded)
                .map_err(|_| anyhow::anyhow!("stored federation peer public key is invalid"))?;
            let public_key = decoded
                .try_into()
                .map_err(|_| anyhow::anyhow!("stored federation peer public key is invalid"))?;
            Ok(PinnedFederationPeer {
                document_hash,
                public_key,
            })
        })
        .transpose()
    }

    /// Store routing/capability data only after its discovery signature and
    /// complete identity chain have been accepted by the trust state machine.
    pub async fn record_authenticated_discovery(
        &self,
        discovery: &FederationDiscoveryV2,
    ) -> anyhow::Result<()> {
        let expires_at = OffsetDateTime::from_unix_timestamp(discovery.expires_at)
            .map_err(|_| anyhow::anyhow!("federation discovery expiry is out of range"))?;
        let capabilities = serde_json::to_value(&discovery.capabilities)?;
        sqlx::query(
            "UPDATE federation_peer_identities
             SET current_api_base = $2, capabilities = $3,
                 discovery_expires_at = $4, last_discovery_error = NULL,
                 updated_at = now()
             WHERE domain = $1",
        )
        .bind(&discovery.server)
        .bind(&discovery.api_base)
        .bind(capabilities)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn record_discovery_error(&self, domain: &str, error: &str) -> anyhow::Result<()> {
        validate_server_name(domain).map_err(anyhow::Error::msg)?;
        let error: String = error.chars().take(500).collect();
        sqlx::query(
            "UPDATE federation_peer_identities
             SET last_discovery_error = $2, updated_at = now() WHERE domain = $1",
        )
        .bind(domain)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Promote an exact pinned fingerprint from TOFU to operator-verified.
    /// Quarantine can only be resolved by the explicit re-pin operation.
    pub async fn verify_peer(
        &self,
        domain: &str,
        expected_fingerprint: &str,
        admin_user_id: Uuid,
        now: OffsetDateTime,
    ) -> anyhow::Result<()> {
        validate_server_name(domain).map_err(anyhow::Error::msg)?;
        validate_exact_fingerprint(expected_fingerprint)?;
        let mut transaction = self.pool.begin().await?;
        lock_domain(&mut transaction, domain).await?;
        let peer = load_peer(&mut transaction, domain)
            .await?
            .ok_or_else(|| anyhow::anyhow!("federation peer {domain} is not pinned"))?;
        if peer.trust == PeerTrustState::Quarantined {
            anyhow::bail!("federation peer {domain} is quarantined; use explicit re-pin");
        }
        if peer.current_key_id != expected_fingerprint {
            anyhow::bail!("fingerprint confirmation does not match the pinned identity");
        }
        sqlx::query(
            "UPDATE federation_peer_identities
             SET trust_state = 'verified', verified_at = $2, updated_at = $2
             WHERE domain = $1",
        )
        .bind(domain)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        insert_audit(
            &mut transaction,
            Some(admin_user_id),
            "federation.identity.verify",
            json!({
                "actorType": "admin",
                "domain": domain,
                "sequence": peer.current_sequence,
                "fingerprint": peer.current_key_id,
                "fingerprintDisplay": grouped_fingerprint(expected_fingerprint)?,
            }),
            now,
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Break-glass recovery from a conflicting, but cryptographically valid,
    /// chain requires the domain plus both full old and new fingerprints.
    pub async fn repin_quarantined_peer(
        &self,
        domain: &str,
        expected_old_fingerprint: &str,
        expected_new_fingerprint: &str,
        confirmed_domain: &str,
        admin_user_id: Uuid,
        now: OffsetDateTime,
    ) -> anyhow::Result<FederationIdentityDocumentV1> {
        validate_server_name(domain).map_err(anyhow::Error::msg)?;
        if confirmed_domain != domain {
            anyhow::bail!("typed domain confirmation does not match the quarantined peer");
        }
        validate_exact_fingerprint(expected_old_fingerprint)?;
        validate_exact_fingerprint(expected_new_fingerprint)?;
        let mut transaction = self.pool.begin().await?;
        lock_domain(&mut transaction, domain).await?;
        let peer = load_peer(&mut transaction, domain)
            .await?
            .ok_or_else(|| anyhow::anyhow!("federation peer {domain} is not pinned"))?;
        if peer.trust != PeerTrustState::Quarantined {
            anyhow::bail!("federation peer {domain} is not quarantined");
        }
        if peer.current_key_id != expected_old_fingerprint {
            anyhow::bail!("old fingerprint confirmation does not match retained identity");
        }
        let pending_chain_value = peer.pending_identity_chain.ok_or_else(|| {
            anyhow::anyhow!("quarantined peer has no preserved candidate identity chain")
        })?;
        let pending_chain: Vec<FederationIdentityDocumentV1> =
            serde_json::from_value(pending_chain_value)?;
        verify_identity_chain(domain, &pending_chain).map_err(anyhow::Error::msg)?;
        let candidate = pending_chain
            .last()
            .ok_or_else(|| anyhow::anyhow!("preserved candidate identity chain is empty"))?;
        let candidate_hash = candidate.document_hash()?;
        if candidate.key.key_id != expected_new_fingerprint
            || peer.pending_document_hash.as_deref() != Some(candidate_hash.as_str())
        {
            anyhow::bail!("new fingerprint confirmation does not match quarantined identity");
        }

        sqlx::query(
            "UPDATE federation_peer_identity_documents
             SET acceptance = 'superseded'
             WHERE domain = $1 AND acceptance = 'accepted'",
        )
        .bind(domain)
        .execute(&mut *transaction)
        .await?;
        accept_identity_documents(&mut transaction, domain, &pending_chain, now).await?;
        let sequence = i64::try_from(candidate.sequence)
            .map_err(|_| anyhow::anyhow!("peer identity sequence exceeds PostgreSQL BIGINT"))?;
        sqlx::query(
            "UPDATE federation_peer_identities
             SET trust_state = 'verified', current_sequence = $2,
                 current_document_hash = $3, current_key_id = $4,
                 current_public_key = $5, verified_at = $6,
                 quarantine_reason = NULL, pending_document = NULL,
                 pending_identity_chain = NULL, pending_document_hash = NULL,
                 last_seen_at = $6, updated_at = $6
             WHERE domain = $1",
        )
        .bind(domain)
        .bind(sequence)
        .bind(&candidate_hash)
        .bind(&candidate.key.key_id)
        .bind(&candidate.key.public_key)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        insert_audit(
            &mut transaction,
            Some(admin_user_id),
            "federation.identity.repin",
            json!({
                "actorType": "admin-break-glass",
                "domain": domain,
                "oldFingerprint": expected_old_fingerprint,
                "oldFingerprintDisplay": grouped_fingerprint(expected_old_fingerprint)?,
                "newFingerprint": expected_new_fingerprint,
                "newFingerprintDisplay": grouped_fingerprint(expected_new_fingerprint)?,
                "newSequence": candidate.sequence,
            }),
            now,
        )
        .await?;
        transaction.commit().await?;
        Ok(candidate.clone())
    }
}

#[derive(Debug)]
struct StoredPeer {
    trust: PeerTrustState,
    current_sequence: u64,
    current_document_hash: String,
    current_key_id: String,
    pending_identity_chain: Option<serde_json::Value>,
    pending_document_hash: Option<String>,
}

async fn observe_existing(
    transaction: &mut Transaction<'_, Postgres>,
    existing: StoredPeer,
    candidate_chain: &[FederationIdentityDocumentV1],
    candidate: &FederationIdentityDocumentV1,
    candidate_hash: &str,
    now: OffsetDateTime,
) -> anyhow::Result<FederationPeerObservation> {
    let domain = candidate.server.as_str();
    if existing.trust == PeerTrustState::Quarantined {
        insert_identity_documents(transaction, domain, candidate_chain, "quarantined", now).await?;
        touch_peer(transaction, domain, now).await?;
        return Ok(FederationPeerObservation::AlreadyQuarantined {
            retained_sequence: existing.current_sequence,
        });
    }

    let pinned_index = usize::try_from(existing.current_sequence)
        .map_err(|_| anyhow::anyhow!("pinned identity sequence exceeds platform limits"))?;
    let pinned_in_candidate = candidate_chain.get(pinned_index);
    let chain_conflicts = pinned_in_candidate
        .map(|document| document.document_hash())
        .transpose()?
        .as_deref()
        != Some(existing.current_document_hash.as_str());
    if chain_conflicts {
        let reason = if candidate.sequence < existing.current_sequence {
            "candidate identity chain rolls back the pinned sequence"
        } else {
            "candidate identity chain conflicts with pinned history"
        };
        quarantine_peer(
            transaction,
            &existing,
            candidate_chain,
            candidate,
            candidate_hash,
            reason,
            now,
        )
        .await?;
        return Ok(FederationPeerObservation::Quarantined {
            retained_sequence: existing.current_sequence,
            candidate_sequence: candidate.sequence,
            reason: reason.into(),
        });
    }

    if candidate.sequence == existing.current_sequence {
        touch_peer(transaction, domain, now).await?;
        return Ok(FederationPeerObservation::Unchanged {
            sequence: existing.current_sequence,
            trust: existing.trust,
        });
    }

    let suffix = candidate_chain
        .get(pinned_index.saturating_add(1)..)
        .ok_or_else(|| {
            anyhow::anyhow!("candidate identity chain does not extend pinned history")
        })?;
    insert_identity_documents(transaction, domain, suffix, "accepted", now).await?;
    let sequence = i64::try_from(candidate.sequence)
        .map_err(|_| anyhow::anyhow!("peer identity sequence exceeds PostgreSQL BIGINT"))?;
    sqlx::query(
        "UPDATE federation_peer_identities
         SET current_sequence = $2, current_document_hash = $3,
             current_key_id = $4, current_public_key = $5,
             last_seen_at = $6, updated_at = $6
         WHERE domain = $1",
    )
    .bind(domain)
    .bind(sequence)
    .bind(candidate_hash)
    .bind(&candidate.key.key_id)
    .bind(&candidate.key.public_key)
    .bind(now)
    .execute(&mut **transaction)
    .await?;
    insert_audit(
        transaction,
        None,
        "federation.identity.advance-remote",
        json!({
            "actorType": "system",
            "domain": domain,
            "previousSequence": existing.current_sequence,
            "sequence": candidate.sequence,
            "fingerprint": candidate.key.key_id,
            "trust": existing.trust.as_str(),
        }),
        now,
    )
    .await?;
    Ok(FederationPeerObservation::Advanced {
        previous_sequence: existing.current_sequence,
        sequence: candidate.sequence,
        trust: existing.trust,
    })
}

#[allow(clippy::too_many_arguments)]
async fn quarantine_peer(
    transaction: &mut Transaction<'_, Postgres>,
    existing: &StoredPeer,
    candidate_chain: &[FederationIdentityDocumentV1],
    candidate: &FederationIdentityDocumentV1,
    candidate_hash: &str,
    reason: &str,
    now: OffsetDateTime,
) -> anyhow::Result<()> {
    let domain = candidate.server.as_str();
    insert_identity_documents(transaction, domain, candidate_chain, "quarantined", now).await?;
    sqlx::query(
        "UPDATE federation_peer_identities
         SET trust_state = 'quarantined', quarantine_reason = $2,
             pending_document = $3, pending_identity_chain = $4,
             pending_document_hash = $5, last_seen_at = $6, updated_at = $6
         WHERE domain = $1",
    )
    .bind(domain)
    .bind(reason)
    .bind(serde_json::to_value(candidate)?)
    .bind(serde_json::to_value(candidate_chain)?)
    .bind(candidate_hash)
    .bind(now)
    .execute(&mut **transaction)
    .await?;
    insert_audit(
        transaction,
        None,
        "federation.identity.quarantine",
        json!({
            "actorType": "system",
            "domain": domain,
            "reason": reason,
            "retainedSequence": existing.current_sequence,
            "retainedFingerprint": existing.current_key_id,
            "candidateSequence": candidate.sequence,
            "candidateFingerprint": candidate.key.key_id,
        }),
        now,
    )
    .await?;
    Ok(())
}

async fn load_peer(
    transaction: &mut Transaction<'_, Postgres>,
    domain: &str,
) -> anyhow::Result<Option<StoredPeer>> {
    type StoredPeerRow = (
        String,
        i64,
        String,
        String,
        Option<serde_json::Value>,
        Option<String>,
    );
    let row: Option<StoredPeerRow> = sqlx::query_as(
        "SELECT trust_state, current_sequence, current_document_hash,
                    current_key_id, pending_identity_chain, pending_document_hash
             FROM federation_peer_identities WHERE domain = $1",
    )
    .bind(domain)
    .fetch_optional(&mut **transaction)
    .await?;
    row.map(
        |(trust, sequence, document_hash, key_id, pending_chain, pending_hash)| {
            Ok(StoredPeer {
                trust: trust.parse()?,
                current_sequence: u64::try_from(sequence)
                    .map_err(|_| anyhow::anyhow!("stored peer identity sequence is negative"))?,
                current_document_hash: document_hash,
                current_key_id: key_id,
                pending_identity_chain: pending_chain,
                pending_document_hash: pending_hash,
            })
        },
    )
    .transpose()
}

async fn insert_peer(
    transaction: &mut Transaction<'_, Postgres>,
    domain: &str,
    trust: PeerTrustState,
    document: &FederationIdentityDocumentV1,
    document_hash: &str,
    now: OffsetDateTime,
) -> anyhow::Result<()> {
    let sequence = i64::try_from(document.sequence)
        .map_err(|_| anyhow::anyhow!("peer identity sequence exceeds PostgreSQL BIGINT"))?;
    sqlx::query(
        "INSERT INTO federation_peer_identities
         (domain, trust_state, current_sequence, current_document_hash,
          current_key_id, current_public_key, first_seen_at, last_seen_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $7)",
    )
    .bind(domain)
    .bind(trust.as_str())
    .bind(sequence)
    .bind(document_hash)
    .bind(&document.key.key_id)
    .bind(&document.key.public_key)
    .bind(now)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_identity_documents(
    transaction: &mut Transaction<'_, Postgres>,
    domain: &str,
    documents: &[FederationIdentityDocumentV1],
    acceptance: &str,
    now: OffsetDateTime,
) -> anyhow::Result<()> {
    for document in documents {
        let sequence = i64::try_from(document.sequence)
            .map_err(|_| anyhow::anyhow!("peer identity sequence exceeds PostgreSQL BIGINT"))?;
        sqlx::query(
            "INSERT INTO federation_peer_identity_documents
             (domain, sequence, document_hash, key_id, document, acceptance, recorded_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (domain, sequence, document_hash) DO NOTHING",
        )
        .bind(domain)
        .bind(sequence)
        .bind(document.document_hash()?)
        .bind(&document.key.key_id)
        .bind(serde_json::to_value(document)?)
        .bind(acceptance)
        .bind(now)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn accept_identity_documents(
    transaction: &mut Transaction<'_, Postgres>,
    domain: &str,
    documents: &[FederationIdentityDocumentV1],
    now: OffsetDateTime,
) -> anyhow::Result<()> {
    for document in documents {
        let sequence = i64::try_from(document.sequence)
            .map_err(|_| anyhow::anyhow!("peer identity sequence exceeds PostgreSQL BIGINT"))?;
        sqlx::query(
            "INSERT INTO federation_peer_identity_documents
             (domain, sequence, document_hash, key_id, document, acceptance, recorded_at)
             VALUES ($1, $2, $3, $4, $5, 'accepted', $6)
             ON CONFLICT (domain, sequence, document_hash) DO UPDATE
             SET acceptance = 'accepted'",
        )
        .bind(domain)
        .bind(sequence)
        .bind(document.document_hash()?)
        .bind(&document.key.key_id)
        .bind(serde_json::to_value(document)?)
        .bind(now)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn touch_peer(
    transaction: &mut Transaction<'_, Postgres>,
    domain: &str,
    now: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE federation_peer_identities
         SET last_seen_at = $2, updated_at = $2 WHERE domain = $1",
    )
    .bind(domain)
    .bind(now)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn lock_domain(
    transaction: &mut Transaction<'_, Postgres>,
    domain: &str,
) -> Result<(), sqlx::Error> {
    let digest = Sha256::digest(domain.as_bytes());
    let key = i64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("a SHA-256 digest always contains eight bytes"),
    );
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(key)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn insert_audit(
    transaction: &mut Transaction<'_, Postgres>,
    admin_user_id: Option<Uuid>,
    action: &str,
    payload: serde_json::Value,
    occurred_at: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO admin_audit_log
         (admin_user_id, action, target_user_id, payload, occurred_at)
         VALUES ($1, $2, NULL, $3, $4)",
    )
    .bind(admin_user_id.unwrap_or_else(Uuid::nil))
    .bind(action)
    .bind(payload)
    .bind(occurred_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn validate_exact_fingerprint(value: &str) -> anyhow::Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("fingerprint must be the full lowercase SHA-256 value");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_state_and_full_fingerprint_parsing_are_closed() {
        assert_eq!(
            "tofu".parse::<PeerTrustState>().unwrap(),
            PeerTrustState::Tofu
        );
        assert_eq!(
            "verified".parse::<PeerTrustState>().unwrap(),
            PeerTrustState::Verified
        );
        assert_eq!(
            "quarantined".parse::<PeerTrustState>().unwrap(),
            PeerTrustState::Quarantined
        );
        assert!("trusted".parse::<PeerTrustState>().is_err());
        assert!(validate_exact_fingerprint(&"ab".repeat(32)).is_ok());
        assert!(validate_exact_fingerprint(&"AB".repeat(32)).is_err());
        assert!(validate_exact_fingerprint(&"ab".repeat(16)).is_err());
    }
}
