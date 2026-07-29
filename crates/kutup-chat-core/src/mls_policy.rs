//! Independent verification of authenticated MLS ordering-service policies.

use kutup_chat_proto::MlsOrderingServicePolicyV1;
use kutup_federation_proto::{FederatedFeaturePolicyHistoryV1, FederatedFeaturePolicyTypeV1};
use serde::{Deserialize, Serialize};

use crate::error::{ChatError, Result};

/// One independently authenticated ordering-policy revision, projected into a
/// browser-safe view only after both the federation identity/policy chain and
/// the feature-owned canonical payload have been verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedMlsOrderingPolicyEntry {
    pub sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_policy_hash: Option<String>,
    pub policy_hash: String,
    pub payload_digest: String,
    pub issued_at: i64,
    pub federation_identity_generation: u64,
    pub federation_identity_key_id: String,
    pub federation_identity_public_key: String,
    pub policy: MlsOrderingServicePolicyV1,
}

/// Complete authenticated MLS ordering-policy history for one authority.
///
/// This deliberately excludes signatures and opaque payload bytes: the
/// browser gets the exact public keys, fingerprints, policy hashes, and typed
/// policy values it needs to inspect, but cannot accidentally reinterpret an
/// unverified wire document as trusted UI state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedMlsOrderingPolicyHistory {
    pub domain: String,
    pub policies: Vec<VerifiedMlsOrderingPolicyEntry>,
}

/// Verify the complete federation-identity and MLS policy chain before using
/// an ordering authority key. The browser receives history, never a
/// server-computed "verified" status label.
pub fn verify_mls_ordering_policy_history(
    history: &FederatedFeaturePolicyHistoryV1,
    expected_domain: &str,
) -> Result<MlsOrderingServicePolicyV1> {
    let verified = verify_mls_ordering_policy_history_details(history, expected_domain)?;
    verified
        .policies
        .last()
        .map(|entry| entry.policy.clone())
        .ok_or_else(|| ChatError::Trust("MLS ordering policy history is empty".into()))
}

/// Verify and retain the exact authenticated metadata needed by the browser's
/// group security-details UI. Every historical feature payload is parsed and
/// domain-bound, not only the current revision.
pub fn verify_mls_ordering_policy_history_details(
    history: &FederatedFeaturePolicyHistoryV1,
    expected_domain: &str,
) -> Result<VerifiedMlsOrderingPolicyHistory> {
    kutup_federation_proto::validate_server_name(expected_domain)
        .map_err(|error| ChatError::Trust(error.to_string()))?;
    if history.domain != expected_domain
        || history.feature_type != FederatedFeaturePolicyTypeV1::MlsOrderingService
    {
        return Err(ChatError::Trust(
            "MLS ordering policy history has the wrong domain or type".into(),
        ));
    }
    history
        .verify()
        .map_err(|error| ChatError::Trust(error.to_string()))?;

    let mut policies = Vec::with_capacity(history.policies.len());
    for envelope in &history.policies {
        let policy = MlsOrderingServicePolicyV1::from_canonical_bytes(
            &envelope
                .payload_bytes()
                .map_err(|error| ChatError::Trust(error.to_string()))?,
        )
        .map_err(ChatError::Trust)?;
        if policy.canonical_domain != expected_domain {
            return Err(ChatError::Trust(
                "MLS ordering policy payload has the wrong canonical domain".into(),
            ));
        }
        let identity = history
            .identities
            .iter()
            .find(|identity| identity.sequence == envelope.federation_identity_generation)
            .ok_or_else(|| {
                ChatError::Trust(
                    "MLS ordering policy identity generation is absent after verification".into(),
                )
            })?;
        policies.push(VerifiedMlsOrderingPolicyEntry {
            sequence: envelope.sequence,
            previous_policy_hash: envelope.previous_policy_hash.clone(),
            policy_hash: envelope
                .policy_hash()
                .map_err(|error| ChatError::Trust(error.to_string()))?,
            payload_digest: envelope.payload_digest.clone(),
            issued_at: envelope.issued_at,
            federation_identity_generation: identity.sequence,
            federation_identity_key_id: identity.key.key_id.clone(),
            federation_identity_public_key: identity.key.public_key.clone(),
            policy,
        });
    }
    Ok(VerifiedMlsOrderingPolicyHistory {
        domain: expected_domain.to_owned(),
        policies,
    })
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;
    use kutup_chat_proto::{
        MlsAbuseLimitsV1, MlsAnonymousDeliverySuiteV1, MlsCipherSuiteId,
        PendingMessageRequestPolicyV1, MLS_ORDERING_SERVICE_POLICY_VERSION,
    };
    use kutup_federation_proto::{
        FederatedFeaturePolicyEnvelopeV1, FederatedFeaturePolicyHistoryV1,
        FederatedFeaturePolicyTypeV1, FederationIdentityDocumentV1,
    };
    use sha2::{Digest as _, Sha256};

    use super::*;

    fn policy(domain: &str) -> MlsOrderingServicePolicyV1 {
        let control_key = SigningKey::from_bytes(&[44; 32]);
        let public_key = control_key.verifying_key().to_bytes();
        MlsOrderingServicePolicyV1 {
            policy_version: MLS_ORDERING_SERVICE_POLICY_VERSION,
            canonical_domain: domain.into(),
            suite: MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256,
            anonymous_delivery_suite: MlsAnonymousDeliverySuiteV1::DhKemP256HkdfSha256Aes128Gcm,
            control_signing_key_id: hex::encode(Sha256::digest(public_key)),
            control_signing_public_key: BASE64.encode(public_key),
            accepts_group_ordering: true,
            maximum_group_members: 1000,
            maximum_authorities: 64,
            maximum_control_payload_bytes: 1024 * 1024,
            pending_message_requests: PendingMessageRequestPolicyV1::default(),
            abuse_limits: MlsAbuseLimitsV1::default(),
        }
    }

    fn history(
        domain: &str,
        payload_domain: &str,
        feature_type: FederatedFeaturePolicyTypeV1,
    ) -> FederatedFeaturePolicyHistoryV1 {
        let identity_key = SigningKey::from_bytes(&[33; 32]);
        let identity =
            FederationIdentityDocumentV1::genesis(domain, 1_700_000_000, &identity_key).unwrap();
        let envelope = FederatedFeaturePolicyEnvelopeV1::sign(
            domain,
            feature_type,
            1,
            None,
            &identity,
            &policy(payload_domain).canonical_bytes().unwrap(),
            1_700_000_001,
            &identity_key,
        )
        .unwrap();
        FederatedFeaturePolicyHistoryV1 {
            domain: domain.into(),
            feature_type,
            identities: vec![identity],
            policies: vec![envelope],
        }
    }

    #[test]
    fn verifies_identity_policy_and_typed_payload_together() {
        let history = history(
            "alpha.example",
            "alpha.example",
            FederatedFeaturePolicyTypeV1::MlsOrderingService,
        );
        let details =
            verify_mls_ordering_policy_history_details(&history, "alpha.example").unwrap();
        assert_eq!(details.domain, "alpha.example");
        assert_eq!(details.policies.len(), 1);
        assert_eq!(details.policies[0].sequence, 1);
        assert_eq!(
            details.policies[0].federation_identity_key_id,
            history.identities[0].key.key_id
        );
        assert_eq!(
            details.policies[0].federation_identity_public_key,
            history.identities[0].key.public_key
        );
        assert_eq!(details.policies[0].policy.canonical_domain, "alpha.example");
        assert_eq!(
            verify_mls_ordering_policy_history(&history, "alpha.example")
                .unwrap()
                .canonical_domain,
            "alpha.example"
        );
    }

    #[test]
    fn rejects_domain_type_payload_and_signature_substitution() {
        let valid = history(
            "alpha.example",
            "alpha.example",
            FederatedFeaturePolicyTypeV1::MlsOrderingService,
        );
        assert!(verify_mls_ordering_policy_history(&valid, "beta.example").is_err());

        let wrong_payload = history(
            "alpha.example",
            "beta.example",
            FederatedFeaturePolicyTypeV1::MlsOrderingService,
        );
        assert!(verify_mls_ordering_policy_history(&wrong_payload, "alpha.example").is_err());

        let wrong_type = history(
            "alpha.example",
            "alpha.example",
            FederatedFeaturePolicyTypeV1::SealedSenderService,
        );
        assert!(verify_mls_ordering_policy_history(&wrong_type, "alpha.example").is_err());

        let mut forged = valid;
        forged.policies[0].signature = BASE64.encode([0_u8; 64]);
        assert!(verify_mls_ordering_policy_history(&forged, "alpha.example").is_err());
    }

    #[test]
    fn rejects_an_authenticated_history_with_an_unparseable_old_feature_payload() {
        let identity_key = SigningKey::from_bytes(&[33; 32]);
        let identity =
            FederationIdentityDocumentV1::genesis("alpha.example", 1_700_000_000, &identity_key)
                .unwrap();
        let first = FederatedFeaturePolicyEnvelopeV1::sign(
            "alpha.example",
            FederatedFeaturePolicyTypeV1::MlsOrderingService,
            1,
            None,
            &identity,
            b"{}",
            1_700_000_001,
            &identity_key,
        )
        .unwrap();
        let second = FederatedFeaturePolicyEnvelopeV1::sign(
            "alpha.example",
            FederatedFeaturePolicyTypeV1::MlsOrderingService,
            2,
            Some(first.policy_hash().unwrap()),
            &identity,
            &policy("alpha.example").canonical_bytes().unwrap(),
            1_700_000_002,
            &identity_key,
        )
        .unwrap();
        let history = FederatedFeaturePolicyHistoryV1 {
            domain: "alpha.example".into(),
            feature_type: FederatedFeaturePolicyTypeV1::MlsOrderingService,
            identities: vec![identity],
            policies: vec![first, second],
        };

        assert!(history.verify().is_ok());
        assert!(
            verify_mls_ordering_policy_history_details(&history, "alpha.example").is_err(),
            "an authenticated but malformed historical feature payload must remain visible"
        );
    }
}
