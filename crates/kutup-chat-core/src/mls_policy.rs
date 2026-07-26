//! Independent verification of authenticated MLS ordering-service policies.

use kutup_chat_proto::MlsOrderingServicePolicyV1;
use kutup_federation_proto::{FederatedFeaturePolicyHistoryV1, FederatedFeaturePolicyTypeV1};

use crate::error::{ChatError, Result};

/// Verify the complete federation-identity and MLS policy chain before using
/// an ordering authority key. The browser receives history, never a
/// server-computed "verified" status label.
pub fn verify_mls_ordering_policy_history(
    history: &FederatedFeaturePolicyHistoryV1,
    expected_domain: &str,
) -> Result<MlsOrderingServicePolicyV1> {
    kutup_federation_proto::validate_server_name(expected_domain)
        .map_err(|error| ChatError::Trust(error.to_string()))?;
    if history.domain != expected_domain
        || history.feature_type != FederatedFeaturePolicyTypeV1::MlsOrderingService
    {
        return Err(ChatError::Trust(
            "MLS ordering policy history has the wrong domain or type".into(),
        ));
    }
    let envelope = history
        .verify()
        .map_err(|error| ChatError::Trust(error.to_string()))?;
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
    Ok(policy)
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
}
