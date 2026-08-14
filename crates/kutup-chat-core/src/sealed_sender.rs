//! Client-side authentication of sealed-sender service policy and certificates.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::{SealedSenderServicePolicyV1, SenderCertificateResponseV1};
use kutup_federation_proto::{FederatedFeaturePolicyHistoryV1, FederatedFeaturePolicyTypeV1};
use libsignal_protocol::{PublicKey, SenderCertificate, Timestamp};

use crate::error::{crypto, ChatError, Result};

#[derive(Clone)]
pub(crate) struct SealedSenderPolicyPin {
    pub sequence: u64,
    pub policy: SealedSenderServicePolicyV1,
    active_roots: Vec<PublicKey>,
}

impl SealedSenderPolicyPin {
    pub fn verify_history(
        history: &FederatedFeaturePolicyHistoryV1,
        expected_domain: &str,
        now_seconds: i64,
    ) -> Result<Self> {
        if history.domain != expected_domain
            || history.feature_type != FederatedFeaturePolicyTypeV1::SealedSenderService
        {
            return Err(ChatError::Trust(
                "sealed sender policy history has the wrong domain or type".into(),
            ));
        }
        let current = history
            .verify()
            .map_err(|error| ChatError::Trust(error.to_string()))?;
        let policy = SealedSenderServicePolicyV1::from_canonical_bytes(
            &current
                .payload_bytes()
                .map_err(|error| ChatError::Trust(error.to_string()))?,
        )
        .map_err(ChatError::Trust)?;
        if policy.canonical_domain != expected_domain {
            return Err(ChatError::Trust(
                "sealed sender policy payload has the wrong canonical domain".into(),
            ));
        }
        let active_roots = policy
            .roots
            .iter()
            .filter(|root| {
                root.activates_at <= now_seconds
                    && root.revokes_at.is_none_or(|revokes| revokes > now_seconds)
            })
            .map(|root| {
                let bytes = STANDARD
                    .decode(&root.public_key)
                    .map_err(|_| ChatError::Trust("sealed sender root is not base64".into()))?;
                crypto(PublicKey::deserialize(&bytes))
            })
            .collect::<Result<Vec<_>>>()?;
        if active_roots.is_empty() {
            return Err(ChatError::Trust(
                "sealed sender policy has no currently active trust root".into(),
            ));
        }
        Ok(Self {
            sequence: current.sequence,
            policy,
            active_roots,
        })
    }

    pub fn validate_certificate_response(
        &self,
        response: &SenderCertificateResponseV1,
        expected_sender: &str,
        expected_device_id: u32,
        expected_identity: &PublicKey,
        now_seconds: i64,
    ) -> Result<SenderCertificate> {
        if response.suite != self.policy.suite
            || response.service_policy_sequence != self.sequence
            || !response_expiry_is_valid(&self.policy, response.expires_at, now_seconds)
        {
            return Err(ChatError::Trust(
                "sender certificate response suite, policy, or expiry is invalid".into(),
            ));
        }
        let encoded = STANDARD
            .decode(&response.certificate)
            .map_err(|_| ChatError::Trust("sender certificate is not canonical base64".into()))?;
        if STANDARD.encode(&encoded) != response.certificate {
            return Err(ChatError::Trust(
                "sender certificate is not canonical base64".into(),
            ));
        }
        let certificate = SenderCertificate::deserialize(&encoded)?;
        self.validate_certificate(
            &certificate,
            expected_sender,
            expected_device_id,
            expected_identity,
            now_seconds,
        )?;
        if certificate.expiration()?.epoch_millis()
            != u64::try_from(response.expires_at)
                .ok()
                .and_then(|value| value.checked_mul(1000))
                .ok_or_else(|| ChatError::Trust("sender certificate expiry is invalid".into()))?
        {
            return Err(ChatError::Trust(
                "sender certificate body and response expiry differ".into(),
            ));
        }
        Ok(certificate)
    }

    pub fn validate_certificate(
        &self,
        certificate: &SenderCertificate,
        expected_sender: &str,
        expected_device_id: u32,
        expected_identity: &PublicKey,
        now_seconds: i64,
    ) -> Result<()> {
        self.validating_root(
            certificate,
            expected_sender,
            expected_device_id,
            expected_identity,
            now_seconds,
        )?;
        Ok(())
    }

    pub fn validating_root(
        &self,
        certificate: &SenderCertificate,
        expected_sender: &str,
        expected_device_id: u32,
        expected_identity: &PublicKey,
        now_seconds: i64,
    ) -> Result<PublicKey> {
        if certificate.sender_uuid()? != expected_sender
            || u32::from(certificate.sender_device_id()?) != expected_device_id
            || certificate.key()?.serialize() != expected_identity.serialize()
        {
            return Err(ChatError::Trust(
                "sender certificate identity does not match the transparent account manifest"
                    .into(),
            ));
        }
        let sender_domain = expected_sender
            .split_once('@')
            .map(|(_, domain)| domain)
            .ok_or_else(|| {
                ChatError::Trust("sender certificate address is not canonical".into())
            })?;
        if sender_domain != self.policy.canonical_domain {
            return Err(ChatError::Trust(
                "sender certificate domain does not match its service policy".into(),
            ));
        }
        let signer = certificate.signer()?;
        let signer_id = signer.key_id()?;
        let signer_serialized = STANDARD.encode(signer.serialized()?);
        let allowed = self.policy.server_certificates.iter().any(|reference| {
            reference.certificate_id == signer_id
                && reference.certificate == signer_serialized
                && reference.activates_at <= now_seconds
                && reference.expires_at > now_seconds
        });
        let timestamp = Timestamp::from_epoch_millis(
            u64::try_from(now_seconds)
                .ok()
                .and_then(|value| value.checked_mul(1000))
                .ok_or_else(|| ChatError::Trust("certificate validation time is invalid".into()))?,
        );
        if !allowed {
            return Err(ChatError::Trust(
                "sender certificate is not valid under the authenticated service policy".into(),
            ));
        }
        for root in &self.active_roots {
            if certificate.validate(root, timestamp)? {
                return Ok(*root);
            }
        }
        Err(ChatError::Trust(
            "sender certificate is not valid under the authenticated service policy".into(),
        ))
    }
}

fn response_expiry_is_valid(
    policy: &SealedSenderServicePolicyV1,
    expires_at: i64,
    now_seconds: i64,
) -> bool {
    let latest = now_seconds
        .checked_add(i64::from(policy.sender_certificate_lifetime_seconds))
        .and_then(|value| value.checked_add(i64::from(policy.maximum_clock_skew_seconds)));
    expires_at > now_seconds && latest.is_some_and(|latest| expires_at <= latest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kutup_chat_proto::{DirectChatSuiteId, SealedSenderRootV1, SealedSenderSuiteId};

    fn policy() -> SealedSenderServicePolicyV1 {
        SealedSenderServicePolicyV1 {
            policy_version: 1,
            canonical_domain: "a.test".into(),
            suite: SealedSenderSuiteId::LibsignalV2DeliveryCapabilityV1,
            roots: vec![SealedSenderRootV1 {
                root_id: "root".into(),
                public_key: "key".into(),
                activates_at: 0,
                revokes_at: None,
            }],
            server_certificates: vec![],
            sender_certificate_lifetime_seconds: 86_400,
            maximum_clock_skew_seconds: 300,
            direct_chat_suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
        }
    }

    #[test]
    fn response_expiry_accepts_authenticated_clock_skew() {
        let policy = policy();
        assert!(response_expiry_is_valid(&policy, 186_401, 100_000));
        assert!(response_expiry_is_valid(&policy, 186_700, 100_000));
    }

    #[test]
    fn response_expiry_rejects_expired_excessive_and_overflowing_values() {
        let policy = policy();
        assert!(!response_expiry_is_valid(&policy, 100_000, 100_000));
        assert!(!response_expiry_is_valid(&policy, 186_701, 100_000));
        assert!(!response_expiry_is_valid(&policy, i64::MAX, i64::MAX - 1));
    }
}
