//! Authentication envelope for opaque feature security policies.
//!
//! The federation layer authenticates the domain, feature type, sequence,
//! predecessor, identity generation, and exact payload bytes. It intentionally
//! does not parse the feature-owned payload.

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    decode_base64, federation_key_id, push_string, validate_hash, validate_server_name,
    FederationIdentityDocumentV1, FederationProtocolError,
};

const POLICY_SIGNING_DOMAIN: &[u8] = b"kutup-federated-feature-policy-envelope-v1\0";
const POLICY_HASH_DOMAIN: &[u8] = b"kutup-federated-feature-policy-envelope-hash-v1\0";

pub const FEDERATED_FEATURE_POLICY_VERSION: u16 = 1;
pub const MAX_FEDERATED_FEATURE_POLICY_PAYLOAD_BYTES: usize = 256 * 1024;

/// Complete independently verifiable identity and feature-policy history for
/// a domain. Same-origin clients receive this bundle rather than trusting a
/// server-computed status label or only the latest policy document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedFeaturePolicyHistoryV1 {
    pub domain: String,
    pub feature_type: FederatedFeaturePolicyTypeV1,
    pub identities: Vec<FederationIdentityDocumentV1>,
    pub policies: Vec<FederatedFeaturePolicyEnvelopeV1>,
}

impl FederatedFeaturePolicyHistoryV1 {
    pub fn verify(&self) -> Result<&FederatedFeaturePolicyEnvelopeV1, FederationProtocolError> {
        validate_server_name(&self.domain)?;
        if self.identities.is_empty()
            || self.policies.is_empty()
            || self.identities.len() > 1024
            || self.policies.len() > 1024
        {
            return Err(crate::error::invalid_field(
                "policyHistory",
                "must contain bounded, non-empty identity and policy chains",
            ));
        }
        crate::verify_identity_chain(&self.domain, &self.identities)?;
        let mut previous = None;
        for policy in &self.policies {
            if policy.domain != self.domain || policy.feature_type != self.feature_type {
                return Err(crate::error::invalid_field(
                    "policies",
                    "contains the wrong domain or feature type",
                ));
            }
            let identity = self
                .identities
                .iter()
                .find(|identity| identity.sequence == policy.federation_identity_generation)
                .ok_or_else(|| {
                    crate::error::invalid_field(
                        "federationIdentityGeneration",
                        "is absent from the authenticated identity history",
                    )
                })?;
            policy.verify_successor(previous, identity)?;
            previous = Some(policy);
        }
        previous.ok_or_else(|| crate::error::invalid_field("policies", "is empty"))
    }
}

/// Closed registry. Unknown numeric values fail during deserialization rather
/// than being treated as a policy for a known feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum FederatedFeaturePolicyTypeV1 {
    ChatTransparency = 1,
    SealedSenderService = 2,
}

impl FederatedFeaturePolicyTypeV1 {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl From<FederatedFeaturePolicyTypeV1> for u16 {
    fn from(value: FederatedFeaturePolicyTypeV1) -> Self {
        value.as_u16()
    }
}

impl TryFrom<u16> for FederatedFeaturePolicyTypeV1 {
    type Error = FederationProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ChatTransparency),
            2 => Ok(Self::SealedSenderService),
            _ => Err(crate::error::invalid_field(
                "featureType",
                "is not a supported feature policy type",
            )),
        }
    }
}

/// Purpose-scoped signing surface. Backends may keep key material in a
/// protected provider; callers never need an exportable private key.
pub trait FederationAuthSigner {
    fn key_id(&self) -> String;
    fn sign_federation_auth(&self, message: &[u8]) -> Result<[u8; 64], FederationProtocolError>;
}

/// Protected-memory software backend. PKCS#11 providers implement the same
/// narrow trait and must return an error rather than export/fallback.
pub struct Ed25519FederationAuthSigner(SigningKey);

impl Ed25519FederationAuthSigner {
    pub fn new(signing_key: SigningKey) -> Self {
        Self(signing_key)
    }

    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
}

impl FederationAuthSigner for Ed25519FederationAuthSigner {
    fn key_id(&self) -> String {
        federation_key_id(&self.verifying_key_bytes())
    }

    fn sign_federation_auth(&self, message: &[u8]) -> Result<[u8; 64], FederationProtocolError> {
        Ok(self.0.sign(message).to_bytes())
    }
}

impl FederationAuthSigner for SigningKey {
    fn key_id(&self) -> String {
        federation_key_id(&self.verifying_key().to_bytes())
    }

    fn sign_federation_auth(&self, message: &[u8]) -> Result<[u8; 64], FederationProtocolError> {
        Ok(self.sign(message).to_bytes())
    }
}

/// Exact, federation-identity-authenticated feature policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedFeaturePolicyEnvelopeV1 {
    pub policy_version: u16,
    pub domain: String,
    pub feature_type: FederatedFeaturePolicyTypeV1,
    pub sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_policy_hash: Option<String>,
    pub federation_identity_generation: u64,
    /// Canonical feature-owned bytes, padded base64.
    pub payload: String,
    pub payload_digest: String,
    pub issued_at: i64,
    pub signer_key_id: String,
    pub signature: String,
}

impl FederatedFeaturePolicyEnvelopeV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        domain: impl Into<String>,
        feature_type: FederatedFeaturePolicyTypeV1,
        sequence: u64,
        previous_policy_hash: Option<String>,
        identity: &FederationIdentityDocumentV1,
        payload: &[u8],
        issued_at: i64,
        signer: &impl FederationAuthSigner,
    ) -> Result<Self, FederationProtocolError> {
        let mut envelope = Self {
            policy_version: FEDERATED_FEATURE_POLICY_VERSION,
            domain: domain.into(),
            feature_type,
            sequence,
            previous_policy_hash,
            federation_identity_generation: identity.sequence,
            payload: base64::engine::general_purpose::STANDARD.encode(payload),
            payload_digest: hex::encode(Sha256::digest(payload)),
            issued_at,
            signer_key_id: signer.key_id(),
            signature: String::new(),
        };
        envelope.validate_signing_shape()?;
        if envelope.domain != identity.server
            || envelope.federation_identity_generation != identity.sequence
            || envelope.signer_key_id != identity.key.key_id
        {
            return Err(FederationProtocolError::InvalidIdentityChain(
                "policy signer does not match its federation identity generation",
            ));
        }
        envelope.signature = base64::engine::general_purpose::STANDARD
            .encode(signer.sign_federation_auth(&envelope.signing_bytes()?)?);
        envelope.verify(identity)?;
        Ok(envelope)
    }

    pub fn payload_bytes(&self) -> Result<Vec<u8>, FederationProtocolError> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.payload)
            .map_err(|_| FederationProtocolError::InvalidBase64("payload"))?;
        if bytes.len() > MAX_FEDERATED_FEATURE_POLICY_PAYLOAD_BYTES
            || base64::engine::general_purpose::STANDARD.encode(&bytes) != self.payload
        {
            return Err(crate::error::invalid_field(
                "payload",
                "is too large or not canonical padded base64",
            ));
        }
        if Sha256::digest(&bytes).as_slice()
            != validate_hash("payloadDigest", &self.payload_digest)?.as_slice()
        {
            return Err(FederationProtocolError::ContentDigestMismatch);
        }
        Ok(bytes)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, FederationProtocolError> {
        self.validate_signing_shape()?;
        let mut out = Vec::with_capacity(256 + self.payload.len());
        out.extend_from_slice(POLICY_SIGNING_DOMAIN);
        out.extend_from_slice(&self.policy_version.to_be_bytes());
        push_string(&mut out, "domain", &self.domain)?;
        out.extend_from_slice(&self.feature_type.as_u16().to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        match &self.previous_policy_hash {
            Some(hash) => {
                out.push(1);
                out.extend_from_slice(&validate_hash("previousPolicyHash", hash)?);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.federation_identity_generation.to_be_bytes());
        out.extend_from_slice(&validate_hash("payloadDigest", &self.payload_digest)?);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&validate_hash("signerKeyId", &self.signer_key_id)?);
        // Bind the exact canonical payload, not only the redundant digest.
        let payload = self.payload_bytes()?;
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        Ok(out)
    }

    pub fn policy_hash(&self) -> Result<String, FederationProtocolError> {
        self.validate_shape()?;
        let mut bytes = Vec::with_capacity(384 + self.payload.len());
        bytes.extend_from_slice(POLICY_HASH_DOMAIN);
        bytes.extend_from_slice(&self.signing_bytes()?);
        bytes.extend_from_slice(&decode_base64::<64>("signature", &self.signature)?);
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    /// `identity` must already have been accepted by the federation identity
    /// chain verifier. This function never performs TOFU on a key carried by a
    /// policy.
    pub fn verify(
        &self,
        identity: &FederationIdentityDocumentV1,
    ) -> Result<(), FederationProtocolError> {
        self.validate_shape()?;
        identity.verify_current()?;
        if self.domain != identity.server
            || self.federation_identity_generation != identity.sequence
            || self.signer_key_id != identity.key.key_id
        {
            return Err(FederationProtocolError::InvalidIdentityChain(
                "policy does not match the authenticated federation identity",
            ));
        }
        let signature = Signature::from_bytes(&decode_base64::<64>("signature", &self.signature)?);
        identity
            .key
            .verifying_key()?
            .verify_strict(&self.signing_bytes()?, &signature)
            .map_err(|_| FederationProtocolError::InvalidIdentitySignature("feature policy"))
    }

    pub fn verify_successor(
        &self,
        previous: Option<&Self>,
        identity: &FederationIdentityDocumentV1,
    ) -> Result<(), FederationProtocolError> {
        self.verify(identity)?;
        match previous {
            None => {
                if self.sequence != 1 || self.previous_policy_hash.is_some() {
                    return Err(FederationProtocolError::InvalidIdentityChain(
                        "feature policy genesis must be sequence one without a predecessor",
                    ));
                }
            }
            Some(previous) => {
                if previous.domain != self.domain || previous.feature_type != self.feature_type {
                    return Err(FederationProtocolError::InvalidIdentityChain(
                        "feature policy predecessor has the wrong domain or type",
                    ));
                }
                if self.sequence
                    != previous.sequence.checked_add(1).ok_or(
                        FederationProtocolError::InvalidIdentityChain(
                            "feature policy sequence overflow",
                        ),
                    )?
                {
                    return Err(FederationProtocolError::InvalidIdentityChain(
                        "feature policy sequence must advance by exactly one",
                    ));
                }
                if self.previous_policy_hash.as_deref() != Some(&previous.policy_hash()?) {
                    return Err(FederationProtocolError::InvalidIdentityChain(
                        "feature policy predecessor hash does not match",
                    ));
                }
                if self.issued_at < previous.issued_at
                    || self.federation_identity_generation < previous.federation_identity_generation
                {
                    return Err(FederationProtocolError::InvalidIdentityChain(
                        "feature policy time or identity generation rolled back",
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_signing_shape(&self) -> Result<(), FederationProtocolError> {
        if self.policy_version != FEDERATED_FEATURE_POLICY_VERSION {
            return Err(crate::error::invalid_field(
                "policyVersion",
                "is not supported",
            ));
        }
        validate_server_name(&self.domain)?;
        if self.sequence == 0 || self.issued_at < 0 {
            return Err(crate::error::invalid_field(
                "sequence",
                "policy sequence must be positive and issuedAt non-negative",
            ));
        }
        if self.sequence == 1 && self.previous_policy_hash.is_some() {
            return Err(FederationProtocolError::InvalidIdentityChain(
                "feature policy genesis cannot contain a predecessor",
            ));
        }
        if self.sequence > 1 && self.previous_policy_hash.is_none() {
            return Err(FederationProtocolError::InvalidIdentityChain(
                "feature policy successor requires a predecessor",
            ));
        }
        validate_hash("signerKeyId", &self.signer_key_id)?;
        self.payload_bytes()?;
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), FederationProtocolError> {
        self.validate_signing_shape()?;
        decode_base64::<64>("signature", &self.signature)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(key: &SigningKey) -> FederationIdentityDocumentV1 {
        FederationIdentityDocumentV1::genesis("alpha.example", 10, key).unwrap()
    }

    #[test]
    fn deterministic_vector_and_contiguous_chain() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let identity = identity(&key);
        let first = FederatedFeaturePolicyEnvelopeV1::sign(
            "alpha.example",
            FederatedFeaturePolicyTypeV1::ChatTransparency,
            1,
            None,
            &identity,
            b"canonical policy bytes",
            20,
            &key,
        )
        .unwrap();
        first.verify_successor(None, &identity).unwrap();
        assert_eq!(
            first.signing_bytes().unwrap(),
            first.signing_bytes().unwrap()
        );
        let second = FederatedFeaturePolicyEnvelopeV1::sign(
            "alpha.example",
            first.feature_type,
            2,
            Some(first.policy_hash().unwrap()),
            &identity,
            b"next canonical policy bytes",
            21,
            &key,
        )
        .unwrap();
        second.verify_successor(Some(&first), &identity).unwrap();
    }

    #[test]
    fn rollback_gap_wrong_domain_type_digest_and_signature_fail() {
        let key = SigningKey::from_bytes(&[8; 32]);
        let identity = identity(&key);
        let first = FederatedFeaturePolicyEnvelopeV1::sign(
            "alpha.example",
            FederatedFeaturePolicyTypeV1::ChatTransparency,
            1,
            None,
            &identity,
            b"one",
            20,
            &key,
        )
        .unwrap();
        let mut bad = first.clone();
        bad.domain = "beta.example".into();
        assert!(bad.verify(&identity).is_err());
        let mut bad = first.clone();
        bad.payload_digest = "00".repeat(32);
        assert!(bad.verify(&identity).is_err());
        let mut bad = first.clone();
        bad.signature = base64::engine::general_purpose::STANDARD.encode([0; 64]);
        assert!(bad.verify(&identity).is_err());
        let mut gap = first.clone();
        gap.sequence = 3;
        gap.previous_policy_hash = Some(first.policy_hash().unwrap());
        assert!(gap.verify_successor(Some(&first), &identity).is_err());
    }
}
