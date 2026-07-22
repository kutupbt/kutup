//! Feature-owned payloads carried by the common authenticated federation
//! policy envelope.

use std::collections::BTreeSet;

use base64::Engine as _;
use ed25519_dalek::VerifyingKey;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::{transparency_signing_key_id, DirectChatSuiteId};

pub const CHAT_TRANSPARENCY_POLICY_VERSION: u16 = 1;
pub const SEALED_SENDER_SERVICE_POLICY_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum TransparencyProofProfileV1 {
    Rfc6962IndividualInclusionV1 = 1,
}

impl From<TransparencyProofProfileV1> for u16 {
    fn from(value: TransparencyProofProfileV1) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for TransparencyProofProfileV1 {
    type Error = String;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Rfc6962IndividualInclusionV1),
            _ => Err(format!("unknown transparency proof profile {value}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransparencyWitnessPolicyV1 {
    pub witness_id: String,
    pub key_id: String,
    pub public_key: String,
    pub public_endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatTransparencyPolicyV1 {
    pub policy_version: u16,
    pub log_id: String,
    pub operator_key_id: String,
    pub operator_public_key: String,
    pub witnesses: Vec<TransparencyWitnessPolicyV1>,
    pub required_quorum: u16,
    pub proof_profile: TransparencyProofProfileV1,
    pub maximum_checkpoint_age_seconds: u64,
    pub maximum_clock_skew_seconds: u32,
    pub maximum_range_page_entries: u16,
    pub maximum_range_response_bytes: u32,
}

impl ChatTransparencyPolicyV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.policy_version != CHAT_TRANSPARENCY_POLICY_VERSION {
            return Err("unsupported chat transparency policy version".into());
        }
        decode_hash("logId", &self.log_id)?;
        validate_ed25519_key("operator", &self.operator_key_id, &self.operator_public_key)?;
        if self.witnesses.is_empty()
            || self.required_quorum == 0
            || usize::from(self.required_quorum) > self.witnesses.len()
        {
            return Err(
                "production transparency policy requires a satisfiable independent witness quorum"
                    .into(),
            );
        }
        if self.maximum_checkpoint_age_seconds < 60
            || self.maximum_checkpoint_age_seconds > 7 * 24 * 60 * 60
            || self.maximum_clock_skew_seconds > 15 * 60
            || self.maximum_range_page_entries == 0
            || self.maximum_range_page_entries > 64
            || self.maximum_range_response_bytes < 4096
            || self.maximum_range_response_bytes > 8 * 1024 * 1024
        {
            return Err("transparency policy security parameters are outside the v1 bounds".into());
        }
        let mut ids = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for witness in &self.witnesses {
            if !ids.insert(witness.witness_id.as_str()) {
                return Err("transparency policy repeats a witness id".into());
            }
            validate_ed25519_key("witness", &witness.key_id, &witness.public_key)?;
            if !keys.insert(witness.key_id.as_str()) || witness.key_id == self.operator_key_id {
                return Err(
                    "transparency witness keys must be unique and independent of the operator"
                        .into(),
                );
            }
            validate_https_endpoint(&witness.public_endpoint)?;
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        decode_canonical(bytes, Self::validate)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum SealedSenderSuiteId {
    LibsignalV2DeliveryCapabilityV1 = 1,
}

impl From<SealedSenderSuiteId> for u16 {
    fn from(value: SealedSenderSuiteId) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for SealedSenderSuiteId {
    type Error = String;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::LibsignalV2DeliveryCapabilityV1),
            _ => Err(format!("unknown sealed sender suite {value}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedSenderRootV1 {
    pub root_id: String,
    /// Serialized libsignal X25519 public key (including its type byte).
    pub public_key: String,
    pub activates_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revokes_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedSenderServerCertificateV1 {
    pub certificate_id: u32,
    pub root_id: String,
    pub certificate: String,
    pub activates_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedSenderServicePolicyV1 {
    pub policy_version: u16,
    pub canonical_domain: String,
    pub suite: SealedSenderSuiteId,
    pub roots: Vec<SealedSenderRootV1>,
    pub server_certificates: Vec<SealedSenderServerCertificateV1>,
    pub sender_certificate_lifetime_seconds: u32,
    pub maximum_clock_skew_seconds: u32,
    pub direct_chat_suite: DirectChatSuiteId,
}

impl SealedSenderServicePolicyV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.policy_version != SEALED_SENDER_SERVICE_POLICY_VERSION {
            return Err("unsupported sealed sender service policy version".into());
        }
        kutup_federation_proto::validate_server_name(&self.canonical_domain)
            .map_err(|error| error.to_string())?;
        if self.roots.is_empty() || self.server_certificates.is_empty() {
            return Err(
                "sealed sender policy requires an active root and server certificate".into(),
            );
        }
        if self.sender_certificate_lifetime_seconds == 0
            || self.sender_certificate_lifetime_seconds > 24 * 60 * 60
            || self.maximum_clock_skew_seconds > 15 * 60
        {
            return Err(
                "sealed sender certificate lifetime or clock skew exceeds v1 limits".into(),
            );
        }
        let mut roots = BTreeSet::new();
        for root in &self.roots {
            decode_hash("rootId", &root.root_id)?;
            let key = decode_canonical_base64("root publicKey", &root.public_key, 33, 33)?;
            if hex::encode(Sha256::digest(&key)) != root.root_id
                || root.activates_at < 0
                || root
                    .revokes_at
                    .is_some_and(|value| value <= root.activates_at)
                || !roots.insert(root.root_id.as_str())
            {
                return Err(
                    "sealed sender root is malformed, duplicated, or has an invalid window".into(),
                );
            }
        }
        let mut cert_ids = BTreeSet::new();
        for cert in &self.server_certificates {
            if cert.certificate_id == 0
                || !cert_ids.insert(cert.certificate_id)
                || !roots.contains(cert.root_id.as_str())
                || cert.expires_at <= cert.activates_at
            {
                return Err(
                    "sealed sender server certificate is malformed or references an unknown root"
                        .into(),
                );
            }
            decode_canonical_base64("server certificate", &cert.certificate, 1, 16 * 1024)?;
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        decode_canonical(bytes, Self::validate)
    }
}

fn decode_canonical<T>(bytes: &[u8], validate: fn(&T) -> Result<(), String>) -> Result<T, String>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.len() > 256 * 1024 {
        return Err("feature policy payload is too large".into());
    }
    let value: T = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    validate(&value)?;
    let encoded = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
    if encoded != bytes {
        return Err("feature policy payload is not in canonical JSON encoding".into());
    }
    Ok(value)
}

fn validate_ed25519_key(name: &str, key_id: &str, encoded: &str) -> Result<(), String> {
    decode_hash(name, key_id)?;
    let bytes = decode_canonical_base64(name, encoded, 32, 32)?;
    let key = VerifyingKey::from_bytes(
        &bytes
            .try_into()
            .map_err(|_| format!("{name} key has the wrong length"))?,
    )
    .map_err(|_| format!("{name} key is not Ed25519"))?;
    if transparency_signing_key_id(&key) != key_id {
        return Err(format!("{name} key id does not match its public key"));
    }
    Ok(())
}

fn validate_https_endpoint(value: &str) -> Result<(), String> {
    let parsed = Url::parse(value).map_err(|_| "witness endpoint must be an absolute URL")?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.host_str().is_none()
        || parsed.path().ends_with('/')
    {
        return Err("witness endpoint must be canonical HTTPS without credentials, query, fragment, or trailing slash".into());
    }
    Ok(())
}

fn decode_hash(name: &str, value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|_| format!("{name} must be lowercase SHA-256 hex"))?;
    if bytes.len() != 32 || hex::encode(&bytes) != value {
        return Err(format!("{name} must be lowercase SHA-256 hex"));
    }
    bytes
        .try_into()
        .map_err(|_| format!("{name} has the wrong length"))
}

fn decode_canonical_base64(
    name: &str,
    value: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| format!("{name} must be canonical padded base64"))?;
    if bytes.len() < minimum
        || bytes.len() > maximum
        || base64::engine::general_purpose::STANDARD.encode(&bytes) != value
    {
        return Err(format!(
            "{name} must be canonical padded base64 within its size limit"
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn transparency_policy_has_one_canonical_encoding_and_independent_quorum() {
        let operator = SigningKey::from_bytes(&[1; 32]).verifying_key();
        let witness = SigningKey::from_bytes(&[2; 32]).verifying_key();
        let policy = ChatTransparencyPolicyV1 {
            policy_version: 1,
            log_id: "11".repeat(32),
            operator_key_id: transparency_signing_key_id(&operator),
            operator_public_key: base64::engine::general_purpose::STANDARD
                .encode(operator.as_bytes()),
            witnesses: vec![TransparencyWitnessPolicyV1 {
                witness_id: "witness.example".into(),
                key_id: transparency_signing_key_id(&witness),
                public_key: base64::engine::general_purpose::STANDARD.encode(witness.as_bytes()),
                public_endpoint: "https://witness.example/v1".into(),
            }],
            required_quorum: 1,
            proof_profile: TransparencyProofProfileV1::Rfc6962IndividualInclusionV1,
            maximum_checkpoint_age_seconds: 3600,
            maximum_clock_skew_seconds: 60,
            maximum_range_page_entries: 64,
            maximum_range_response_bytes: 2 * 1024 * 1024,
        };
        let bytes = policy.canonical_bytes().unwrap();
        assert_eq!(
            ChatTransparencyPolicyV1::from_canonical_bytes(&bytes).unwrap(),
            policy
        );
        let pretty = serde_json::to_vec_pretty(&policy).unwrap();
        assert!(ChatTransparencyPolicyV1::from_canonical_bytes(&pretty).is_err());
    }
}
