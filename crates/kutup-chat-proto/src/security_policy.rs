//! Feature-owned payloads carried by the common authenticated federation
//! policy envelope.

use std::collections::BTreeSet;

use base64::Engine as _;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::DirectChatSuiteId;

pub const SEALED_SENDER_SERVICE_POLICY_VERSION: u16 = 1;

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
    // Purpose-specific policy vectors live beside each remaining policy type.
}
