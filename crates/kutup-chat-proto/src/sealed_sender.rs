//! Contacts-only sealed delivery wire structures and capability derivation.

use base64::Engine as _;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{AccountAddress, DirectChatSuiteId};

pub const DELIVERY_CAPABILITY_CONTEXT: &[u8] = b"kutup/sealed-delivery-capability/v1";

pub fn derive_delivery_capability(
    profile_key: &[u8; 32],
    canonical_recipient: &str,
) -> Result<[u8; 16], String> {
    let address: AccountAddress = canonical_recipient
        .parse()
        .map_err(|error: crate::AddressError| error.to_string())?;
    if address.server.is_none() || address.canonical() != canonical_recipient {
        return Err(
            "sealed delivery capability requires a canonical federated recipient address".into(),
        );
    }
    let hkdf = Hkdf::<Sha256>::new(Some(canonical_recipient.as_bytes()), profile_key);
    let mut output = [0u8; 16];
    hkdf.expand(DELIVERY_CAPABILITY_CONTEXT, &mut output)
        .map_err(|_| "sealed delivery capability derivation failed".to_string())?;
    Ok(output)
}

pub fn capability_hash(capability: &[u8; 16]) -> [u8; 32] {
    Sha256::digest(capability).into()
}

pub fn constant_time_capability_hash_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedOutgoingEnvelopeV1 {
    pub device_id: u32,
    pub registration_id: u32,
    pub suite: DirectChatSuiteId,
    /// Serialized libsignal sealed-sender message, canonical padded base64.
    pub content: String,
}

impl SealedOutgoingEnvelopeV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.device_id == 0 || self.device_id > 127 || self.registration_id >= 16_384 {
            return Err("sealed envelope has an invalid device or registration id".into());
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.content)
            .map_err(|_| "sealed envelope content must be canonical padded base64")?;
        if bytes.is_empty()
            || bytes.len() > 1024 * 1024
            || base64::engine::general_purpose::STANDARD.encode(bytes) != self.content
        {
            return Err("sealed envelope content is empty, oversized, or non-canonical".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedMessageSubmissionV1 {
    pub send_id: String,
    /// Raw 16-byte capability, canonical padded base64. It is never persisted.
    pub capability: String,
    pub envelopes: Vec<SealedOutgoingEnvelopeV1>,
}

/// Body for the cookie- and bearer-free anonymous prekey endpoint. Keeping the
/// capability in the body prevents it from entering access-log URLs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnonymousPreKeyRequestV1 {
    pub capability: String,
    #[serde(
        default,
        serialize_with = "serialize_decimal_u64",
        deserialize_with = "deserialize_decimal_u64"
    )]
    pub transparency_tree_size: u64,
}

impl AnonymousPreKeyRequestV1 {
    pub fn capability_bytes(&self) -> Result<[u8; 16], String> {
        SealedMessageSubmissionV1 {
            send_id: "00000000-0000-0000-0000-000000000000".into(),
            capability: self.capability.clone(),
            envelopes: Vec::new(),
        }
        .capability_bytes()
    }
}

impl SealedMessageSubmissionV1 {
    pub fn capability_bytes(&self) -> Result<[u8; 16], String> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.capability)
            .map_err(|_| "delivery capability must be canonical padded base64")?;
        if base64::engine::general_purpose::STANDARD.encode(&bytes) != self.capability {
            return Err("delivery capability must be canonical padded base64".into());
        }
        bytes
            .try_into()
            .map_err(|_| "delivery capability must be exactly 16 bytes".into())
    }

    pub fn validate(&self) -> Result<(), String> {
        if uuid_shape(&self.send_id).is_none() {
            return Err("sealed sendId must be a lowercase hyphenated UUID".into());
        }
        self.capability_bytes()?;
        if self.envelopes.is_empty() || self.envelopes.len() > 32 {
            return Err("sealed send requires 1-32 envelopes".into());
        }
        let mut devices = std::collections::BTreeSet::new();
        let mut total = 0usize;
        for envelope in &self.envelopes {
            envelope.validate()?;
            if !devices.insert(envelope.device_id) {
                return Err("sealed send repeats a device".into());
            }
            total = total.saturating_add(envelope.content.len());
        }
        if total > 1024 * 1024 {
            return Err("sealed send exceeds the 1 MiB encoded envelope budget".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedSealedTransactionV1 {
    pub version: u16,
    pub origin: String,
    /// Local username at the destination, never a sender identity.
    pub recipient: String,
    pub sequence: u64,
    pub send_id: String,
    pub capability: String,
    pub envelopes: Vec<SealedOutgoingEnvelopeV1>,
}

impl FederatedSealedTransactionV1 {
    pub fn validate(
        &self,
        expected_origin: &str,
        expected_destination: &str,
    ) -> Result<(), String> {
        if self.version != 1 || self.sequence == 0 || self.origin != expected_origin {
            return Err(
                "sealed federation transaction version, origin, or sequence is invalid".into(),
            );
        }
        kutup_federation_proto::validate_server_name(expected_destination)
            .map_err(|error| error.to_string())?;
        let recipient =
            AccountAddress::local(&self.recipient).map_err(|error| error.to_string())?;
        SealedMessageSubmissionV1 {
            send_id: self.send_id.clone(),
            capability: self.capability.clone(),
            envelopes: self.envelopes.clone(),
        }
        .validate()?;
        if recipient.server.is_some() {
            return Err("sealed federation recipient must be local".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SenderCertificateResponseV1 {
    pub suite: crate::SealedSenderSuiteId,
    pub certificate: String,
    pub expires_at: i64,
    pub service_policy_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedDeliveryResponseV1 {
    pub stored: usize,
    pub deduplicated: bool,
}

fn uuid_shape(value: &str) -> Option<()> {
    if value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
    {
        Some(())
    } else {
        None
    }
}

fn serialize_decimal_u64<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&value.to_string())
}

fn deserialize_decimal_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(serde::de::Error::custom(
            "transparencyTreeSize must be a canonical decimal u64 string",
        ));
    }
    value.parse().map_err(|_| {
        serde::de::Error::custom("transparencyTreeSize must be a canonical decimal u64 string")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_vector_is_domain_and_recipient_bound() {
        let first = derive_delivery_capability(&[7; 32], "alice@example.com").unwrap();
        assert_eq!(hex::encode(first), "49970b0f7ca86853933be7f8fd741f7f");
        let second = derive_delivery_capability(&[7; 32], "bob@example.com").unwrap();
        assert_ne!(first, second);
        assert!(constant_time_capability_hash_eq(
            &capability_hash(&first),
            &capability_hash(&first)
        ));
        assert!(!constant_time_capability_hash_eq(
            &capability_hash(&first),
            &capability_hash(&second)
        ));
    }

    #[test]
    fn anonymous_prekey_cursor_has_one_lossless_canonical_encoding() {
        let request = AnonymousPreKeyRequestV1 {
            capability: "SZcLD3yoaFOTO+f4/XQffw==".into(),
            transparency_tree_size: u64::MAX,
        };
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"capability":"SZcLD3yoaFOTO+f4/XQffw==","transparencyTreeSize":"18446744073709551615"}"#
        );
        assert_eq!(
            serde_json::from_str::<AnonymousPreKeyRequestV1>(
                r#"{"capability":"SZcLD3yoaFOTO+f4/XQffw==","transparencyTreeSize":"18446744073709551615"}"#
            )
            .unwrap(),
            request
        );
        for invalid in [
            r#"{"capability":"SZcLD3yoaFOTO+f4/XQffw==","transparencyTreeSize":2}"#,
            r#"{"capability":"SZcLD3yoaFOTO+f4/XQffw==","transparencyTreeSize":"02"}"#,
            r#"{"capability":"SZcLD3yoaFOTO+f4/XQffw==","transparencyTreeSize":"18446744073709551616"}"#,
        ] {
            assert!(serde_json::from_str::<AnonymousPreKeyRequestV1>(invalid).is_err());
        }
    }
}
