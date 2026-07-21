//! Pure wire, identity, discovery, and authentication primitives for Kutup's
//! unified federation protocol.
//!
//! This crate performs no DNS, HTTP, database, policy, or feature work. Chat
//! and Drive are opaque feature protocols above this boundary.

mod discovery;
mod error;
mod http_signatures;
mod identity;

use std::net::IpAddr;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub use discovery::{
    FederationCapabilityId, FederationDiscoveryTransportPolicy, FederationDiscoveryV2,
};
pub use error::FederationProtocolError;
pub use http_signatures::{
    content_digest_sha256, content_digest_sha256_from_digest, FederationFeature,
    FederationHttpRequest, FederationHttpResponse, FederationReplayMetadata,
    FederationSignatureHeaders, FederationSignedRequest, FederationVerifiedRequest,
};
pub use identity::{
    verify_identity_chain, FederationIdentityDocumentV1, FederationIdentityKeyAlgorithm,
    FederationIdentityKeyV1, FederationIdentityVersion,
};

use error::invalid_field;

/// The only accepted unified federation wire version.
pub const FEDERATION_VERSION: u16 = 2;
/// The only accepted identity-document format.
pub const FEDERATION_IDENTITY_VERSION: u16 = 1;
/// RFC 9421 application tag and fixed signature label for this profile.
pub const FEDERATION_SIGNATURE_TAG: &str = "kutup-federation-v2";
pub const FEDERATION_SIGNATURE_LABEL: &str = "kutup";
/// Both request and response signatures have a maximum five-minute lifetime.
pub const MAX_SIGNATURE_LIFETIME_SECONDS: i64 = 5 * 60;
/// Discovery documents have a maximum 24-hour validity window.
pub const MAX_DISCOVERY_LIFETIME_SECONDS: i64 = 24 * 60 * 60;
/// Small allowance for clock disagreement; it does not extend the signed
/// lifetime itself.
pub const CLOCK_SKEW_SECONDS: i64 = 60;

/// Closed protocol version. An unknown or old value is never interpreted as
/// the current profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum FederationProtocolVersion {
    V2 = FEDERATION_VERSION,
}

impl FederationProtocolVersion {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    pub const fn auth_profile(self) -> FederationAuthProfileId {
        match self {
            Self::V2 => FederationAuthProfileId::HttpSignaturesV2,
        }
    }
}

impl From<FederationProtocolVersion> for u16 {
    fn from(value: FederationProtocolVersion) -> Self {
        value.as_u16()
    }
}

impl TryFrom<u16> for FederationProtocolVersion {
    type Error = FederationProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            FEDERATION_VERSION => Ok(Self::V2),
            other => Err(FederationProtocolError::UnknownFederationVersion(other)),
        }
    }
}

/// Purpose-specific registry for server-to-server authentication. It is not
/// serialized separately: federation version 2 selects exactly this profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum FederationAuthProfileId {
    HttpSignaturesV2 = 1,
}

impl FederationAuthProfileId {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for FederationAuthProfileId {
    type Error = FederationProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::HttpSignaturesV2),
            other => Err(FederationProtocolError::UnknownAuthProfile(other)),
        }
    }
}

pub fn auth_profile_for_version(
    version: u16,
) -> Result<FederationAuthProfileId, FederationProtocolError> {
    Ok(FederationProtocolVersion::try_from(version)?.auth_profile())
}

/// Lowercase SHA-256 fingerprint of a raw Ed25519 public key.
pub fn federation_key_id(public_key: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(public_key))
}

/// Human-readable full fingerprint. No abbreviated fingerprint is accepted by
/// protocol APIs; this is display formatting only.
pub fn grouped_fingerprint(fingerprint: &str) -> Result<String, FederationProtocolError> {
    validate_hash("fingerprint", fingerprint)?;
    Ok(fingerprint
        .as_bytes()
        .chunks(8)
        .map(|chunk| std::str::from_utf8(chunk).expect("hex is ASCII"))
        .collect::<Vec<_>>()
        .join(" "))
}

/// Validate a canonical lowercase DNS identity. IP literals, trailing dots,
/// Unicode, uppercase, and path/port syntax are rejected.
pub fn validate_server_name(server: &str) -> Result<(), FederationProtocolError> {
    if server.is_empty() || server.len() > 253 || !server.is_ascii() {
        return Err(invalid_field(
            "server",
            "must be a 1-253 byte ASCII DNS name",
        ));
    }
    if server.parse::<IpAddr>().is_ok()
        || server.starts_with('.')
        || server.ends_with('.')
        || !server.contains('.')
    {
        return Err(invalid_field(
            "server",
            "must be a canonical DNS name, not an IP or single label",
        ));
    }
    for label in server.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(invalid_field(
                "server",
                "contains a non-canonical DNS label",
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_hash(
    field: &'static str,
    value: &str,
) -> Result<[u8; 32], FederationProtocolError> {
    let decoded =
        hex::decode(value).map_err(|_| invalid_field(field, "must be lowercase SHA-256 hex"))?;
    if decoded.len() != 32 || hex::encode(&decoded) != value {
        return Err(invalid_field(field, "must be lowercase SHA-256 hex"));
    }
    decoded
        .try_into()
        .map_err(|_| invalid_field(field, "must be 32 bytes"))
}

pub(crate) fn decode_base64<const N: usize>(
    field: &'static str,
    value: &str,
) -> Result<[u8; N], FederationProtocolError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| FederationProtocolError::InvalidBase64(field))?;
    if bytes.len() != N || base64::engine::general_purpose::STANDARD.encode(&bytes) != value {
        return Err(invalid_field(
            field,
            "has a non-canonical length or encoding",
        ));
    }
    bytes
        .try_into()
        .map_err(|_| invalid_field(field, "has the wrong decoded length"))
}

pub(crate) fn push_string(
    out: &mut Vec<u8>,
    field: &'static str,
    value: &str,
) -> Result<(), FederationProtocolError> {
    let len = u32::try_from(value.len()).map_err(|_| invalid_field(field, "is too long"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_selects_one_profile_without_fallback() {
        assert_eq!(
            auth_profile_for_version(2).unwrap(),
            FederationAuthProfileId::HttpSignaturesV2
        );
        for version in [0, 1, 3, u16::MAX] {
            assert_eq!(
                auth_profile_for_version(version).unwrap_err(),
                FederationProtocolError::UnknownFederationVersion(version)
            );
            assert!(
                serde_json::from_str::<FederationProtocolVersion>(&version.to_string()).is_err()
            );
        }
        assert_eq!(
            serde_json::to_string(&FederationProtocolVersion::V2).unwrap(),
            "2"
        );
    }

    #[test]
    fn canonical_server_names_and_full_fingerprints_are_strict() {
        validate_server_name("chat.example").unwrap();
        for invalid in [
            "Chat.example",
            "chat",
            "chat.example.",
            "127.0.0.1",
            "chat_example.org",
            "-chat.example",
            "chat.example:443",
        ] {
            assert!(validate_server_name(invalid).is_err(), "accepted {invalid}");
        }
        let value = "01".repeat(32);
        assert_eq!(grouped_fingerprint(&value).unwrap().replace(' ', ""), value);
        assert!(grouped_fingerprint(&"01".repeat(16)).is_err());
    }
}
