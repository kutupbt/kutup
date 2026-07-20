use std::{fmt, str::FromStr};

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    decode_base64, push_string, validate_hash, validate_server_name, FederationIdentityDocumentV1,
    FederationProtocolError, FederationProtocolVersion, CLOCK_SKEW_SECONDS,
    MAX_DISCOVERY_LIFETIME_SECONDS,
};

const DISCOVERY_SIGNING_DOMAIN: &[u8] = b"kutup-federation-discovery-v2\0";

/// A closed-format, extensible capability identifier. Capabilities select
/// feature protocols; they do not negotiate cryptographic primitives.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FederationCapabilityId(String);

impl FederationCapabilityId {
    pub fn chat_v1() -> Self {
        Self("chat.v1".into())
    }

    pub fn drive_v1() -> Self {
        Self("drive.v1".into())
    }

    pub fn identity_v1() -> Self {
        Self("identity.v1".into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FederationCapabilityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl From<FederationCapabilityId> for String {
    fn from(value: FederationCapabilityId) -> Self {
        value.0
    }
}

impl TryFrom<String> for FederationCapabilityId {
    type Error = FederationProtocolError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_capability(&value)?;
        Ok(Self(value))
    }
}

impl FromStr for FederationCapabilityId {
    type Err = FederationProtocolError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value.to_owned())
    }
}

/// Signed discovery is the only binding between a canonical server identity,
/// its HTTPS API endpoint, its current identity document, and feature support.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FederationDiscoveryV2 {
    pub fed_version: FederationProtocolVersion,
    pub server: String,
    pub api_base: String,
    pub capabilities: Vec<FederationCapabilityId>,
    pub identity: FederationIdentityDocumentV1,
    pub identity_document_hash: String,
    pub signed_at: i64,
    pub expires_at: i64,
    pub signature: String,
}

impl FederationDiscoveryV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        server: impl Into<String>,
        api_base: impl Into<String>,
        mut capabilities: Vec<FederationCapabilityId>,
        identity: FederationIdentityDocumentV1,
        signed_at: i64,
        expires_at: i64,
        signing_key: &SigningKey,
    ) -> Result<Self, FederationProtocolError> {
        capabilities.sort();
        let mut discovery = Self {
            fed_version: FederationProtocolVersion::V2,
            server: server.into(),
            api_base: api_base.into(),
            capabilities,
            identity_document_hash: identity.document_hash()?,
            identity,
            signed_at,
            expires_at,
            signature: String::new(),
        };
        discovery.validate_unsigned_shape()?;
        discovery.identity.verify_current()?;
        if discovery.identity.server != discovery.server {
            return Err(FederationProtocolError::InvalidDiscovery(
                "embedded identity belongs to a different server",
            ));
        }
        if discovery.identity.key.public_key_bytes()? != signing_key.verifying_key().to_bytes() {
            return Err(FederationProtocolError::InvalidDiscovery(
                "signing key does not match the embedded identity",
            ));
        }
        discovery.signature = base64::engine::general_purpose::STANDARD
            .encode(signing_key.sign(&discovery.signing_bytes()?).to_bytes());
        Ok(discovery)
    }

    /// Verify a discovery document using its authenticated embedded identity.
    /// Pinning/advancing that identity remains a caller policy decision.
    pub fn verify_at(
        &self,
        expected_server: &str,
        now: i64,
    ) -> Result<(), FederationProtocolError> {
        self.validate_shape()?;
        if self.server != expected_server || self.identity.server != expected_server {
            return Err(FederationProtocolError::InvalidDiscovery(
                "server is not bound to the expected peer identity",
            ));
        }
        self.identity.verify_current()?;
        if self.identity_document_hash != self.identity.document_hash()? {
            return Err(FederationProtocolError::InvalidDiscovery(
                "embedded identity document hash does not match",
            ));
        }
        if now < self.signed_at.saturating_sub(CLOCK_SKEW_SECONDS) {
            return Err(FederationProtocolError::InvalidDiscovery(
                "document is not yet valid",
            ));
        }
        if now > self.expires_at.saturating_add(CLOCK_SKEW_SECONDS) {
            return Err(FederationProtocolError::InvalidDiscovery(
                "document has expired",
            ));
        }
        let signature = Signature::from_bytes(&decode_base64::<64>("signature", &self.signature)?);
        self.identity
            .key
            .verifying_key()?
            .verify_strict(&self.signing_bytes()?, &signature)
            .map_err(|_| FederationProtocolError::InvalidDiscovery("signature verification failed"))
    }

    pub fn verify_genesis_at(
        &self,
        expected_server: &str,
        now: i64,
    ) -> Result<(), FederationProtocolError> {
        self.verify_at(expected_server, now)?;
        self.identity.verify_genesis(expected_server)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, FederationProtocolError> {
        self.validate_unsigned_shape()?;
        let mut output = Vec::with_capacity(512);
        output.extend_from_slice(DISCOVERY_SIGNING_DOMAIN);
        output.extend_from_slice(&u16::from(self.fed_version).to_be_bytes());
        push_string(&mut output, "server", &self.server)?;
        push_string(&mut output, "apiBase", &self.api_base)?;
        let count = u16::try_from(self.capabilities.len()).map_err(|_| {
            crate::error::invalid_field("capabilities", "contains too many entries")
        })?;
        output.extend_from_slice(&count.to_be_bytes());
        for capability in &self.capabilities {
            push_string(&mut output, "capabilities", capability.as_str())?;
        }
        output.extend_from_slice(&validate_hash(
            "identityDocumentHash",
            &self.identity_document_hash,
        )?);
        output.extend_from_slice(&self.signed_at.to_be_bytes());
        output.extend_from_slice(&self.expires_at.to_be_bytes());
        Ok(output)
    }

    fn validate_unsigned_shape(&self) -> Result<(), FederationProtocolError> {
        validate_server_name(&self.server)?;
        let canonical_api_base = normalize_api_base(&self.api_base)?;
        if canonical_api_base != self.api_base {
            return Err(crate::error::invalid_field(
                "apiBase",
                "must use its canonical HTTPS representation",
            ));
        }
        if self.capabilities.is_empty()
            || self.capabilities.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(crate::error::invalid_field(
                "capabilities",
                "must be non-empty, unique, and sorted",
            ));
        }
        if self
            .capabilities
            .binary_search(&FederationCapabilityId::identity_v1())
            .is_err()
        {
            return Err(FederationProtocolError::InvalidDiscovery(
                "identity.v1 capability is required",
            ));
        }
        if self.signed_at < 0
            || self.expires_at <= self.signed_at
            || self.expires_at - self.signed_at > MAX_DISCOVERY_LIFETIME_SECONDS
        {
            return Err(FederationProtocolError::InvalidDiscovery(
                "validity window must be positive and no longer than 24 hours",
            ));
        }
        validate_hash("identityDocumentHash", &self.identity_document_hash)?;
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), FederationProtocolError> {
        self.validate_unsigned_shape()?;
        decode_base64::<64>("signature", &self.signature)?;
        Ok(())
    }
}

fn validate_capability(value: &str) -> Result<(), FederationProtocolError> {
    if value.is_empty()
        || value.len() > 64
        || !value.is_ascii()
        || !value.contains('.')
        || value.starts_with('.')
        || value.ends_with('.')
        || value.split('.').any(|segment| {
            segment.is_empty()
                || segment.starts_with('-')
                || segment.ends_with('-')
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return Err(crate::error::invalid_field(
            "capabilities",
            "contains a non-canonical capability identifier",
        ));
    }
    Ok(())
}

fn normalize_api_base(value: &str) -> Result<String, FederationProtocolError> {
    let parsed = Url::parse(value)
        .map_err(|_| crate::error::invalid_field("apiBase", "must be an absolute HTTPS URL"))?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(crate::error::invalid_field(
            "apiBase",
            "must be HTTPS without credentials, query, or fragment",
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| crate::error::invalid_field("apiBase", "must contain a DNS host"))?;
    validate_server_name(host)
        .map_err(|_| crate::error::invalid_field("apiBase", "must contain a canonical DNS host"))?;
    if matches!(parsed.port(), Some(0 | 443)) {
        return Err(crate::error::invalid_field(
            "apiBase",
            "must use a valid non-default HTTPS port",
        ));
    }

    let mut canonical = format!("https://{host}");
    if let Some(port) = parsed.port() {
        canonical.push(':');
        canonical.push_str(&port.to_string());
    }
    let path = parsed.path().trim_end_matches('/');
    if !path.is_empty() {
        canonical.push_str(path);
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use sha2::{Digest as _, Sha256};

    fn identity() -> (SigningKey, FederationIdentityDocumentV1) {
        let key = SigningKey::from_bytes(&[7; 32]);
        let identity = FederationIdentityDocumentV1::genesis("alpha.example", 100, &key).unwrap();
        (key, identity)
    }

    fn discovery() -> FederationDiscoveryV2 {
        let (key, identity) = identity();
        FederationDiscoveryV2::sign(
            "alpha.example",
            "https://fed.example/api/fed",
            vec![
                FederationCapabilityId::identity_v1(),
                FederationCapabilityId::drive_v1(),
                FederationCapabilityId::chat_v1(),
            ],
            identity,
            200,
            3_800,
            &key,
        )
        .unwrap()
    }

    #[test]
    fn deterministic_discovery_is_sorted_and_verifies() {
        let discovery = discovery();
        assert_eq!(
            discovery
                .capabilities
                .iter()
                .map(FederationCapabilityId::as_str)
                .collect::<Vec<_>>(),
            ["chat.v1", "drive.v1", "identity.v1"]
        );
        discovery.verify_genesis_at("alpha.example", 500).unwrap();
    }

    #[test]
    fn every_discovery_binding_is_authenticated() {
        let original = discovery();
        let mut cases = Vec::new();
        let mut server = original.clone();
        server.server = "other.example".into();
        cases.push(server);
        let mut api = original.clone();
        api.api_base = "https://elsewhere.example/api/fed".into();
        cases.push(api);
        let mut capabilities = original.clone();
        capabilities.capabilities.remove(0);
        cases.push(capabilities);
        let mut hash = original.clone();
        hash.identity_document_hash = "00".repeat(32);
        cases.push(hash);
        let mut time = original.clone();
        time.expires_at -= 1;
        cases.push(time);

        for case in cases {
            assert!(case.verify_at("alpha.example", 500).is_err());
        }
    }

    #[test]
    fn validity_and_canonical_api_base_are_strict() {
        let original = discovery();
        assert!(original.verify_at("alpha.example", 3_861).is_err());
        assert!(original.verify_at("alpha.example", 139).is_err());

        let (key, identity) = identity();
        for invalid in [
            "http://fed.example/api/fed",
            "https://FED.example/api/fed",
            "https://fed.example:443/api/fed",
            "https://fed.example:0/api/fed",
            "https://user@fed.example/api/fed",
            "https://127.0.0.1/api/fed",
            "https://fed.example/api/fed/",
        ] {
            assert!(
                FederationDiscoveryV2::sign(
                    "alpha.example",
                    invalid,
                    vec![FederationCapabilityId::identity_v1()],
                    identity.clone(),
                    200,
                    3_800,
                    &key,
                )
                .is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn capabilities_are_closed_format_sorted_and_unique() {
        for invalid in ["chat", "Chat.v1", ".chat", "chat.", "chat..v1", "chat_v1"] {
            assert!(invalid.parse::<FederationCapabilityId>().is_err());
        }
        let (key, identity) = identity();
        assert!(FederationDiscoveryV2::sign(
            "alpha.example",
            "https://fed.example",
            vec![FederationCapabilityId::chat_v1()],
            identity,
            200,
            3_800,
            &key,
        )
        .is_err());
    }

    #[test]
    fn unknown_fields_and_versions_fail_during_decoding() {
        let mut json = serde_json::to_value(discovery()).unwrap();
        json["fedVersion"] = serde_json::json!(1);
        assert!(serde_json::from_value::<FederationDiscoveryV2>(json).is_err());

        let mut json = serde_json::to_value(discovery()).unwrap();
        json["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<FederationDiscoveryV2>(json).is_err());
    }

    #[test]
    fn signing_key_must_match_identity() {
        let (_, identity) = identity();
        assert!(FederationDiscoveryV2::sign(
            "alpha.example",
            "https://fed.example",
            vec![FederationCapabilityId::identity_v1()],
            identity,
            200,
            3_800,
            &SigningKey::from_bytes(&[9; 32]),
        )
        .is_err());
    }

    #[test]
    fn signature_tampering_fails() {
        let mut document = discovery();
        document.signature = base64::engine::general_purpose::STANDARD.encode([0; 64]);
        assert!(document.verify_at("alpha.example", 500).is_err());
    }

    #[test]
    fn signing_bytes_are_not_json_dependent() {
        let document = discovery();
        let first = document.signing_bytes().unwrap();
        let encoded = serde_json::to_string_pretty(&document).unwrap();
        let decoded: FederationDiscoveryV2 = serde_json::from_str(&encoded).unwrap();
        assert_eq!(first, decoded.signing_bytes().unwrap());
        assert_eq!(hex::encode(Sha256::digest(first)).len(), 64);
    }
}
