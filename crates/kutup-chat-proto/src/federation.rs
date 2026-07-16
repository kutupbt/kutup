//! Transport-only chat federation wire primitives.
//!
//! Federation authenticates mailbox servers, not message plaintext. Clients
//! still verify account-signed device manifests and libsignal identities.

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{AccountAddress, DeviceListMismatch, SendMessagesRequest};

pub const FEDERATION_VERSION: u16 = 1;
pub const FEDERATION_AUTH_SCHEME: &str = "Kutup ";

#[derive(Debug, Clone, Copy)]
pub struct FederationRequest<'a> {
    pub method: &'a str,
    pub uri: &'a str,
    pub body: &'a [u8],
}

/// One Ed25519 server key published by federation discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct FederationSigningKey {
    /// Lowercase SHA-256 of the raw 32-byte Ed25519 public key.
    pub key_id: String,
    /// Base64 raw Ed25519 public key.
    pub public_key: String,
}

/// `/.well-known/kutup/federation.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct FederationDiscovery {
    pub fed_version: u16,
    /// Canonical lowercase DNS server name used in `username@server`.
    pub server: String,
    /// HTTPS API origin selected by the server-name owner. This is what lets
    /// canonical addresses remain port- and deployment-topology-independent.
    pub api_base: String,
    pub signing_keys: Vec<FederationSigningKey>,
}

/// One in-order ciphertext delivery from an origin mailbox server to a
/// destination mailbox server. No room state is replicated.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct FederatedChatTransaction {
    pub fed_version: u16,
    pub transaction_id: String,
    pub sequence: u64,
    pub origin: String,
    pub destination: String,
    /// Canonical `username@destination`.
    pub recipient: String,
    /// Canonical `username@origin`; plaintext until sealed sender lands as a
    /// complete abuse-controlled system.
    pub sender: String,
    pub message: SendMessagesRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct FederationDeliveryResponse {
    pub stored: usize,
    pub deduplicated: bool,
    pub accepted_sequence: u64,
    /// A terminal delivery failure still consumes the in-order sequence so one
    /// unavailable account cannot poison every later send to that server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection: Option<FederationDeliveryRejection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub enum FederationDeliveryRejection {
    RecipientUnavailable,
}

/// Typed 409 response. Device mismatch is relayed to the originating client so
/// it can re-fetch the signed manifest and re-encrypt under the same send id;
/// a sequence gap tells the origin server which durable transaction must lead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(
    tag = "code",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum FederationDeliveryError {
    DeviceListMismatch {
        #[serde(flatten)]
        mismatch: DeviceListMismatch,
    },
    SequenceGap {
        expected_sequence: u64,
    },
}

/// The signed server-to-server request identity carried in `Authorization`.
///
/// The signature covers method, request-target URI, origin, destination,
/// timestamp, request id, key id, and SHA-256 of the exact HTTP body. The
/// destination binding prevents a valid request being replayed at another
/// Kutup server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FederationAuthorization {
    pub origin: String,
    pub destination: String,
    pub key_id: String,
    pub timestamp: i64,
    pub request_id: String,
    /// Base64 Ed25519 signature over [`Self::signing_bytes`].
    pub signature: String,
}

impl FederationAuthorization {
    pub fn sign(
        origin: impl Into<String>,
        destination: impl Into<String>,
        timestamp: i64,
        request_id: impl Into<String>,
        request: FederationRequest<'_>,
        signing_key: &SigningKey,
    ) -> Result<Self, String> {
        let key_id = server_key_id(signing_key.verifying_key().as_bytes());
        let mut authorization = Self {
            origin: origin.into(),
            destination: destination.into(),
            key_id,
            timestamp,
            request_id: request_id.into(),
            signature: String::new(),
        };
        let bytes = authorization.signing_bytes(request.method, request.uri, request.body)?;
        authorization.signature =
            base64::engine::general_purpose::STANDARD.encode(signing_key.sign(&bytes).to_bytes());
        Ok(authorization)
    }

    pub fn verify(
        &self,
        method: &str,
        uri: &str,
        body: &[u8],
        public_key: &[u8; 32],
    ) -> Result<(), String> {
        if self.key_id != server_key_id(public_key) {
            return Err("federation keyId does not match public key".into());
        }
        let signature = base64::engine::general_purpose::STANDARD
            .decode(&self.signature)
            .map_err(|_| "federation signature must be base64".to_string())?;
        let signature = Signature::from_slice(&signature)
            .map_err(|_| "federation signature must be 64 bytes".to_string())?;
        let verifying_key = VerifyingKey::from_bytes(public_key)
            .map_err(|_| "invalid federation Ed25519 public key".to_string())?;
        verifying_key
            .verify_strict(&self.signing_bytes(method, uri, body)?, &signature)
            .map_err(|_| "invalid federation request signature".to_string())
    }

    /// Domain-separated deterministic encoding for server request signatures.
    pub fn signing_bytes(&self, method: &str, uri: &str, body: &[u8]) -> Result<Vec<u8>, String> {
        const DOMAIN: &[u8] = b"kutup-chat-federation-request-v1\0";

        validate_server_name(&self.origin)?;
        validate_server_name(&self.destination)?;
        validate_key_id(&self.key_id)?;
        if self.request_id.is_empty() || self.request_id.len() > 128 {
            return Err("federation requestId must be 1-128 characters".into());
        }
        if method.is_empty() || method.bytes().any(|byte| !byte.is_ascii_uppercase()) {
            return Err("federation method must be uppercase ASCII".into());
        }
        if !uri.starts_with('/') || uri.contains('#') {
            return Err("federation URI must be an origin-form request target".into());
        }

        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(DOMAIN);
        push_string(&mut out, method)?;
        push_string(&mut out, uri)?;
        push_string(&mut out, &self.origin)?;
        push_string(&mut out, &self.destination)?;
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        push_string(&mut out, &self.request_id)?;
        push_string(&mut out, &self.key_id)?;
        out.extend_from_slice(&Sha256::digest(body));
        Ok(out)
    }

    /// Serialize for `Authorization: Kutup <base64url-json>`.
    pub fn to_header_value(&self) -> Result<String, String> {
        let json = serde_json::to_vec(self)
            .map_err(|error| format!("serialize federation authorization: {error}"))?;
        Ok(format!(
            "{FEDERATION_AUTH_SCHEME}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
        ))
    }

    pub fn from_header_value(value: &str) -> Result<Self, String> {
        let encoded = value
            .strip_prefix(FEDERATION_AUTH_SCHEME)
            .ok_or_else(|| "missing Kutup federation authorization scheme".to_string())?;
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| "invalid federation authorization encoding".to_string())?;
        serde_json::from_slice(&json)
            .map_err(|_| "invalid federation authorization payload".to_string())
    }
}

pub fn server_key_id(public_key: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(public_key))
}

fn validate_server_name(server: &str) -> Result<(), String> {
    let address = AccountAddress::federated("server", server).map_err(|error| error.to_string())?;
    if address.server.as_deref() != Some(server) {
        return Err("federation server name must already be canonical lowercase DNS".into());
    }
    Ok(())
}

fn validate_key_id(key_id: &str) -> Result<(), String> {
    let decoded = hex::decode(key_id)
        .map_err(|_| "federation keyId must be lowercase SHA-256 hex".to_string())?;
    if decoded.len() != 32 || hex::encode(decoded) != key_id {
        return Err("federation keyId must be lowercase SHA-256 hex".into());
    }
    Ok(())
}

fn push_string(out: &mut Vec<u8>, value: &str) -> Result<(), String> {
    let len = u32::try_from(value.len()).map_err(|_| "federation field is too long")?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_authorization_round_trips_and_binds_destination_and_body() {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let auth = FederationAuthorization::sign(
            "origin.example",
            "dest.example",
            1_700_000_000,
            "request-1",
            FederationRequest {
                method: "POST",
                uri: "/api/fed/chat/messages",
                body: br#"{"ciphertext":"AAEC"}"#,
            },
            &signing,
        )
        .unwrap();
        let header = auth.to_header_value().unwrap();
        let parsed = FederationAuthorization::from_header_value(&header).unwrap();
        let public = *signing.verifying_key().as_bytes();

        parsed
            .verify(
                "POST",
                "/api/fed/chat/messages",
                br#"{"ciphertext":"AAEC"}"#,
                &public,
            )
            .unwrap();
        assert!(parsed
            .verify(
                "POST",
                "/api/fed/chat/messages",
                br#"{"ciphertext":"changed"}"#,
                &public,
            )
            .is_err());

        let mut wrong_destination = parsed;
        wrong_destination.destination = "other.example".into();
        assert!(wrong_destination
            .verify(
                "POST",
                "/api/fed/chat/messages",
                br#"{"ciphertext":"AAEC"}"#,
                &public,
            )
            .is_err());
    }

    #[test]
    fn discovery_shape_is_stable() {
        let discovery = FederationDiscovery {
            fed_version: FEDERATION_VERSION,
            server: "chat.example".into(),
            api_base: "https://edge.example".into(),
            signing_keys: vec![FederationSigningKey {
                key_id: "00".repeat(32),
                public_key: "AAEC".into(),
            }],
        };
        assert_eq!(
            serde_json::to_string(&discovery).unwrap(),
            format!(
                r#"{{"fedVersion":1,"server":"chat.example","apiBase":"https://edge.example","signingKeys":[{{"keyId":"{}","publicKey":"AAEC"}}]}}"#,
                "00".repeat(32)
            )
        );
    }

    #[test]
    fn delivery_conflicts_are_typed() {
        let error = FederationDeliveryError::DeviceListMismatch {
            mismatch: DeviceListMismatch {
                missing_devices: vec![2],
                stale_devices: vec![3],
                extra_devices: vec![],
            },
        };
        assert_eq!(
            serde_json::to_string(&error).unwrap(),
            r#"{"code":"deviceListMismatch","missingDevices":[2],"staleDevices":[3],"extraDevices":[]}"#
        );
        let gap = FederationDeliveryError::SequenceGap {
            expected_sequence: 9,
        };
        assert_eq!(
            serde_json::to_string(&gap).unwrap(),
            r#"{"code":"sequenceGap","expectedSequence":9}"#
        );
    }

    #[test]
    fn terminal_rejection_is_additive_and_sequence_advancing() {
        let response = FederationDeliveryResponse {
            stored: 0,
            deduplicated: false,
            accepted_sequence: 9,
            rejection: Some(FederationDeliveryRejection::RecipientUnavailable),
        };
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            serde_json::json!({
                "stored": 0,
                "deduplicated": false,
                "acceptedSequence": 9,
                "rejection": "recipientUnavailable"
            })
        );
    }
}
