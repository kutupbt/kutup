//! Temporary compatibility implementation for the deployed experimental Chat
//! federation v1 wire format.
//!
//! It is intentionally server-private: unified federation concepts are owned
//! by `kutup-federation-proto`. Phase C removes this module in the same atomic
//! change that switches the runtime to federation v2; no v1 fallback remains.

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub(crate) const FEDERATION_VERSION: u16 = 1;
const FEDERATION_AUTH_SCHEME: &str = "Kutup ";

#[derive(Debug, Clone, Copy)]
pub(crate) struct FederationRequest<'a> {
    pub method: &'a str,
    pub uri: &'a str,
    pub body: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FederationSigningKey {
    pub key_id: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FederationDiscovery {
    pub fed_version: u16,
    pub server: String,
    pub api_base: String,
    pub signing_keys: Vec<FederationSigningKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FederationAuthorization {
    pub origin: String,
    pub destination: String,
    pub key_id: String,
    pub timestamp: i64,
    pub request_id: String,
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
        let key_id =
            kutup_federation_proto::federation_key_id(signing_key.verifying_key().as_bytes());
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
        if self.key_id != kutup_federation_proto::federation_key_id(public_key) {
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

    fn signing_bytes(&self, method: &str, uri: &str, body: &[u8]) -> Result<Vec<u8>, String> {
        const DOMAIN: &[u8] = b"kutup-chat-federation-request-v1\0";

        kutup_federation_proto::validate_server_name(&self.origin)
            .map_err(|error| error.to_string())?;
        kutup_federation_proto::validate_server_name(&self.destination)
            .map_err(|error| error.to_string())?;
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

        let mut output = Vec::with_capacity(256);
        output.extend_from_slice(DOMAIN);
        push_string(&mut output, method)?;
        push_string(&mut output, uri)?;
        push_string(&mut output, &self.origin)?;
        push_string(&mut output, &self.destination)?;
        output.extend_from_slice(&self.timestamp.to_be_bytes());
        push_string(&mut output, &self.request_id)?;
        push_string(&mut output, &self.key_id)?;
        output.extend_from_slice(&Sha256::digest(body));
        Ok(output)
    }

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

fn validate_key_id(key_id: &str) -> Result<(), String> {
    let decoded = hex::decode(key_id)
        .map_err(|_| "federation keyId must be lowercase SHA-256 hex".to_string())?;
    if decoded.len() != 32 || hex::encode(decoded) != key_id {
        return Err("federation keyId must be lowercase SHA-256 hex".into());
    }
    Ok(())
}

fn push_string(output: &mut Vec<u8>, value: &str) -> Result<(), String> {
    let len = u32::try_from(value.len()).map_err(|_| "federation field is too long")?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatibility_authorization_still_round_trips() {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let request = FederationRequest {
            method: "POST",
            uri: "/api/fed/chat/messages",
            body: br#"{"ciphertext":"AAEC"}"#,
        };
        let authorization = FederationAuthorization::sign(
            "origin.example",
            "dest.example",
            1_700_000_000,
            "request-1",
            request,
            &signing,
        )
        .unwrap();
        let parsed =
            FederationAuthorization::from_header_value(&authorization.to_header_value().unwrap())
                .unwrap();
        parsed
            .verify(
                request.method,
                request.uri,
                request.body,
                signing.verifying_key().as_bytes(),
            )
            .unwrap();
    }
}
