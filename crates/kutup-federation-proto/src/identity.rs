use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    decode_base64, federation_key_id, push_string, validate_hash, validate_server_name,
    FederationProtocolError, FEDERATION_IDENTITY_VERSION,
};

const IDENTITY_SIGNING_DOMAIN: &[u8] = b"kutup-federation-identity-document-v1\0";
const IDENTITY_HASH_DOMAIN: &[u8] = b"kutup-federation-identity-document-hash-v1\0";

/// Closed identity-document version. Unknown versions fail during decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "u16", try_from = "u16")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[repr(u16)]
pub enum FederationIdentityVersion {
    V1 = FEDERATION_IDENTITY_VERSION,
}

impl From<FederationIdentityVersion> for u16 {
    fn from(value: FederationIdentityVersion) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for FederationIdentityVersion {
    type Error = FederationProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            FEDERATION_IDENTITY_VERSION => Ok(Self::V1),
            _ => Err(crate::error::invalid_field(
                "identityVersion",
                "is not a supported identity version",
            )),
        }
    }
}

/// Closed key-algorithm registry for federation identity documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum FederationIdentityKeyAlgorithm {
    Ed25519,
}

impl FederationIdentityKeyAlgorithm {
    fn wire_name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
        }
    }
}

/// Public identity key embedded in a signed identity document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FederationIdentityKeyV1 {
    pub algorithm: FederationIdentityKeyAlgorithm,
    pub key_id: String,
    pub public_key: String,
}

impl FederationIdentityKeyV1 {
    pub fn from_signing_key(signing_key: &SigningKey) -> Self {
        let public_key = signing_key.verifying_key().to_bytes();
        Self {
            algorithm: FederationIdentityKeyAlgorithm::Ed25519,
            key_id: federation_key_id(&public_key),
            public_key: base64::engine::general_purpose::STANDARD.encode(public_key),
        }
    }

    pub fn public_key_bytes(&self) -> Result<[u8; 32], FederationProtocolError> {
        let bytes = decode_base64::<32>("publicKey", &self.public_key)?;
        if federation_key_id(&bytes) != self.key_id {
            return Err(FederationProtocolError::KeyIdMismatch);
        }
        Ok(bytes)
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey, FederationProtocolError> {
        VerifyingKey::from_bytes(&self.public_key_bytes()?)
            .map_err(|_| crate::error::invalid_field("publicKey", "is not an Ed25519 public key"))
    }

    fn validate(&self) -> Result<(), FederationProtocolError> {
        if self.algorithm != FederationIdentityKeyAlgorithm::Ed25519 {
            return Err(crate::error::invalid_field("algorithm", "is not supported"));
        }
        validate_hash("keyId", &self.key_id)?;
        self.verifying_key()?;
        Ok(())
    }
}

/// A self-authenticating genesis document or an old-and-new-key-authenticated
/// successor in a server's append-only federation identity chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FederationIdentityDocumentV1 {
    pub identity_version: FederationIdentityVersion,
    pub server: String,
    pub sequence: u64,
    pub key: FederationIdentityKeyV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_document_hash: Option<String>,
    pub issued_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_signature: Option<String>,
    pub current_signature: String,
}

impl FederationIdentityDocumentV1 {
    pub fn genesis(
        server: impl Into<String>,
        issued_at: i64,
        signing_key: &SigningKey,
    ) -> Result<Self, FederationProtocolError> {
        let mut document = Self {
            identity_version: FederationIdentityVersion::V1,
            server: server.into(),
            sequence: 0,
            key: FederationIdentityKeyV1::from_signing_key(signing_key),
            previous_document_hash: None,
            issued_at,
            previous_signature: None,
            current_signature: String::new(),
        };
        document.validate_signing_shape()?;
        document.current_signature =
            encode_signature(&signing_key.sign(&document.signing_bytes()?));
        Ok(document)
    }

    pub fn rotate(
        previous: &Self,
        issued_at: i64,
        previous_signing_key: &SigningKey,
        current_signing_key: &SigningKey,
    ) -> Result<Self, FederationProtocolError> {
        previous.verify_current()?;
        if previous_signing_key.verifying_key().to_bytes() != previous.key.public_key_bytes()? {
            return Err(FederationProtocolError::InvalidIdentityChain(
                "the previous signing key does not match the predecessor document",
            ));
        }
        if previous_signing_key.verifying_key() == current_signing_key.verifying_key() {
            return Err(FederationProtocolError::InvalidIdentityChain(
                "a rotation must introduce a different key",
            ));
        }

        let mut document = Self {
            identity_version: FederationIdentityVersion::V1,
            server: previous.server.clone(),
            sequence: previous.sequence.checked_add(1).ok_or(
                FederationProtocolError::InvalidIdentityChain("identity sequence overflow"),
            )?,
            key: FederationIdentityKeyV1::from_signing_key(current_signing_key),
            previous_document_hash: Some(previous.document_hash()?),
            issued_at,
            previous_signature: None,
            current_signature: String::new(),
        };
        document.validate_signing_shape()?;
        let signing_bytes = document.signing_bytes()?;
        document.previous_signature =
            Some(encode_signature(&previous_signing_key.sign(&signing_bytes)));
        document.current_signature = encode_signature(&current_signing_key.sign(&signing_bytes));
        document.verify_successor(previous, &document.server)?;
        Ok(document)
    }

    /// Canonical bytes signed by the current key and, for rotations, the old
    /// key. Length-prefixing removes JSON and delimiter ambiguity.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, FederationProtocolError> {
        self.validate_signing_shape()?;
        let mut output = Vec::with_capacity(256);
        output.extend_from_slice(IDENTITY_SIGNING_DOMAIN);
        output.extend_from_slice(&u16::from(self.identity_version).to_be_bytes());
        push_string(&mut output, "server", &self.server)?;
        output.extend_from_slice(&self.sequence.to_be_bytes());
        push_string(&mut output, "algorithm", self.key.algorithm.wire_name())?;
        output.extend_from_slice(&self.key.public_key_bytes()?);
        output.extend_from_slice(&validate_hash("keyId", &self.key.key_id)?);
        match &self.previous_document_hash {
            Some(hash) => {
                output.push(1);
                output.extend_from_slice(&validate_hash("previousDocumentHash", hash)?);
            }
            None => output.push(0),
        }
        output.extend_from_slice(&self.issued_at.to_be_bytes());
        Ok(output)
    }

    /// Hash of the canonical authenticated payload used by the next rotation's
    /// link. Signatures authenticate this payload but are not themselves part
    /// of the document hash.
    pub fn document_hash(&self) -> Result<String, FederationProtocolError> {
        self.validate_shape()?;
        let mut bytes = Vec::with_capacity(320);
        bytes.extend_from_slice(IDENTITY_HASH_DOMAIN);
        bytes.extend_from_slice(&self.signing_bytes()?);
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    pub fn verify_current(&self) -> Result<(), FederationProtocolError> {
        self.validate_shape()?;
        let key = self.key.verifying_key()?;
        let signature = decode_signature("currentSignature", &self.current_signature)?;
        key.verify_strict(&self.signing_bytes()?, &signature)
            .map_err(|_| FederationProtocolError::InvalidIdentitySignature("current key signature"))
    }

    pub fn verify_genesis(&self, expected_server: &str) -> Result<(), FederationProtocolError> {
        if self.server != expected_server {
            return Err(FederationProtocolError::InvalidIdentityChain(
                "identity server does not match the expected peer",
            ));
        }
        if self.sequence != 0
            || self.previous_document_hash.is_some()
            || self.previous_signature.is_some()
        {
            return Err(FederationProtocolError::InvalidIdentityChain(
                "genesis must be sequence zero without a predecessor",
            ));
        }
        self.verify_current()
    }

    pub fn verify_successor(
        &self,
        previous: &Self,
        expected_server: &str,
    ) -> Result<(), FederationProtocolError> {
        previous.verify_current()?;
        self.verify_current()?;
        if self.server != expected_server || previous.server != expected_server {
            return Err(FederationProtocolError::InvalidIdentityChain(
                "identity server does not match the expected peer",
            ));
        }
        if self.sequence
            != previous.sequence.checked_add(1).ok_or(
                FederationProtocolError::InvalidIdentityChain("identity sequence overflow"),
            )?
        {
            return Err(FederationProtocolError::InvalidIdentityChain(
                "identity sequence must advance by exactly one",
            ));
        }
        if self.issued_at < previous.issued_at {
            return Err(FederationProtocolError::InvalidIdentityChain(
                "identity issue time moved backwards",
            ));
        }
        if self.key.public_key_bytes()? == previous.key.public_key_bytes()? {
            return Err(FederationProtocolError::InvalidIdentityChain(
                "a rotation must introduce a different key",
            ));
        }
        if self.previous_document_hash.as_deref() != Some(&previous.document_hash()?) {
            return Err(FederationProtocolError::InvalidIdentityChain(
                "predecessor document hash does not match",
            ));
        }
        let signature = decode_signature(
            "previousSignature",
            self.previous_signature.as_deref().ok_or(
                FederationProtocolError::InvalidIdentityChain(
                    "a successor requires the previous key signature",
                ),
            )?,
        )?;
        previous
            .key
            .verifying_key()?
            .verify_strict(&self.signing_bytes()?, &signature)
            .map_err(|_| {
                FederationProtocolError::InvalidIdentitySignature("previous key signature")
            })
    }

    fn validate_signing_shape(&self) -> Result<(), FederationProtocolError> {
        validate_server_name(&self.server)?;
        if self.issued_at < 0 {
            return Err(crate::error::invalid_field(
                "issuedAt",
                "must be a non-negative Unix timestamp",
            ));
        }
        self.key.validate()?;
        if self.sequence == 0 {
            if self.previous_document_hash.is_some() {
                return Err(FederationProtocolError::InvalidIdentityChain(
                    "genesis cannot contain a predecessor hash",
                ));
            }
        } else if self.previous_document_hash.is_none() {
            return Err(FederationProtocolError::InvalidIdentityChain(
                "a successor requires a predecessor hash",
            ));
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), FederationProtocolError> {
        self.validate_signing_shape()?;
        if self.sequence == 0 && self.previous_signature.is_some() {
            return Err(FederationProtocolError::InvalidIdentityChain(
                "genesis cannot contain a predecessor signature",
            ));
        }
        if self.sequence > 0 && self.previous_signature.is_none() {
            return Err(FederationProtocolError::InvalidIdentityChain(
                "a successor requires the previous key signature",
            ));
        }
        decode_signature("currentSignature", &self.current_signature)?;
        if let Some(signature) = &self.previous_signature {
            decode_signature("previousSignature", signature)?;
        }
        Ok(())
    }
}

/// Verify a complete chain from self-signed genesis through every exact
/// successor. Omitting an intermediate document is never accepted.
pub fn verify_identity_chain(
    expected_server: &str,
    documents: &[FederationIdentityDocumentV1],
) -> Result<(), FederationProtocolError> {
    let (genesis, successors) =
        documents
            .split_first()
            .ok_or(FederationProtocolError::InvalidIdentityChain(
                "identity chain is empty",
            ))?;
    genesis.verify_genesis(expected_server)?;
    let mut previous = genesis;
    for current in successors {
        current.verify_successor(previous, expected_server)?;
        previous = current;
    }
    Ok(())
}

fn encode_signature(signature: &Signature) -> String {
    base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
}

fn decode_signature(
    field: &'static str,
    value: &str,
) -> Result<Signature, FederationProtocolError> {
    Ok(Signature::from_bytes(&decode_base64::<64>(field, value)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    #[test]
    fn valid_multi_step_chain_and_fingerprints() {
        let first = FederationIdentityDocumentV1::genesis("alpha.example", 10, &key(1)).unwrap();
        let second = FederationIdentityDocumentV1::rotate(&first, 20, &key(1), &key(2)).unwrap();
        let third = FederationIdentityDocumentV1::rotate(&second, 30, &key(2), &key(3)).unwrap();
        verify_identity_chain("alpha.example", &[first, second, third]).unwrap();
    }

    #[test]
    fn rotation_rejects_wrong_old_key_same_key_and_time_rollback() {
        let genesis = FederationIdentityDocumentV1::genesis("alpha.example", 10, &key(1)).unwrap();
        assert!(FederationIdentityDocumentV1::rotate(&genesis, 20, &key(9), &key(2)).is_err());
        assert!(FederationIdentityDocumentV1::rotate(&genesis, 20, &key(1), &key(1)).is_err());
        assert!(FederationIdentityDocumentV1::rotate(&genesis, 9, &key(1), &key(2)).is_err());
    }

    #[test]
    fn chain_rejects_skip_rollback_equivocation_and_wrong_domain() {
        let genesis = FederationIdentityDocumentV1::genesis("alpha.example", 10, &key(1)).unwrap();
        let second = FederationIdentityDocumentV1::rotate(&genesis, 20, &key(1), &key(2)).unwrap();

        let mut skipped = second.clone();
        skipped.sequence = 2;
        assert!(skipped.verify_successor(&genesis, "alpha.example").is_err());

        let competing =
            FederationIdentityDocumentV1::rotate(&genesis, 21, &key(1), &key(3)).unwrap();
        assert_ne!(
            second.document_hash().unwrap(),
            competing.document_hash().unwrap()
        );
        assert!(second
            .verify_successor(&competing, "alpha.example")
            .is_err());
        assert!(
            verify_identity_chain("other.example", &[genesis.clone(), second.clone()]).is_err()
        );

        let mut rollback = second;
        rollback.issued_at = 9;
        assert!(rollback
            .verify_successor(&genesis, "alpha.example")
            .is_err());
    }

    #[test]
    fn tampering_every_authenticated_class_fails() {
        let genesis = FederationIdentityDocumentV1::genesis("alpha.example", 10, &key(1)).unwrap();
        let rotation =
            FederationIdentityDocumentV1::rotate(&genesis, 20, &key(1), &key(2)).unwrap();

        let mut cases = Vec::new();
        let mut server = rotation.clone();
        server.server = "beta.example".into();
        cases.push(server);
        let mut hash = rotation.clone();
        hash.previous_document_hash = Some("00".repeat(32));
        cases.push(hash);
        let mut old_signature = rotation.clone();
        old_signature.previous_signature =
            Some(base64::engine::general_purpose::STANDARD.encode([0; 64]));
        cases.push(old_signature);
        let mut new_signature = rotation.clone();
        new_signature.current_signature = base64::engine::general_purpose::STANDARD.encode([0; 64]);
        cases.push(new_signature);

        for case in cases {
            assert!(case.verify_successor(&genesis, "alpha.example").is_err());
        }
    }

    #[test]
    fn malformed_keys_hashes_signatures_and_versions_fail_closed() {
        let genesis = FederationIdentityDocumentV1::genesis("alpha.example", 10, &key(1)).unwrap();
        let mut malformed = genesis.clone();
        malformed.key.public_key.push('=');
        assert!(malformed.verify_current().is_err());

        let mut wrong_id = genesis.clone();
        wrong_id.key.key_id = "00".repeat(32);
        assert_eq!(
            wrong_id.verify_current().unwrap_err(),
            FederationProtocolError::KeyIdMismatch
        );

        let mut bad_signature = genesis;
        bad_signature.current_signature = "not-base64".into();
        assert!(bad_signature.verify_current().is_err());

        let json = r#"{"identityVersion":2,"server":"alpha.example","sequence":0,"key":{"algorithm":"ed25519","keyId":"00","publicKey":"AA=="},"issuedAt":1,"currentSignature":"AA=="}"#;
        assert!(serde_json::from_str::<FederationIdentityDocumentV1>(json).is_err());
    }
}
