//! Account-authority-signed, hash-linked collection key epochs.

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::drive_object::parse_canonical_uuid;
use crate::error::{CryptoError, Result};

const MAGIC: &[u8; 8] = b"KUTPCE1\0";
const SIGNED_LEN: usize = 8 + 2 + 2 + 16 + 16 + 4 + 32 + 32 + 32;
const WIRE_LEN: usize = SIGNED_LEN + 64;
const KEY_COMMITMENT_DOMAIN: &[u8] = b"kutup/drive/collection-key-commitment/v1\0";
const RECORD_HASH_DOMAIN: &[u8] = b"kutup/drive/collection-epoch-record-hash/v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum CollectionEpochSuiteId {
    Ed25519Sha256V1 = 1,
}

impl CollectionEpochSuiteId {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for CollectionEpochSuiteId {
    type Error = CryptoError;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::Ed25519Sha256V1),
            _ => Err(CryptoError::InvalidInput(format!(
                "unknown collection epoch suite {value}"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionEpochStatementV1 {
    pub suite: CollectionEpochSuiteId,
    pub collection_id: [u8; 16],
    pub owner_user_id: [u8; 16],
    pub epoch: u32,
    pub previous_statement_hash: [u8; 32],
    pub collection_key_commitment: [u8; 32],
    pub authority_key_id: [u8; 32],
    pub signature: [u8; 64],
}

impl CollectionEpochStatementV1 {
    pub fn create(
        collection_id: &str,
        owner_user_id: &str,
        epoch: u32,
        previous_statement_hash: Option<&str>,
        collection_key: &[u8],
        authority: &SigningKey,
    ) -> Result<Self> {
        if epoch == 0 || collection_key.len() != 32 {
            return Err(CryptoError::InvalidInput(
                "collection epoch and key length are invalid".into(),
            ));
        }
        let previous_statement_hash = parse_previous_hash(epoch, previous_statement_hash)?;
        let collection_id = parse_canonical_uuid(collection_id, "collection")?;
        let owner_user_id = parse_canonical_uuid(owner_user_id, "owner")?;
        let collection_key_commitment =
            collection_key_commitment(collection_id, epoch, collection_key);
        let authority_key_id = Sha256::digest(authority.verifying_key().to_bytes()).into();
        let mut statement = Self {
            suite: CollectionEpochSuiteId::Ed25519Sha256V1,
            collection_id,
            owner_user_id,
            epoch,
            previous_statement_hash,
            collection_key_commitment,
            authority_key_id,
            signature: [0u8; 64],
        };
        statement.signature = authority.sign(&statement.signing_bytes()).to_bytes();
        Ok(statement)
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(SIGNED_LEN);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.suite.as_u16().to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&self.collection_id);
        bytes.extend_from_slice(&self.owner_user_id);
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.previous_statement_hash);
        bytes.extend_from_slice(&self.collection_key_commitment);
        bytes.extend_from_slice(&self.authority_key_id);
        debug_assert_eq!(bytes.len(), SIGNED_LEN);
        bytes
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.signing_bytes();
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    pub fn encode_b64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.encode())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != WIRE_LEN || bytes.get(..MAGIC.len()) != Some(MAGIC) {
            return Err(CryptoError::InvalidInput(
                "collection epoch statement length or magic is invalid".into(),
            ));
        }
        let suite = CollectionEpochSuiteId::try_from(u16::from_be_bytes([bytes[8], bytes[9]]))?;
        if bytes[10] != 0 || bytes[11] != 0 {
            return Err(CryptoError::InvalidInput(
                "collection epoch reserved bytes are non-zero".into(),
            ));
        }
        let epoch = u32::from_be_bytes(bytes[44..48].try_into().expect("four-byte slice"));
        if epoch == 0 {
            return Err(CryptoError::InvalidInput(
                "collection epoch must be non-zero".into(),
            ));
        }
        let statement = Self {
            suite,
            collection_id: bytes[12..28].try_into().expect("sixteen-byte slice"),
            owner_user_id: bytes[28..44].try_into().expect("sixteen-byte slice"),
            epoch,
            previous_statement_hash: bytes[48..80].try_into().expect("32-byte slice"),
            collection_key_commitment: bytes[80..112].try_into().expect("32-byte slice"),
            authority_key_id: bytes[112..144].try_into().expect("32-byte slice"),
            signature: bytes[144..208].try_into().expect("64-byte slice"),
        };
        if (epoch == 1)
            != statement
                .previous_statement_hash
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(CryptoError::InvalidInput(
                "collection epoch previous hash shape is invalid".into(),
            ));
        }
        Ok(statement)
    }

    pub fn decode_b64(value: &str) -> Result<Self> {
        let decoded = base64::engine::general_purpose::STANDARD.decode(value)?;
        if base64::engine::general_purpose::STANDARD.encode(&decoded) != value {
            return Err(CryptoError::InvalidInput(
                "collection epoch statement must use canonical base64".into(),
            ));
        }
        Self::decode(&decoded)
    }

    pub fn verify_authority(&self, expected_authority_public_key: &[u8]) -> Result<()> {
        let authority: [u8; 32] =
            expected_authority_public_key
                .try_into()
                .map_err(|_| CryptoError::InvalidLength {
                    expected: 32,
                    got: expected_authority_public_key.len(),
                })?;
        if self.authority_key_id != Sha256::digest(authority).as_slice() {
            return Err(CryptoError::AuthFailed);
        }
        let verifying_key =
            VerifyingKey::from_bytes(&authority).map_err(|_| CryptoError::AuthFailed)?;
        verifying_key
            .verify(
                &self.signing_bytes(),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| CryptoError::AuthFailed)
    }

    pub fn verify_binding(
        &self,
        expected_collection_id: &str,
        expected_owner_user_id: &str,
        expected_epoch: u32,
        expected_previous_statement_hash: Option<&str>,
    ) -> Result<()> {
        if self.collection_id != parse_canonical_uuid(expected_collection_id, "collection")?
            || self.owner_user_id != parse_canonical_uuid(expected_owner_user_id, "owner")?
            || self.epoch != expected_epoch
            || self.previous_statement_hash
                != parse_previous_hash(expected_epoch, expected_previous_statement_hash)?
        {
            return Err(CryptoError::InvalidInput(
                "collection epoch statement binding does not match".into(),
            ));
        }
        Ok(())
    }

    /// Verify the stable identity and current epoch fields when the caller is
    /// validating a server-returned current record. Hash-chain continuity is
    /// checked separately when advancing from a pinned predecessor.
    pub fn verify_current_binding(
        &self,
        expected_collection_id: &str,
        expected_owner_user_id: &str,
        expected_epoch: u32,
    ) -> Result<()> {
        if self.collection_id != parse_canonical_uuid(expected_collection_id, "collection")?
            || self.owner_user_id != parse_canonical_uuid(expected_owner_user_id, "owner")?
            || self.epoch != expected_epoch
        {
            return Err(CryptoError::InvalidInput(
                "collection epoch statement binding does not match".into(),
            ));
        }
        Ok(())
    }

    pub fn verify_collection_key(&self, collection_key: &[u8]) -> Result<()> {
        if collection_key.len() != 32
            || self.collection_key_commitment
                != collection_key_commitment(self.collection_id, self.epoch, collection_key)
        {
            return Err(CryptoError::AuthFailed);
        }
        Ok(())
    }

    pub fn statement_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(RECORD_HASH_DOMAIN);
        hasher.update(self.encode());
        hex::encode(hasher.finalize())
    }
}

fn parse_previous_hash(epoch: u32, value: Option<&str>) -> Result<[u8; 32]> {
    match (epoch, value) {
        (1, None) => Ok([0u8; 32]),
        (1, Some(_)) | (_, None) => Err(CryptoError::InvalidInput(
            "collection epoch previous hash shape is invalid".into(),
        )),
        (_, Some(value)) => {
            if value.len() != 64
                || !value
                    .as_bytes()
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
            {
                return Err(CryptoError::InvalidInput(
                    "collection epoch previous hash is invalid".into(),
                ));
            }
            let decoded = hex::decode(value)
                .map_err(|_| CryptoError::InvalidInput("invalid previous hash".into()))?;
            Ok(decoded.try_into().expect("validated 32-byte hash"))
        }
    }
}

fn collection_key_commitment(
    collection_id: [u8; 16],
    epoch: u32,
    collection_key: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEY_COMMITMENT_DOMAIN);
    hasher.update(collection_id);
    hasher.update(epoch.to_be_bytes());
    hasher.update(collection_key);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create() -> CollectionEpochStatementV1 {
        CollectionEpochStatementV1::create(
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            1,
            None,
            &[0x33; 32],
            &SigningKey::from_bytes(&[0x44; 32]),
        )
        .unwrap()
    }

    #[test]
    fn round_trip_signature_binding_commitment_and_hash() {
        let statement = create();
        assert_eq!(
            statement.encode_b64(),
            "S1VUUENFMQAAAQAAERERERERQRGBERERERERESIiIiIiIkIigiIiIiIiIiIAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACLGwfeTeCI1SFFWyABYUccNvETzSWg5IBC6YQWdBHiqrFHBYiPSmg5GgmqWWjdJdFsO7p7s7bRW/NU2Nyq6FpHCkykGjzpiuAuNy1QqZhOjvNqAZ8Ec2tI7WXXrOsBuGhObEaG2JkRFEEPSKcavCdKQUZmEeGIUVaHHU+5iiGXDw=="
        );
        assert_eq!(
            statement.statement_hash(),
            "c08cafb6eaa364dda50b3bfd62abe1db19d1a52c6a82de8582b43cbab7d04f6e"
        );
        let decoded = CollectionEpochStatementV1::decode_b64(&statement.encode_b64()).unwrap();
        let authority = SigningKey::from_bytes(&[0x44; 32])
            .verifying_key()
            .to_bytes();
        decoded.verify_authority(&authority).unwrap();
        decoded
            .verify_binding(
                "11111111-1111-4111-8111-111111111111",
                "22222222-2222-4222-8222-222222222222",
                1,
                None,
            )
            .unwrap();
        decoded.verify_collection_key(&[0x33; 32]).unwrap();
        assert_eq!(decoded.statement_hash().len(), 64);
    }

    #[test]
    fn tamper_wrong_key_and_invalid_chain_shape_fail_closed() {
        let statement = create();
        assert!(statement.verify_collection_key(&[0x34; 32]).is_err());
        let mut encoded = statement.encode();
        encoded[80] ^= 1;
        let decoded = CollectionEpochStatementV1::decode(&encoded).unwrap();
        let authority = SigningKey::from_bytes(&[0x44; 32])
            .verifying_key()
            .to_bytes();
        assert!(decoded.verify_authority(&authority).is_err());
        assert!(CollectionEpochStatementV1::create(
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            2,
            None,
            &[0x33; 32],
            &SigningKey::from_bytes(&[0x44; 32]),
        )
        .is_err());
    }
}
