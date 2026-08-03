//! Authenticated HPKE envelopes for named local and federated Drive shares.

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use hpke_rs::hpke_types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs::{Hpke, HpkePrivateKey, HpkePublicKey, Mode};
use hpke_rs_rust_crypto::HpkeRustCrypto;

use crate::drive_object::parse_canonical_uuid;
use crate::error::{CryptoError, Result};

const MAGIC: &[u8; 8] = b"KUTPNS1\0";
const HPKE_INFO: &[u8] = b"kutup/drive/named-share-hpke/v1\0";
const FIXED_AAD_LEN: usize = 8 + 2 + 2 + 16 + 4 + 32 + 32 + 2 + 2;
const X25519_ENCAPSULATED_KEY_LEN: usize = 32;
const COLLECTION_KEY_CIPHERTEXT_LEN: usize = 32 + 16;
const SIGNATURE_LEN: usize = 64;
const MAX_ACCOUNT_LEN: usize = 320;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum NamedShareSuiteId {
    X25519HkdfSha256ChaCha20Poly1305Ed25519V1 = 1,
}

impl NamedShareSuiteId {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for NamedShareSuiteId {
    type Error = CryptoError;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::X25519HkdfSha256ChaCha20Poly1305Ed25519V1),
            _ => Err(CryptoError::InvalidInput(format!(
                "unknown named-share suite {value}"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedShareEnvelopeV1 {
    pub suite: NamedShareSuiteId,
    pub collection_id: [u8; 16],
    pub epoch: u32,
    pub sender_incarnation_id: [u8; 32],
    pub recipient_incarnation_id: [u8; 32],
    pub sender_account: String,
    pub recipient_account: String,
    pub encapsulated_key: [u8; X25519_ENCAPSULATED_KEY_LEN],
    pub ciphertext: [u8; COLLECTION_KEY_CIPHERTEXT_LEN],
    pub signature: [u8; SIGNATURE_LEN],
}

impl NamedShareEnvelopeV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        collection_key: &[u8],
        collection_id: &str,
        epoch: u32,
        sender_account: &str,
        sender_incarnation_id: &str,
        sender_signing_key: &SigningKey,
        recipient_account: &str,
        recipient_incarnation_id: &str,
        recipient_hpke_public_key: &[u8],
    ) -> Result<Self> {
        if collection_key.len() != 32 || recipient_hpke_public_key.len() != 32 || epoch == 0 {
            return Err(CryptoError::InvalidInput(
                "named-share key length or epoch is invalid".into(),
            ));
        }
        let mut envelope = Self {
            suite: NamedShareSuiteId::X25519HkdfSha256ChaCha20Poly1305Ed25519V1,
            collection_id: parse_canonical_uuid(collection_id, "collection")?,
            epoch,
            sender_incarnation_id: parse_hex_32(sender_incarnation_id, "sender incarnation")?,
            recipient_incarnation_id: parse_hex_32(
                recipient_incarnation_id,
                "recipient incarnation",
            )?,
            sender_account: canonical_account(sender_account)?,
            recipient_account: canonical_account(recipient_account)?,
            encapsulated_key: [0u8; X25519_ENCAPSULATED_KEY_LEN],
            ciphertext: [0u8; COLLECTION_KEY_CIPHERTEXT_LEN],
            signature: [0u8; SIGNATURE_LEN],
        };
        if envelope.sender_account == envelope.recipient_account
            && envelope.sender_incarnation_id == envelope.recipient_incarnation_id
        {
            return Err(CryptoError::InvalidInput(
                "named share sender and recipient must differ".into(),
            ));
        }
        let aad = envelope.aad_bytes()?;
        let mut hpke = hpke_suite();
        let (encapsulated_key, ciphertext) = hpke
            .seal(
                &HpkePublicKey::new(recipient_hpke_public_key.to_vec()),
                HPKE_INFO,
                &aad,
                collection_key,
                None,
                None,
                None,
            )
            .map_err(|error| CryptoError::Backend(format!("named-share HPKE seal: {error}")))?;
        envelope.encapsulated_key =
            encapsulated_key
                .try_into()
                .map_err(|value: Vec<u8>| CryptoError::InvalidLength {
                    expected: X25519_ENCAPSULATED_KEY_LEN,
                    got: value.len(),
                })?;
        envelope.ciphertext =
            ciphertext
                .try_into()
                .map_err(|value: Vec<u8>| CryptoError::InvalidLength {
                    expected: COLLECTION_KEY_CIPHERTEXT_LEN,
                    got: value.len(),
                })?;
        envelope.signature = sender_signing_key
            .sign(&envelope.signing_bytes()?)
            .to_bytes();
        Ok(envelope)
    }

    fn aad_bytes(&self) -> Result<Vec<u8>> {
        let sender_len = u16::try_from(self.sender_account.len())
            .map_err(|_| CryptoError::InvalidInput("sender account is too long".into()))?;
        let recipient_len = u16::try_from(self.recipient_account.len())
            .map_err(|_| CryptoError::InvalidInput("recipient account is too long".into()))?;
        let mut bytes = Vec::with_capacity(
            FIXED_AAD_LEN + self.sender_account.len() + self.recipient_account.len(),
        );
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.suite.as_u16().to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&self.collection_id);
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.sender_incarnation_id);
        bytes.extend_from_slice(&self.recipient_incarnation_id);
        bytes.extend_from_slice(&sender_len.to_be_bytes());
        bytes.extend_from_slice(self.sender_account.as_bytes());
        bytes.extend_from_slice(&recipient_len.to_be_bytes());
        bytes.extend_from_slice(self.recipient_account.as_bytes());
        Ok(bytes)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = self.aad_bytes()?;
        bytes.extend_from_slice(&(X25519_ENCAPSULATED_KEY_LEN as u16).to_be_bytes());
        bytes.extend_from_slice(&self.encapsulated_key);
        bytes.extend_from_slice(&(COLLECTION_KEY_CIPHERTEXT_LEN as u16).to_be_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        Ok(bytes)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = self.signing_bytes()?;
        bytes.extend_from_slice(&self.signature);
        Ok(bytes)
    }

    pub fn encode_b64(&self) -> Result<String> {
        Ok(base64::engine::general_purpose::STANDARD.encode(self.encode()?))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < FIXED_AAD_LEN + 1 + 1 + 2 + 32 + 2 + 48 + 64
            || bytes.get(..MAGIC.len()) != Some(MAGIC)
        {
            return Err(CryptoError::TooShort);
        }
        let suite = NamedShareSuiteId::try_from(u16::from_be_bytes([bytes[8], bytes[9]]))?;
        if bytes[10] != 0 || bytes[11] != 0 {
            return Err(CryptoError::InvalidInput(
                "named-share reserved bytes are non-zero".into(),
            ));
        }
        let collection_id = bytes[12..28].try_into().expect("sixteen-byte slice");
        let epoch = u32::from_be_bytes(bytes[28..32].try_into().expect("four-byte slice"));
        if epoch == 0 {
            return Err(CryptoError::InvalidInput(
                "named-share epoch must be non-zero".into(),
            ));
        }
        let sender_incarnation_id = bytes[32..64].try_into().expect("32-byte slice");
        let recipient_incarnation_id = bytes[64..96].try_into().expect("32-byte slice");
        let mut cursor = 96usize;
        let sender_account = read_account(bytes, &mut cursor, "sender")?;
        let recipient_account = read_account(bytes, &mut cursor, "recipient")?;
        if sender_account == recipient_account && sender_incarnation_id == recipient_incarnation_id
        {
            return Err(CryptoError::InvalidInput(
                "named share sender and recipient must differ".into(),
            ));
        }
        if read_u16(bytes, &mut cursor)? as usize != X25519_ENCAPSULATED_KEY_LEN {
            return Err(CryptoError::InvalidInput(
                "named-share encapsulated key length is invalid".into(),
            ));
        }
        let encapsulated_key = take(bytes, &mut cursor, X25519_ENCAPSULATED_KEY_LEN)?
            .try_into()
            .expect("32-byte slice");
        if read_u16(bytes, &mut cursor)? as usize != COLLECTION_KEY_CIPHERTEXT_LEN {
            return Err(CryptoError::InvalidInput(
                "named-share ciphertext length is invalid".into(),
            ));
        }
        let ciphertext = take(bytes, &mut cursor, COLLECTION_KEY_CIPHERTEXT_LEN)?
            .try_into()
            .expect("48-byte slice");
        let signature = take(bytes, &mut cursor, SIGNATURE_LEN)?
            .try_into()
            .expect("64-byte slice");
        if cursor != bytes.len() {
            return Err(CryptoError::InvalidInput(
                "named-share envelope has trailing data".into(),
            ));
        }
        Ok(Self {
            suite,
            collection_id,
            epoch,
            sender_incarnation_id,
            recipient_incarnation_id,
            sender_account,
            recipient_account,
            encapsulated_key,
            ciphertext,
            signature,
        })
    }

    pub fn decode_b64(value: &str) -> Result<Self> {
        let bytes = base64::engine::general_purpose::STANDARD.decode(value)?;
        if base64::engine::general_purpose::STANDARD.encode(&bytes) != value {
            return Err(CryptoError::InvalidInput(
                "named-share envelope must use canonical base64".into(),
            ));
        }
        Self::decode(&bytes)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open(
        &self,
        expected_collection_id: &str,
        expected_epoch: u32,
        expected_sender_account: &str,
        expected_sender_incarnation_id: &str,
        sender_signing_public_key: &[u8],
        expected_recipient_account: &str,
        expected_recipient_incarnation_id: &str,
        recipient_hpke_private_key: &[u8],
    ) -> Result<Vec<u8>> {
        self.verify_binding_and_signature(
            expected_collection_id,
            expected_epoch,
            expected_sender_account,
            expected_sender_incarnation_id,
            sender_signing_public_key,
            expected_recipient_account,
            expected_recipient_incarnation_id,
        )?;
        if recipient_hpke_private_key.len() != 32 {
            return Err(CryptoError::InvalidLength {
                expected: 32,
                got: recipient_hpke_private_key.len(),
            });
        }
        let hpke = hpke_suite();
        let plaintext = hpke
            .open(
                &self.encapsulated_key,
                &HpkePrivateKey::new(recipient_hpke_private_key.to_vec()),
                HPKE_INFO,
                &self.aad_bytes()?,
                &self.ciphertext,
                None,
                None,
                None,
            )
            .map_err(|_| CryptoError::AuthFailed)?;
        if plaintext.len() != 32 {
            return Err(CryptoError::AuthFailed);
        }
        Ok(plaintext)
    }

    /// Validate all public routing/binding fields and the manifest-bound
    /// sender signature without attempting HPKE decryption. Servers use this
    /// before persisting or relaying a share; recipients repeat it as part of
    /// [`Self::open`].
    #[allow(clippy::too_many_arguments)]
    pub fn verify_binding_and_signature(
        &self,
        expected_collection_id: &str,
        expected_epoch: u32,
        expected_sender_account: &str,
        expected_sender_incarnation_id: &str,
        sender_signing_public_key: &[u8],
        expected_recipient_account: &str,
        expected_recipient_incarnation_id: &str,
    ) -> Result<()> {
        if self.collection_id != parse_canonical_uuid(expected_collection_id, "collection")?
            || self.epoch != expected_epoch
            || self.sender_account != canonical_account(expected_sender_account)?
            || self.sender_incarnation_id
                != parse_hex_32(expected_sender_incarnation_id, "sender incarnation")?
            || self.recipient_account != canonical_account(expected_recipient_account)?
            || self.recipient_incarnation_id
                != parse_hex_32(expected_recipient_incarnation_id, "recipient incarnation")?
        {
            return Err(CryptoError::AuthFailed);
        }
        let signing_public: [u8; 32] =
            sender_signing_public_key
                .try_into()
                .map_err(|_| CryptoError::InvalidLength {
                    expected: 32,
                    got: sender_signing_public_key.len(),
                })?;
        let signing_public =
            VerifyingKey::from_bytes(&signing_public).map_err(|_| CryptoError::AuthFailed)?;
        signing_public
            .verify(
                &self.signing_bytes()?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| CryptoError::AuthFailed)
    }
}

fn hpke_suite() -> Hpke<HpkeRustCrypto> {
    Hpke::new(
        Mode::Base,
        KemAlgorithm::DhKem25519,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::ChaCha20Poly1305,
    )
}

fn canonical_account(value: &str) -> Result<String> {
    if value.len() < 3
        || value.len() > MAX_ACCOUNT_LEN
        || value != value.trim()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_uppercase() || byte.is_ascii_control())
        || value.matches('@').count() != 1
    {
        return Err(CryptoError::InvalidInput(
            "named-share account is not canonical".into(),
        ));
    }
    let (username, domain) = value.split_once('@').expect("one at sign");
    if username.is_empty()
        || domain.is_empty()
        || !username
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte))
        || !domain
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(&byte))
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return Err(CryptoError::InvalidInput(
            "named-share account is not canonical".into(),
        ));
    }
    Ok(value.to_string())
}

fn parse_hex_32(value: &str, field: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CryptoError::InvalidInput(format!(
            "named-share {field} is invalid"
        )));
    }
    Ok(hex::decode(value)
        .map_err(|_| CryptoError::InvalidInput(format!("named-share {field} is invalid")))?
        .try_into()
        .expect("validated 32-byte hex"))
}

fn read_account(bytes: &[u8], cursor: &mut usize, field: &str) -> Result<String> {
    let len = read_u16(bytes, cursor)? as usize;
    if len == 0 || len > MAX_ACCOUNT_LEN {
        return Err(CryptoError::InvalidInput(format!(
            "named-share {field} account length is invalid"
        )));
    }
    let value = std::str::from_utf8(take(bytes, cursor, len)?)
        .map_err(|_| CryptoError::InvalidInput("named-share account is not UTF-8".into()))?;
    canonical_account(value)
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16> {
    Ok(u16::from_be_bytes(
        take(bytes, cursor, 2)?.try_into().expect("two-byte slice"),
    ))
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = cursor.checked_add(len).ok_or(CryptoError::TooShort)?;
    let value = bytes.get(*cursor..end).ok_or(CryptoError::TooShort)?;
    *cursor = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AccountIdentityKeysV1;

    #[test]
    fn named_share_round_trip_is_signature_identity_and_incarnation_bound() {
        let sender = AccountIdentityKeysV1::derive(&[1u8; 32]).unwrap();
        let recipient = AccountIdentityKeysV1::derive(&[2u8; 32]).unwrap();
        let envelope = NamedShareEnvelopeV1::seal(
            &[0x55; 32],
            "11111111-1111-4111-8111-111111111111",
            3,
            "alice@a.test",
            &sender.incarnation_id(),
            sender.drive_signing_key(),
            "bob@b.test",
            &recipient.incarnation_id(),
            &recipient.drive_hpke_public_key(),
        )
        .unwrap();
        let decoded = NamedShareEnvelopeV1::decode_b64(&envelope.encode_b64().unwrap()).unwrap();
        assert_eq!(
            decoded
                .open(
                    "11111111-1111-4111-8111-111111111111",
                    3,
                    "alice@a.test",
                    &sender.incarnation_id(),
                    &sender.drive_signing_public_key(),
                    "bob@b.test",
                    &recipient.incarnation_id(),
                    recipient.drive_hpke_private_key(),
                )
                .unwrap(),
            vec![0x55; 32]
        );
        assert!(decoded
            .open(
                "11111111-1111-4111-8111-111111111111",
                4,
                "alice@a.test",
                &sender.incarnation_id(),
                &sender.drive_signing_public_key(),
                "bob@b.test",
                &recipient.incarnation_id(),
                recipient.drive_hpke_private_key(),
            )
            .is_err());
    }

    #[test]
    fn parser_rejects_tamper_trailing_unknown_and_noncanonical_accounts() {
        let sender = AccountIdentityKeysV1::derive(&[1u8; 32]).unwrap();
        let recipient = AccountIdentityKeysV1::derive(&[2u8; 32]).unwrap();
        assert!(NamedShareEnvelopeV1::seal(
            &[0x55; 32],
            "11111111-1111-4111-8111-111111111111",
            3,
            "Alice@a.test",
            &sender.incarnation_id(),
            sender.drive_signing_key(),
            "bob@b.test",
            &recipient.incarnation_id(),
            &recipient.drive_hpke_public_key(),
        )
        .is_err());
        let envelope = NamedShareEnvelopeV1::seal(
            &[0x55; 32],
            "11111111-1111-4111-8111-111111111111",
            3,
            "alice@a.test",
            &sender.incarnation_id(),
            sender.drive_signing_key(),
            "bob@b.test",
            &recipient.incarnation_id(),
            &recipient.drive_hpke_public_key(),
        )
        .unwrap();
        let mut bytes = envelope.encode().unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        let tampered = NamedShareEnvelopeV1::decode(&bytes).unwrap();
        assert!(tampered
            .open(
                "11111111-1111-4111-8111-111111111111",
                3,
                "alice@a.test",
                &sender.incarnation_id(),
                &sender.drive_signing_public_key(),
                "bob@b.test",
                &recipient.incarnation_id(),
                recipient.drive_hpke_private_key(),
            )
            .is_err());
        bytes.push(0);
        assert!(NamedShareEnvelopeV1::decode(&bytes).is_err());
        bytes = envelope.encode().unwrap();
        bytes[9] = 2;
        assert!(NamedShareEnvelopeV1::decode(&bytes).is_err());
    }
}
