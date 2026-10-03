//! A person's profile key, given to someone they share Drive files with
//! (docs/plans/unified-profile.md).
//!
//! The profile (name, picture, "about") is end-to-end encrypted under a
//! random 32-byte profile key; whoever holds the key can fetch and read it.
//! Drive hands the key over with a share: HPKE-sealed to the recipient's
//! Drive public key and signed with the sender's Drive signing key, like a
//! named share (`named_share.rs`), so a server can neither read it nor swap
//! in a key for a profile of its own making. It is bound to both accounts
//! and incarnations, not to a folder: the same key reaches the same person
//! for every share, in both directions (owner to member, member to owner).

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use hpke_rs::{HpkePrivateKey, HpkePublicKey};

use crate::error::{CryptoError, Result};
use crate::named_share::{canonical_account, hpke_suite, parse_hex_32, read_account, take};

const MAGIC: &[u8; 8] = b"KUTPPK1\0";
const HPKE_INFO: &[u8] = b"kutup/drive/profile-key-hpke/v1\0";
const SUITE_V1: u16 = 1;
const ENCAPSULATED_KEY_LEN: usize = 32;
const PROFILE_KEY_LEN: usize = 32;
const CIPHERTEXT_LEN: usize = PROFILE_KEY_LEN + 16;
const SIGNATURE_LEN: usize = 64;
/// Magic, suite, reserved, two incarnations.
const FIXED_HEADER_LEN: usize = 8 + 2 + 2 + 32 + 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileKeyEnvelopeV1 {
    pub sender_incarnation_id: [u8; 32],
    pub recipient_incarnation_id: [u8; 32],
    pub sender_account: String,
    pub recipient_account: String,
    pub encapsulated_key: [u8; ENCAPSULATED_KEY_LEN],
    pub ciphertext: [u8; CIPHERTEXT_LEN],
    pub signature: [u8; SIGNATURE_LEN],
}

/// Who a profile key goes from and to.
pub struct ProfileKeyParties<'a> {
    pub sender_account: &'a str,
    pub sender_incarnation_id: &'a str,
    pub recipient_account: &'a str,
    pub recipient_incarnation_id: &'a str,
}

impl ProfileKeyEnvelopeV1 {
    pub fn seal(
        profile_key: &[u8],
        parties: &ProfileKeyParties<'_>,
        sender_signing_key: &SigningKey,
        recipient_hpke_public_key: &[u8],
    ) -> Result<Self> {
        if profile_key.len() != PROFILE_KEY_LEN || recipient_hpke_public_key.len() != 32 {
            return Err(CryptoError::InvalidInput(
                "profile key or recipient key has an invalid length".into(),
            ));
        }
        let mut envelope = Self {
            sender_incarnation_id: parse_hex_32(
                parties.sender_incarnation_id,
                "sender incarnation",
            )?,
            recipient_incarnation_id: parse_hex_32(
                parties.recipient_incarnation_id,
                "recipient incarnation",
            )?,
            sender_account: canonical_account(parties.sender_account)?,
            recipient_account: canonical_account(parties.recipient_account)?,
            encapsulated_key: [0u8; ENCAPSULATED_KEY_LEN],
            ciphertext: [0u8; CIPHERTEXT_LEN],
            signature: [0u8; SIGNATURE_LEN],
        };
        if envelope.sender_account == envelope.recipient_account {
            return Err(CryptoError::InvalidInput(
                "a profile key goes to someone else".into(),
            ));
        }
        let aad = envelope.header_bytes()?;
        let (encapsulated_key, ciphertext) = hpke_suite()
            .seal(
                &HpkePublicKey::new(recipient_hpke_public_key.to_vec()),
                HPKE_INFO,
                &aad,
                profile_key,
                None,
                None,
                None,
            )
            .map_err(|error| CryptoError::Backend(format!("profile-key HPKE seal: {error}")))?;
        envelope.encapsulated_key =
            encapsulated_key
                .try_into()
                .map_err(|value: Vec<u8>| CryptoError::InvalidLength {
                    expected: ENCAPSULATED_KEY_LEN,
                    got: value.len(),
                })?;
        envelope.ciphertext =
            ciphertext
                .try_into()
                .map_err(|value: Vec<u8>| CryptoError::InvalidLength {
                    expected: CIPHERTEXT_LEN,
                    got: value.len(),
                })?;
        envelope.signature = sender_signing_key
            .sign(&envelope.signing_bytes()?)
            .to_bytes();
        Ok(envelope)
    }

    fn header_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(
            FIXED_HEADER_LEN + 4 + self.sender_account.len() + self.recipient_account.len(),
        );
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&SUITE_V1.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&self.sender_incarnation_id);
        bytes.extend_from_slice(&self.recipient_incarnation_id);
        for account in [&self.sender_account, &self.recipient_account] {
            let length = u16::try_from(account.len())
                .map_err(|_| CryptoError::InvalidInput("account is too long".into()))?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(account.as_bytes());
        }
        Ok(bytes)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = self.header_bytes()?;
        bytes.extend_from_slice(&self.encapsulated_key);
        bytes.extend_from_slice(&self.ciphertext);
        Ok(bytes)
    }

    pub fn encode_b64(&self) -> Result<String> {
        let mut bytes = self.signing_bytes()?;
        bytes.extend_from_slice(&self.signature);
        Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn decode_b64(value: &str) -> Result<Self> {
        let bytes = base64::engine::general_purpose::STANDARD.decode(value)?;
        if base64::engine::general_purpose::STANDARD.encode(&bytes) != value {
            return Err(CryptoError::InvalidInput(
                "profile-key envelope must use canonical base64".into(),
            ));
        }
        if bytes.len() < FIXED_HEADER_LEN || bytes.get(..MAGIC.len()) != Some(MAGIC) {
            return Err(CryptoError::TooShort);
        }
        if u16::from_be_bytes([bytes[8], bytes[9]]) != SUITE_V1 || bytes[10] != 0 || bytes[11] != 0
        {
            return Err(CryptoError::InvalidInput(
                "unknown profile-key envelope suite".into(),
            ));
        }
        let sender_incarnation_id = bytes[12..44].try_into().expect("32-byte slice");
        let recipient_incarnation_id = bytes[44..76].try_into().expect("32-byte slice");
        let mut cursor = FIXED_HEADER_LEN;
        let sender_account = read_account(&bytes, &mut cursor, "sender")?;
        let recipient_account = read_account(&bytes, &mut cursor, "recipient")?;
        let encapsulated_key = take(&bytes, &mut cursor, ENCAPSULATED_KEY_LEN)?
            .try_into()
            .expect("32-byte slice");
        let ciphertext = take(&bytes, &mut cursor, CIPHERTEXT_LEN)?
            .try_into()
            .expect("48-byte slice");
        let signature = take(&bytes, &mut cursor, SIGNATURE_LEN)?
            .try_into()
            .expect("64-byte slice");
        if cursor != bytes.len() {
            return Err(CryptoError::InvalidInput(
                "profile-key envelope has trailing data".into(),
            ));
        }
        Ok(Self {
            sender_incarnation_id,
            recipient_incarnation_id,
            sender_account,
            recipient_account,
            encapsulated_key,
            ciphertext,
            signature,
        })
    }

    /// Check who it is from and to, and the sender's signature, without
    /// opening it. Servers do this before storing one.
    pub fn verify(
        &self,
        expected: &ProfileKeyParties<'_>,
        sender_signing_public_key: &[u8],
    ) -> Result<()> {
        if self.sender_account != canonical_account(expected.sender_account)?
            || self.recipient_account != canonical_account(expected.recipient_account)?
            || self.sender_incarnation_id
                != parse_hex_32(expected.sender_incarnation_id, "sender incarnation")?
            || self.recipient_incarnation_id
                != parse_hex_32(expected.recipient_incarnation_id, "recipient incarnation")?
        {
            return Err(CryptoError::AuthFailed);
        }
        let public: [u8; 32] =
            sender_signing_public_key
                .try_into()
                .map_err(|_| CryptoError::InvalidLength {
                    expected: 32,
                    got: sender_signing_public_key.len(),
                })?;
        VerifyingKey::from_bytes(&public)
            .map_err(|_| CryptoError::AuthFailed)?
            .verify(
                &self.signing_bytes()?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| CryptoError::AuthFailed)
    }

    /// The profile key, after checking the parties and the signature.
    pub fn open(
        &self,
        expected: &ProfileKeyParties<'_>,
        sender_signing_public_key: &[u8],
        recipient_hpke_private_key: &[u8],
    ) -> Result<Vec<u8>> {
        self.verify(expected, sender_signing_public_key)?;
        if recipient_hpke_private_key.len() != 32 {
            return Err(CryptoError::InvalidLength {
                expected: 32,
                got: recipient_hpke_private_key.len(),
            });
        }
        let key = hpke_suite()
            .open(
                &self.encapsulated_key,
                &HpkePrivateKey::new(recipient_hpke_private_key.to_vec()),
                HPKE_INFO,
                &self.header_bytes()?,
                &self.ciphertext,
                None,
                None,
                None,
            )
            .map_err(|_| CryptoError::AuthFailed)?;
        if key.len() != PROFILE_KEY_LEN {
            return Err(CryptoError::AuthFailed);
        }
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AccountIdentityKeysV1;

    const ALICE_INC: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const BOB_INC: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn parties<'a>() -> ProfileKeyParties<'a> {
        ProfileKeyParties {
            sender_account: "alice@a.test",
            sender_incarnation_id: ALICE_INC,
            recipient_account: "bob@b.test",
            recipient_incarnation_id: BOB_INC,
        }
    }

    #[test]
    fn a_profile_key_reaches_only_its_recipient_from_its_sender() {
        let alice = AccountIdentityKeysV1::derive(&[1u8; 32]).unwrap();
        let bob = AccountIdentityKeysV1::derive(&[2u8; 32]).unwrap();
        let key = [9u8; 32];
        let envelope = ProfileKeyEnvelopeV1::seal(
            &key,
            &parties(),
            alice.drive_signing_key(),
            &bob.drive_hpke_public_key(),
        )
        .unwrap();
        let encoded = envelope.encode_b64().unwrap();
        let decoded = ProfileKeyEnvelopeV1::decode_b64(&encoded).unwrap();
        assert_eq!(decoded, envelope);
        let alice_signing = alice.drive_signing_key().verifying_key().to_bytes();
        assert_eq!(
            decoded
                .open(&parties(), &alice_signing, bob.drive_hpke_private_key())
                .unwrap(),
            key
        );

        // Another reader, another claimed sender, or swapped parties fail.
        let carol = AccountIdentityKeysV1::derive(&[3u8; 32]).unwrap();
        assert!(decoded
            .open(&parties(), &alice_signing, carol.drive_hpke_private_key())
            .is_err());
        let bob_signing = bob.drive_signing_key().verifying_key().to_bytes();
        assert!(decoded.verify(&parties(), &bob_signing).is_err());
        let other = ProfileKeyParties {
            recipient_account: "carol@c.test",
            ..parties()
        };
        assert!(decoded.verify(&other, &alice_signing).is_err());

        // Any changed byte breaks the signature.
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .unwrap();
        let last = bytes.len() - 70;
        bytes[last] ^= 1;
        let tampered = ProfileKeyEnvelopeV1::decode_b64(
            &base64::engine::general_purpose::STANDARD.encode(bytes),
        )
        .unwrap();
        assert!(tampered.verify(&parties(), &alice_signing).is_err());
    }
}
