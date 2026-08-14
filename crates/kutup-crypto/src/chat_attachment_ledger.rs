//! Typed account-private envelopes for the Chat attachment reference ledger.
//!
//! The server uses the public header only for bounded compare-and-swap
//! persistence. Conversation, message, media class and display metadata remain
//! inside the XChaCha20-Poly1305 ciphertext and are projected locally.

use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dryoc::rng::copy_randombytes;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::drive_object::parse_canonical_uuid;
use crate::error::{CryptoError, Result};

const MAGIC: &[u8; 8] = b"KUTPCL1\0";
const KEY_DERIVATION_SALT: &[u8] = b"kutup/chat-attachment-ledger/key/v1\0";
const ACCOUNT_LEDGER_KEY_SALT: &[u8] = b"kutup/account-private-subkey/v1\0";
const ACCOUNT_LEDGER_KEY_INFO: &[u8] = b"kutup/chat-attachment-ledger/account-key/v1\0";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const DIGEST_LEN: usize = 32;
pub const CHAT_ATTACHMENT_LEDGER_HEADER_BYTES: usize = 128;
pub const MAX_CHAT_ATTACHMENT_LEDGER_PLAINTEXT_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum ChatAttachmentLedgerSuiteId {
    XChaCha20Poly1305V1 = 1,
}

impl ChatAttachmentLedgerSuiteId {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl From<ChatAttachmentLedgerSuiteId> for u16 {
    fn from(value: ChatAttachmentLedgerSuiteId) -> Self {
        value.as_u16()
    }
}

impl TryFrom<u16> for ChatAttachmentLedgerSuiteId {
    type Error = CryptoError;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::XChaCha20Poly1305V1),
            _ => Err(CryptoError::InvalidInput(format!(
                "unknown Chat attachment-ledger suite {value}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ChatAttachmentLedgerPurpose {
    AttachmentEntry = 1,
}

impl ChatAttachmentLedgerPurpose {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for ChatAttachmentLedgerPurpose {
    type Error = CryptoError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::AttachmentEntry),
            _ => Err(CryptoError::InvalidInput(format!(
                "unknown Chat attachment-ledger purpose {value}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChatAttachmentLedgerContextV1 {
    pub account_incarnation_id: [u8; 32],
    pub entity_id: [u8; 16],
    pub revision: u64,
    pub previous_envelope_digest: [u8; DIGEST_LEN],
}

impl ChatAttachmentLedgerContextV1 {
    pub fn new(
        account_incarnation_id: &str,
        entity_id: &str,
        revision: u64,
        previous_envelope_digest: Option<&str>,
    ) -> Result<Self> {
        if revision == 0 {
            return Err(CryptoError::InvalidInput(
                "Chat attachment-ledger revision must be non-zero".into(),
            ));
        }
        let previous_envelope_digest = match previous_envelope_digest {
            None if revision == 1 => [0u8; DIGEST_LEN],
            Some(value) if revision > 1 => parse_digest(value)?,
            _ => {
                return Err(CryptoError::InvalidInput(
                    "Chat attachment-ledger predecessor does not match revision".into(),
                ))
            }
        };
        if revision > 1 && previous_envelope_digest == [0u8; DIGEST_LEN] {
            return Err(CryptoError::InvalidInput(
                "Chat attachment-ledger predecessor must be non-zero".into(),
            ));
        }
        Ok(Self {
            account_incarnation_id: parse_lower_hex_32(
                account_incarnation_id,
                "Chat attachment-ledger account incarnation",
            )?,
            entity_id: parse_canonical_uuid(entity_id, "Chat attachment-ledger entity")?,
            revision,
            previous_envelope_digest,
        })
    }
}

fn parse_lower_hex_32(value: &str, field: &str) -> Result<[u8; 32]> {
    let decoded = hex::decode(value)
        .map_err(|_| CryptoError::InvalidInput(format!("{field} must be lowercase hex")))?;
    if decoded.len() != 32 || hex::encode(&decoded) != value {
        return Err(CryptoError::InvalidInput(format!(
            "{field} must be canonical 32-byte lowercase hex"
        )));
    }
    decoded
        .try_into()
        .map_err(|_| CryptoError::InvalidInput(format!("{field} length is invalid")))
}

/// Derive the account-private ledger root from the recoverable master key.
/// This is a typed subkey, never a Drive, profile, Signal, MLS, or attachment
/// object key, and requires no second remote account-secret envelope.
pub fn derive_account_ledger_key(master_key: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if master_key.len() != KEY_LEN {
        return Err(CryptoError::InvalidLength {
            expected: KEY_LEN,
            got: master_key.len(),
        });
    }
    let hkdf = Hkdf::<Sha256>::new(Some(ACCOUNT_LEDGER_KEY_SALT), master_key);
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    hkdf.expand(ACCOUNT_LEDGER_KEY_INFO, key.as_mut_slice())
        .map_err(|_| CryptoError::Backend("Chat attachment-ledger account HKDF expand".into()))?;
    Ok(key)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChatAttachmentLedgerHeaderV1 {
    pub suite: ChatAttachmentLedgerSuiteId,
    pub purpose: ChatAttachmentLedgerPurpose,
    pub context: ChatAttachmentLedgerContextV1,
    pub ciphertext_len: u32,
}

struct ParsedEnvelope<'a> {
    header: ChatAttachmentLedgerHeaderV1,
    aad: &'a [u8],
    nonce: &'a [u8],
    ciphertext: &'a [u8],
}

fn parse_digest(value: &str) -> Result<[u8; DIGEST_LEN]> {
    let decoded = hex::decode(value)
        .map_err(|_| CryptoError::InvalidInput("ledger digest must be lowercase hex".into()))?;
    if decoded.len() != DIGEST_LEN || hex::encode(&decoded) != value {
        return Err(CryptoError::InvalidInput(
            "ledger digest must be canonical SHA-256 hex".into(),
        ));
    }
    decoded
        .try_into()
        .map_err(|_| CryptoError::InvalidInput("ledger digest length is invalid".into()))
}

fn build_header(
    context: ChatAttachmentLedgerContextV1,
    nonce: &[u8; NONCE_LEN],
    ciphertext_len: u32,
) -> [u8; CHAT_ATTACHMENT_LEDGER_HEADER_BYTES] {
    let mut header = [0u8; CHAT_ATTACHMENT_LEDGER_HEADER_BYTES];
    header[..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(
        &ChatAttachmentLedgerSuiteId::XChaCha20Poly1305V1
            .as_u16()
            .to_be_bytes(),
    );
    header[10] = ChatAttachmentLedgerPurpose::AttachmentEntry.as_u8();
    header[12..44].copy_from_slice(&context.account_incarnation_id);
    header[44..60].copy_from_slice(&context.entity_id);
    header[60..68].copy_from_slice(&context.revision.to_be_bytes());
    header[68..100].copy_from_slice(&context.previous_envelope_digest);
    header[100..124].copy_from_slice(nonce);
    header[124..128].copy_from_slice(&ciphertext_len.to_be_bytes());
    header
}

fn derive_key(
    ledger_key: &[u8],
    header: &[u8; CHAT_ATTACHMENT_LEDGER_HEADER_BYTES],
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if ledger_key.len() != KEY_LEN {
        return Err(CryptoError::InvalidLength {
            expected: KEY_LEN,
            got: ledger_key.len(),
        });
    }
    let hkdf = Hkdf::<Sha256>::new(Some(KEY_DERIVATION_SALT), ledger_key);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(header, key.as_mut_slice())
        .map_err(|_| CryptoError::Backend("Chat attachment-ledger HKDF expand".into()))?;
    Ok(key)
}

pub fn seal(
    plaintext: &[u8],
    ledger_key: &[u8],
    context: ChatAttachmentLedgerContextV1,
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    copy_randombytes(&mut nonce);
    seal_with_nonce(plaintext, ledger_key, context, &nonce)
}

/// Deterministic-nonce entry point for canonical vectors only.
pub fn seal_with_nonce(
    plaintext: &[u8],
    ledger_key: &[u8],
    context: ChatAttachmentLedgerContextV1,
    nonce: &[u8],
) -> Result<Vec<u8>> {
    if plaintext.is_empty() || plaintext.len() > MAX_CHAT_ATTACHMENT_LEDGER_PLAINTEXT_BYTES {
        return Err(CryptoError::InvalidInput(
            "Chat attachment-ledger plaintext length is invalid".into(),
        ));
    }
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: NONCE_LEN,
        got: nonce.len(),
    })?;
    let ciphertext_len = u32::try_from(plaintext.len() + TAG_LEN)
        .map_err(|_| CryptoError::InvalidInput("ledger plaintext is too long".into()))?;
    let header = build_header(context, &nonce, ciphertext_len);
    let key = derive_key(ledger_key, &header)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| CryptoError::Backend("Chat attachment-ledger AEAD init".into()))?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| CryptoError::Backend("Chat attachment-ledger seal".into()))?;
    let mut envelope = header.to_vec();
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn parse(envelope: &[u8]) -> Result<ParsedEnvelope<'_>> {
    if envelope.len() < CHAT_ATTACHMENT_LEDGER_HEADER_BYTES + TAG_LEN + 1
        || envelope.get(..8) != Some(MAGIC)
    {
        return Err(CryptoError::TooShort);
    }
    let suite =
        ChatAttachmentLedgerSuiteId::try_from(u16::from_be_bytes([envelope[8], envelope[9]]))?;
    let purpose = ChatAttachmentLedgerPurpose::try_from(envelope[10])?;
    if envelope[11] != 0 {
        return Err(CryptoError::InvalidInput(
            "Chat attachment-ledger reserved byte is non-zero".into(),
        ));
    }
    let revision = u64::from_be_bytes(envelope[60..68].try_into().expect("eight-byte slice"));
    let previous_envelope_digest: [u8; DIGEST_LEN] =
        envelope[68..100].try_into().expect("digest slice");
    if revision == 0
        || (revision == 1 && previous_envelope_digest != [0u8; DIGEST_LEN])
        || (revision > 1 && previous_envelope_digest == [0u8; DIGEST_LEN])
    {
        return Err(CryptoError::InvalidInput(
            "Chat attachment-ledger revision/predecessor is invalid".into(),
        ));
    }
    let ciphertext_len = u32::from_be_bytes(
        envelope[124..128]
            .try_into()
            .expect("four-byte length slice"),
    );
    let ciphertext_len_usize = ciphertext_len as usize;
    if !(TAG_LEN + 1..=MAX_CHAT_ATTACHMENT_LEDGER_PLAINTEXT_BYTES + TAG_LEN)
        .contains(&ciphertext_len_usize)
        || CHAT_ATTACHMENT_LEDGER_HEADER_BYTES.checked_add(ciphertext_len_usize)
            != Some(envelope.len())
    {
        return Err(CryptoError::InvalidInput(
            "Chat attachment-ledger ciphertext length is invalid".into(),
        ));
    }
    Ok(ParsedEnvelope {
        header: ChatAttachmentLedgerHeaderV1 {
            suite,
            purpose,
            context: ChatAttachmentLedgerContextV1 {
                account_incarnation_id: envelope[12..44]
                    .try_into()
                    .expect("account incarnation slice"),
                entity_id: envelope[44..60].try_into().expect("entity id slice"),
                revision,
                previous_envelope_digest,
            },
            ciphertext_len,
        },
        aad: &envelope[..CHAT_ATTACHMENT_LEDGER_HEADER_BYTES],
        nonce: &envelope[100..124],
        ciphertext: &envelope[CHAT_ATTACHMENT_LEDGER_HEADER_BYTES..],
    })
}

pub fn inspect(envelope: &[u8]) -> Result<ChatAttachmentLedgerHeaderV1> {
    Ok(parse(envelope)?.header)
}

pub fn envelope_digest(envelope: &[u8]) -> Result<String> {
    parse(envelope)?;
    Ok(hex::encode(Sha256::digest(envelope)))
}

pub fn open(
    envelope: &[u8],
    ledger_key: &[u8],
    expected: ChatAttachmentLedgerContextV1,
) -> Result<Vec<u8>> {
    let parsed = parse(envelope)?;
    if parsed.header.suite != ChatAttachmentLedgerSuiteId::XChaCha20Poly1305V1
        || parsed.header.purpose != ChatAttachmentLedgerPurpose::AttachmentEntry
        || parsed.header.context != expected
    {
        return Err(CryptoError::AuthFailed);
    }
    let header: &[u8; CHAT_ATTACHMENT_LEDGER_HEADER_BYTES] = parsed
        .aad
        .try_into()
        .expect("parser returns the fixed ledger header");
    let key = derive_key(ledger_key, header)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| CryptoError::Backend("Chat attachment-ledger AEAD init".into()))?;
    cipher
        .decrypt(
            XNonce::from_slice(parsed.nonce),
            Payload {
                msg: parsed.ciphertext,
                aad: parsed.aad,
            },
        )
        .map_err(|_| CryptoError::AuthFailed)
}

pub fn seal_b64(
    plaintext: &[u8],
    ledger_key: &[u8],
    context: ChatAttachmentLedgerContextV1,
) -> Result<String> {
    Ok(base64::engine::general_purpose::STANDARD.encode(seal(plaintext, ledger_key, context)?))
}

pub fn decode_canonical_b64(value: &str) -> Result<Vec<u8>> {
    let decoded = base64::engine::general_purpose::STANDARD.decode(value)?;
    if base64::engine::general_purpose::STANDARD.encode(&decoded) != value {
        return Err(CryptoError::InvalidInput(
            "Chat attachment-ledger envelope must use canonical base64".into(),
        ));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first_context() -> ChatAttachmentLedgerContextV1 {
        ChatAttachmentLedgerContextV1::new(
            &"11".repeat(32),
            "22222222-2222-4222-8222-222222222222",
            1,
            None,
        )
        .unwrap()
    }

    #[test]
    fn deterministic_round_trip_and_header_are_stable() {
        assert_eq!(
            hex::encode(derive_account_ledger_key(&[0x33; 32]).unwrap().as_slice()),
            "0cc9ac119e8d3527d3ee5d76e26b0e8e863fd147cedac605b4ca90c19de6d925"
        );
        let envelope = seal_with_nonce(
            b"canonical ledger entry",
            &[0x42; 32],
            first_context(),
            &[0x11; 24],
        )
        .unwrap();
        assert_eq!(&envelope[..8], MAGIC);
        assert_eq!(&envelope[100..124], &[0x11; 24]);
        assert_eq!(
            open(&envelope, &[0x42; 32], first_context()).unwrap(),
            b"canonical ledger entry"
        );
        let header = inspect(&envelope).unwrap();
        assert_eq!(header.context.revision, 1);
        assert_eq!(header.ciphertext_len, 38);
        assert_eq!(envelope_digest(&envelope).unwrap().len(), 64);
    }

    #[test]
    fn context_tamper_relocation_and_trailing_bytes_fail_closed() {
        let envelope = seal_with_nonce(b"entry", &[7; 32], first_context(), &[9; 24]).unwrap();
        let other = ChatAttachmentLedgerContextV1::new(
            &"11".repeat(32),
            "33333333-3333-4333-8333-333333333333",
            1,
            None,
        )
        .unwrap();
        assert!(open(&envelope, &[7; 32], other).is_err());
        let mut reserved = envelope.clone();
        reserved[11] = 1;
        assert!(inspect(&reserved).is_err());
        let mut trailing = envelope;
        trailing.push(0);
        assert!(inspect(&trailing).is_err());
    }

    #[test]
    fn revision_requires_exact_predecessor_shape() {
        assert!(ChatAttachmentLedgerContextV1::new(
            &"11".repeat(32),
            "22222222-2222-4222-8222-222222222222",
            2,
            None,
        )
        .is_err());
        let previous = "11".repeat(32);
        assert!(ChatAttachmentLedgerContextV1::new(
            &"11".repeat(32),
            "22222222-2222-4222-8222-222222222222",
            2,
            Some(&previous),
        )
        .is_ok());
    }
}
