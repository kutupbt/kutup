//! Canonical cryptographic framing for continuous E2EE Chat history.
//!
//! Backup keys are rooted in a random account secret wrapped with
//! [`AccountEnvelopePurpose::ChatBackupRoot`](crate::account_envelope::AccountEnvelopePurpose::ChatBackupRoot).
//! This module never accepts Direct, MLS, Drive, Chat-media, attachment-ledger,
//! or device-transfer keys as substitutes.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dryoc::rng::copy_randombytes;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

const MAGIC: &[u8; 8] = b"KUTPCB1\0";
const HKDF_SALT: &[u8] = b"kutup/chat-backup/v1\0";
const MESSAGE_ARCHIVE_LABEL: &[u8] = b"kutup/chat-backup/message-archive-key/v1\0";
const EVENT_SEGMENT_LABEL: &[u8] = b"kutup/chat-backup/event-segment-key/v1\0";
const MEDIA_ID_LABEL: &[u8] = b"kutup/chat-backup/media-id-key/v1\0";
const MEDIA_ENCRYPTION_LABEL: &[u8] = b"kutup/chat-backup/media-encryption-root/v1\0";
const MANIFEST_SIGNING_LABEL: &[u8] = b"kutup/chat-backup/manifest-signing-seed/v1\0";
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
pub const CHAT_BACKUP_OBJECT_HEADER_BYTES: usize =
    8 + 2 + 1 + 1 + 32 + 16 + 16 + 4 + 8 + 32 + 4 + NONCE_LEN;

pub const CHAT_BACKUP_KEY_BYTES: usize = 32;
pub const MAX_CHAT_BACKUP_SEGMENT_PLAINTEXT_BYTES: usize = 256 * 1024;
pub const MAX_CHAT_BACKUP_BASE_PLAINTEXT_BYTES: usize = 128 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum ChatBackupSuiteId {
    HkdfSha256XChaCha20Poly1305V1 = 1,
}

impl From<ChatBackupSuiteId> for u16 {
    fn from(value: ChatBackupSuiteId) -> Self {
        value.as_u16()
    }
}

impl ChatBackupSuiteId {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for ChatBackupSuiteId {
    type Error = CryptoError;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::HkdfSha256XChaCha20Poly1305V1),
            _ => Err(CryptoError::InvalidInput(format!(
                "unknown Chat backup suite {value}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "u8", try_from = "u8")]
#[repr(u8)]
pub enum ChatBackupProtectionDomainV1 {
    StandardChat = 1,
}

impl From<ChatBackupProtectionDomainV1> for u8 {
    fn from(value: ChatBackupProtectionDomainV1) -> Self {
        value.as_u8()
    }
}

impl ChatBackupProtectionDomainV1 {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for ChatBackupProtectionDomainV1 {
    type Error = CryptoError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::StandardChat),
            _ => Err(CryptoError::InvalidInput(format!(
                "unknown Chat backup protection domain {value}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ChatBackupObjectPurposeV1 {
    BaseSnapshot = 1,
    EventSegment = 2,
}

impl ChatBackupObjectPurposeV1 {
    const fn as_u8(self) -> u8 {
        self as u8
    }

    const fn label(self) -> &'static [u8] {
        match self {
            Self::BaseSnapshot => MESSAGE_ARCHIVE_LABEL,
            Self::EventSegment => EVENT_SEGMENT_LABEL,
        }
    }

    const fn maximum_plaintext_bytes(self) -> usize {
        match self {
            Self::BaseSnapshot => MAX_CHAT_BACKUP_BASE_PLAINTEXT_BYTES,
            Self::EventSegment => MAX_CHAT_BACKUP_SEGMENT_PLAINTEXT_BYTES,
        }
    }
}

impl TryFrom<u8> for ChatBackupObjectPurposeV1 {
    type Error = CryptoError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::BaseSnapshot),
            2 => Ok(Self::EventSegment),
            _ => Err(CryptoError::InvalidInput(format!(
                "unknown Chat backup object purpose {value}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChatBackupContextV1 {
    pub account_incarnation_id: [u8; 32],
    pub backup_incarnation_id: [u8; 16],
    pub protection_domain: ChatBackupProtectionDomainV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChatBackupObjectContextV1 {
    pub backup: ChatBackupContextV1,
    pub purpose: ChatBackupObjectPurposeV1,
    pub object_id: [u8; 16],
    pub source_device_id: u32,
    pub device_sequence: u64,
    pub previous_segment_digest: [u8; 32],
}

impl ChatBackupObjectContextV1 {
    pub fn validate(self) -> Result<()> {
        if self.source_device_id == 0 && self.purpose == ChatBackupObjectPurposeV1::EventSegment {
            return Err(CryptoError::InvalidInput(
                "Chat backup event segment requires a source device".into(),
            ));
        }
        if self.purpose == ChatBackupObjectPurposeV1::BaseSnapshot
            && (self.source_device_id != 0
                || self.device_sequence != 0
                || self.previous_segment_digest != [0u8; 32])
        {
            return Err(CryptoError::InvalidInput(
                "Chat backup base snapshot has event-only context".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatBackupObjectHeaderV1 {
    pub suite: ChatBackupSuiteId,
    pub context: ChatBackupObjectContextV1,
    pub plaintext_bytes: u32,
}

struct ParsedObject<'a> {
    header: ChatBackupObjectHeaderV1,
    aad: &'a [u8],
    nonce: &'a [u8],
    ciphertext: &'a [u8],
}

fn require_root(root: &[u8]) -> Result<()> {
    if root.len() != CHAT_BACKUP_KEY_BYTES {
        return Err(CryptoError::InvalidInput(
            "Chat backup root must be 32 bytes".into(),
        ));
    }
    Ok(())
}

fn derivation_info(context: ChatBackupObjectContextV1) -> Vec<u8> {
    let mut info = Vec::with_capacity(160);
    info.extend_from_slice(context.purpose.label());
    info.extend_from_slice(
        &ChatBackupSuiteId::HkdfSha256XChaCha20Poly1305V1
            .as_u16()
            .to_be_bytes(),
    );
    info.push(context.backup.protection_domain.as_u8());
    info.extend_from_slice(&context.backup.account_incarnation_id);
    info.extend_from_slice(&context.backup.backup_incarnation_id);
    info.extend_from_slice(&context.object_id);
    info.extend_from_slice(&context.source_device_id.to_be_bytes());
    info.extend_from_slice(&context.device_sequence.to_be_bytes());
    info.extend_from_slice(&context.previous_segment_digest);
    info
}

fn derive_object_key(
    root: &[u8],
    context: ChatBackupObjectContextV1,
) -> Result<Zeroizing<[u8; CHAT_BACKUP_KEY_BYTES]>> {
    require_root(root)?;
    context.validate()?;
    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), root);
    let mut key = Zeroizing::new([0u8; CHAT_BACKUP_KEY_BYTES]);
    hkdf.expand(&derivation_info(context), key.as_mut_slice())
        .map_err(|_| CryptoError::Backend("Chat backup object HKDF expand".into()))?;
    Ok(key)
}

fn derive_subkey(
    root: &[u8],
    context: ChatBackupContextV1,
    label: &[u8],
    binding: &[u8],
) -> Result<Zeroizing<[u8; CHAT_BACKUP_KEY_BYTES]>> {
    require_root(root)?;
    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), root);
    let mut info = Vec::with_capacity(label.len() + 100 + binding.len());
    info.extend_from_slice(label);
    info.extend_from_slice(
        &ChatBackupSuiteId::HkdfSha256XChaCha20Poly1305V1
            .as_u16()
            .to_be_bytes(),
    );
    info.push(context.protection_domain.as_u8());
    info.extend_from_slice(&context.account_incarnation_id);
    info.extend_from_slice(&context.backup_incarnation_id);
    info.extend_from_slice(binding);
    let mut key = Zeroizing::new([0u8; CHAT_BACKUP_KEY_BYTES]);
    hkdf.expand(&info, key.as_mut_slice())
        .map_err(|_| CryptoError::Backend("Chat backup subkey HKDF expand".into()))?;
    Ok(key)
}

pub fn derive_media_id(
    root: &[u8],
    context: ChatBackupContextV1,
    stable_source_binding: &[u8],
) -> Result<[u8; CHAT_BACKUP_KEY_BYTES]> {
    if stable_source_binding.is_empty() {
        return Err(CryptoError::InvalidInput(
            "Chat backup media source binding is empty".into(),
        ));
    }
    Ok(*derive_subkey(
        root,
        context,
        MEDIA_ID_LABEL,
        stable_source_binding,
    )?)
}

pub fn derive_media_encryption_key(
    root: &[u8],
    context: ChatBackupContextV1,
    media_id: &[u8; CHAT_BACKUP_KEY_BYTES],
) -> Result<Zeroizing<[u8; CHAT_BACKUP_KEY_BYTES]>> {
    derive_subkey(root, context, MEDIA_ENCRYPTION_LABEL, media_id)
}

pub fn derive_manifest_signing_seed(
    root: &[u8],
    context: ChatBackupContextV1,
) -> Result<Zeroizing<[u8; CHAT_BACKUP_KEY_BYTES]>> {
    derive_subkey(root, context, MANIFEST_SIGNING_LABEL, &[])
}

fn build_header(
    context: ChatBackupObjectContextV1,
    plaintext_bytes: u32,
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let mut header = Vec::with_capacity(CHAT_BACKUP_OBJECT_HEADER_BYTES);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(
        &ChatBackupSuiteId::HkdfSha256XChaCha20Poly1305V1
            .as_u16()
            .to_be_bytes(),
    );
    header.push(context.purpose.as_u8());
    header.push(context.backup.protection_domain.as_u8());
    header.extend_from_slice(&context.backup.account_incarnation_id);
    header.extend_from_slice(&context.backup.backup_incarnation_id);
    header.extend_from_slice(&context.object_id);
    header.extend_from_slice(&context.source_device_id.to_be_bytes());
    header.extend_from_slice(&context.device_sequence.to_be_bytes());
    header.extend_from_slice(&context.previous_segment_digest);
    header.extend_from_slice(&plaintext_bytes.to_be_bytes());
    header.extend_from_slice(nonce);
    debug_assert_eq!(header.len(), CHAT_BACKUP_OBJECT_HEADER_BYTES);
    header
}

pub fn seal_object(
    plaintext: &[u8],
    root: &[u8],
    context: ChatBackupObjectContextV1,
) -> Result<Vec<u8>> {
    context.validate()?;
    if plaintext.is_empty() || plaintext.len() > context.purpose.maximum_plaintext_bytes() {
        return Err(CryptoError::InvalidInput(
            "Chat backup plaintext length is invalid".into(),
        ));
    }
    let plaintext_bytes = u32::try_from(plaintext.len())
        .map_err(|_| CryptoError::InvalidInput("Chat backup plaintext is too large".into()))?;
    let mut nonce = [0u8; NONCE_LEN];
    copy_randombytes(&mut nonce);
    let header = build_header(context, plaintext_bytes, &nonce);
    let key = derive_object_key(root, context)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| CryptoError::Backend("Chat backup AEAD key".into()))?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| CryptoError::Backend("Chat backup encryption failed".into()))?;
    let mut out = header;
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn parse_header(header: &[u8]) -> Result<ChatBackupObjectHeaderV1> {
    if header.len() != CHAT_BACKUP_OBJECT_HEADER_BYTES || &header[..MAGIC.len()] != MAGIC {
        return Err(CryptoError::InvalidInput(
            "invalid Chat backup object header".into(),
        ));
    }
    let mut cursor = MAGIC.len();
    let suite = ChatBackupSuiteId::try_from(u16::from_be_bytes(
        header[cursor..cursor + 2].try_into().expect("bounded"),
    ))?;
    cursor += 2;
    let purpose = ChatBackupObjectPurposeV1::try_from(header[cursor])?;
    cursor += 1;
    let protection_domain = ChatBackupProtectionDomainV1::try_from(header[cursor])?;
    cursor += 1;
    let account_incarnation_id = header[cursor..cursor + 32].try_into().expect("bounded");
    cursor += 32;
    let backup_incarnation_id = header[cursor..cursor + 16].try_into().expect("bounded");
    cursor += 16;
    let object_id = header[cursor..cursor + 16].try_into().expect("bounded");
    cursor += 16;
    let source_device_id =
        u32::from_be_bytes(header[cursor..cursor + 4].try_into().expect("bounded"));
    cursor += 4;
    let device_sequence =
        u64::from_be_bytes(header[cursor..cursor + 8].try_into().expect("bounded"));
    cursor += 8;
    let previous_segment_digest = header[cursor..cursor + 32].try_into().expect("bounded");
    cursor += 32;
    let plaintext_bytes =
        u32::from_be_bytes(header[cursor..cursor + 4].try_into().expect("bounded"));
    cursor += 4;
    cursor += NONCE_LEN;
    debug_assert_eq!(cursor, CHAT_BACKUP_OBJECT_HEADER_BYTES);
    let context = ChatBackupObjectContextV1 {
        backup: ChatBackupContextV1 {
            account_incarnation_id,
            backup_incarnation_id,
            protection_domain,
        },
        purpose,
        object_id,
        source_device_id,
        device_sequence,
        previous_segment_digest,
    };
    context.validate()?;
    if plaintext_bytes == 0 || plaintext_bytes as usize > purpose.maximum_plaintext_bytes() {
        return Err(CryptoError::InvalidInput(
            "Chat backup object length is invalid".into(),
        ));
    }
    Ok(ChatBackupObjectHeaderV1 {
        suite,
        context,
        plaintext_bytes,
    })
}

fn parse_object(object: &[u8]) -> Result<ParsedObject<'_>> {
    if object.len() < CHAT_BACKUP_OBJECT_HEADER_BYTES + TAG_LEN {
        return Err(CryptoError::InvalidInput(
            "invalid Chat backup object header".into(),
        ));
    }
    let header = parse_header(&object[..CHAT_BACKUP_OBJECT_HEADER_BYTES])?;
    if object.len() != CHAT_BACKUP_OBJECT_HEADER_BYTES + header.plaintext_bytes as usize + TAG_LEN {
        return Err(CryptoError::InvalidInput(
            "Chat backup object length is invalid".into(),
        ));
    }
    Ok(ParsedObject {
        header,
        aad: &object[..CHAT_BACKUP_OBJECT_HEADER_BYTES],
        nonce: &object
            [CHAT_BACKUP_OBJECT_HEADER_BYTES - NONCE_LEN..CHAT_BACKUP_OBJECT_HEADER_BYTES],
        ciphertext: &object[CHAT_BACKUP_OBJECT_HEADER_BYTES..],
    })
}

pub fn inspect_object(object: &[u8]) -> Result<ChatBackupObjectHeaderV1> {
    Ok(parse_object(object)?.header)
}

/// Inspect a large opaque object using only its fixed public header and its
/// independently measured complete length. Storage relays can therefore
/// validate snapshot framing without buffering ciphertext in memory.
pub fn inspect_object_header(
    header: &[u8],
    complete_object_bytes: usize,
) -> Result<ChatBackupObjectHeaderV1> {
    if header.len() != CHAT_BACKUP_OBJECT_HEADER_BYTES {
        return Err(CryptoError::InvalidInput(
            "invalid Chat backup object header length".into(),
        ));
    }
    let parsed = parse_header(header)?;
    let expected = CHAT_BACKUP_OBJECT_HEADER_BYTES
        .checked_add(parsed.plaintext_bytes as usize)
        .and_then(|value| value.checked_add(TAG_LEN))
        .ok_or_else(|| CryptoError::InvalidInput("Chat backup object length overflow".into()))?;
    if complete_object_bytes != expected {
        return Err(CryptoError::InvalidInput(
            "Chat backup object length does not match its header".into(),
        ));
    }
    Ok(parsed)
}

pub fn open_object(
    object: &[u8],
    root: &[u8],
    expected: ChatBackupObjectContextV1,
) -> Result<Vec<u8>> {
    let parsed = parse_object(object)?;
    if parsed.header.context != expected {
        return Err(CryptoError::AuthFailed);
    }
    let key = derive_object_key(root, expected)?;
    XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| CryptoError::Backend("Chat backup AEAD key".into()))?
        .decrypt(
            XNonce::from_slice(parsed.nonce),
            Payload {
                msg: parsed.ciphertext,
                aad: parsed.aad,
            },
        )
        .map_err(|_| CryptoError::AuthFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backup_context() -> ChatBackupContextV1 {
        ChatBackupContextV1 {
            account_incarnation_id: [7u8; 32],
            backup_incarnation_id: [8u8; 16],
            protection_domain: ChatBackupProtectionDomainV1::StandardChat,
        }
    }

    fn segment_context() -> ChatBackupObjectContextV1 {
        ChatBackupObjectContextV1 {
            backup: backup_context(),
            purpose: ChatBackupObjectPurposeV1::EventSegment,
            object_id: [9u8; 16],
            source_device_id: 3,
            device_sequence: 4,
            previous_segment_digest: [5u8; 32],
        }
    }

    #[test]
    fn segment_round_trip_and_all_context_is_authenticated() {
        let root = [6u8; 32];
        let context = segment_context();
        let object = seal_object(b"canonical event", &root, context).unwrap();
        assert_eq!(inspect_object(&object).unwrap().context, context);
        assert_eq!(
            open_object(&object, &root, context).unwrap(),
            b"canonical event"
        );

        let mut wrong = context;
        wrong.device_sequence += 1;
        assert!(open_object(&object, &root, wrong).is_err());
        assert!(open_object(&object, &[0u8; 32], context).is_err());

        let mut tampered = object;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open_object(&tampered, &root, context).is_err());
    }

    #[test]
    fn purposes_and_subkeys_are_separated() {
        let root = [6u8; 32];
        let backup = backup_context();
        let media_id = derive_media_id(&root, backup, b"source binding").unwrap();
        let media_key = derive_media_encryption_key(&root, backup, &media_id).unwrap();
        let signing = derive_manifest_signing_seed(&root, backup).unwrap();
        assert_ne!(media_id.as_slice(), media_key.as_slice());
        assert_ne!(media_key.as_slice(), signing.as_slice());
        assert_ne!(media_id.as_slice(), signing.as_slice());
        assert_ne!(
            media_id,
            derive_media_id(&root, backup, b"other source").unwrap()
        );
    }

    #[test]
    fn rejects_malformed_lengths_and_eventless_segments() {
        let root = [6u8; 32];
        let context = segment_context();
        assert!(seal_object(&[], &root, context).is_err());
        let mut invalid = context;
        invalid.source_device_id = 0;
        assert!(seal_object(b"event", &root, invalid).is_err());
        let mut object = seal_object(b"event", &root, context).unwrap();
        object.push(0);
        assert!(inspect_object(&object).is_err());
    }

    #[test]
    fn rejects_all_context_substitution_and_framing_attacks() {
        let root = [6u8; 32];
        let context = segment_context();
        let object = seal_object(b"authenticated archive", &root, context).unwrap();

        let mut substitutions = Vec::new();
        let mut wrong = context;
        wrong.backup.account_incarnation_id[0] ^= 1;
        substitutions.push(wrong);
        let mut wrong = context;
        wrong.backup.backup_incarnation_id[0] ^= 1;
        substitutions.push(wrong);
        let mut wrong = context;
        wrong.object_id[0] ^= 1;
        substitutions.push(wrong);
        let mut wrong = context;
        wrong.source_device_id += 1;
        substitutions.push(wrong);
        let mut wrong = context;
        wrong.device_sequence += 1;
        substitutions.push(wrong);
        let mut wrong = context;
        wrong.previous_segment_digest[0] ^= 1;
        substitutions.push(wrong);
        let mut wrong = context;
        wrong.purpose = ChatBackupObjectPurposeV1::BaseSnapshot;
        wrong.source_device_id = 0;
        wrong.device_sequence = 0;
        wrong.previous_segment_digest = [0; 32];
        substitutions.push(wrong);

        for substituted in substitutions {
            assert!(matches!(
                open_object(&object, &root, substituted),
                Err(CryptoError::AuthFailed)
            ));
        }

        for offset in [8usize, 10, 11] {
            let mut unknown = object.clone();
            unknown[offset] = 0xff;
            assert!(inspect_object(&unknown).is_err());
        }
        let mut nonce = object.clone();
        nonce[CHAT_BACKUP_OBJECT_HEADER_BYTES - NONCE_LEN] ^= 1;
        assert!(open_object(&nonce, &root, context).is_err());

        let mut oversized_declaration = object.clone();
        // The fixed header is rejected before any allocation based on the
        // attacker-controlled declared plaintext length.
        oversized_declaration[120..124].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(inspect_object(&oversized_declaration).is_err());

        let mut truncated = object.clone();
        truncated.pop();
        assert!(inspect_object(&truncated).is_err());
        let mut extended = object;
        extended.push(0);
        assert!(inspect_object(&extended).is_err());
    }
}
