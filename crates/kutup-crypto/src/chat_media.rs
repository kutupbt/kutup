//! Canonical immutable Chat-media object framing.
//!
//! Direct Chat, MLS groups, linked devices and future broadcast all carry the
//! same random attachment key inside their own E2EE content. The object itself
//! is encrypted once and can therefore be durably copied between homeservers
//! without teaching them a filename, MIME type, sender or conversation.

use dryoc::rng::copy_randombytes;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::drive_object::parse_canonical_uuid;
use crate::error::{CryptoError, Result};
use crate::stream::{
    StreamDecryptor, StreamEncryptor, ABYTES, CHUNK_SIZE, HEADER_BYTES as STREAM_HEADER_BYTES,
    TAG_FINAL, TAG_MESSAGE,
};

const OBJECT_MAGIC: &[u8; 8] = b"KUTPCM1\0";
const OBJECT_KEY_SALT: &[u8] = b"kutup/chat-media/object-key/v1\0";
const KEY_LEN: usize = 32;

/// One protocol attachment is capped at 2 GiB of plaintext-class content.
pub const MAX_CHAT_MEDIA_PLAINTEXT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const CHAT_MEDIA_OBJECT_HEADER_BYTES: usize = 28;
pub const CHAT_MEDIA_OBJECT_PREFIX_BYTES: usize =
    CHAT_MEDIA_OBJECT_HEADER_BYTES + STREAM_HEADER_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum ChatMediaSuiteId {
    XChaCha20Poly1305SecretStreamV1 = 1,
}

impl ChatMediaSuiteId {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl From<ChatMediaSuiteId> for u16 {
    fn from(value: ChatMediaSuiteId) -> Self {
        value.as_u16()
    }
}

impl TryFrom<u16> for ChatMediaSuiteId {
    type Error = CryptoError;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::XChaCha20Poly1305SecretStreamV1),
            _ => Err(CryptoError::InvalidInput(format!(
                "unknown Chat-media suite {value}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ChatMediaObjectPurpose {
    AttachmentBlob = 1,
}

impl ChatMediaObjectPurpose {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for ChatMediaObjectPurpose {
    type Error = CryptoError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::AttachmentBlob),
            _ => Err(CryptoError::InvalidInput(format!(
                "unknown Chat-media object purpose {value}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChatMediaObjectContextV1 {
    pub attachment_id: [u8; 16],
}

impl ChatMediaObjectContextV1 {
    pub fn new(attachment_id: &str) -> Result<Self> {
        Ok(Self {
            attachment_id: parse_canonical_uuid(attachment_id, "Chat-media attachment")?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChatMediaObjectHeaderV1 {
    pub suite: ChatMediaSuiteId,
    pub purpose: ChatMediaObjectPurpose,
    pub context: ChatMediaObjectContextV1,
}

pub fn generate_attachment_key() -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    copy_randombytes(key.as_mut_slice());
    key
}

pub fn object_header(context: ChatMediaObjectContextV1) -> [u8; CHAT_MEDIA_OBJECT_HEADER_BYTES] {
    let mut header = [0u8; CHAT_MEDIA_OBJECT_HEADER_BYTES];
    header[..8].copy_from_slice(OBJECT_MAGIC);
    header[8..10].copy_from_slice(
        &ChatMediaSuiteId::XChaCha20Poly1305SecretStreamV1
            .as_u16()
            .to_be_bytes(),
    );
    header[10] = ChatMediaObjectPurpose::AttachmentBlob.as_u8();
    header[12..28].copy_from_slice(&context.attachment_id);
    header
}

pub fn inspect_object_header(header: &[u8]) -> Result<ChatMediaObjectHeaderV1> {
    if header.len() != CHAT_MEDIA_OBJECT_HEADER_BYTES || header.get(..8) != Some(OBJECT_MAGIC) {
        return Err(CryptoError::TooShort);
    }
    let suite = ChatMediaSuiteId::try_from(u16::from_be_bytes([header[8], header[9]]))?;
    let purpose = ChatMediaObjectPurpose::try_from(header[10])?;
    if header[11] != 0 {
        return Err(CryptoError::InvalidInput(
            "Chat-media object reserved byte is non-zero".into(),
        ));
    }
    Ok(ChatMediaObjectHeaderV1 {
        suite,
        purpose,
        context: ChatMediaObjectContextV1 {
            attachment_id: header[12..28].try_into().expect("sixteen-byte slice"),
        },
    })
}

pub fn validate_object_header(header: &[u8], expected: ChatMediaObjectContextV1) -> Result<()> {
    let parsed = inspect_object_header(header)?;
    if parsed.suite != ChatMediaSuiteId::XChaCha20Poly1305SecretStreamV1
        || parsed.purpose != ChatMediaObjectPurpose::AttachmentBlob
        || parsed.context != expected
    {
        return Err(CryptoError::InvalidInput(
            "Chat-media object context does not match".into(),
        ));
    }
    Ok(())
}

pub fn derive_object_key(
    attachment_key: &[u8],
    context: ChatMediaObjectContextV1,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if attachment_key.len() != KEY_LEN {
        return Err(CryptoError::InvalidLength {
            expected: KEY_LEN,
            got: attachment_key.len(),
        });
    }
    let header = object_header(context);
    let hkdf = Hkdf::<Sha256>::new(Some(OBJECT_KEY_SALT), attachment_key);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(&header, key.as_mut_slice())
        .map_err(|_| CryptoError::Backend("Chat-media object HKDF expand".into()))?;
    Ok(key)
}

pub fn object_ciphertext_size(plaintext_bytes: u64) -> Result<u64> {
    if plaintext_bytes > MAX_CHAT_MEDIA_PLAINTEXT_BYTES {
        return Err(CryptoError::InvalidInput(
            "Chat-media object exceeds the V1 plaintext limit".into(),
        ));
    }
    let chunk_size = CHUNK_SIZE as u64;
    let chunks = plaintext_bytes.div_ceil(chunk_size).max(1);
    (CHAT_MEDIA_OBJECT_PREFIX_BYTES as u64)
        .checked_add(plaintext_bytes)
        .and_then(|value| value.checked_add(chunks * ABYTES as u64))
        .ok_or_else(|| CryptoError::InvalidInput("Chat-media object size overflow".into()))
}

pub fn max_object_ciphertext_bytes() -> u64 {
    object_ciphertext_size(MAX_CHAT_MEDIA_PLAINTEXT_BYTES)
        .expect("the fixed V1 object limit fits u64")
}

/// Validate the public prefix and bounded frame-length shape without claiming
/// to authenticate secretstream tags (only a key holder can do that).
pub fn validate_public_object(object: &[u8], expected: ChatMediaObjectContextV1) -> Result<()> {
    let len = object.len() as u64;
    if len < object_ciphertext_size(0)? || len > max_object_ciphertext_bytes() {
        return Err(CryptoError::InvalidInput(
            "Chat-media ciphertext length is invalid".into(),
        ));
    }
    validate_object_header(&object[..CHAT_MEDIA_OBJECT_HEADER_BYTES], expected)?;
    let body_len = object.len() - CHAT_MEDIA_OBJECT_PREFIX_BYTES;
    let frame_size = CHUNK_SIZE + ABYTES;
    let remainder = body_len % frame_size;
    if body_len < ABYTES || (remainder != 0 && remainder < ABYTES) {
        return Err(CryptoError::InvalidInput(
            "Chat-media frame lengths are invalid".into(),
        ));
    }
    Ok(())
}

pub fn object_sha256(object: &[u8]) -> String {
    hex::encode(Sha256::digest(object))
}

pub fn encrypt_object(
    plaintext: &[u8],
    attachment_key: &[u8],
    context: ChatMediaObjectContextV1,
) -> Result<Vec<u8>> {
    object_ciphertext_size(plaintext.len() as u64)?;
    let header = object_header(context);
    let stream_key = derive_object_key(attachment_key, context)?;
    let (mut encryptor, stream_header) =
        StreamEncryptor::new_with_aad(stream_key.as_slice(), &header)?;
    let chunks = plaintext.len().div_ceil(CHUNK_SIZE).max(1);
    let mut output = Vec::with_capacity(
        CHAT_MEDIA_OBJECT_PREFIX_BYTES + plaintext.len() + chunks.saturating_mul(ABYTES),
    );
    output.extend_from_slice(&header);
    output.extend_from_slice(&stream_header);
    if plaintext.is_empty() {
        output.extend_from_slice(&encryptor.push(&[], TAG_FINAL)?);
        return Ok(output);
    }
    for (index, chunk) in plaintext.chunks(CHUNK_SIZE).enumerate() {
        output.extend_from_slice(&encryptor.push(
            chunk,
            if index + 1 == chunks {
                TAG_FINAL
            } else {
                TAG_MESSAGE
            },
        )?);
    }
    Ok(output)
}

pub fn decrypt_object(
    ciphertext: &[u8],
    attachment_key: &[u8],
    expected: ChatMediaObjectContextV1,
) -> Result<Vec<u8>> {
    validate_public_object(ciphertext, expected)?;
    let object_header = &ciphertext[..CHAT_MEDIA_OBJECT_HEADER_BYTES];
    let stream_header = &ciphertext[CHAT_MEDIA_OBJECT_HEADER_BYTES..CHAT_MEDIA_OBJECT_PREFIX_BYTES];
    let stream_key = derive_object_key(attachment_key, expected)?;
    let mut decryptor =
        StreamDecryptor::new_with_aad(stream_key.as_slice(), stream_header, object_header)?;
    let body = &ciphertext[CHAT_MEDIA_OBJECT_PREFIX_BYTES..];
    let frame_size = CHUNK_SIZE + ABYTES;
    let mut output = Vec::with_capacity(body.len());
    let mut offset = 0usize;
    let mut saw_final = false;
    while offset < body.len() {
        let end = (offset + frame_size).min(body.len());
        let (plaintext, tag) = decryptor.pull(&body[offset..end])?;
        output.extend_from_slice(&plaintext);
        offset = end;
        if tag == TAG_FINAL {
            saw_final = true;
            if offset != body.len() {
                return Err(CryptoError::InvalidInput(
                    "Chat-media object has bytes after FINAL".into(),
                ));
            }
        } else if tag != TAG_MESSAGE || offset == body.len() {
            return Err(CryptoError::InvalidInput(
                "Chat-media object ended before FINAL".into(),
            ));
        }
    }
    if !saw_final || output.len() as u64 > MAX_CHAT_MEDIA_PLAINTEXT_BYTES {
        return Err(CryptoError::InvalidInput(
            "Chat-media object has no valid FINAL frame".into(),
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> ChatMediaObjectContextV1 {
        ChatMediaObjectContextV1::new("11111111-1111-4111-8111-111111111111").unwrap()
    }

    #[test]
    fn header_key_and_empty_object_are_stable() {
        let key = [0x42; 32];
        let header = object_header(context());
        assert_eq!(
            hex::encode(header),
            "4b555450434d31000001010011111111111141118111111111111111"
        );
        assert_eq!(
            hex::encode(derive_object_key(&key, context()).unwrap().as_slice()),
            "a55e24c97bec5fa36b1b12667fd4954f790d199bb6120c164160bfa92da46c5f"
        );
        let object = encrypt_object(&[], &key, context()).unwrap();
        assert_eq!(object.len() as u64, object_ciphertext_size(0).unwrap());
        assert_eq!(decrypt_object(&object, &key, context()).unwrap(), b"");
    }

    #[test]
    fn relocation_truncation_trailing_and_unknown_suite_fail_closed() {
        let key = [0x24; 32];
        let object = encrypt_object(b"photo bytes", &key, context()).unwrap();
        let other = ChatMediaObjectContextV1::new("22222222-2222-4222-8222-222222222222").unwrap();
        assert!(decrypt_object(&object, &key, other).is_err());
        assert!(decrypt_object(&object[..object.len() - 1], &key, context()).is_err());
        let mut trailing = object.clone();
        trailing.push(0);
        assert!(decrypt_object(&trailing, &key, context()).is_err());
        let mut unknown_suite = object;
        unknown_suite[9] = 2;
        assert!(inspect_object_header(&unknown_suite[..CHAT_MEDIA_OBJECT_HEADER_BYTES]).is_err());
    }

    #[test]
    fn public_length_validation_rejects_impossible_short_final_frame() {
        let key = [7; 32];
        let mut object = encrypt_object(b"payload", &key, context()).unwrap();
        object.truncate(CHAT_MEDIA_OBJECT_PREFIX_BYTES + ABYTES - 1);
        assert!(validate_public_object(&object, context()).is_err());
    }

    #[test]
    fn size_formula_has_one_final_frame_and_a_fixed_ceiling() {
        assert_eq!(
            object_ciphertext_size(0).unwrap(),
            (CHAT_MEDIA_OBJECT_PREFIX_BYTES + ABYTES) as u64
        );
        assert_eq!(
            object_ciphertext_size(CHUNK_SIZE as u64).unwrap(),
            (CHAT_MEDIA_OBJECT_PREFIX_BYTES + CHUNK_SIZE + ABYTES) as u64
        );
        assert!(object_ciphertext_size(MAX_CHAT_MEDIA_PLAINTEXT_BYTES + 1).is_err());
        assert!(max_object_ciphertext_bytes() > MAX_CHAT_MEDIA_PLAINTEXT_BYTES);
    }
}
