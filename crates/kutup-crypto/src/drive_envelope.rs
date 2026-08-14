//! Purpose-separated, object-bound persistent Drive envelopes.
//!
//! V1 uses a fixed-width canonical header because every encrypted Drive object
//! is identified by UUID. The complete header is AEAD associated data and its
//! stable scope fields also derive a purpose-specific subkey from the caller's
//! root key. Raw master, collection, file, and link keys are never used as an
//! AEAD key directly.

use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dryoc::rng::copy_randombytes;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::drive_object::{parse_canonical_uuid, DriveObjectSuiteId};
use crate::error::{CryptoError, Result};

const MAGIC: &[u8; 8] = b"KUTPDE1\0";
const HEADER_LEN: usize = 8 + 2 + 1 + 1 + 4 + 8 + 16 + 16 + 24 + 4;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const KEY_DERIVATION_SALT: &[u8] = b"kutup/drive-envelope/key/v1\0";
const WHITEBOARD_ASSET_BINDING_LABEL: &[u8] = b"kutup/drive-envelope/whiteboard-asset/v1\0";
pub const MAX_WHITEBOARD_ASSET_PLAINTEXT_BYTES: usize = 25 * 1024 * 1024;
pub const MAX_WHITEBOARD_ASSET_ENVELOPE_BYTES: usize =
    HEADER_LEN + MAX_WHITEBOARD_ASSET_PLAINTEXT_BYTES + TAG_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DriveEnvelopePurpose {
    CollectionKey = 1,
    CollectionName = 2,
    FileKey = 3,
    FileMetadata = 4,
    PublicLinkCollectionKey = 5,
    WhiteboardAsset = 6,
}

impl DriveEnvelopePurpose {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    fn validate_plaintext_len(self, len: usize) -> Result<()> {
        let valid = match self {
            Self::CollectionKey | Self::FileKey | Self::PublicLinkCollectionKey => len == KEY_LEN,
            Self::CollectionName => (1..=1024).contains(&len),
            Self::FileMetadata => (1..=65_536).contains(&len),
            Self::WhiteboardAsset => (1..=MAX_WHITEBOARD_ASSET_PLAINTEXT_BYTES).contains(&len),
        };
        if !valid {
            return Err(CryptoError::InvalidInput(format!(
                "invalid plaintext length for Drive envelope purpose {}",
                self.as_u8()
            )));
        }
        Ok(())
    }
}

impl TryFrom<u8> for DriveEnvelopePurpose {
    type Error = CryptoError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::CollectionKey),
            2 => Ok(Self::CollectionName),
            3 => Ok(Self::FileKey),
            4 => Ok(Self::FileMetadata),
            5 => Ok(Self::PublicLinkCollectionKey),
            6 => Ok(Self::WhiteboardAsset),
            _ => Err(CryptoError::InvalidInput(format!(
                "unknown Drive envelope purpose {value}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DriveEnvelopeContextV1 {
    pub purpose: DriveEnvelopePurpose,
    pub epoch: u32,
    pub revision: u64,
    pub object_id: [u8; 16],
    pub parent_id: [u8; 16],
}

impl DriveEnvelopeContextV1 {
    pub fn new(
        purpose: DriveEnvelopePurpose,
        epoch: u32,
        revision: u64,
        object_id: &str,
        parent_id: &str,
    ) -> Result<Self> {
        if epoch == 0 || revision == 0 {
            return Err(CryptoError::InvalidInput(
                "Drive envelope epoch and revision must be non-zero".into(),
            ));
        }
        Ok(Self {
            purpose,
            epoch,
            revision,
            object_id: parse_canonical_uuid(object_id, "object")?,
            parent_id: parse_canonical_uuid(parent_id, "parent")?,
        })
    }

    pub fn whiteboard_asset(
        file_id: &str,
        collection_id: &str,
        asset_id: &str,
        epoch: u32,
    ) -> Result<Self> {
        if epoch == 0 {
            return Err(CryptoError::InvalidInput(
                "Drive whiteboard asset epoch must be non-zero".into(),
            ));
        }
        if asset_id.is_empty()
            || asset_id.len() > 128
            || asset_id.contains('/')
            || asset_id.contains('\\')
            || asset_id.contains("..")
        {
            return Err(CryptoError::InvalidInput(
                "Drive whiteboard asset id is invalid".into(),
            ));
        }
        let file_id = parse_canonical_uuid(file_id, "whiteboard file")?;
        let collection_id = parse_canonical_uuid(collection_id, "whiteboard collection")?;
        let mut digest = Sha256::new();
        digest.update(WHITEBOARD_ASSET_BINDING_LABEL);
        digest.update(collection_id);
        digest.update((asset_id.len() as u16).to_be_bytes());
        digest.update(asset_id.as_bytes());
        let digest = digest.finalize();
        Ok(Self {
            purpose: DriveEnvelopePurpose::WhiteboardAsset,
            epoch,
            revision: 1,
            object_id: file_id,
            parent_id: digest[..16].try_into().expect("sixteen-byte digest prefix"),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DriveEnvelopeHeaderV1 {
    pub suite: DriveObjectSuiteId,
    pub context: DriveEnvelopeContextV1,
    pub ciphertext_len: u32,
}

struct ParsedEnvelope<'a> {
    header: DriveEnvelopeHeaderV1,
    aad: &'a [u8],
    nonce: &'a [u8],
    ciphertext: &'a [u8],
}

fn key_info(context: DriveEnvelopeContextV1) -> Vec<u8> {
    let mut info = Vec::with_capacity(2 + 1 + 4 + 8 + 16 + 16);
    info.extend_from_slice(&DriveObjectSuiteId::KutupDriveV1.as_u16().to_be_bytes());
    info.push(context.purpose.as_u8());
    info.extend_from_slice(&context.epoch.to_be_bytes());
    info.extend_from_slice(&context.revision.to_be_bytes());
    info.extend_from_slice(&context.object_id);
    info.extend_from_slice(&context.parent_id);
    info
}

pub fn derive_key(
    root_key: &[u8],
    context: DriveEnvelopeContextV1,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if root_key.len() != KEY_LEN {
        return Err(CryptoError::InvalidLength {
            expected: KEY_LEN,
            got: root_key.len(),
        });
    }
    let hkdf = Hkdf::<Sha256>::new(Some(KEY_DERIVATION_SALT), root_key);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(&key_info(context), key.as_mut_slice())
        .map_err(|_| CryptoError::Backend("Drive envelope HKDF expand".into()))?;
    Ok(key)
}

fn build_header(
    context: DriveEnvelopeContextV1,
    nonce: &[u8; NONCE_LEN],
    ciphertext_len: u32,
) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&DriveObjectSuiteId::KutupDriveV1.as_u16().to_be_bytes());
    header.push(context.purpose.as_u8());
    header.push(0);
    header.extend_from_slice(&context.epoch.to_be_bytes());
    header.extend_from_slice(&context.revision.to_be_bytes());
    header.extend_from_slice(&context.object_id);
    header.extend_from_slice(&context.parent_id);
    header.extend_from_slice(nonce);
    header.extend_from_slice(&ciphertext_len.to_be_bytes());
    debug_assert_eq!(header.len(), HEADER_LEN);
    header
}

pub fn seal(plaintext: &[u8], root_key: &[u8], context: DriveEnvelopeContextV1) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    copy_randombytes(&mut nonce);
    seal_with_nonce(plaintext, root_key, context, &nonce)
}

/// Deterministic-nonce entry point for checked-in vectors only.
pub fn seal_with_nonce(
    plaintext: &[u8],
    root_key: &[u8],
    context: DriveEnvelopeContextV1,
    nonce: &[u8],
) -> Result<Vec<u8>> {
    context.purpose.validate_plaintext_len(plaintext.len())?;
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: NONCE_LEN,
        got: nonce.len(),
    })?;
    let ciphertext_len = u32::try_from(plaintext.len() + TAG_LEN)
        .map_err(|_| CryptoError::InvalidInput("Drive envelope plaintext is too long".into()))?;
    let header = build_header(context, &nonce, ciphertext_len);
    let key = derive_key(root_key, context)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| CryptoError::Backend("Drive envelope AEAD init".into()))?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| CryptoError::Backend("Drive envelope seal".into()))?;
    let mut envelope = header;
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn parse(envelope: &[u8]) -> Result<ParsedEnvelope<'_>> {
    if envelope.len() < HEADER_LEN + TAG_LEN + 1 || envelope.get(..MAGIC.len()) != Some(MAGIC) {
        return Err(CryptoError::TooShort);
    }
    let suite = DriveObjectSuiteId::try_from(u16::from_be_bytes([envelope[8], envelope[9]]))?;
    let purpose = DriveEnvelopePurpose::try_from(envelope[10])?;
    if envelope[11] != 0 {
        return Err(CryptoError::InvalidInput(
            "Drive envelope reserved byte is non-zero".into(),
        ));
    }
    let epoch = u32::from_be_bytes(envelope[12..16].try_into().expect("four-byte slice"));
    let revision = u64::from_be_bytes(envelope[16..24].try_into().expect("eight-byte slice"));
    if epoch == 0 || revision == 0 {
        return Err(CryptoError::InvalidInput(
            "Drive envelope epoch and revision must be non-zero".into(),
        ));
    }
    let object_id: [u8; 16] = envelope[24..40].try_into().expect("sixteen-byte slice");
    let parent_id: [u8; 16] = envelope[40..56].try_into().expect("sixteen-byte slice");
    let ciphertext_len = u32::from_be_bytes(envelope[80..84].try_into().expect("four-byte slice"));
    let ciphertext_len_usize = usize::try_from(ciphertext_len)
        .map_err(|_| CryptoError::InvalidInput("Drive envelope ciphertext is too long".into()))?;
    if HEADER_LEN.checked_add(ciphertext_len_usize) != Some(envelope.len()) {
        return Err(CryptoError::InvalidInput(
            "Drive envelope ciphertext length is invalid".into(),
        ));
    }
    purpose.validate_plaintext_len(ciphertext_len_usize.saturating_sub(TAG_LEN))?;
    Ok(ParsedEnvelope {
        header: DriveEnvelopeHeaderV1 {
            suite,
            context: DriveEnvelopeContextV1 {
                purpose,
                epoch,
                revision,
                object_id,
                parent_id,
            },
            ciphertext_len,
        },
        aad: &envelope[..HEADER_LEN],
        nonce: &envelope[56..80],
        ciphertext: &envelope[HEADER_LEN..],
    })
}

pub fn inspect(envelope: &[u8]) -> Result<DriveEnvelopeHeaderV1> {
    Ok(parse(envelope)?.header)
}

pub fn validate(envelope: &[u8], expected: DriveEnvelopeContextV1) -> Result<()> {
    if parse(envelope)?.header.context != expected {
        return Err(CryptoError::InvalidInput(
            "Drive envelope context does not match".into(),
        ));
    }
    Ok(())
}

pub fn open(envelope: &[u8], root_key: &[u8], expected: DriveEnvelopeContextV1) -> Result<Vec<u8>> {
    let parsed = parse(envelope)?;
    if parsed.header.context != expected {
        return Err(CryptoError::AuthFailed);
    }
    let key = derive_key(root_key, expected)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| CryptoError::Backend("Drive envelope AEAD init".into()))?;
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
    root_key: &[u8],
    context: DriveEnvelopeContextV1,
) -> Result<String> {
    Ok(base64::engine::general_purpose::STANDARD.encode(seal(plaintext, root_key, context)?))
}

pub fn open_b64(
    envelope_b64: &str,
    root_key: &[u8],
    expected: DriveEnvelopeContextV1,
) -> Result<Vec<u8>> {
    let envelope = base64::engine::general_purpose::STANDARD.decode(envelope_b64)?;
    if base64::engine::general_purpose::STANDARD.encode(&envelope) != envelope_b64 {
        return Err(CryptoError::InvalidInput(
            "Drive envelope must use canonical base64".into(),
        ));
    }
    open(&envelope, root_key, expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(purpose: DriveEnvelopePurpose) -> DriveEnvelopeContextV1 {
        DriveEnvelopeContextV1::new(
            purpose,
            7,
            11,
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
        )
        .unwrap()
    }

    #[test]
    fn purpose_context_and_epoch_are_both_key_and_aad_bound() {
        let scope = context(DriveEnvelopePurpose::CollectionName);
        let envelope = seal_with_nonce(b"projects", &[0x33; 32], scope, &[0x44; 24]).unwrap();
        assert_eq!(inspect(&envelope).unwrap().context, scope);
        assert_eq!(open(&envelope, &[0x33; 32], scope).unwrap(), b"projects");

        let mut moved = scope;
        moved.revision += 1;
        assert!(open(&envelope, &[0x33; 32], moved).is_err());
        moved = scope;
        moved.epoch += 1;
        assert!(open(&envelope, &[0x33; 32], moved).is_err());
        moved = scope;
        moved.object_id = [0u8; 16];
        assert!(open(&envelope, &[0x33; 32], moved).is_err());
    }

    #[test]
    fn unknown_fields_lengths_and_tampering_fail_closed() {
        let scope = context(DriveEnvelopePurpose::FileKey);
        let envelope = seal_with_nonce(&[0x55; 32], &[0x33; 32], scope, &[0x44; 24]).unwrap();

        let mut unknown_suite = envelope.clone();
        unknown_suite[9] = 2;
        assert!(inspect(&unknown_suite).is_err());
        let mut reserved = envelope.clone();
        reserved[11] = 1;
        assert!(inspect(&reserved).is_err());
        let mut tampered = envelope.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open(&tampered, &[0x33; 32], scope).is_err());
        let mut trailing = envelope;
        trailing.push(0);
        assert!(inspect(&trailing).is_err());
    }

    #[test]
    fn purpose_limits_and_canonical_uuid_are_strict() {
        let scope = context(DriveEnvelopePurpose::CollectionKey);
        assert!(seal(&[0u8; 31], &[0u8; 32], scope).is_err());
        assert!(DriveEnvelopeContextV1::new(
            DriveEnvelopePurpose::CollectionName,
            1,
            1,
            "11111111-1111-4111-8111-111111111111",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
                .to_uppercase()
                .as_str(),
        )
        .is_err());
    }
}
