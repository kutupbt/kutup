//! Canonical encrypted and signed collaborative-edit frame.
//!
//! Rust owns the complete V1 construction. Browser code receives and returns
//! opaque packed bytes through WASM; it does not duplicate this parser, KDF or
//! AEAD framing.
//!
//! Wire layout (big-endian):
//! `[96-byte header][ciphertext+tag][64-byte Ed25519 signature]`.
//! The complete fixed header is AEAD associated data. The signature covers the
//! header and ciphertext, but not its own trailing bytes.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dryoc::rng::copy_randombytes;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::drive_object::parse_canonical_uuid;
use crate::error::{CryptoError, Result};

const MAGIC: &[u8; 8] = b"KUTPCF1\0";
const KEY_DERIVATION_SALT: &[u8] = b"kutup/collab-frame/key/v1\0";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
pub const HEADER_SIZE: usize = 96;
pub const SIGNATURE_SIZE: usize = 64;
pub const MIN_PACKED: usize = HEADER_SIZE + TAG_LEN + SIGNATURE_SIZE;
pub const MAX_PLAINTEXT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum CollabFrameSuiteId {
    XChaCha20Poly1305Ed25519V1 = 1,
}

impl CollabFrameSuiteId {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for CollabFrameSuiteId {
    type Error = CryptoError;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::XChaCha20Poly1305Ed25519V1),
            _ => Err(CryptoError::InvalidInput(format!(
                "unknown collaboration frame suite {value}"
            ))),
        }
    }
}

/// Frame kind discriminants. Values are permanent within suite 1.
pub mod kind {
    pub const YJS_UPDATE: u8 = 1;
    pub const YJS_AWARENESS: u8 = 2;
    pub const SNAPSHOT_ANNOUNCE: u8 = 3;
    pub const OO_OP: u8 = 4;
    pub const OO_LOCK: u8 = 5;
    pub const OO_CHECKPOINT_META: u8 = 6;
    pub const OO_CURSOR: u8 = 7;
    pub const EXCALIDRAW_OP: u8 = 8;
    pub const EXCALIDRAW_CURSOR: u8 = 9;

    pub const fn is_supported(value: u8) -> bool {
        matches!(value, 1..=9)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CollabFrameContextV1 {
    pub kind: u8,
    pub key_epoch: u32,
    pub doc_key_id: u32,
    pub file_id: [u8; 16],
    pub collection_id: [u8; 16],
    pub sender_device_id: u64,
    pub sequence: u64,
}

impl CollabFrameContextV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: u8,
        key_epoch: u32,
        doc_key_id: u32,
        file_id: &str,
        collection_id: &str,
        sender_device_id: u64,
        sequence: u64,
    ) -> Result<Self> {
        if !kind::is_supported(kind) {
            return Err(CryptoError::InvalidInput(format!(
                "unsupported collaboration frame kind {kind}"
            )));
        }
        if key_epoch == 0 || doc_key_id == 0 || sender_device_id == 0 || sequence == 0 {
            return Err(CryptoError::InvalidInput(
                "collaboration frame counters and identifiers must be non-zero".into(),
            ));
        }
        Ok(Self {
            kind,
            key_epoch,
            doc_key_id,
            file_id: parse_canonical_uuid(file_id, "collaboration file")?,
            collection_id: parse_canonical_uuid(collection_id, "collaboration collection")?,
            sender_device_id,
            sequence,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub suite: CollabFrameSuiteId,
    pub kind: u8,
    pub key_epoch: u32,
    pub doc_key_id: u32,
    pub file_id: [u8; 16],
    pub collection_id: [u8; 16],
    pub sender_device_id: u64,
    pub sequence: u64,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub signature: [u8; SIGNATURE_SIZE],
}

impl Frame {
    pub fn context(&self) -> CollabFrameContextV1 {
        CollabFrameContextV1 {
            kind: self.kind,
            key_epoch: self.key_epoch,
            doc_key_id: self.doc_key_id,
            file_id: self.file_id,
            collection_id: self.collection_id,
            sender_device_id: self.sender_device_id,
            sequence: self.sequence,
        }
    }

    pub fn header(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[..8].copy_from_slice(MAGIC);
        out[8..10].copy_from_slice(&self.suite.as_u16().to_be_bytes());
        out[10] = self.kind;
        // byte 11 is reserved and remains zero.
        out[12..16].copy_from_slice(&self.key_epoch.to_be_bytes());
        out[16..20].copy_from_slice(&self.doc_key_id.to_be_bytes());
        out[20..36].copy_from_slice(&self.file_id);
        out[36..52].copy_from_slice(&self.collection_id);
        out[52..60].copy_from_slice(&self.sender_device_id.to_be_bytes());
        out[60..68].copy_from_slice(&self.sequence.to_be_bytes());
        out[68..92].copy_from_slice(&self.nonce);
        out[92..96].copy_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        out
    }

    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE + self.ciphertext.len() + SIGNATURE_SIZE);
        out.extend_from_slice(&self.header());
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn unpack(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < MIN_PACKED || bytes.get(..8) != Some(MAGIC) {
            return Err(CryptoError::TooShort);
        }
        let suite = CollabFrameSuiteId::try_from(u16::from_be_bytes([bytes[8], bytes[9]]))?;
        let frame_kind = bytes[10];
        if !kind::is_supported(frame_kind) || bytes[11] != 0 {
            return Err(CryptoError::InvalidInput(
                "invalid collaboration frame kind or reserved byte".into(),
            ));
        }
        let key_epoch = u32::from_be_bytes(bytes[12..16].try_into().expect("four-byte slice"));
        let doc_key_id = u32::from_be_bytes(bytes[16..20].try_into().expect("four-byte slice"));
        let sender_device_id =
            u64::from_be_bytes(bytes[52..60].try_into().expect("eight-byte slice"));
        let sequence = u64::from_be_bytes(bytes[60..68].try_into().expect("eight-byte slice"));
        if key_epoch == 0 || doc_key_id == 0 || sender_device_id == 0 || sequence == 0 {
            return Err(CryptoError::InvalidInput(
                "collaboration frame identifiers must be non-zero".into(),
            ));
        }
        let ciphertext_len =
            u32::from_be_bytes(bytes[92..96].try_into().expect("four-byte slice")) as usize;
        if !(TAG_LEN..=MAX_PLAINTEXT_BYTES + TAG_LEN).contains(&ciphertext_len)
            || HEADER_SIZE
                .checked_add(ciphertext_len)
                .and_then(|size| size.checked_add(SIGNATURE_SIZE))
                != Some(bytes.len())
        {
            return Err(CryptoError::InvalidInput(
                "invalid collaboration ciphertext length".into(),
            ));
        }
        let mut signature = [0u8; SIGNATURE_SIZE];
        signature.copy_from_slice(&bytes[HEADER_SIZE + ciphertext_len..]);
        Ok(Self {
            suite,
            kind: frame_kind,
            key_epoch,
            doc_key_id,
            file_id: bytes[20..36].try_into().expect("sixteen-byte slice"),
            collection_id: bytes[36..52].try_into().expect("sixteen-byte slice"),
            sender_device_id,
            sequence,
            nonce: bytes[68..92].try_into().expect("twenty-four-byte slice"),
            ciphertext: bytes[HEADER_SIZE..HEADER_SIZE + ciphertext_len].to_vec(),
            signature,
        })
    }
}

fn derive_key(
    collection_key: &[u8],
    context: CollabFrameContextV1,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if collection_key.len() != KEY_LEN {
        return Err(CryptoError::InvalidLength {
            expected: KEY_LEN,
            got: collection_key.len(),
        });
    }
    let mut info = Vec::with_capacity(2 + 1 + 4 + 4 + 16 + 16);
    info.extend_from_slice(
        &CollabFrameSuiteId::XChaCha20Poly1305Ed25519V1
            .as_u16()
            .to_be_bytes(),
    );
    info.push(context.kind);
    info.extend_from_slice(&context.key_epoch.to_be_bytes());
    info.extend_from_slice(&context.doc_key_id.to_be_bytes());
    info.extend_from_slice(&context.file_id);
    info.extend_from_slice(&context.collection_id);
    let hkdf = Hkdf::<Sha256>::new(Some(KEY_DERIVATION_SALT), collection_key);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(&info, key.as_mut_slice())
        .map_err(|_| CryptoError::Backend("collaboration frame HKDF expand".into()))?;
    Ok(key)
}

pub fn seal_unsigned(
    plaintext: &[u8],
    collection_key: &[u8],
    context: CollabFrameContextV1,
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    copy_randombytes(&mut nonce);
    seal_unsigned_with_nonce(plaintext, collection_key, context, &nonce)
}

/// Deterministic nonce entry point for checked-in vectors only.
pub fn seal_unsigned_with_nonce(
    plaintext: &[u8],
    collection_key: &[u8],
    context: CollabFrameContextV1,
    nonce: &[u8],
) -> Result<Vec<u8>> {
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(CryptoError::InvalidInput(
            "collaboration plaintext exceeds V1 limit".into(),
        ));
    }
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: NONCE_LEN,
        got: nonce.len(),
    })?;
    let mut frame = Frame {
        suite: CollabFrameSuiteId::XChaCha20Poly1305Ed25519V1,
        kind: context.kind,
        key_epoch: context.key_epoch,
        doc_key_id: context.doc_key_id,
        file_id: context.file_id,
        collection_id: context.collection_id,
        sender_device_id: context.sender_device_id,
        sequence: context.sequence,
        nonce,
        ciphertext: vec![0u8; plaintext.len() + TAG_LEN],
        signature: [0u8; SIGNATURE_SIZE],
    };
    let aad = frame.header();
    let key = derive_key(collection_key, context)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| CryptoError::Backend("collaboration frame AEAD init".into()))?;
    frame.ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Backend("collaboration frame seal".into()))?;
    Ok(frame.pack())
}

pub fn signing_bytes(packed: &[u8]) -> Result<&[u8]> {
    Frame::unpack(packed)?;
    Ok(&packed[..packed.len() - SIGNATURE_SIZE])
}

pub fn attach_signature(packed: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
    Frame::unpack(packed)?;
    if signature.len() != SIGNATURE_SIZE {
        return Err(CryptoError::InvalidLength {
            expected: SIGNATURE_SIZE,
            got: signature.len(),
        });
    }
    let mut output = packed.to_vec();
    output[packed.len() - SIGNATURE_SIZE..].copy_from_slice(signature);
    Ok(output)
}

pub fn sign(frame: &Frame, signing_seed: &[u8]) -> Result<Vec<u8>> {
    let seed: [u8; 32] = signing_seed
        .try_into()
        .map_err(|_| CryptoError::InvalidLength {
            expected: 32,
            got: signing_seed.len(),
        })?;
    let mut unsigned = frame.clone();
    unsigned.signature = [0u8; SIGNATURE_SIZE];
    let packed = unsigned.pack();
    let signature = SigningKey::from_bytes(&seed).sign(signing_bytes(&packed)?);
    attach_signature(&packed, &signature.to_bytes())
}

pub fn verify(packed: &[u8], public_key: &[u8]) -> Result<()> {
    let frame = Frame::unpack(packed)?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| CryptoError::InvalidLength {
            expected: 32,
            got: public_key.len(),
        })?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| CryptoError::AuthFailed)?;
    let signature = Signature::from_bytes(&frame.signature);
    verifying_key
        .verify_strict(signing_bytes(packed)?, &signature)
        .map_err(|_| CryptoError::AuthFailed)
}

pub fn open(
    packed: &[u8],
    collection_key: &[u8],
    expected_file_id: &str,
    expected_collection_id: &str,
    expected_key_epoch: u32,
) -> Result<(Frame, Vec<u8>)> {
    let frame = Frame::unpack(packed)?;
    let expected_file_id = parse_canonical_uuid(expected_file_id, "collaboration file")?;
    let expected_collection_id =
        parse_canonical_uuid(expected_collection_id, "collaboration collection")?;
    if frame.file_id != expected_file_id
        || frame.collection_id != expected_collection_id
        || frame.key_epoch != expected_key_epoch
    {
        return Err(CryptoError::InvalidInput(
            "collaboration frame context does not match".into(),
        ));
    }
    let key = derive_key(collection_key, frame.context())?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| CryptoError::Backend("collaboration frame AEAD init".into()))?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&frame.nonce),
            Payload {
                msg: &frame.ciphertext,
                aad: &frame.header(),
            },
        )
        .map_err(|_| CryptoError::AuthFailed)?;
    Ok((frame, plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> CollabFrameContextV1 {
        CollabFrameContextV1::new(
            kind::YJS_UPDATE,
            7,
            3,
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            9,
            11,
        )
        .unwrap()
    }

    #[test]
    fn encrypted_signed_round_trip_is_context_bound() {
        let collection_key = [0x41; 32];
        let seed = [0x51; 32];
        let unsigned = seal_unsigned(b"collaboration", &collection_key, context()).unwrap();
        let frame = Frame::unpack(&unsigned).unwrap();
        let signed = sign(&frame, &seed).unwrap();
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        verify(&signed, &public).unwrap();
        assert_eq!(
            open(
                &signed,
                &collection_key,
                "11111111-1111-4111-8111-111111111111",
                "22222222-2222-4222-8222-222222222222",
                7,
            )
            .unwrap()
            .1,
            b"collaboration"
        );
    }

    #[test]
    fn unknown_tampered_relocated_and_oversized_frames_fail_closed() {
        let collection_key = [0x41; 32];
        let unsigned = seal_unsigned(b"frame", &collection_key, context()).unwrap();
        let mut unknown = unsigned.clone();
        unknown[8..10].copy_from_slice(&99u16.to_be_bytes());
        assert!(Frame::unpack(&unknown).is_err());
        let mut tampered = unsigned.clone();
        tampered[HEADER_SIZE] ^= 1;
        assert!(open(
            &tampered,
            &collection_key,
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            7,
        )
        .is_err());
        assert!(open(
            &unsigned,
            &collection_key,
            "33333333-3333-4333-8333-333333333333",
            "22222222-2222-4222-8222-222222222222",
            7,
        )
        .is_err());
        assert!(seal_unsigned(
            &vec![0u8; MAX_PLAINTEXT_BYTES + 1],
            &collection_key,
            context(),
        )
        .is_err());
    }
}
