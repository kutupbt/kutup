//! Canonical encrypted and signed collaborative-edit frame.
//!
//! Rust owns the complete construction (format V3, docs/plans/one-device-list.md
//! §8). Browser code receives and returns opaque packed bytes through WASM; it
//! does not duplicate this parser, KDF or AEAD framing.
//!
//! Wire layout (big-endian):
//! `[88-byte header][ciphertext+tag][64-byte Ed25519 signature]`.
//!
//! A frame's sender is a device of an account: the header names the device
//! (its id in the account's manifest, and the manifest sequence it sealed
//! under), and the account travels beside the frame on every transport. The
//! signature covers the account too, so whoever relays the frame can't name
//! another sender.
//!
//! Frames are sealed under the file key and bound to the file and the key's
//! generation; they name no folder, so a document's log survives a move
//! (docs/plans/drive-move.md).
//! The complete fixed header is AEAD associated data. The signature covers its
//! domain, the sender account, the header and the ciphertext: the file id, key
//! generation and the device's sequence are all signed, so a frame can't be
//! replayed into another file (a key holder could re-encrypt; it can't
//! re-sign).

use crate::primitives::{Aead, Kdf, SigningKey, Suite, VerifyingKey};
use zeroize::Zeroizing;

use crate::account_ref::AccountRef;
use crate::drive_object::parse_canonical_uuid;
use crate::error::{CryptoError, Result};

const MAGIC: &[u8; 8] = b"KUTPCF3\0";
const SIGNATURE_DOMAIN: &[u8] = crate::labels::COLLAB_FRAME_V3;
const KEY_DERIVATION_SALT: &[u8] = crate::labels::COLLAB_FRAME_KEY_V1;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
pub const HEADER_SIZE: usize = 88;
/// A device id is an entry of the account's manifest: 1..=127.
pub const MAX_DEVICE_ID: u32 = 127;
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
pub struct CollabFrameContextV3 {
    pub kind: u8,
    pub key_generation: u32,
    pub doc_key_id: u32,
    pub file_id: [u8; 16],
    /// The sender's id in its account's manifest.
    pub device_id: u32,
    /// The sequence of the sender account's manifest it sealed under.
    pub manifest_sequence: u64,
    /// The device's own frame counter in this file.
    pub sequence: u64,
}

impl CollabFrameContextV3 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: u8,
        key_generation: u32,
        doc_key_id: u32,
        file_id: &str,
        device_id: u32,
        manifest_sequence: u64,
        sequence: u64,
    ) -> Result<Self> {
        if !kind::is_supported(kind) {
            return Err(CryptoError::InvalidInput(format!(
                "unsupported collaboration frame kind {kind}"
            )));
        }
        check_identifiers(
            key_generation,
            doc_key_id,
            device_id,
            manifest_sequence,
            sequence,
        )?;
        Ok(Self {
            kind,
            key_generation,
            doc_key_id,
            file_id: parse_canonical_uuid(file_id, "collaboration file")?,
            device_id,
            manifest_sequence,
            sequence,
        })
    }
}

fn check_identifiers(
    key_generation: u32,
    doc_key_id: u32,
    device_id: u32,
    manifest_sequence: u64,
    sequence: u64,
) -> Result<()> {
    if key_generation == 0 || doc_key_id == 0 || manifest_sequence == 0 || sequence == 0 {
        return Err(CryptoError::InvalidInput(
            "collaboration frame counters and identifiers must be non-zero".into(),
        ));
    }
    if !(1..=MAX_DEVICE_ID).contains(&device_id) {
        return Err(CryptoError::InvalidInput(
            "collaboration frame device id must be 1-127".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub suite: CollabFrameSuiteId,
    pub kind: u8,
    pub key_generation: u32,
    pub doc_key_id: u32,
    pub file_id: [u8; 16],
    pub device_id: u32,
    pub manifest_sequence: u64,
    pub sequence: u64,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub signature: [u8; SIGNATURE_SIZE],
}

impl Frame {
    pub fn context(&self) -> CollabFrameContextV3 {
        CollabFrameContextV3 {
            kind: self.kind,
            key_generation: self.key_generation,
            doc_key_id: self.doc_key_id,
            file_id: self.file_id,
            device_id: self.device_id,
            manifest_sequence: self.manifest_sequence,
            sequence: self.sequence,
        }
    }

    pub fn header(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[..8].copy_from_slice(MAGIC);
        out[8..10].copy_from_slice(&self.suite.as_u16().to_be_bytes());
        out[10] = self.kind;
        // byte 11 is reserved and remains zero.
        out[12..16].copy_from_slice(&self.key_generation.to_be_bytes());
        out[16..20].copy_from_slice(&self.doc_key_id.to_be_bytes());
        out[20..36].copy_from_slice(&self.file_id);
        out[36..40].copy_from_slice(&self.device_id.to_be_bytes());
        // bytes 40..44 are reserved and remain zero.
        out[44..52].copy_from_slice(&self.manifest_sequence.to_be_bytes());
        out[52..60].copy_from_slice(&self.sequence.to_be_bytes());
        out[60..84].copy_from_slice(&self.nonce);
        out[84..88].copy_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
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
        if !kind::is_supported(frame_kind) || bytes[11] != 0 || bytes[40..44] != [0; 4] {
            return Err(CryptoError::InvalidInput(
                "invalid collaboration frame kind or reserved byte".into(),
            ));
        }
        let key_generation = u32::from_be_bytes(bytes[12..16].try_into().expect("four-byte slice"));
        let doc_key_id = u32::from_be_bytes(bytes[16..20].try_into().expect("four-byte slice"));
        let device_id = u32::from_be_bytes(bytes[36..40].try_into().expect("four-byte slice"));
        let manifest_sequence =
            u64::from_be_bytes(bytes[44..52].try_into().expect("eight-byte slice"));
        let sequence = u64::from_be_bytes(bytes[52..60].try_into().expect("eight-byte slice"));
        check_identifiers(
            key_generation,
            doc_key_id,
            device_id,
            manifest_sequence,
            sequence,
        )?;
        let ciphertext_len =
            u32::from_be_bytes(bytes[84..88].try_into().expect("four-byte slice")) as usize;
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
            key_generation,
            doc_key_id,
            file_id: bytes[20..36].try_into().expect("sixteen-byte slice"),
            device_id,
            manifest_sequence,
            sequence,
            nonce: bytes[60..84].try_into().expect("twenty-four-byte slice"),
            ciphertext: bytes[HEADER_SIZE..HEADER_SIZE + ciphertext_len].to_vec(),
            signature,
        })
    }
}

fn derive_key(file_key: &[u8], context: CollabFrameContextV3) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if file_key.len() != KEY_LEN {
        return Err(CryptoError::InvalidLength {
            expected: KEY_LEN,
            got: file_key.len(),
        });
    }
    let mut info = Vec::with_capacity(2 + 1 + 4 + 4 + 16);
    info.extend_from_slice(
        &CollabFrameSuiteId::XChaCha20Poly1305Ed25519V1
            .as_u16()
            .to_be_bytes(),
    );
    info.push(context.kind);
    info.extend_from_slice(&context.key_generation.to_be_bytes());
    info.extend_from_slice(&context.doc_key_id.to_be_bytes());
    info.extend_from_slice(&context.file_id);
    let hkdf = Kdf::new(Suite::V1, KEY_DERIVATION_SALT, file_key);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(&info, key.as_mut_slice())
        .map_err(|_| CryptoError::Backend("collaboration frame HKDF expand".into()))?;
    Ok(key)
}

pub fn seal_unsigned(
    plaintext: &[u8],
    file_key: &[u8],
    context: CollabFrameContextV3,
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    crate::primitives::random(&mut nonce);
    seal_unsigned_with_nonce(plaintext, file_key, context, &nonce)
}

/// Deterministic nonce entry point for checked-in vectors only.
pub fn seal_unsigned_with_nonce(
    plaintext: &[u8],
    file_key: &[u8],
    context: CollabFrameContextV3,
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
        key_generation: context.key_generation,
        doc_key_id: context.doc_key_id,
        file_id: context.file_id,
        device_id: context.device_id,
        manifest_sequence: context.manifest_sequence,
        sequence: context.sequence,
        nonce,
        ciphertext: vec![0u8; plaintext.len() + TAG_LEN],
        signature: [0u8; SIGNATURE_SIZE],
    };
    let aad = frame.header();
    let key = derive_key(file_key, context)?;
    let cipher = Aead::new(Suite::V1, key.as_slice())
        .map_err(|_| CryptoError::Backend("collaboration frame AEAD init".into()))?;
    frame.ciphertext = cipher
        .seal_with_nonce(&nonce, &aad, plaintext)
        .map_err(|_| CryptoError::Backend("collaboration frame seal".into()))?;
    Ok(frame.pack())
}

/// What the sender's frame key signs: the domain, the sender account, and the
/// packed frame without its signature.
pub fn signing_bytes(packed: &[u8], sender: &AccountRef) -> Result<Vec<u8>> {
    Frame::unpack(packed)?;
    let account = sender.bytes();
    let mut out =
        Vec::with_capacity(SIGNATURE_DOMAIN.len() + account.len() + packed.len() - SIGNATURE_SIZE);
    out.extend_from_slice(SIGNATURE_DOMAIN);
    out.extend_from_slice(&account);
    out.extend_from_slice(&packed[..packed.len() - SIGNATURE_SIZE]);
    Ok(out)
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

pub fn sign(frame: &Frame, sender: &AccountRef, signing_seed: &[u8]) -> Result<Vec<u8>> {
    let seed: [u8; 32] = signing_seed
        .try_into()
        .map_err(|_| CryptoError::InvalidLength {
            expected: 32,
            got: signing_seed.len(),
        })?;
    let mut unsigned = frame.clone();
    unsigned.signature = [0u8; SIGNATURE_SIZE];
    let packed = unsigned.pack();
    let signature = SigningKey::from_seed(Suite::V1, &seed).sign(&signing_bytes(&packed, sender)?);
    attach_signature(&packed, &signature)
}

/// The frame is `sender`'s, signed with `public_key` (the frame key its
/// account's manifest lists for the frame's device).
pub fn verify(packed: &[u8], sender: &AccountRef, public_key: &[u8]) -> Result<()> {
    let frame = Frame::unpack(packed)?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| CryptoError::InvalidLength {
            expected: 32,
            got: public_key.len(),
        })?;
    let verifying_key =
        VerifyingKey::from_bytes(Suite::V1, &public_key).map_err(|_| CryptoError::AuthFailed)?;
    verifying_key
        .verify(&signing_bytes(packed, sender)?, &frame.signature)
        .map_err(|_| CryptoError::AuthFailed)
}

/// A frame as a server delivers it: its sender account
/// ([`AccountRef::bytes`]) then the packed frame. Senders send the bare
/// frame; the server that authenticated them names them.
pub fn deliver(sender: &AccountRef, packed: &[u8]) -> Vec<u8> {
    let mut out = sender.bytes();
    out.extend_from_slice(packed);
    out
}

/// The sender and the packed frame of a [`deliver`]ed frame. Whether the
/// sender signed it is [`verify`]'s question.
pub fn delivered(bytes: &[u8]) -> Result<(AccountRef, &[u8])> {
    let (sender, used) = AccountRef::read(bytes)?;
    let packed = &bytes[used..];
    Frame::unpack(packed)?;
    Ok((sender, packed))
}

pub fn open(
    packed: &[u8],
    file_key: &[u8],
    expected_file_id: &str,
    expected_key_generation: u32,
) -> Result<(Frame, Vec<u8>)> {
    let frame = Frame::unpack(packed)?;
    let expected_file_id = parse_canonical_uuid(expected_file_id, "collaboration file")?;
    if frame.file_id != expected_file_id || frame.key_generation != expected_key_generation {
        return Err(CryptoError::InvalidInput(
            "collaboration frame context does not match".into(),
        ));
    }
    let key = derive_key(file_key, frame.context())?;
    let cipher = Aead::new(Suite::V1, key.as_slice())
        .map_err(|_| CryptoError::Backend("collaboration frame AEAD init".into()))?;
    let plaintext = cipher
        .open_with_nonce(&frame.nonce, &frame.header(), &frame.ciphertext)
        .map_err(|_| CryptoError::AuthFailed)
        .map(crate::primitives::into_vec)?;
    Ok((frame, plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> CollabFrameContextV3 {
        CollabFrameContextV3::new(
            kind::YJS_UPDATE,
            7,
            3,
            "11111111-1111-4111-8111-111111111111",
            9,
            4,
            11,
        )
        .unwrap()
    }

    fn sender() -> AccountRef {
        AccountRef::new("example.test", "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b").unwrap()
    }

    #[test]
    fn encrypted_signed_round_trip_is_context_bound() {
        let file_key = [0x41; 32];
        let seed = [0x51; 32];
        let unsigned = seal_unsigned(b"collaboration", &file_key, context()).unwrap();
        let frame = Frame::unpack(&unsigned).unwrap();
        let signed = sign(&frame, &sender(), &seed).unwrap();
        let public = SigningKey::from_seed(Suite::V1, &seed)
            .verifying_key()
            .to_array::<32>();
        verify(&signed, &sender(), &public).unwrap();
        // Another account named beside it: the signature is someone else's.
        let other = AccountRef::new("other.test", "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b").unwrap();
        assert!(verify(&signed, &other, &public).is_err());
        // The device, manifest sequence and sequence are signed.
        for byte in [39, 51, 59] {
            let mut moved = signed.clone();
            moved[byte] ^= 1;
            assert!(verify(&moved, &sender(), &public).is_err(), "byte {byte}");
        }
        assert_eq!(
            open(
                &signed,
                &file_key,
                "11111111-1111-4111-8111-111111111111",
                7,
            )
            .unwrap()
            .1,
            b"collaboration"
        );
    }

    #[test]
    fn a_delivered_frame_names_its_sender() {
        let unsigned = seal_unsigned(b"frame", &[0x41; 32], context()).unwrap();
        let delivered_bytes = deliver(&sender(), &unsigned);
        let (named, packed) = delivered(&delivered_bytes).unwrap();
        assert_eq!(named, sender());
        assert_eq!(packed, unsigned.as_slice());
        assert!(delivered(&unsigned).is_err());
        assert!(delivered(&delivered_bytes[..delivered_bytes.len() - 1]).is_err());
    }

    #[test]
    fn unknown_tampered_relocated_and_oversized_frames_fail_closed() {
        let file_key = [0x41; 32];
        let unsigned = seal_unsigned(b"frame", &file_key, context()).unwrap();
        let mut unknown = unsigned.clone();
        unknown[8..10].copy_from_slice(&99u16.to_be_bytes());
        assert!(Frame::unpack(&unknown).is_err());
        let mut tampered = unsigned.clone();
        tampered[HEADER_SIZE] ^= 1;
        assert!(open(
            &tampered,
            &file_key,
            "11111111-1111-4111-8111-111111111111",
            7,
        )
        .is_err());
        assert!(open(
            &unsigned,
            &file_key,
            "33333333-3333-4333-8333-333333333333",
            7,
        )
        .is_err());
        // Another generation of the same file's key is another binding.
        assert!(open(
            &unsigned,
            &file_key,
            "11111111-1111-4111-8111-111111111111",
            8
        )
        .is_err());
        assert!(seal_unsigned(&vec![0u8; MAX_PLAINTEXT_BYTES + 1], &file_key, context(),).is_err());
        // Device ids are manifest entries; the reserved bytes stay zero.
        for device_id in [0, 128] {
            assert!(CollabFrameContextV3::new(
                kind::YJS_UPDATE,
                7,
                3,
                "11111111-1111-4111-8111-111111111111",
                device_id,
                4,
                11
            )
            .is_err());
        }
        let mut reserved = unsigned.clone();
        reserved[41] = 1;
        assert!(Frame::unpack(&reserved).is_err());
    }
}
