//! Collaborative-edit frame envelope — mirrors `backend/services/envelope/`
//! (`envelope.go` + `sign.go`).
//!
//! Wire layout (little-endian):
//! ```text
//! header(30) || nonce_remaining(16) || ciphertext_len(4) || ciphertext || signature(64)
//! ```
//! The 30-byte header is used as AEAD associated data; its last 8 bytes are the
//! first 8 bytes of the 24-byte nonce, the remaining 16 nonce bytes live in the
//! body so the header stays a clean fixed-size AAD prefix.
//!
//! The server never decrypts frames — it only verifies the Ed25519 signature
//! (over everything but the trailing 64 bytes) and routes them.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::error::{CryptoError, Result};

/// Frame `kind` discriminants (see `envelope.go`).
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
}

/// Fixed-size header prefix used as AAD.
pub const HEADER_SIZE: usize = 30;
/// Ed25519 signature length.
pub const SIGNATURE_SIZE: usize = 64;
/// Minimum packed length: header + 16 nonce bytes + 4 length bytes + signature.
pub const MIN_PACKED: usize = HEADER_SIZE + 16 + 4 + SIGNATURE_SIZE;

/// In-memory representation of a collab frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub version: u8,
    pub kind: u8,
    pub doc_key_id: u32,
    pub sender_device_id: u64,
    pub sequence: u64,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
    pub signature: [u8; SIGNATURE_SIZE],
}

impl Frame {
    /// Returns the first 30 bytes (the AAD header). Mirrors `Frame.Header`.
    pub fn header(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[0] = self.version;
        out[1] = self.kind;
        out[2..6].copy_from_slice(&self.doc_key_id.to_le_bytes());
        out[6..14].copy_from_slice(&self.sender_device_id.to_le_bytes());
        out[14..22].copy_from_slice(&self.sequence.to_le_bytes());
        out[22..30].copy_from_slice(&self.nonce[..8]);
        out
    }

    /// Serializes the frame into the wire format. Mirrors `Pack`.
    pub fn pack(&self) -> Vec<u8> {
        let clen = self.ciphertext.len() as u32;
        let mut out = Vec::with_capacity(MIN_PACKED + self.ciphertext.len());
        out.extend_from_slice(&self.header());
        out.extend_from_slice(&self.nonce[8..]);
        out.extend_from_slice(&clen.to_le_bytes());
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parses bytes into a frame. Mirrors `Unpack`.
    pub fn unpack(bs: &[u8]) -> Result<Frame> {
        if bs.len() < MIN_PACKED {
            return Err(CryptoError::TooShort);
        }
        let version = bs[0];
        let kind = bs[1];
        let doc_key_id = u32::from_le_bytes(bs[2..6].try_into().unwrap());
        let sender_device_id = u64::from_le_bytes(bs[6..14].try_into().unwrap());
        let sequence = u64::from_le_bytes(bs[14..22].try_into().unwrap());

        let mut nonce = [0u8; 24];
        nonce[..8].copy_from_slice(&bs[22..30]);
        nonce[8..].copy_from_slice(&bs[30..46]);

        let clen = u32::from_le_bytes(bs[46..50].try_into().unwrap()) as usize;
        if bs.len() != 50 + clen + SIGNATURE_SIZE {
            return Err(CryptoError::Backend(
                "envelope: bad ciphertext length".into(),
            ));
        }
        let ciphertext = bs[50..50 + clen].to_vec();
        let mut signature = [0u8; SIGNATURE_SIZE];
        signature.copy_from_slice(&bs[50 + clen..50 + clen + SIGNATURE_SIZE]);

        Ok(Frame {
            version,
            kind,
            doc_key_id,
            sender_device_id,
            sequence,
            nonce,
            ciphertext,
            signature,
        })
    }
}

/// Signs the frame body (everything but the trailing 64 signature bytes) with
/// the Ed25519 `signing_seed` (32-byte seed) and returns the full packed bytes.
/// Mirrors `Sign` (whose Go private key is the 64-byte `seed || public` form).
pub fn sign(frame: &Frame, signing_seed: &[u8]) -> Result<Vec<u8>> {
    let seed: [u8; 32] = signing_seed
        .try_into()
        .map_err(|_| CryptoError::InvalidLength {
            expected: 32,
            got: signing_seed.len(),
        })?;
    let sk = SigningKey::from_bytes(&seed);

    let mut f = frame.clone();
    let packed = f.pack();
    let body = &packed[..packed.len() - SIGNATURE_SIZE];
    let sig: Signature = sk.sign(body);
    f.signature = sig.to_bytes();
    Ok(f.pack())
}

/// Verifies the Ed25519 signature on already-packed `bs` against the 32-byte
/// `public_key`. Mirrors `Verify`.
///
/// Uses `verify_strict` (rejects non-canonical / small-order signatures) — a
/// security hardening over Go's `ed25519.Verify`; honest, canonical frames
/// signed by our clients verify identically under both.
pub fn verify(bs: &[u8], public_key: &[u8]) -> Result<()> {
    if bs.len() < SIGNATURE_SIZE {
        return Err(CryptoError::TooShort);
    }
    let pk_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| CryptoError::InvalidLength {
            expected: 32,
            got: public_key.len(),
        })?;
    let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| CryptoError::AuthFailed)?;

    let (body, sig_bytes) = bs.split_at(bs.len() - SIGNATURE_SIZE);
    let sig = Signature::from_bytes(sig_bytes.try_into().unwrap());
    vk.verify_strict(body, &sig)
        .map_err(|_| CryptoError::AuthFailed)
}
