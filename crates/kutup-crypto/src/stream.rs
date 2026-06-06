//! XChaCha20-Poly1305 secretstream — mirrors `cmd/kutup/internal/crypto/stream.go`
//! and `frontend/src/crypto/{streamEncryptor,streamDecryptor}.ts`
//! (libsodium `crypto_secretstream_xchacha20poly1305`).
//!
//! File content is encrypted as a sequence of 5 MiB plaintext chunks. The wire
//! format is `[24-byte header][chunk_0][chunk_1]…` where each chunk is
//! `plaintext + 17 bytes` (16-byte Poly1305 MAC + 1-byte tag). The last chunk
//! carries `TAG_FINAL`; intermediate chunks carry `TAG_MESSAGE`.
//!
//! Quirk preserved from the Go/TS reference: an **empty** plaintext produces a
//! header-only blob with *no* terminating FINAL chunk (the chunk loop simply
//! never runs). [`decrypt_stream`] mirrors this and returns empty.

use dryoc::classic::crypto_secretstream_xchacha20poly1305::{
    crypto_secretstream_xchacha20poly1305_init_pull,
    crypto_secretstream_xchacha20poly1305_init_push, crypto_secretstream_xchacha20poly1305_pull,
    crypto_secretstream_xchacha20poly1305_push, Header, Key, State,
};
use dryoc::constants::{
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
};

use crate::error::{CryptoError, Result};

/// Stream key length (32 bytes).
pub const KEY_BYTES: usize = CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES;
/// Stream header length (24 bytes), prepended once at the start of the blob.
pub const HEADER_BYTES: usize = CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES;
/// Per-chunk AEAD overhead (17 bytes = 16-byte MAC + 1-byte tag).
pub const ABYTES: usize = CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;
/// Plaintext chunk size (5 MiB) — must match the frontend.
pub const CHUNK_SIZE: usize = 5 * 1024 * 1024;

/// Intermediate-chunk tag (`0x00`).
pub const TAG_MESSAGE: u8 = CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
/// Final-chunk tag (`0x03` = PUSH | REKEY).
pub const TAG_FINAL: u8 = CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL;

fn key_array(key: &[u8]) -> Result<Key> {
    key.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: KEY_BYTES,
        got: key.len(),
    })
}

/// Incremental stream encryptor. Mirrors the Go `Encryptor`.
pub struct StreamEncryptor {
    state: State,
}

impl StreamEncryptor {
    /// Initializes a new stream, returning the encryptor and the 24-byte header
    /// that must be written first.
    pub fn new(key: &[u8]) -> Result<(Self, [u8; HEADER_BYTES])> {
        let k = key_array(key)?;
        let mut state = State::new();
        let mut header: Header = [0u8; HEADER_BYTES];
        crypto_secretstream_xchacha20poly1305_init_push(&mut state, &mut header, &k);
        Ok((Self { state }, header))
    }

    /// Encrypts one chunk with `tag`, returning `plaintext.len() + ABYTES` bytes.
    pub fn push(&mut self, plaintext: &[u8], tag: u8) -> Result<Vec<u8>> {
        let mut ciphertext = vec![0u8; plaintext.len() + ABYTES];
        crypto_secretstream_xchacha20poly1305_push(
            &mut self.state,
            &mut ciphertext,
            plaintext,
            None,
            tag,
        )
        .map_err(|e| CryptoError::Backend(format!("secretstream push: {e}")))?;
        Ok(ciphertext)
    }
}

/// Incremental stream decryptor. Mirrors the Go `Decryptor`.
pub struct StreamDecryptor {
    state: State,
}

impl StreamDecryptor {
    /// Initializes a decryptor from `key` and the 24-byte stream `header`.
    pub fn new(key: &[u8], header: &[u8]) -> Result<Self> {
        let k = key_array(key)?;
        let h: Header = header.try_into().map_err(|_| CryptoError::InvalidLength {
            expected: HEADER_BYTES,
            got: header.len(),
        })?;
        let mut state = State::new();
        crypto_secretstream_xchacha20poly1305_init_pull(&mut state, &h, &k);
        Ok(Self { state })
    }

    /// Decrypts and authenticates one chunk, returning `(plaintext, tag)`.
    pub fn pull(&mut self, ciphertext: &[u8]) -> Result<(Vec<u8>, u8)> {
        if ciphertext.len() < ABYTES {
            return Err(CryptoError::TooShort);
        }
        let mut plaintext = vec![0u8; ciphertext.len() - ABYTES];
        let mut tag: u8 = 0;
        crypto_secretstream_xchacha20poly1305_pull(
            &mut self.state,
            &mut plaintext,
            &mut tag,
            ciphertext,
            None,
        )
        .map_err(|_| CryptoError::AuthFailed)?;
        Ok((plaintext, tag))
    }
}

/// Encrypts `plaintext` into a self-contained secretstream blob with 5 MiB
/// chunks. Output: `[24-byte header][encrypted chunks…]`. Mirrors `EncryptStream`.
pub fn encrypt_stream(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let (mut enc, header) = StreamEncryptor::new(key)?;
    let chunks = plaintext.len() / CHUNK_SIZE + 1;
    let mut out = Vec::with_capacity(HEADER_BYTES + plaintext.len() + chunks * ABYTES);
    out.extend_from_slice(&header);

    let mut offset = 0;
    while offset < plaintext.len() {
        let end = (offset + CHUNK_SIZE).min(plaintext.len());
        let is_last = end == plaintext.len();
        let tag = if is_last { TAG_FINAL } else { TAG_MESSAGE };
        out.extend_from_slice(&enc.push(&plaintext[offset..end], tag)?);
        offset = end;
    }
    Ok(out)
}

/// Decrypts a secretstream blob produced by [`encrypt_stream`] or the frontend.
/// Mirrors `DecryptStream`.
pub fn decrypt_stream(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < HEADER_BYTES {
        return Err(CryptoError::TooShort);
    }
    let (header, body) = ciphertext.split_at(HEADER_BYTES);
    let mut dec = StreamDecryptor::new(key, header)?;

    let enc_chunk_size = CHUNK_SIZE + ABYTES;
    let mut out = Vec::with_capacity(body.len());
    let mut offset = 0;
    while offset < body.len() {
        let end = (offset + enc_chunk_size).min(body.len());
        let (plain, tag) = dec.pull(&body[offset..end])?;
        out.extend_from_slice(&plain);
        if tag == TAG_FINAL {
            break;
        }
        offset = end;
    }
    Ok(out)
}
