//! # kutup-crypto
//!
//! Shared end-to-end-encryption primitives for kutup. This crate is the **Rust
//! mirror** of `frontend/src/crypto/` (libsodium-wrappers) and the successor to
//! `cmd/kutup/internal/crypto/` + `backend/services/envelope/` (Go). All three
//! must stay byte-for-byte compatible on the wire — when you change one, change
//! the others and update the test vectors.
//!
//! Backing libraries:
//! - [`dryoc`] — pure-Rust, libsodium-compatible `crypto_pwhash` (Argon2id),
//!   `crypto_secretbox` (XSalsa20-Poly1305), `crypto_box_seal` (X25519), and
//!   `crypto_secretstream_xchacha20poly1305`.
//! - [`hkdf`] + [`sha2`] — HKDF-SHA256 for the per-file content key.
//! - [`chacha20poly1305`] — XChaCha20-Poly1305-IETF AEAD for asset blobs.
//! - [`ed25519_dalek`] — Ed25519 collab-frame signatures.
//!
//! ## Modules
//! - [`kdf`] — Argon2id KEK / login-key derivation + HKDF content key.
//! - [`mnemonic`] — BIP39 recovery-phrase encode/decode (registration).
//! - [`secretbox`] — XSalsa20-Poly1305 (keys, metadata).
//! - [`sealedbox`] — anonymous X25519 sealed box (key sharing).
//! - [`stream`] — XChaCha20-Poly1305 secretstream (file content, 5 MiB chunks).
//! - [`asset`] — XChaCha20-Poly1305-IETF asset blobs.
//! - [`envelope`] — collab-edit frame wire format + Ed25519 sign/verify.

pub mod asset;
pub mod envelope;
pub mod error;
pub mod kdf;
pub mod mnemonic;
pub mod sealedbox;
pub mod secretbox;
pub mod stream;

pub use error::{CryptoError, Result};
