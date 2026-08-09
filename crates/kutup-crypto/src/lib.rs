//! # kutup-crypto
//!
//! Canonical shared end-to-end-encryption implementation for Kutup. Browser
//! clients consume this crate through the thin `kutup-crypto-wasm` wrapper;
//! CLI and native clients call it directly. Kutup-owned headers, derivation
//! labels, validation and suite policy live here rather than in each client.
//!
//! Backing libraries:
//! - [`dryoc`] — pure-Rust, libsodium-compatible `crypto_pwhash` (Argon2id)
//!   and `crypto_secretstream_xchacha20poly1305`.
//! - [`hkdf`] + [`sha2`] — purpose-separated HKDF-SHA256 subkeys.
//! - [`chacha20poly1305`] — XChaCha20-Poly1305-IETF AEAD for typed envelopes.
//! - [`ed25519_dalek`] — Ed25519 collab-frame signatures.
//!
//! ## Modules
//! - [`kdf`] — one-root Argon2id account protection and recovery proof.
//! - [`mnemonic`] — BIP39 recovery-phrase encode/decode (registration).
//! - [`account_envelope`] — suite-bearing, purpose- and account-bound XChaCha account wraps.
//! - [`chat_attachment_ledger`] — account-private attachment-index envelopes.
//! - [`chat_media`] — immutable typed Chat-media secretstream objects.
//! - [`drive_envelope`] — suite-bearing, purpose/key-separated and UUID/epoch/revision-bound Drive values.
//! - [`drive_object`] — the Drive suite registry and typed, context-bound file-blob framing.
//! - [`named_share`] — authenticated HPKE named-recipient collection sharing.
//! - [`stream`] — XChaCha20-Poly1305 secretstream (file content, 5 MiB chunks).
//! - [`asset`] — XChaCha20-Poly1305-IETF asset blobs.
//! - [`envelope`] — collab-edit frame wire format + Ed25519 sign/verify.
//! - [`local_state`] — typed XChaCha client-local state such as CLI sessions.

pub mod account_envelope;
pub mod asset;
pub mod chat_attachment_ledger;
pub mod chat_media;
pub mod collection_epoch;
pub mod drive_envelope;
pub mod drive_object;
pub mod envelope;
pub mod error;
pub mod identity;
pub mod kdf;
pub mod local_state;
#[cfg(feature = "mnemonic")]
pub mod mnemonic;
pub mod named_share;
pub mod stream;

pub use error::{CryptoError, Result};
