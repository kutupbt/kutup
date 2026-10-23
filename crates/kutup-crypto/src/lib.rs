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
//! - [`key_binding`] — the account's permanent random key binding, which its own seals bind.
//! - [`chat_attachment_ledger`] — account-private attachment-index envelopes.
//! - [`chat_media`] — immutable typed Chat-media secretstream objects.
//! - [`drive_envelope`] — suite-bearing, purpose/key-separated and UUID/epoch/revision-bound Drive values.
//! - [`drive_object`] — the Drive suite registry and typed, file-bound file-blob framing.
//! - [`file_metadata`] — a Drive file's metadata (name, type, size, photo details), canonical JSON.
//! - [`file_keyring`] — a file's key generations, each sealing the one before.
//! - [`photos_library`] — an account's own marks on photos (favourites, archived, hidden).
//! - [`named_share`] — authenticated HPKE named-recipient collection sharing.
//! - [`stream`] — XChaCha20-Poly1305 secretstream (file content, 5 MiB chunks).
//! - [`asset`] — whiteboard asset envelopes under the file key.
//! - [`envelope`] — collab-edit frame wire format + Ed25519 sign/verify.
//! - [`local_state`] — typed XChaCha client-local state such as CLI sessions.
//! - [`contact_card`] — signed contact summaries and sealed contact cards.
//! - [`mail_names`] — sealed names of mail folders, labels and filters.
//! - [`mail_search`] — the browser's Mail search index at rest.
//! - [`mail_key`] — OpenPGP mail address keys (rPGP) and their signed key lists.
//! - [`mail_forwarding`] — end-to-end mail forwarding (proxy re-encryption).
//! - [`calendar`] — calendar keys, passphrases and session-key packets (rPGP).
//! - [`calendar_recurrence`] — Proton's RRULE subset and the expansion of a series.
//! - [`pass_vault`] — Kutup Pass vault secrets sealed under the master key.

pub mod account_envelope;
pub mod account_head;
pub mod account_ref;
pub mod account_rename;
pub mod asset;
#[cfg(feature = "calendar")]
pub mod calendar;
#[cfg(feature = "calendar")]
pub mod calendar_event;
#[cfg(feature = "calendar")]
pub mod calendar_recurrence;
pub mod chat_attachment_ledger;
pub mod chat_backup;
pub mod chat_backup_media;
pub mod chat_contact_list;
pub mod chat_group;
pub mod chat_group_list;
pub mod chat_media;
pub mod collection_epoch;
pub mod collection_keyring;
pub mod contact_card;
pub mod device_registration;
#[cfg(feature = "mail")]
pub mod dkim_key;
pub mod drive_envelope;
pub mod drive_key_binding;
pub mod drive_names;
pub mod drive_object;
pub mod envelope;
pub mod error;
pub mod file_keyring;
pub mod file_metadata;
// The HPKE suite's backend (hpke-rs, X-Wing), which primitives::hpke calls.
#[allow(clippy::disallowed_types, clippy::disallowed_methods)]
pub mod hpke_xwing;
pub mod identity;
pub mod identity_pins;
pub mod kdf;
pub mod key_binding;
pub mod live_location;
pub mod local_state;
pub mod mail_address;
#[cfg(feature = "mail")]
pub mod mail_forwarding;
#[cfg(feature = "mail")]
pub mod mail_group;
#[cfg(feature = "mail")]
// Adapter (docs/plans/crypto-primitives.md): OpenPGP (RFC 9580, rPGP) names its own algorithms.
#[allow(clippy::disallowed_types, clippy::disallowed_methods)]
pub mod mail_key;
pub mod mail_names;
pub mod mail_search;
#[cfg(feature = "mnemonic")]
pub mod mnemonic;
pub mod named_share;
pub mod names;
// Adapter: Oblivious HTTP (RFC 9458) on the HPKE suite, with its own response AEAD.
#[allow(clippy::disallowed_types, clippy::disallowed_methods)]
pub mod oblivious;
// Adapter: OPAQUE (RFC 9807, opaque-ke) and its ciphersuite.
#[allow(clippy::disallowed_types, clippy::disallowed_methods)]
pub mod opaque;
pub mod opaque_login_state;
pub mod padding;
// The one module that names algorithms (docs/plans/crypto-primitives.md).
// Adapter: KeePass KDBX's composite key.
#[allow(clippy::disallowed_types, clippy::disallowed_methods)]
pub mod pass_vault;
pub mod photos_library;
#[allow(clippy::disallowed_types, clippy::disallowed_methods)]
pub mod primitives;
pub mod profile_key_share;
// Adapter: Signal's ProvisioningCipher (AES-256-CBC + HMAC-SHA256).
#[allow(clippy::disallowed_types, clippy::disallowed_methods)]
pub mod provisioning;
pub mod revision_guard;
// Adapter: Signal's safety number (iterated SHA-512).
#[allow(clippy::disallowed_types, clippy::disallowed_methods)]
pub mod safety_number;
// Legacy: libsodium's secretstream, until the block format replaces it
// (docs/plans/drive-block-format.md).
#[allow(clippy::disallowed_types, clippy::disallowed_methods)]
pub mod stream;
pub mod thumbnail;
pub mod yjs_seed;

pub use error::{CryptoError, Result};
