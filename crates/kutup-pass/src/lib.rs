//! Kutup Pass core (docs/plans/pass.md).
//!
//! A vault is a standard KeePass file (KDBX 4.1) kept in Kutup Drive and
//! edited offline on every device. This crate opens and saves vaults
//! ([`kdbx`]) and merges two edited copies against the version both started
//! from ([`merge`]), so that no edit is lost when devices meet again. It has
//! no server or UI dependencies: the website (through WASM), the `kutup` CLI
//! and later the native apps all use the same code.
//!
//! Vaults are `keepass::Database` values from the patched copy of the
//! `keepass` crate in `crates/kutup-pass/vendor/keepass`, re-exported here as [`keepass`].

pub mod edit;
pub mod import;
pub mod kdbx;
pub mod merge;
mod refs;
pub mod ssh;
pub mod view;

pub use kdbx::{key_file_secret, open, save, KdbxError, VaultKey};
pub use keepass;
pub use merge::{merge, Conflict, MergeReport, REVIEW_KEY};
