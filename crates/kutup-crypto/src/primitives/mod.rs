//! The one place that names a cryptographic algorithm
//! (docs/plans/crypto-primitives.md, W2 of docs/plans/wipe-unification.md).
//!
//! Every Kutup-owned format asks for operations by [`Suite`], never by
//! algorithm: hash, MAC, KDF, AEAD, signatures, sealing to a key (HPKE),
//! randomness, constant-time comparison and password hashing. A suite is a
//! whole, fixed tuple of algorithms ([`suite::SuiteParams`]); changing an
//! algorithm is a new row with its vectors, never a change at the call sites.
//! Each format allowlists the suites it reads and keeps the suite in its AAD,
//! so one format can neither pick nor be downgraded to another's algorithms.
//!
//! Purpose labels (`kutup/<area>/<purpose>/vN\0`) stay with each caller: the
//! primitives never invent one. Interoperable formats that negotiate their
//! own algorithms (OpenPGP, libsignal, TLS, OPAQUE, Web Push, KDBX, the SSH
//! agent, …) stay behind their adapters, outside the table.

mod aead;
mod ct;
mod hash;
mod hpke;
mod kdf;
mod mac;
mod pwhash;
mod random;
mod sign;
pub mod suite;

pub use aead::{Aead, AeadKey};
pub use ct::ct_eq;
pub use hash::{hash, Digest, Hasher};
pub use hpke::{hpke_open, hpke_public_key, hpke_seal, HpkeSealed};
pub use kdf::kdf;
pub use mac::{mac, mac_verify, subkey, Tag};
pub use pwhash::{pwhash, PwhashParams};
pub use random::{random, random_array, random_key};
pub use sign::{SigningKey, VerifyingKey};
pub use suite::{Suite, SuiteParams};

/// Formats being moved here: secretstream stays as it is until the block
/// format replaces it at the wipe (docs/plans/drive-block-format.md).
pub mod legacy {
    pub use crate::stream as secretstream;
}

#[cfg(test)]
mod tests;
