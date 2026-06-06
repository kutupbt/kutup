//! Error type for `kutup-crypto`.

use thiserror::Error;

/// Errors returned by the crypto primitives.
///
/// Authentication failures are deliberately coarse (`AuthFailed`) so callers
/// cannot distinguish *why* a decryption failed — mirroring the Go code, which
/// returns a single opaque "decryption failed" for secretbox/sealed-box/asset.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// A key, nonce, or other fixed-size input had the wrong length.
    #[error("invalid length: expected {expected} bytes, got {got}")]
    InvalidLength { expected: usize, got: usize },

    /// Ciphertext was shorter than the minimum framing/overhead allows.
    #[error("input too short")]
    TooShort,

    /// AEAD/MAC verification failed (wrong key, tampered ciphertext, bad AAD).
    #[error("authentication failed")]
    AuthFailed,

    /// A base64 input could not be decoded.
    #[error("invalid base64: {0}")]
    Base64(#[from] base64::DecodeError),

    /// An underlying primitive reported an unexpected error.
    #[error("crypto backend error: {0}")]
    Backend(String),
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, CryptoError>;
