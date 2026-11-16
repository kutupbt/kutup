//! Error type for `kutup-crypto`.

use thiserror::Error;

/// Errors returned by the crypto primitives.
///
/// Authentication failures are deliberately coarse (`AuthFailed`) so callers
/// cannot distinguish *why* a decryption failed — mirroring the Go code, which
/// returns a single opaque authentication failure for every typed envelope.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// A structurally valid value is not permitted by the selected suite.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// The bytes are well formed but from a newer writer than this reader:
    /// a minimum reader version above its own, or a code of a *refuse* enum
    /// it does not know (docs/plans/format-evolution.md, rule 5). Show
    /// "update Kutup to open this" and keep the bytes; never delete,
    /// overwrite or repair them.
    #[error("newer format: {0}")]
    NewerThanMe(String),

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

/// How [`CryptoError::NewerThanMe`] starts as text: what the browser and
/// other string-error boundaries match on.
pub const NEWER_FORMAT_PREFIX: &str = "newer format: ";

impl CryptoError {
    /// Whether the error is *newer than me* rather than *corrupt*.
    pub fn is_newer(&self) -> bool {
        matches!(self, CryptoError::NewerThanMe(_))
    }
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, CryptoError>;
