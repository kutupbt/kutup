//! Typed errors — libsignal's error type is wrapped, never exposed.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, ChatError>;

#[derive(Debug, Error)]
pub enum ChatError {
    /// A libsignal protocol failure (bad signature, untrusted identity, AEAD
    /// failure, malformed frame, …). The message is safe to surface; it never
    /// contains key material.
    #[error("crypto: {0}")]
    Protocol(String),
    /// A wire blob wasn't valid base64 / had the wrong length / wrong type.
    #[error("malformed wire field: {0}")]
    Wire(String),
    /// The decrypted plaintext wasn't a valid content document.
    #[error("malformed content: {0}")]
    Content(String),
    /// A device id, registration id, or address was out of range.
    #[error("invalid parameter: {0}")]
    Invalid(String),
    /// The durable store (SQLite / IndexedDB) failed a read or a commit.
    #[error("store: {0}")]
    Db(String),
    /// The transport (the platform's HTTP/WS client) failed a request.
    #[error("transport: {0}")]
    Transport(String),
    /// A send exhausted its 409 device-list recovery attempts.
    #[error("send did not converge after {0} attempts")]
    SendNotConverged(u32),
    /// A 409 named a device the served bundles didn't include (server inconsistency).
    #[error("no bundle for device {0}")]
    MissingBundle(u32),
}

impl From<libsignal_protocol::SignalProtocolError> for ChatError {
    fn from(e: libsignal_protocol::SignalProtocolError) -> Self {
        // Display, not Debug: keep it human and free of internal structure.
        ChatError::Protocol(e.to_string())
    }
}

impl From<base64::DecodeError> for ChatError {
    fn from(e: base64::DecodeError) -> Self {
        ChatError::Wire(e.to_string())
    }
}

/// Maps any libsignal crypto error (`SignalProtocolError`, `CurveError`, …) to
/// [`ChatError::Protocol`] by its `Display`, without naming the lower-level
/// error types that libsignal doesn't re-export.
pub(crate) fn crypto<T, E: std::fmt::Display>(r: std::result::Result<T, E>) -> Result<T> {
    r.map_err(|e| ChatError::Protocol(e.to_string()))
}
