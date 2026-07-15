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
    /// A session or prekey needed to decrypt is unavailable and may be repaired.
    #[error("missing session or prekey: {0}")]
    MissingKeyMaterial(String),
    /// libsignal rejected a changed/untrusted identity.
    #[error("untrusted identity: {0}")]
    UntrustedIdentity(String),
    /// Authenticated replay / already-consumed message.
    #[error("duplicate message: {0}")]
    DuplicateMessage(String),
    /// Structurally or cryptographically invalid ciphertext.
    #[error("malformed ciphertext: {0}")]
    MalformedCiphertext(String),
    /// The envelope selected a suite this client does not implement.
    #[error("unsupported encryption suite {0}")]
    UnsupportedSuite(u16),
    /// Plaintext-sender mode requires a sender address on every envelope.
    #[error("delivered envelope has no sender")]
    MissingSender,
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
    /// A signed device manifest was missing, invalid, rolled back, equivocated,
    /// or inconsistent with the served prekey bundles.
    #[error("device trust: {0}")]
    Trust(String),
    /// A send exhausted its 409 device-list recovery attempts.
    #[error("send did not converge after {0} attempts")]
    SendNotConverged(u32),
    /// A 409 named a device the served bundles didn't include (server inconsistency).
    #[error("no bundle for device {0}")]
    MissingBundle(u32),
}

impl From<libsignal_protocol::SignalProtocolError> for ChatError {
    fn from(e: libsignal_protocol::SignalProtocolError) -> Self {
        use libsignal_protocol::SignalProtocolError as Signal;
        let message = e.to_string();
        match e {
            Signal::InvalidPreKeyId
            | Signal::InvalidSignedPreKeyId
            | Signal::InvalidKyberPreKeyId
            | Signal::SessionNotFound(_)
            | Signal::NoSenderKeyState { .. } => ChatError::MissingKeyMaterial(message),
            Signal::UntrustedIdentity(_) => ChatError::UntrustedIdentity(message),
            Signal::DuplicatedMessage(_, _) => ChatError::DuplicateMessage(message),
            Signal::ApplicationCallbackError(_, _) => ChatError::Db(message),
            Signal::InvalidProtobufEncoding
            | Signal::CiphertextMessageTooShort(_)
            | Signal::LegacyCiphertextVersion(_)
            | Signal::UnrecognizedCiphertextVersion(_)
            | Signal::UnrecognizedMessageVersion(_)
            | Signal::NoKeyTypeIdentifier
            | Signal::BadKeyType(_)
            | Signal::BadKeyLength(_, _)
            | Signal::InvalidKeyAgreement
            | Signal::SignatureValidationFailed
            | Signal::InvalidMacKeyLength(_)
            | Signal::InvalidSessionStructure(_)
            | Signal::InvalidSenderKeySession { .. }
            | Signal::InvalidRegistrationId(_, _)
            | Signal::InvalidMessage(_, _)
            | Signal::InvalidSealedSenderMessage(_)
            | Signal::UnknownSealedSenderVersion(_)
            | Signal::SealedSenderSelfSend
            | Signal::UnknownSealedSenderServerCertificateId(_)
            | Signal::BadKEMKeyType(_)
            | Signal::WrongKEMKeyType(_, _)
            | Signal::BadKEMKeyLength(_, _)
            | Signal::BadKEMCiphertextLength(_, _) => ChatError::MalformedCiphertext(message),
            Signal::InvalidArgument(_)
            | Signal::InvalidState(_, _)
            | Signal::InvalidProtocolAddress { .. }
            | Signal::FfiBindingError(_) => ChatError::Protocol(message),
        }
    }
}

impl From<base64::DecodeError> for ChatError {
    fn from(e: base64::DecodeError) -> Self {
        ChatError::Wire(e.to_string())
    }
}

impl ChatError {
    pub(crate) fn inbound_failure_kind(&self) -> crate::InboundFailureKind {
        use crate::InboundFailureKind as Kind;
        match self {
            Self::Wire(_) => Kind::MalformedEnvelope,
            Self::MalformedCiphertext(_) => Kind::MalformedCiphertext,
            Self::MissingKeyMaterial(_) => Kind::MissingKeyMaterial,
            Self::UntrustedIdentity(_) => Kind::UntrustedIdentity,
            Self::UnsupportedSuite(_) => Kind::UnsupportedSuite,
            Self::MissingSender => Kind::MissingSender,
            Self::Db(_) => Kind::Store,
            Self::DuplicateMessage(_) => Kind::Duplicate,
            Self::Protocol(_)
            | Self::Content(_)
            | Self::Invalid(_)
            | Self::Transport(_)
            | Self::Trust(_)
            | Self::SendNotConverged(_)
            | Self::MissingBundle(_) => Kind::Unknown,
        }
    }
}

/// Maps any libsignal crypto error (`SignalProtocolError`, `CurveError`, …) to
/// [`ChatError::Protocol`] by its `Display`, without naming the lower-level
/// error types that libsignal doesn't re-export.
pub(crate) fn crypto<T, E: std::fmt::Display>(r: std::result::Result<T, E>) -> Result<T> {
    r.map_err(|e| ChatError::Protocol(e.to_string()))
}
