use thiserror::Error;

/// Fail-closed errors produced before federation state or feature payloads are
/// touched. Network and persistence errors deliberately live outside this
/// protocol crate.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FederationProtocolError {
    #[error("unknown federation protocol version {0}")]
    UnknownFederationVersion(u16),
    #[error("unknown federation authentication profile {0}")]
    UnknownAuthProfile(u16),
    #[error("invalid federation field {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("invalid base64 in federation field {0}")]
    InvalidBase64(&'static str),
    #[error("federation key identifier does not match the public key")]
    KeyIdMismatch,
    #[error("invalid federation identity signature: {0}")]
    InvalidIdentitySignature(&'static str),
    #[error("invalid federation identity chain: {0}")]
    InvalidIdentityChain(&'static str),
    #[error("invalid federation discovery: {0}")]
    InvalidDiscovery(&'static str),
    #[error("invalid federation HTTP signature profile: {0}")]
    InvalidHttpSignature(&'static str),
    #[error("federation message signature is not yet valid")]
    SignatureNotYetValid,
    #[error("federation message signature has expired")]
    SignatureExpired,
    #[error("federation content digest does not match the exact message content")]
    ContentDigestMismatch,
}

pub(crate) fn invalid_field(field: &'static str, reason: &'static str) -> FederationProtocolError {
    FederationProtocolError::InvalidField { field, reason }
}
