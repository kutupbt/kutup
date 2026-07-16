use kutup_chat_core::{
    ChatContent, ChatError, InboundEnvelope, InboundFailure, InboundFailureKind, ManifestTrust,
    PreKeyMaintenanceReport, ReceiveReport, ReceivedMessage, SendSummary,
};

pub type Result<T> = std::result::Result<T, KutupChatError>;

/// Stable error taxonomy shared by Swift and Kotlin. Messages never contain
/// key material, HTTP response bodies, or database keys.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum KutupChatError {
    #[error("crypto protocol: {message}")]
    Protocol { message: String },
    #[error("missing key material: {message}")]
    MissingKeyMaterial { message: String },
    #[error("untrusted identity: {message}")]
    UntrustedIdentity { message: String },
    #[error("duplicate message: {message}")]
    DuplicateMessage { message: String },
    #[error("malformed ciphertext: {message}")]
    MalformedCiphertext { message: String },
    #[error("unsupported encryption suite {suite}")]
    UnsupportedSuite { suite: u16 },
    #[error("invalid input: {message}")]
    InvalidInput { message: String },
    #[error("encrypted chat store: {message}")]
    Storage { message: String },
    #[error("chat transport: {message}")]
    Transport { message: String },
    #[error("device trust: {message}")]
    Trust { message: String },
    #[error("send did not converge after {attempts} attempts")]
    SendNotConverged { attempts: u32 },
    #[error("no bundle for device {device_id}")]
    MissingBundle { device_id: u32 },
    #[error("chat client is closed")]
    Closed,
}

impl From<ChatError> for KutupChatError {
    fn from(error: ChatError) -> Self {
        match error {
            ChatError::Protocol(message)
            | ChatError::Wire(message)
            | ChatError::Content(message) => Self::Protocol { message },
            ChatError::MissingKeyMaterial(message) => Self::MissingKeyMaterial { message },
            ChatError::UntrustedIdentity(message) => Self::UntrustedIdentity { message },
            ChatError::DuplicateMessage(message) => Self::DuplicateMessage { message },
            ChatError::MalformedCiphertext(message) => Self::MalformedCiphertext { message },
            ChatError::UnsupportedSuite(suite) => Self::UnsupportedSuite { suite },
            ChatError::MissingSender => Self::Protocol {
                message: "delivered envelope has no sender".into(),
            },
            ChatError::Invalid(message) => Self::InvalidInput { message },
            ChatError::Db(message) => Self::Storage { message },
            ChatError::Transport(message) => Self::Transport { message },
            ChatError::Trust(message) => Self::Trust { message },
            ChatError::SendNotConverged(attempts) => Self::SendNotConverged { attempts },
            ChatError::MissingBundle(device_id) => Self::MissingBundle { device_id },
        }
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for KutupChatError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Transport {
            message: format!("native HTTP callback failed: {error}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ChatHttpMethod {
    Get,
    Post,
    Put,
}

/// A relative request under the authenticated server API base (`…/api`). The
/// platform adapter adds authorization and executes it with URLSession/OkHttp.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ChatHttpRequest {
    pub method: ChatHttpMethod,
    pub path: String,
    pub body_json: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ChatHttpResponse {
    pub status: u16,
    pub body_json: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ChatDirection {
    Incoming,
    Outgoing,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ChatContentRecord {
    pub version: u16,
    pub kind: String,
    pub sent_at: String,
    pub sequence: u64,
    /// Preserves unknown/newer content kinds without making foreign clients
    /// understand Rust's serde_json value model.
    pub body_json: String,
    pub text: Option<String>,
}

impl From<ChatContent> for ChatContentRecord {
    fn from(content: ChatContent) -> Self {
        let text = content.as_text().map(|body| body.text);
        Self {
            version: content.v,
            kind: content.kind,
            sent_at: content.sent_at,
            sequence: content.seq,
            body_json: serde_json::to_string(&content.body).unwrap_or_else(|_| "null".into()),
            text,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ChatHistoryEntry {
    pub id: String,
    pub peer: String,
    pub direction: ChatDirection,
    pub sender_device_id: Option<u32>,
    pub cursor: Option<u64>,
    pub timestamp_ms: i64,
    pub delivered: bool,
    pub deduplicated: bool,
    pub content: ChatContentRecord,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ChatSendSummary {
    pub delivered: bool,
    pub deduplicated: bool,
    pub attempts: u32,
    pub safety_number_changes: Vec<String>,
}

impl From<SendSummary> for ChatSendSummary {
    fn from(summary: SendSummary) -> Self {
        Self {
            delivered: summary.delivered,
            deduplicated: summary.deduplicated,
            attempts: summary.attempts,
            safety_number_changes: summary
                .safety_number_changes
                .into_iter()
                .map(|address| address.name())
                .collect(),
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ChatReceivedMessage {
    pub id: String,
    pub peer: String,
    pub sender_device_id: u32,
    pub cursor: u64,
    pub content: ChatContentRecord,
}

impl From<ReceivedMessage> for ChatReceivedMessage {
    fn from(message: ReceivedMessage) -> Self {
        Self {
            id: message.id,
            peer: message.from.name(),
            sender_device_id: message.from.device_id,
            cursor: message.cursor,
            content: message.content.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ChatInboundFailureKind {
    MalformedEnvelope,
    MalformedCiphertext,
    MissingKeyMaterial,
    UntrustedIdentity,
    UnsupportedSuite,
    MissingSender,
    Store,
    Duplicate,
    Unknown,
}

impl From<InboundFailureKind> for ChatInboundFailureKind {
    fn from(kind: InboundFailureKind) -> Self {
        match kind {
            InboundFailureKind::MalformedEnvelope => Self::MalformedEnvelope,
            InboundFailureKind::MalformedCiphertext => Self::MalformedCiphertext,
            InboundFailureKind::MissingKeyMaterial => Self::MissingKeyMaterial,
            InboundFailureKind::UntrustedIdentity => Self::UntrustedIdentity,
            InboundFailureKind::UnsupportedSuite => Self::UnsupportedSuite,
            InboundFailureKind::MissingSender => Self::MissingSender,
            InboundFailureKind::Store => Self::Store,
            InboundFailureKind::Duplicate => Self::Duplicate,
            InboundFailureKind::Unknown => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ChatInboundFailure {
    pub id: String,
    pub kind: ChatInboundFailureKind,
    pub message: String,
}

impl From<InboundFailure> for ChatInboundFailure {
    fn from(failure: InboundFailure) -> Self {
        Self {
            id: failure.id,
            kind: failure.kind.into(),
            message: failure.error,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ChatReceiveReport {
    pub messages: Vec<ChatReceivedMessage>,
    pub synced: Vec<String>,
    pub undecodable: Vec<String>,
    pub errors: Vec<ChatInboundFailure>,
    pub duplicates: Vec<String>,
}

impl From<ReceiveReport> for ChatReceiveReport {
    fn from(report: ReceiveReport) -> Self {
        Self {
            messages: report.messages.into_iter().map(Into::into).collect(),
            synced: report.synced,
            undecodable: report.undecodable,
            errors: report.errors.into_iter().map(Into::into).collect(),
            duplicates: report.duplicates,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ChatPreKeyCount {
    pub ec: u64,
    pub kyber: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ChatPreKeyMaintenance {
    pub before: ChatPreKeyCount,
    pub after: ChatPreKeyCount,
    pub uploaded_ec: u64,
    pub uploaded_kyber: u64,
}

impl From<PreKeyMaintenanceReport> for ChatPreKeyMaintenance {
    fn from(report: PreKeyMaintenanceReport) -> Self {
        Self {
            before: ChatPreKeyCount {
                ec: report.before.one_time_pre_keys,
                kyber: report.before.one_time_kyber_pre_keys,
            },
            after: ChatPreKeyCount {
                ec: report.after.one_time_pre_keys,
                kyber: report.after.one_time_kyber_pre_keys,
            },
            uploaded_ec: report.uploaded_ec as u64,
            uploaded_kyber: report.uploaded_kyber as u64,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ChatInboundAttention {
    pub id: String,
    pub cursor: u64,
    pub attempts: u32,
    pub failure_kind: Option<ChatInboundFailureKind>,
    pub last_error: Option<String>,
    pub received_at_ms: i64,
}

impl From<InboundEnvelope> for ChatInboundAttention {
    fn from(item: InboundEnvelope) -> Self {
        Self {
            id: item.id,
            cursor: item.cursor,
            attempts: item.attempts,
            failure_kind: item.failure_kind.map(Into::into),
            last_error: item.last_error,
            received_at_ms: item.received_at,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ChatTrustLevel {
    Tofu,
    Verified,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ChatManifestTrust {
    pub peer: String,
    pub authority_key_id: String,
    pub self_authority_key: String,
    pub highest_version: u64,
    pub manifest_hash: String,
    pub trust: ChatTrustLevel,
    pub continuity_gap: bool,
}

impl From<ManifestTrust> for ChatManifestTrust {
    fn from(trust: ManifestTrust) -> Self {
        Self {
            peer: trust.peer,
            authority_key_id: trust.authority_key_id,
            self_authority_key: trust.self_authority_key,
            highest_version: trust.highest_version,
            manifest_hash: trust.manifest_hash,
            trust: match trust.trust {
                kutup_chat_core::AuthorityTrust::Tofu => ChatTrustLevel::Tofu,
                kutup_chat_core::AuthorityTrust::Verified => ChatTrustLevel::Verified,
            },
            continuity_gap: trust.continuity_gap,
        }
    }
}
