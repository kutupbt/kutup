//! kutup-chat-core — the shared client chat engine.
//!
//! Wraps `libsignal-protocol` (PQXDH + Triple Ratchet) behind kutup-owned types
//! and speaks the `kutup-chat-proto` wire contract (`docs/chat-protocol.md`).
//! The same crate compiles to wasm for the web client and links natively into
//! the Android/iOS apps. **libsignal types never appear in this crate's public
//! API** — callers see kutup types and the wire DTOs only.
//!
//! Persistence is a port: the engine depends on the [`ChatDb`] trait and stores
//! all identity/session/ratchet state through it. Tests and dev builds select
//! bundled SQLite; release native clients select SQLCipher; the browser selects
//! the IndexedDB backend. Every crypto op is a [`Pending`] unit of work committed
//! atomically, giving the decrypt→persist→ack ordering the send/drain
//! orchestration relies on.

mod address;
mod clock;
mod db;
mod engine;
mod error;
mod history_transfer;
mod keys;
mod manifest;
mod mls_engine;
mod mls_policy;
mod profile;
mod sealed_sender;
mod session;
mod store;
mod transport;
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
mod wasm;
mod wire;

pub use address::ChatAddress;
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub use db::indexed_db::IndexedDbChatDb;
#[cfg(feature = "sqlite")]
pub use db::sqlite::SqliteChatDb;
pub use db::{
    AccountManifestHistoryRecordV1, AuthorityTrust, ChatDb, ContactRecord,
    HistoryTransferJournalStateV1, HistoryTransferJournalV1, HistoryTransferRoleV1,
    ImportedHistoryRecordV1, InboundEnvelope, InboundFailureKind, InboundState, InboxMessage,
    LocalIdentity, LocalProfile, ManifestTrust, MlsHistoryMessage, MlsOutboxDelivery,
    MlsOutboxEntry, OutboxEntry, OutboxSyncLeg, PeerProfile, Pending,
    PendingAccountIdentityResetV1, SentMessage,
};
pub use engine::{
    ChatEvent, Engine, EngineState, InboundFailure, PreKeyMaintenanceReport, ReceiveReport,
};
pub use error::{ChatError, Result};
pub use history_transfer::{
    derive_history_transfer_key, open_history_transfer_frame, prepare_history_archive,
    seal_history_transfer_frame, verify_history_archive, verify_history_transfer_acceptance,
    verify_history_transfer_request, HistoryTransferEphemeralSecret, PreparedHistoryArchiveV1,
    PreparedHistoryTransferAcceptance, PreparedHistoryTransferRequest, VerifiedHistoryArchiveV1,
};
pub use kutup_chat_proto::{
    AccountAddress, ChatAttachmentDescriptorV1, ChatContent, ContactControlBody, ContactState,
    ConversationId, DeliveredEnvelope, OutgoingEnvelope, TextBody,
};
pub use manifest::{
    derive_safety_number, verify_bundle_response, verify_manifest, AccountAuthority,
    ManifestPolicy, SafetyNumberV1,
};
pub use mls_engine::{
    AnonymousMlsRecipientDevice, AppliedInboundMlsApplication, AppliedInboundMlsCommit,
    ClaimedMlsCredential, DecryptedMlsApplication, DerivedMlsDeliveryCapability,
    FinalizedMlsAuthorityChange, FinalizedMlsClose, FinalizedMlsMembershipChange,
    FinalizedMlsOwnerChange, FinalizedMlsPolicyChange, FinalizedMlsRecovery, JoinedMlsConversation,
    LocalMlsConversationRecord, LocalMlsConversationStatus, LocalMlsGroupState,
    MlsApplicationEnvelopeContext, MlsApplicationInspection, MlsClient, MlsControlEnvelopeContext,
    MlsDevicePublicMaterial, MlsGroupControlCredential, MlsGroupOwnerCredential,
    MlsInboundCommitInspection, MlsWelcomeInspection, PendingMlsAuthorityChange, PendingMlsClose,
    PendingMlsCommit, PendingMlsMembershipChange, PendingMlsOwnerApprovalRequest,
    PendingMlsOwnerChange, PendingMlsPolicyChange, PendingMlsRecovery, PreparedMlsAuthorityChange,
    PreparedMlsClose, PreparedMlsGroupGenesis, PreparedMlsMembershipChange, PreparedMlsOwnerChange,
    PreparedMlsPolicyChange, PreparedMlsRecovery, ProcessedMlsControlEnvelope,
    StagedMlsApplicationDelivery, VerifiedMlsCredential, VerifiedMlsKeyPackage,
    KUTUP_MLS_V1_CIPHERSUITE, KUTUP_MLS_V1_MAX_PAST_EPOCHS,
};
pub use mls_policy::{
    verify_mls_ordering_policy_history, verify_mls_ordering_policy_history_details,
    VerifiedMlsOrderingPolicyEntry, VerifiedMlsOrderingPolicyHistory,
};
pub use profile::{derive_wrapping_key, MAX_AVATAR_BYTES};
pub use session::{ReceivedMessage, SendSummary, Session};
pub use transport::{
    ChatTransport, HistoryTransferFramePageV1, HistoryTransferListV1, HistoryTransferSummaryV1,
    SendOutcome,
};
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub use wasm::WasmChatClient;
