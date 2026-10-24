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

mod account_identity;
mod address;
mod call_link;
mod clock;
mod contact_list;
mod db;
mod engine;
mod error;
// Exported through the WASM client only (the native FFI comes with the
// native apps): unused in a native build until then. Invitations, claims and
// message contexts are wired by the group messages part of slice 1
// (docs/plans/pairwise-groups.md §10), which also drops this allowance.
#[cfg(test)]
mod contact_list_harness_tests;
#[allow(dead_code)]
mod group;
#[cfg_attr(not(feature = "wasm"), allow(dead_code))]
mod group_avatar;
#[cfg_attr(not(feature = "wasm"), allow(dead_code))]
mod group_client;
#[cfg_attr(not(feature = "wasm"), allow(dead_code))]
mod group_engine;
#[cfg_attr(not(feature = "wasm"), allow(dead_code))]
mod group_gate;
#[cfg(test)]
mod group_harness_tests;
#[cfg_attr(not(feature = "wasm"), allow(dead_code))]
mod group_heal;
#[cfg_attr(not(feature = "wasm"), allow(dead_code))]
mod group_invite;
mod group_lines;
mod group_link;
#[cfg_attr(not(feature = "wasm"), allow(dead_code))]
mod group_list;
mod group_recover;
#[cfg_attr(not(feature = "wasm"), allow(dead_code))]
mod group_send;
mod group_settings;
mod keys;
pub use keys::PublishedKeys;
mod manifest;
mod padding;
mod prekey_rotation;
mod profile;
mod sealed_sender;
// The query side is called from the browser bindings (and tests) only.
mod identity_sync;
#[cfg_attr(not(feature = "wasm"), allow(dead_code))]
pub(crate) mod search;
mod session;
mod store;
#[cfg_attr(not(feature = "wasm"), allow(dead_code))]
pub(crate) mod timeline;
mod transport;
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
mod wasm;
mod wire;

pub use account_identity::{Installation, LinkingDevice, ProvisionedSettings, VerifiedProvision};
pub use address::{parse_account, ChatAddress};
pub use call_link::{
    call_link_fragment, call_link_token_hash, new_call_link_nonce, open_joined_meeting,
    owner_call_link_host_token, owner_call_link_secret, parse_call_link_fragment,
    seal_joined_meeting, CallLinkInfoV1, CallLinkKeys, CallLinkMessageV1, JoinedMeetingV1,
    CALL_INFO_SEALED_BYTES, CALL_NAME_SEALED_BYTES, JOINED_MEETING_SEALED_BYTES,
    MAX_CALL_MESSAGE_BYTES, MAX_CALL_NAME_BYTES, MAX_CALL_TITLE_BYTES,
};
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub use db::indexed_db::IndexedDbChatDb;
#[cfg(feature = "sqlite")]
pub use db::sqlite::SqliteChatDb;
pub use db::{
    AccountManifestHistoryRecord, AuthorityTrust, ChatDb, ContactRecord, InboundEnvelope,
    InboundFailureKind, InboundState, InboxMessage, LocalIdentity, LocalProfile, ManifestTrust,
    OutboxEntry, OutboxSyncLeg, PeerProfile, Pending, PendingAccountIdentityResetV1, SentMessage,
};
pub use engine::{
    ChatEvent, Engine, EngineState, GroupInviteNotice, InboundFailure, OutboxFailure, OutboxFlush,
    PreKeyMaintenanceReport, ReceiveReport,
};
pub use error::{ChatError, Result};
pub use kutup_chat_proto::{
    AccountRef, ChatAttachmentDescriptorV1, ChatContent, ContactControlBody, ContactState,
    ConversationId, DeliveredEnvelope, OutgoingEnvelope, TextBody,
};
pub use manifest::{
    derive_safety_number, verify_bundle_response, verify_manifest, AccountAuthority,
    ManifestPolicy, SafetyNumberV2, SAFETY_QR_PREFIX,
};
pub use profile::{derive_wrapping_key, MAX_AVATAR_BYTES};
pub use session::{ReceivedMessage, SendSummary, Session};
pub use transport::{
    ChatTransport, DistributionOutcome, GroupListItem, IdentityPinsRecord, IdentityPinsWrite,
    SendOutcome,
};
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub use wasm::WasmChatClient;
