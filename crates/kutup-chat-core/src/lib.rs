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
mod keys;
mod manifest;
mod profile;
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
    AuthorityTrust, ChatDb, ContactRecord, InboundEnvelope, InboundFailureKind, InboundState,
    InboxMessage, LocalIdentity, LocalProfile, ManifestTrust, OutboxEntry, OutboxSyncLeg,
    PeerProfile, Pending, SentMessage, TransparencyTrust,
};
pub use engine::{
    ChatEvent, Engine, EngineState, InboundFailure, PreKeyMaintenanceReport, ReceiveReport,
};
pub use error::{ChatError, Result};
pub use kutup_chat_proto::{
    AccountAddress, ChatContent, ContactControlBody, ContactState, ConversationId,
    DeliveredEnvelope, OutgoingEnvelope, TextBody,
};
pub use manifest::{verify_bundle_response, verify_manifest, AccountAuthority, ManifestPolicy};
pub use profile::{derive_wrapping_key, MAX_AVATAR_BYTES};
pub use session::{ReceivedMessage, SendSummary, Session};
pub use transport::{ChatTransport, SendOutcome};
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub use wasm::WasmChatClient;
