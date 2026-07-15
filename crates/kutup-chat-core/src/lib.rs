//! kutup-chat-core — the shared client chat engine.
//!
//! Wraps `libsignal-protocol` (PQXDH + Triple Ratchet) behind kutup-owned types
//! and speaks the `kutup-chat-proto` wire contract (`docs/chat-protocol.md`).
//! The same crate compiles to wasm for the web client and links natively into
//! the Android/iOS apps. **libsignal types never appear in this crate's public
//! API** — callers see kutup types and the wire DTOs only.
//!
//! Persistence is a port: the engine depends on the [`ChatDb`] trait and stores
//! all identity/session/ratchet state through it. Native builds get the bundled
//! [`SqliteChatDb`] (the `sqlite` feature, on by default); the web client
//! supplies an IndexedDB-backed `ChatDb` and turns the feature off. Every crypto
//! op is a [`Pending`] unit of work committed atomically, giving the
//! decrypt→persist→ack ordering the send/drain orchestration relies on.

mod address;
mod db;
mod error;
mod keys;
mod session;
mod store;
mod wire;

pub use address::ChatAddress;
#[cfg(feature = "sqlite")]
pub use db::sqlite::SqliteChatDb;
pub use db::{ChatDb, LocalIdentity, Pending};
pub use error::{ChatError, Result};
pub use kutup_chat_proto::{ChatContent, DeliveredEnvelope, OutgoingEnvelope, TextBody};
pub use session::Session;
