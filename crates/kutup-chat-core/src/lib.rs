//! kutup-chat-core — the shared client chat engine.
//!
//! Wraps `libsignal-protocol` (PQXDH + Triple Ratchet) behind kutup-owned types
//! and speaks the `kutup-chat-proto` wire contract (`docs/chat-protocol.md`).
//! The same crate compiles to wasm for the web client and links natively into
//! the Android/iOS apps. **libsignal types never appear in this crate's public
//! API** — callers see kutup types and the wire DTOs only.
//!
//! This is the first slice: identity/bundle generation, wire<->libsignal
//! conversion, and the 1:1 encrypt/decrypt loop, proven end-to-end through the
//! wire types. The durable store, transport ports, and the send/drain/ack
//! orchestration (with 409 recovery and decrypt→persist→ack ordering) layer on
//! top of these primitives next.

mod address;
mod error;
mod keys;
mod session;
mod wire;

pub use address::ChatAddress;
pub use error::{ChatError, Result};
pub use kutup_chat_proto::{ChatContent, DeliveredEnvelope, OutgoingEnvelope, TextBody};
pub use session::Session;
