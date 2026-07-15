//! The transport port — the seam over the chat REST/WS API.
//!
//! Unlike [`ChatDb`](crate::ChatDb), transport is genuinely **async**: it does
//! network I/O, which pends. Each platform supplies its own implementation (the
//! desktop/CLI a reqwest client, the web client `fetch`, native the OS HTTP
//! stack); `kutup-chat-core` stays transport-agnostic and never links an HTTP
//! client. The engine (`engine.rs`) drives it, interleaving async transport calls
//! with the synchronous crypto/store ops.
//!
//! `#[async_trait(?Send)]` mirrors the engine's single-threaded, `Rc`-based
//! design (and the wasm world, where `fetch` futures are `!Send`).

use async_trait::async_trait;

use crate::error::Result;
use kutup_chat_proto::{
    DeviceListMismatch, MailboxPage, RegisterChatDeviceRequest, SendMessagesRequest,
    UserPreKeyBundlesResponse,
};

/// The result of a `POST …/messages`. A `409 DeviceListMismatch` is modeled as a
/// value (not an error) because it is the expected, recoverable fan-out signal.
pub enum SendOutcome {
    /// Stored in every target device's mailbox. `deduplicated` is true when the
    /// server matched this `sendId` to an earlier delivery (an idempotent retry).
    Delivered { deduplicated: bool },
    /// The request's device set didn't match the recipient's active devices.
    Mismatch(DeviceListMismatch),
}

/// The chat server, as the engine sees it. Implementations translate these to the
/// REST endpoints of `docs/chat-protocol.md` §4 and map non-2xx to
/// [`ChatError::Transport`](crate::ChatError::Transport) — except the 409 send
/// response, which they surface as [`SendOutcome::Mismatch`].
#[async_trait(?Send)]
pub trait ChatTransport {
    /// `POST /api/chat/device` — returns the server-assigned device id.
    async fn register_device(&self, req: &RegisterChatDeviceRequest) -> Result<u32>;

    /// `GET /api/chat/users/{username}/keys` — every active device's bundle
    /// (consumes one one-time prekey per device server-side).
    async fn fetch_bundles(&self, username: &str) -> Result<UserPreKeyBundlesResponse>;

    /// `POST /api/chat/users/{username}/messages` — multi-device send.
    async fn send(&self, username: &str, req: &SendMessagesRequest) -> Result<SendOutcome>;

    /// `GET /api/chat/messages?deviceId&after&limit` — a drain page (oldest-first).
    async fn drain(&self, device_id: u32, after: Option<u64>, limit: u32) -> Result<MailboxPage>;

    /// `POST /api/chat/messages/ack` — delete processed envelopes.
    async fn ack(&self, ids: &[String]) -> Result<()>;
}
