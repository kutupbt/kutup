//! The durable-store port and its unit-of-work.
//!
//! [`ChatDb`] is the seam every platform implements: native (Android/iOS/desktop)
//! over encrypted SQLite ([`sqlite::SqliteChatDb`], behind the `sqlite` feature),
//! the web client over IndexedDB (a separate wasm adapter, `--no-default-features`).
//! It is a **synchronous** blob store — the libsignal store adapters (`store.rs`)
//! run every call inside a future that resolves immediately, so no async executor
//! is required on any platform (the same `now_or_never` trick the wasm spike uses).
//!
//! Reads are typed by domain and return the raw libsignal-serialized record bytes;
//! all writes for one crypto operation are staged in a [`Pending`] and committed in
//! a single atomic [`ChatDb::apply`]. Because nothing is durable until `apply`
//! returns `Ok`, a crash mid-operation leaves the last committed state intact —
//! the foundation for the decrypt→persist→ack ordering invariant (`docs/chat-protocol.md`).

use std::collections::HashMap;

use crate::error::Result;

#[cfg(feature = "sqlite")]
pub mod sqlite;

/// The local device's long-term chat identity. Persisted as a single row and
/// cached in the store for the hot `get_identity_key_pair` path.
#[derive(Clone)]
pub struct LocalIdentity {
    /// `IdentityKeyPair::serialize()` — the private identity material.
    pub identity_key_pair: Vec<u8>,
    /// The libsignal registration id chosen at install (stable run-to-run).
    pub registration_id: u32,
}

/// A decrypted inbound message, persisted atomically with the ratchet advance that
/// produced it (before the mailbox row is acked). `content` is the raw plaintext
/// (`serde_json` of a `ChatContent`) — stored even when its `kind` is unknown, so
/// nothing is ever dropped (the content schema's "render a placeholder" rule).
#[derive(Clone)]
pub struct InboxMessage {
    /// Mailbox id (the server's ack handle) — primary key, so redelivery is idempotent.
    pub id: String,
    /// Sender username (`user@domain` once federation lands).
    pub peer: String,
    pub sender_device_id: u32,
    /// The mailbox cursor (monotonic order + dedup key).
    pub cursor: u64,
    pub content: Vec<u8>,
    pub received_at: i64,
}

/// A pending outbound message, keyed by its `sendId`. Because a ratchet advance is
/// irreversible, a retry MUST resend the exact stored ciphertext (never
/// re-encrypt); `content` is the plaintext, kept so a `409 DeviceListMismatch`
/// can re-encrypt for a newly-added device. Deleted once the send is delivered.
#[derive(Clone)]
pub struct OutboxEntry {
    pub send_id: String,
    /// Recipient username (`user@domain` once federation lands).
    pub peer: String,
    /// `serde_json` of the `ChatContent` plaintext.
    pub content: Vec<u8>,
    /// `serde_json` of the per-device `Vec<OutgoingEnvelope>` ciphertexts.
    pub envelopes: Vec<u8>,
    /// Send attempts so far (bounds the 409 recovery loop).
    pub attempts: u32,
    /// Unix-epoch millis the entry was first enqueued.
    pub created_at: i64,
}

/// A unit of work. Every mutation libsignal makes during one crypto operation
/// accumulates here (last-write-wins per key) and is flushed to the [`ChatDb`] in
/// one atomic `apply`. Reads consult the pending overlay before the durable store,
/// so an operation sees its own not-yet-committed writes; a failed operation drops
/// the `Pending` and touches nothing durable.
///
/// Fields are crate-private: only the in-crate [`ChatDb`] implementations read
/// them. (When an out-of-crate store lands, it gets public accessors then.)
#[derive(Default)]
pub struct Pending {
    /// Set only when installing a freshly generated device.
    pub(crate) local_identity: Option<LocalIdentity>,
    /// address string (`name.deviceId`) → `Some(SessionRecord::serialize())`
    /// (upsert) or `None` (archive — a session dropped on a stale/extra device).
    pub(crate) sessions: HashMap<String, Option<Vec<u8>>>,
    /// address string → `IdentityKey::serialize()` (a peer's public identity).
    pub(crate) identities: HashMap<String, Vec<u8>>,
    /// one-time EC prekey id → `Some(PreKeyRecord::serialize())` (upsert) or
    /// `None` (remove — libsignal consumes a one-time prekey on receipt).
    pub(crate) pre_keys: HashMap<u32, Option<Vec<u8>>>,
    /// signed prekey id → `SignedPreKeyRecord::serialize()`.
    pub(crate) signed_pre_keys: HashMap<u32, Vec<u8>>,
    /// kyber prekey id → `KyberPreKeyRecord::serialize()`.
    pub(crate) kyber_pre_keys: HashMap<u32, Vec<u8>>,
    /// `(kyberId, ecId, baseKey)` combinations already consumed — libsignal's
    /// last-resort-prekey replay guard (a repeat is a rejected PreKey message).
    pub(crate) kyber_seen: Vec<(u32, u32, Vec<u8>)>,
    /// `(address, distributionId)` → `SenderKeyRecord::serialize()` (groups; reserved).
    pub(crate) sender_keys: HashMap<(String, String), Vec<u8>>,
    /// `sendId` → `Some(entry)` (upsert the pending send) or `None` (delivered — delete).
    pub(crate) outbox: HashMap<String, Option<OutboxEntry>>,
    /// Decrypted inbound messages to persist (insert-or-ignore by id).
    pub(crate) messages: Vec<InboxMessage>,
    /// The highest mailbox cursor processed — advanced with each message so a
    /// re-drain never re-decrypts (which the ratchet couldn't do anyway).
    pub(crate) last_cursor: Option<u64>,
}

impl Pending {
    /// Nothing staged — a crypto op that made no writes (e.g. a failed decrypt
    /// that never reached a store call). Lets `commit` short-circuit.
    pub(crate) fn is_empty(&self) -> bool {
        self.local_identity.is_none()
            && self.sessions.is_empty()
            && self.identities.is_empty()
            && self.pre_keys.is_empty()
            && self.signed_pre_keys.is_empty()
            && self.kyber_pre_keys.is_empty()
            && self.kyber_seen.is_empty()
            && self.sender_keys.is_empty()
            && self.outbox.is_empty()
            && self.messages.is_empty()
            && self.last_cursor.is_none()
    }

    pub(crate) fn clear(&mut self) {
        *self = Pending::default();
    }
}

/// The durable client store. All methods are synchronous; implementors are free
/// to be `!Send` (the engine drives one session on one thread). Object-safe by
/// design — the engine holds an `Rc<dyn ChatDb>`.
pub trait ChatDb {
    /// The installed device's identity, or `None` on a fresh store.
    fn load_local_identity(&self) -> Result<Option<LocalIdentity>>;

    /// Serialized `SessionRecord` for `address` (`name.deviceId`).
    fn load_session(&self, address: &str) -> Result<Option<Vec<u8>>>;
    /// Serialized peer `IdentityKey` for `address`.
    fn load_identity(&self, address: &str) -> Result<Option<Vec<u8>>>;
    /// Serialized one-time `PreKeyRecord` by id.
    fn load_pre_key(&self, id: u32) -> Result<Option<Vec<u8>>>;
    /// Serialized `SignedPreKeyRecord` by id.
    fn load_signed_pre_key(&self, id: u32) -> Result<Option<Vec<u8>>>;
    /// Serialized `KyberPreKeyRecord` by id.
    fn load_kyber_pre_key(&self, id: u32) -> Result<Option<Vec<u8>>>;
    /// Whether this `(kyberId, ecId, baseKey)` combination was already consumed.
    fn kyber_base_key_seen(&self, kyber_id: u32, ec_id: u32, base_key: &[u8]) -> Result<bool>;
    /// Serialized `SenderKeyRecord` for `(address, distributionId)`.
    fn load_sender_key(&self, address: &str, distribution_id: &str) -> Result<Option<Vec<u8>>>;

    /// The pending outbound send for `send_id`, if any.
    fn load_outbox(&self, send_id: &str) -> Result<Option<OutboxEntry>>;
    /// Every pending outbound send (oldest first) — for resend-on-startup.
    fn list_outbox(&self) -> Result<Vec<OutboxEntry>>;

    /// The highest mailbox cursor processed so far (the drain resume point).
    fn load_last_cursor(&self) -> Result<Option<u64>>;
    /// Every persisted inbound message (oldest first, by cursor) — the local history.
    fn list_messages(&self) -> Result<Vec<InboxMessage>>;

    /// Commit a whole unit of work atomically. Either every staged write lands or
    /// none does; a partial apply MUST NOT be observable after a crash.
    fn apply(&self, pending: &Pending) -> Result<()>;
}
