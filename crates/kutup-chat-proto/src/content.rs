//! The inner content schema — the decrypted plaintext *inside* a chat
//! envelope. See `docs/chat-protocol.md` §6.
//!
//! The server never sees this (it lives inside the libsignal ciphertext); the
//! type lives here so all three clients (web/wasm, Android, iOS) and the test
//! fixtures share one definition instead of inventing the plaintext shape
//! independently — the single biggest cross-client compatibility risk.
//!
//! Forward-compatibility is structural: `kind` is an open string and `body` is
//! an untyped JSON value, so an unknown `kind` from a newer client
//! deserializes fine and is rendered as a placeholder — never dropped. Typed
//! helpers exist for the kinds a given version understands.

use serde::{Deserialize, Serialize};

/// Reserved `kind` values. [`TEXT`] is user-visible content and
/// [`SENT_TRANSCRIPT`] is the encrypted linked-device synchronization wrapper;
/// the rest are reserved so the registry can't be re-used incompatibly. See
/// the table in `docs/chat-protocol.md` §6.
pub mod kind {
    /// A plain text message.
    pub const TEXT: &str = "text";
    /// An encrypted copy of an outgoing logical message for the sender's other
    /// devices. The server only sees ordinary libsignal ciphertext. [IMPL]
    pub const SENT_TRANSCRIPT: &str = "sentTranscript";
    /// Delivery/read receipts (E2EE content, never a server feature). [RSV]
    pub const RECEIPT: &str = "receipt";
    /// Typing indicator; ephemeral, a client MAY drop it. [RSV]
    pub const TYPING: &str = "typing";
    /// Attachment pointer into the E2EE drive (tus); the blob rides the drive,
    /// not the mailbox. [RSV] (phase 5)
    pub const ATTACHMENT: &str = "attachment";
    /// Encrypted group-state operation. [RSV] (phase 4)
    pub const GROUP_CONTROL: &str = "groupControl";
    /// Session-control notice (e.g. explicit reset). [RSV]
    pub const SESSION_CONTROL: &str = "sessionControl";
}

/// The decrypted plaintext of a chat message.
///
/// `kind` selects how `body` is interpreted; unknown kinds are preserved so a
/// UI can show "message from a newer client". Ordering is by
/// `(sender, senderDevice, seq)` within a sender, interleaved across senders by
/// `sent_at` (the SENDER clock) — never by the envelope's server timestamp
/// alone, which is arrival order and, under federation, a different clock.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatContent {
    /// Content-schema version, independent of the crypto `suite`. A reader
    /// handles any `v` ≤ the one it knows; a higher `v` degrades to a
    /// placeholder rather than an error.
    pub v: u16,
    /// One of [`kind`]; an open string so unknown kinds round-trip.
    pub kind: String,
    /// The sender's clock (RFC 3339). Distinct from the envelope's
    /// `serverTimestamp` (arrival order).
    pub sent_at: String,
    /// Per-`(sender, senderDevice)` monotonic counter → per-sender ordering.
    pub seq: u64,
    /// Kind-specific payload. Untyped so unknown kinds survive; use the typed
    /// accessors ([`ChatContent::as_text`]) for known kinds.
    pub body: serde_json::Value,
    /// Any fields a newer client added are preserved here on round-trip rather
    /// than lost, so re-serialization doesn't silently drop data.
    #[serde(flatten, default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl ChatContent {
    /// The current content-schema version.
    pub const VERSION: u16 = 1;

    /// Builds a `text` message.
    pub fn text(sent_at: impl Into<String>, seq: u64, text: impl Into<String>) -> Self {
        ChatContent {
            v: Self::VERSION,
            kind: kind::TEXT.to_string(),
            sent_at: sent_at.into(),
            seq,
            body: serde_json::to_value(TextBody { text: text.into() }).unwrap_or_default(),
            extra: serde_json::Map::new(),
        }
    }

    /// Returns the text body if this is a `text` message this reader understands.
    pub fn as_text(&self) -> Option<TextBody> {
        if self.kind == kind::TEXT {
            serde_json::from_value(self.body.clone()).ok()
        } else {
            None
        }
    }

    /// Builds the encrypted linked-device wrapper used by Note to Self and,
    /// later, ordinary sent-message synchronization.
    pub fn sent_transcript(
        send_id: impl Into<String>,
        peer: impl Into<String>,
        timestamp_ms: i64,
        content: ChatContent,
    ) -> Self {
        ChatContent {
            v: Self::VERSION,
            kind: kind::SENT_TRANSCRIPT.to_string(),
            sent_at: content.sent_at.clone(),
            seq: content.seq,
            body: serde_json::to_value(SentTranscriptBody {
                send_id: send_id.into(),
                peer: peer.into(),
                timestamp_ms,
                content: Box::new(content),
            })
            .unwrap_or_default(),
            extra: serde_json::Map::new(),
        }
    }

    /// Returns the linked-device transcript body when this reader understands
    /// it. Callers must additionally authenticate that the envelope came from
    /// another device of the local account before treating it as outgoing.
    pub fn as_sent_transcript(&self) -> Option<SentTranscriptBody> {
        if self.kind == kind::SENT_TRANSCRIPT {
            serde_json::from_value(self.body.clone()).ok()
        } else {
            None
        }
    }

    /// True when `kind` is one this build has a typed meaning for. A UI renders
    /// unknown kinds as "message from a newer client".
    pub fn is_known_kind(&self) -> bool {
        matches!(
            self.kind.as_str(),
            kind::TEXT
                | kind::SENT_TRANSCRIPT
                | kind::RECEIPT
                | kind::TYPING
                | kind::ATTACHMENT
                | kind::GROUP_CONTROL
                | kind::SESSION_CONTROL
        )
    }
}

/// Body of a `text` message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TextBody {
    pub text: String,
}

/// Plaintext nested inside a [`kind::SENT_TRANSCRIPT`] wrapper. This whole
/// structure remains E2EE; it is never interpreted by the delivery server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SentTranscriptBody {
    /// Stable logical id used to deduplicate outgoing history across devices.
    pub send_id: String,
    /// Conversation key. Note to Self uses the local username; future ordinary
    /// sent transcripts use the remote peer username.
    pub peer: String,
    /// Original local history timestamp in Unix-epoch milliseconds.
    pub timestamp_ms: i64,
    /// The actual user-visible content, not another transcript wrapper.
    pub content: Box<ChatContent>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_round_trips_with_stable_shape() {
        let c = ChatContent::text("2026-07-13T10:00:00Z", 41, "hi");
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(
            json,
            r#"{"v":1,"kind":"text","sentAt":"2026-07-13T10:00:00Z","seq":41,"body":{"text":"hi"}}"#
        );
        let back: ChatContent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.as_text().unwrap().text, "hi");
    }

    #[test]
    fn unknown_kind_is_preserved_not_dropped() {
        // A message from a hypothetical newer client.
        let src = r#"{"v":2,"kind":"reaction","sentAt":"2026-07-13T10:00:00Z","seq":7,"body":{"emoji":"👍","target":3}}"#;
        let c: ChatContent = serde_json::from_str(src).unwrap();
        assert!(!c.is_known_kind());
        assert!(c.as_text().is_none());
        // Body survives a round-trip so nothing is silently lost.
        let back = serde_json::to_value(&c).unwrap();
        assert_eq!(back["body"]["emoji"], "👍");
        assert_eq!(back["v"], 2);
    }

    #[test]
    fn unknown_top_level_fields_survive() {
        let src =
            r#"{"v":1,"kind":"text","sentAt":"t","seq":1,"body":{"text":"x"},"replyTo":"abc"}"#;
        let c: ChatContent = serde_json::from_str(src).unwrap();
        assert_eq!(c.extra.get("replyTo").and_then(|v| v.as_str()), Some("abc"));
        let back = serde_json::to_value(&c).unwrap();
        assert_eq!(back["replyTo"], "abc");
    }

    #[test]
    fn sent_transcript_round_trips_without_exposing_content_metadata() {
        let original = ChatContent::text("2026-07-16T10:00:00Z", 8, "private note");
        let wrapper = ChatContent::sent_transcript("note-1", "alice", 1234, original.clone());
        assert_eq!(wrapper.kind, kind::SENT_TRANSCRIPT);
        assert_eq!(wrapper.sent_at, original.sent_at);
        assert_eq!(wrapper.seq, original.seq);
        let body = wrapper.as_sent_transcript().unwrap();
        assert_eq!(body.send_id, "note-1");
        assert_eq!(body.peer, "alice");
        assert_eq!(body.timestamp_ms, 1234);
        assert_eq!(*body.content, original);
    }
}
