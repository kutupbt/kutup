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

/// Reserved `kind` values. Only [`TEXT`] ships in phase 2b; the rest are
/// reserved so a newer client's messages are recognized (not dropped) and the
/// registry can't be re-used incompatibly. See the table in
/// `docs/chat-protocol.md` §6.
pub mod kind {
    /// A plain text message — the only kind implemented in phase 2b.
    pub const TEXT: &str = "text";
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

    /// True when `kind` is one this build has a typed meaning for. A UI renders
    /// unknown kinds as "message from a newer client".
    pub fn is_known_kind(&self) -> bool {
        matches!(
            self.kind.as_str(),
            kind::TEXT
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
}
