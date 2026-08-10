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
use uuid::Uuid;

use crate::ChatAttachmentDescriptorV1;

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
    /// Linked-device synchronization for the local contact/request state. This
    /// is accepted only from another authenticated device of the local account
    /// and is never rendered as a chat message. [IMPL]
    pub const CONTACT_CONTROL: &str = "contactControl";
    /// Invisible profile-key distribution message. Like Signal's
    /// `PROFILE_KEY_UPDATE`, it contains no user-visible body; the key itself
    /// is the encrypted top-level [`ChatContent::profile_key`] field. [IMPL]
    pub const PROFILE_KEY_UPDATE: &str = "profileKeyUpdate";
    /// Delivery/read receipts (E2EE content, never a server feature). [IMPL]
    pub const RECEIPT: &str = "receipt";
    /// Typing indicator; ephemeral, a client MAY drop it. [IMPL]
    pub const TYPING: &str = "typing";
    /// Add/remove one bounded emoji reaction to a stable logical message. [IMPL]
    pub const REACTION: &str = "reaction";
    /// Edit or irreversibly tombstone one stable logical message. [IMPL]
    pub const MESSAGE_MUTATION: &str = "messageMutation";
    /// Attachment descriptor for the immutable encrypted Chat-media object;
    /// bytes ride the shared Drive/TUS object stack, not the mailbox. [IMPL]
    /// (phase 6; `docs/chat-media.md`)
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
    /// Stable sender-generated logical identifier. New user-visible messages
    /// use the same UUID as the durable transport `sendId`; legacy v1 content
    /// omits it and remains readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    /// Stable logical message UUID being replied to. It remains inside E2EE
    /// content and never becomes delivery or federation metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    /// The sender's current 32-byte profile key, encoded with standard base64.
    /// This field is inside the libsignal ciphertext and is harvested from
    /// normal messages as well as dedicated `profileKeyUpdate` controls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_key: Option<String>,
    /// Numeric `ProfileSuiteId` for `profileKey`. Kept as an open wire code so
    /// a newer profile suite does not make otherwise-readable message content
    /// fail to deserialize; clients accept the capability only after closed
    /// conversion through the local registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_suite: Option<u16>,
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
            message_id: None,
            reply_to: None,
            profile_key: None,
            profile_suite: None,
            body: serde_json::to_value(TextBody { text: text.into() }).unwrap_or_default(),
            extra: serde_json::Map::new(),
        }
    }

    /// Builds a new text message whose stable content id matches its logical
    /// outbox/send id. References such as receipts and reactions use this id.
    pub fn text_with_id(
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        text: impl Into<String>,
    ) -> Self {
        let mut content = Self::text(sent_at, seq, text);
        content.message_id = Some(message_id.into());
        content
    }

    /// Adds a canonical, non-nil logical message reference.
    pub fn with_reply_to(mut self, reply_to: Option<&str>) -> Result<Self, String> {
        self.reply_to = match reply_to {
            None => None,
            Some(value) => {
                let parsed = Uuid::parse_str(value)
                    .map_err(|_| "Chat reply target must be a UUID".to_string())?;
                if parsed.is_nil() || parsed.to_string() != value {
                    return Err("Chat reply target must be a canonical non-nil UUID".into());
                }
                Some(value.to_owned())
            }
        };
        Ok(self)
    }

    /// Attaches the sender's encrypted-channel profile capability.
    pub fn with_profile_key(mut self, profile_key: impl Into<String>) -> Self {
        self.profile_key = Some(profile_key.into());
        self.profile_suite = Some(crate::profile::ProfileSuiteId::XChaCha20Poly1305V1.as_u16());
        self
    }

    /// Builds an invisible Signal-style profile-key update.
    pub fn profile_key_update_with_id(
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        profile_key: impl Into<String>,
    ) -> Self {
        ChatContent {
            v: Self::VERSION,
            kind: kind::PROFILE_KEY_UPDATE.to_string(),
            sent_at: sent_at.into(),
            seq,
            message_id: Some(message_id.into()),
            reply_to: None,
            profile_key: Some(profile_key.into()),
            profile_suite: Some(crate::profile::ProfileSuiteId::XChaCha20Poly1305V1.as_u16()),
            body: serde_json::Value::Object(serde_json::Map::new()),
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

    /// Builds an attachment message whose descriptor stays inside the Direct
    /// Chat or MLS application ciphertext. The immutable blob is transferred
    /// separately through the authenticated Chat-media service.
    pub fn attachment_with_id(
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        descriptor: ChatAttachmentDescriptorV1,
    ) -> Result<Self, String> {
        descriptor.validate()?;
        Ok(ChatContent {
            v: Self::VERSION,
            kind: kind::ATTACHMENT.to_string(),
            sent_at: sent_at.into(),
            seq,
            message_id: Some(message_id.into()),
            reply_to: None,
            profile_key: None,
            profile_suite: None,
            body: serde_json::to_value(descriptor)
                .map_err(|error| format!("encode Chat attachment descriptor: {error}"))?,
            extra: serde_json::Map::new(),
        })
    }

    /// Returns only a strictly validated V1 attachment descriptor. Unknown
    /// suites and malformed metadata remain a visible unsupported message;
    /// they never authorize object retrieval.
    pub fn as_attachment(&self) -> Option<ChatAttachmentDescriptorV1> {
        if self.kind != kind::ATTACHMENT || self.v != Self::VERSION || self.message_id.is_none() {
            return None;
        }
        let descriptor: ChatAttachmentDescriptorV1 =
            serde_json::from_value(self.body.clone()).ok()?;
        descriptor.validate().ok()?;
        Some(descriptor)
    }

    pub fn reaction_with_id(
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        target_message_id: impl Into<String>,
        emoji: impl Into<String>,
        active: bool,
    ) -> Result<Self, String> {
        let body = ReactionBody {
            target_message_id: target_message_id.into(),
            emoji: emoji.into(),
            active,
        };
        body.validate()?;
        Ok(ChatContent {
            v: Self::VERSION,
            kind: kind::REACTION.to_string(),
            sent_at: sent_at.into(),
            seq,
            message_id: Some(message_id.into()),
            reply_to: None,
            profile_key: None,
            profile_suite: None,
            body: serde_json::to_value(body)
                .map_err(|error| format!("encode Chat reaction: {error}"))?,
            extra: serde_json::Map::new(),
        })
    }

    pub fn as_reaction(&self) -> Option<ReactionBody> {
        if self.kind != kind::REACTION || self.v != Self::VERSION || self.message_id.is_none() {
            return None;
        }
        let body: ReactionBody = serde_json::from_value(self.body.clone()).ok()?;
        body.validate().ok()?;
        Some(body)
    }

    pub fn message_mutation_with_id(
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        target_message_id: impl Into<String>,
        operation: MessageMutationOperation,
        replacement_text: Option<String>,
    ) -> Result<Self, String> {
        let body = MessageMutationBody {
            target_message_id: target_message_id.into(),
            operation,
            replacement_text,
        };
        body.validate()?;
        Ok(ChatContent {
            v: Self::VERSION,
            kind: kind::MESSAGE_MUTATION.to_string(),
            sent_at: sent_at.into(),
            seq,
            message_id: Some(message_id.into()),
            reply_to: None,
            profile_key: None,
            profile_suite: None,
            body: serde_json::to_value(body)
                .map_err(|error| format!("encode Chat message mutation: {error}"))?,
            extra: serde_json::Map::new(),
        })
    }

    pub fn as_message_mutation(&self) -> Option<MessageMutationBody> {
        if self.kind != kind::MESSAGE_MUTATION
            || self.v != Self::VERSION
            || self.message_id.is_none()
        {
            return None;
        }
        let body: MessageMutationBody = serde_json::from_value(self.body.clone()).ok()?;
        body.validate().ok()?;
        Some(body)
    }

    pub fn receipt_with_id(
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        message_ids: Vec<String>,
        state: ReceiptState,
    ) -> Result<Self, String> {
        let body = ReceiptBody { message_ids, state };
        body.validate()?;
        Ok(ChatContent {
            v: Self::VERSION,
            kind: kind::RECEIPT.to_string(),
            sent_at: sent_at.into(),
            seq,
            message_id: Some(message_id.into()),
            reply_to: None,
            profile_key: None,
            profile_suite: None,
            body: serde_json::to_value(body)
                .map_err(|error| format!("encode Chat receipt: {error}"))?,
            extra: serde_json::Map::new(),
        })
    }

    pub fn as_receipt(&self) -> Option<ReceiptBody> {
        if self.kind != kind::RECEIPT || self.v != Self::VERSION || self.message_id.is_none() {
            return None;
        }
        let body: ReceiptBody = serde_json::from_value(self.body.clone()).ok()?;
        body.validate().ok()?;
        Some(body)
    }

    /// Builds a hidden ephemeral typing-state operation. The transport id is
    /// retained for encrypted-mailbox idempotency only; clients must not turn
    /// this control into conversation history or a linked-device transcript.
    pub fn typing_with_id(
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        active: bool,
    ) -> Self {
        ChatContent {
            v: Self::VERSION,
            kind: kind::TYPING.to_string(),
            sent_at: sent_at.into(),
            seq,
            message_id: Some(message_id.into()),
            reply_to: None,
            profile_key: None,
            profile_suite: None,
            body: serde_json::to_value(TypingBody { active }).unwrap_or_default(),
            extra: serde_json::Map::new(),
        }
    }

    pub fn as_typing(&self) -> Option<TypingBody> {
        if self.kind != kind::TYPING || self.v != Self::VERSION || self.message_id.is_none() {
            return None;
        }
        serde_json::from_value(self.body.clone()).ok()
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
            message_id: content.message_id.clone(),
            reply_to: content.reply_to.clone(),
            profile_key: content.profile_key.clone(),
            profile_suite: content.profile_suite,
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

    /// Builds an encrypted linked-device contact-state update. The content is
    /// wrapped in a [`kind::SENT_TRANSCRIPT`] by the sender's sync path, so the
    /// receiving client can require an authenticated local-account sender.
    pub fn contact_control_with_id(
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        body: ContactControlBody,
    ) -> Self {
        ChatContent {
            v: Self::VERSION,
            kind: kind::CONTACT_CONTROL.to_string(),
            sent_at: sent_at.into(),
            seq,
            message_id: Some(message_id.into()),
            reply_to: None,
            profile_key: None,
            profile_suite: None,
            body: serde_json::to_value(body).unwrap_or_default(),
            extra: serde_json::Map::new(),
        }
    }

    pub fn as_contact_control(&self) -> Option<ContactControlBody> {
        if self.kind == kind::CONTACT_CONTROL {
            serde_json::from_value(self.body.clone()).ok()
        } else {
            None
        }
    }

    /// True when `kind` is one this build has a typed meaning for. A UI renders
    /// unknown kinds as "message from a newer client".
    pub fn is_known_kind(&self) -> bool {
        self.v == Self::VERSION
            && matches!(
                self.kind.as_str(),
                kind::TEXT
                    | kind::SENT_TRANSCRIPT
                    | kind::CONTACT_CONTROL
                    | kind::PROFILE_KEY_UPDATE
                    | kind::RECEIPT
                    | kind::TYPING
                    | kind::REACTION
                    | kind::MESSAGE_MUTATION
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

pub const CHAT_REACTION_EMOJIS_V1: [&str; 6] = ["👍", "❤️", "😂", "😮", "😢", "🙏"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReactionBody {
    pub target_message_id: String,
    pub emoji: String,
    pub active: bool,
}

impl ReactionBody {
    pub fn validate(&self) -> Result<(), String> {
        let target = Uuid::parse_str(&self.target_message_id)
            .map_err(|_| "Chat reaction target must be a UUID".to_string())?;
        if target.is_nil() || target.to_string() != self.target_message_id {
            return Err("Chat reaction target must be a canonical non-nil UUID".into());
        }
        if !CHAT_REACTION_EMOJIS_V1.contains(&self.emoji.as_str()) {
            return Err("Chat reaction emoji is not in the V1 set".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MessageMutationOperation {
    Edit,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MessageMutationBody {
    pub target_message_id: String,
    pub operation: MessageMutationOperation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_text: Option<String>,
}

impl MessageMutationBody {
    pub fn validate(&self) -> Result<(), String> {
        let target = Uuid::parse_str(&self.target_message_id)
            .map_err(|_| "Chat message-mutation target must be a UUID".to_string())?;
        if target.is_nil() || target.to_string() != self.target_message_id {
            return Err("Chat message-mutation target must be a canonical non-nil UUID".into());
        }
        match (&self.operation, &self.replacement_text) {
            (MessageMutationOperation::Edit, Some(text))
                if !text.trim().is_empty() && text.chars().count() <= 16_000 =>
            {
                Ok(())
            }
            (MessageMutationOperation::Edit, _) => {
                Err("Chat edit text must contain 1 to 16000 characters".into())
            }
            (MessageMutationOperation::Delete, None) => Ok(()),
            (MessageMutationOperation::Delete, Some(_)) => {
                Err("Chat delete must not contain replacement text".into())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReceiptState {
    Delivered,
    Read,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptBody {
    pub message_ids: Vec<String>,
    pub state: ReceiptState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TypingBody {
    pub active: bool,
}

impl ReceiptBody {
    pub fn validate(&self) -> Result<(), String> {
        if self.message_ids.is_empty() || self.message_ids.len() > 64 {
            return Err("Chat receipt must contain 1 to 64 message IDs".into());
        }
        let mut unique = std::collections::BTreeSet::new();
        for message_id in &self.message_ids {
            let parsed = Uuid::parse_str(message_id)
                .map_err(|_| "Chat receipt message ID must be a UUID".to_string())?;
            if parsed.is_nil() || parsed.to_string() != *message_id || !unique.insert(message_id) {
                return Err(
                    "Chat receipt message IDs must be unique canonical non-nil UUIDs".into(),
                );
            }
        }
        Ok(())
    }
}

/// Local relationship state for one canonical account. Absence means the peer
/// has never been observed. These values are client state, not server routing
/// policy; linked devices exchange them only inside authenticated E2EE control
/// messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ContactState {
    PendingIncoming,
    PendingOutgoing,
    Accepted,
    Rejected,
    Blocked,
}

/// Convergent linked-device contact update. `revision` is incremented from the
/// highest record a device has observed; concurrent equal revisions tie-break
/// by `source_device_id`, so every linked device reaches the same result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactControlBody {
    pub peer: String,
    pub state: ContactState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_state: Option<ContactState>,
    pub revision: u64,
    pub source_device_id: u32,
    pub updated_at_ms: i64,
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
    fn new_text_carries_the_transport_id_inside_ciphertext() {
        let content = ChatContent::text_with_id(
            "018f8ad5-d7db-7c7c-8c4b-4f53467f4431",
            "2026-07-13T10:00:00Z",
            41,
            "hi",
        );
        let value = serde_json::to_value(content).unwrap();
        assert_eq!(value["messageId"], "018f8ad5-d7db-7c7c-8c4b-4f53467f4431");
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
            r#"{"v":1,"kind":"text","sentAt":"t","seq":1,"body":{"text":"x"},"futureField":"abc"}"#;
        let c: ChatContent = serde_json::from_str(src).unwrap();
        assert_eq!(
            c.extra.get("futureField").and_then(|v| v.as_str()),
            Some("abc")
        );
        let back = serde_json::to_value(&c).unwrap();
        assert_eq!(back["futureField"], "abc");
    }

    #[test]
    fn reply_reference_is_canonical_and_round_trips_inside_content() {
        let target = "018f8ad5-d7db-7c7c-8c4b-4f53467f4431";
        let content = ChatContent::text_with_id(
            "018f8ad5-d7db-7c7c-8c4b-4f53467f4432",
            "2026-07-13T10:00:00Z",
            42,
            "reply",
        )
        .with_reply_to(Some(target))
        .unwrap();
        let value = serde_json::to_value(&content).unwrap();
        assert_eq!(value["replyTo"], target);
        assert!(ChatContent::text("t", 1, "x")
            .with_reply_to(Some("not-a-uuid"))
            .is_err());
    }

    #[test]
    fn reaction_is_bounded_typed_and_round_trips() {
        let target = "018f8ad5-d7db-7c7c-8c4b-4f53467f4431";
        let content = ChatContent::reaction_with_id(
            "018f8ad5-d7db-7c7c-8c4b-4f53467f4432",
            "2026-07-13T10:00:00Z",
            43,
            target,
            "👍",
            true,
        )
        .unwrap();
        assert_eq!(content.as_reaction().unwrap().target_message_id, target);
        assert!(ChatContent::reaction_with_id(
            "018f8ad5-d7db-7c7c-8c4b-4f53467f4432",
            "t",
            1,
            target,
            "🔥",
            true,
        )
        .is_err());
    }

    #[test]
    fn message_mutation_is_typed_and_strict() {
        let target = "018f8ad5-d7db-7c7c-8c4b-4f53467f4431";
        let edit = ChatContent::message_mutation_with_id(
            "018f8ad5-d7db-7c7c-8c4b-4f53467f4432",
            "2026-08-10T10:00:00Z",
            44,
            target,
            MessageMutationOperation::Edit,
            Some("corrected".into()),
        )
        .unwrap();
        assert_eq!(
            edit.as_message_mutation()
                .unwrap()
                .replacement_text
                .as_deref(),
            Some("corrected")
        );
        assert!(ChatContent::message_mutation_with_id(
            "018f8ad5-d7db-7c7c-8c4b-4f53467f4432",
            "t",
            1,
            target,
            MessageMutationOperation::Delete,
            Some("forbidden".into()),
        )
        .is_err());
    }

    #[test]
    fn receipt_is_bounded_unique_and_typed() {
        let target = "018f8ad5-d7db-7c7c-8c4b-4f53467f4431";
        let receipt = ChatContent::receipt_with_id(
            "018f8ad5-d7db-7c7c-8c4b-4f53467f4432",
            "2026-08-10T11:00:00Z",
            45,
            vec![target.into()],
            ReceiptState::Read,
        )
        .unwrap();
        assert_eq!(receipt.as_receipt().unwrap().message_ids, [target]);
        assert!(ChatContent::receipt_with_id(
            "018f8ad5-d7db-7c7c-8c4b-4f53467f4432",
            "t",
            1,
            vec![target.into(), target.into()],
            ReceiptState::Delivered,
        )
        .is_err());
    }

    #[test]
    fn typing_is_strict_typed_ephemeral_content() {
        let typing = ChatContent::typing_with_id(
            "018f8ad5-d7db-7c7c-8c4b-4f53467f4432",
            "2026-08-10T11:00:00Z",
            46,
            true,
        );
        assert_eq!(typing.as_typing(), Some(TypingBody { active: true }));

        let mut malformed = typing;
        malformed.body["future"] = serde_json::json!(true);
        assert_eq!(malformed.as_typing(), None);
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

    #[test]
    fn contact_control_round_trips_as_a_known_non_rendered_kind() {
        let body = ContactControlBody {
            peer: "bob@example.org".into(),
            state: ContactState::Blocked,
            previous_state: Some(ContactState::Accepted),
            revision: 4,
            source_device_id: 2,
            updated_at_ms: 1234,
        };
        let content = ChatContent::contact_control_with_id(
            "contact-4-2",
            "2026-07-16T10:00:00Z",
            8,
            body.clone(),
        );
        assert!(content.is_known_kind());
        assert_eq!(content.as_contact_control(), Some(body));
        assert_eq!(content.as_text(), None);
    }

    #[test]
    fn profile_key_update_is_known_and_keeps_the_capability_inside_content() {
        let content = ChatContent::profile_key_update_with_id(
            "profile-1",
            "2026-07-16T10:00:00Z",
            9,
            "cHJvZmlsZS1rZXk=",
        );
        let value = serde_json::to_value(&content).unwrap();
        assert!(content.is_known_kind());
        assert_eq!(content.kind, kind::PROFILE_KEY_UPDATE);
        assert_eq!(value["profileKey"], "cHJvZmlsZS1rZXk=");
        assert_eq!(value["profileSuite"], 1);
        assert_eq!(value["body"], serde_json::json!({}));
        assert_eq!(content.as_text(), None);
    }
}
