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

use crate::{ChatAttachmentDescriptorV1, ConversationId};

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
    /// Conversation-wide disappearing-message timer update. The effective
    /// duration is repeated on each visible message so delivery races cannot
    /// change that message's authenticated expiry. [IMPL]
    pub const DISAPPEARING_TIMER: &str = "disappearingTimer";
    /// Same-account linked-device synchronization for the recipient's first
    /// view of one disappearing message. [IMPL]
    pub const DISAPPEARING_EXPIRY_START: &str = "disappearingExpiryStart";
    /// Same-account linked-device synchronization of one conversation's
    /// list state: pinned, archived, muted, marked unread. [IMPL]
    pub const CONVERSATION_STATE: &str = "conversationState";
    /// Same-account linked-device synchronization of how far one conversation
    /// has been read. [IMPL]
    pub const READ_POSITION: &str = "readPosition";
    /// Same-account linked-device removal of messages from this account's
    /// own history only ("delete for me"). [IMPL]
    pub const DELETE_FOR_ME: &str = "deleteForMe";
    /// Same-account linked-device record that a view-once photo or video was
    /// opened: it is removed on every device and a "Viewed" stands in. [IMPL]
    pub const VIEW_ONCE_OPENED: &str = "viewOnceOpened";
    /// Same-account linked-device sticker collection: one sticker saved
    /// (its small image inline) or removed. [IMPL]
    pub const STICKER_SAVED: &str = "stickerSaved";
    pub const STICKER_REMOVED: &str = "stickerRemoved";
    /// Set/remove one bounded emoji reaction per account on a stable logical message. [IMPL]
    pub const REACTION: &str = "reaction";
    /// A poll: question and options (visible). [IMPL]
    pub const POLL: &str = "poll";
    /// One member's current choice in a poll. [IMPL]
    pub const POLL_VOTE: &str = "pollVote";
    /// The poll's author ends it. [IMPL]
    pub const POLL_TERMINATE: &str = "pollTerminate";
    /// Edit or irreversibly tombstone one stable logical message. [IMPL]
    pub const MESSAGE_MUTATION: &str = "messageMutation";
    /// Attachment descriptor for the immutable encrypted Chat-media object;
    /// bytes ride the shared Drive/TUS object stack, not the mailbox. [IMPL]
    /// (phase 6; `docs/chat-media.md`)
    pub const ATTACHMENT: &str = "attachment";
    /// Encrypted group-state operation. [RSV] (phase 4)
    pub const GROUP_CONTROL: &str = "groupControl";
    /// A timeline notice of an applied group change ("Alice renamed the
    /// group"). Written only by the local engine from an authenticated,
    /// ordered MLS Commit; never sent, and refused if it ever arrives. [IMPL]
    pub const GROUP_UPDATE: &str = "groupUpdate";
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
    /// Shorter timers are too easy to lose to delivery/UI scheduling; longer
    /// timers belong in ordinary retained history rather than this V1 feature.
    pub const MIN_DISAPPEARING_SECONDS: u32 = 30;
    pub const MAX_DISAPPEARING_SECONDS: u32 = 30 * 24 * 60 * 60;
    const DISAPPEARING_AFTER_FIELD: &'static str = "expiresAfterSeconds";

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

    /// Authenticates one visible message's expiry duration independently of
    /// whatever timer controls arrive before or after it.
    pub fn with_disappearing_after(mut self, seconds: u32) -> Result<Self, String> {
        if !matches!(
            self.kind.as_str(),
            kind::TEXT | kind::ATTACHMENT | kind::POLL
        ) {
            return Err("only visible Chat messages may disappear".into());
        }
        validate_disappearing_seconds(seconds)?;
        self.extra.insert(
            Self::DISAPPEARING_AFTER_FIELD.into(),
            serde_json::Value::Number(seconds.into()),
        );
        Ok(self)
    }

    /// Returns the authenticated per-message duration. An invalid standardized
    /// field fails closed instead of silently turning a disappearing message
    /// into retained history.
    pub fn disappearing_after_seconds(&self) -> Result<Option<u32>, String> {
        let Some(value) = self.extra.get(Self::DISAPPEARING_AFTER_FIELD) else {
            return Ok(None);
        };
        if !matches!(
            self.kind.as_str(),
            kind::TEXT | kind::ATTACHMENT | kind::POLL
        ) {
            return Err("only visible Chat messages may carry an expiry".into());
        }
        let seconds = value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| "Chat disappearing duration must be an integer".to_string())?;
        validate_disappearing_seconds(seconds)?;
        Ok(Some(seconds))
    }

    pub fn disappearing_timer_with_id(
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        duration_seconds: Option<u32>,
    ) -> Result<Self, String> {
        let body = DisappearingTimerBody { duration_seconds };
        body.validate()?;
        Ok(ChatContent {
            v: Self::VERSION,
            kind: kind::DISAPPEARING_TIMER.to_string(),
            sent_at: sent_at.into(),
            seq,
            message_id: Some(message_id.into()),
            reply_to: None,
            profile_key: None,
            profile_suite: None,
            body: serde_json::to_value(body)
                .map_err(|error| format!("encode Chat disappearing timer: {error}"))?,
            extra: serde_json::Map::new(),
        })
    }

    pub fn as_disappearing_timer(&self) -> Option<DisappearingTimerBody> {
        if self.kind != kind::DISAPPEARING_TIMER
            || self.v != Self::VERSION
            || self.message_id.is_none()
        {
            return None;
        }
        let body: DisappearingTimerBody = serde_json::from_value(self.body.clone()).ok()?;
        body.validate().ok()?;
        Some(body)
    }

    pub fn disappearing_expiry_start_with_id(
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        conversation: ConversationId,
        target_message_id: impl Into<String>,
        started_at_ms: i64,
    ) -> Result<Self, String> {
        let body = DisappearingExpiryStartBody {
            conversation,
            target_message_id: target_message_id.into(),
            started_at_ms,
        };
        body.validate()?;
        Ok(ChatContent {
            v: Self::VERSION,
            kind: kind::DISAPPEARING_EXPIRY_START.to_string(),
            sent_at: sent_at.into(),
            seq,
            message_id: Some(message_id.into()),
            reply_to: None,
            profile_key: None,
            profile_suite: None,
            body: serde_json::to_value(body)
                .map_err(|error| format!("encode Chat disappearing expiry start: {error}"))?,
            extra: serde_json::Map::new(),
        })
    }

    pub fn as_disappearing_expiry_start(&self) -> Option<DisappearingExpiryStartBody> {
        if self.kind != kind::DISAPPEARING_EXPIRY_START
            || self.v != Self::VERSION
            || self.message_id.is_none()
        {
            return None;
        }
        let body: DisappearingExpiryStartBody = serde_json::from_value(self.body.clone()).ok()?;
        body.validate().ok()?;
        Some(body)
    }

    /// Builds a same-account control. These travel only to the local
    /// account's other devices, inside a [`kind::SENT_TRANSCRIPT`].
    fn account_control<T: Serialize>(
        kind: &str,
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        body: &T,
    ) -> Result<Self, String> {
        Ok(ChatContent {
            v: Self::VERSION,
            kind: kind.to_string(),
            sent_at: sent_at.into(),
            seq,
            message_id: Some(message_id.into()),
            reply_to: None,
            profile_key: None,
            profile_suite: None,
            body: serde_json::to_value(body)
                .map_err(|error| format!("encode Chat {kind}: {error}"))?,
            extra: serde_json::Map::new(),
        })
    }

    fn as_account_control<T: serde::de::DeserializeOwned>(&self, kind: &str) -> Option<T> {
        if self.kind != kind || self.v != Self::VERSION || self.message_id.is_none() {
            return None;
        }
        serde_json::from_value(self.body.clone()).ok()
    }

    pub fn conversation_state_with_id(
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        body: ConversationStateBody,
    ) -> Result<Self, String> {
        body.validate()?;
        Self::account_control(kind::CONVERSATION_STATE, message_id, sent_at, seq, &body)
    }

    pub fn as_conversation_state(&self) -> Option<ConversationStateBody> {
        let body: ConversationStateBody = self.as_account_control(kind::CONVERSATION_STATE)?;
        body.validate().ok()?;
        Some(body)
    }

    pub fn read_position_with_id(
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        body: ReadPositionBody,
    ) -> Result<Self, String> {
        body.validate()?;
        Self::account_control(kind::READ_POSITION, message_id, sent_at, seq, &body)
    }

    pub fn as_read_position(&self) -> Option<ReadPositionBody> {
        let body: ReadPositionBody = self.as_account_control(kind::READ_POSITION)?;
        body.validate().ok()?;
        Some(body)
    }

    pub fn delete_for_me_with_id(
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        body: DeleteForMeBody,
    ) -> Result<Self, String> {
        body.validate()?;
        Self::account_control(kind::DELETE_FOR_ME, message_id, sent_at, seq, &body)
    }

    pub fn as_delete_for_me(&self) -> Option<DeleteForMeBody> {
        let body: DeleteForMeBody = self.as_account_control(kind::DELETE_FOR_ME)?;
        body.validate().ok()?;
        Some(body)
    }

    pub fn view_once_opened_with_id(
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        body: ViewOnceOpenedBody,
    ) -> Result<Self, String> {
        body.validate()?;
        Self::account_control(kind::VIEW_ONCE_OPENED, message_id, sent_at, seq, &body)
    }

    pub fn as_view_once_opened(&self) -> Option<ViewOnceOpenedBody> {
        let body: ViewOnceOpenedBody = self.as_account_control(kind::VIEW_ONCE_OPENED)?;
        body.validate().ok()?;
        Some(body)
    }

    pub fn sticker_saved_with_id(
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        body: StickerSavedBody,
    ) -> Result<Self, String> {
        body.validate()?;
        Self::account_control(kind::STICKER_SAVED, message_id, sent_at, seq, &body)
    }

    pub fn as_sticker_saved(&self) -> Option<StickerSavedBody> {
        let body: StickerSavedBody = self.as_account_control(kind::STICKER_SAVED)?;
        body.validate().ok()?;
        Some(body)
    }

    pub fn sticker_removed_with_id(
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        body: StickerRemovedBody,
    ) -> Result<Self, String> {
        validate_message_id(&body.sticker_id, "sticker")?;
        Self::account_control(kind::STICKER_REMOVED, message_id, sent_at, seq, &body)
    }

    pub fn as_sticker_removed(&self) -> Option<StickerRemovedBody> {
        let body: StickerRemovedBody = self.as_account_control(kind::STICKER_REMOVED)?;
        validate_message_id(&body.sticker_id, "sticker").ok()?;
        Some(body)
    }

    /// True for the same-account controls ([`kind::CONVERSATION_STATE`],
    /// [`kind::READ_POSITION`], [`kind::DELETE_FOR_ME`],
    /// [`kind::DISAPPEARING_EXPIRY_START`]): accepted only from another
    /// device of the local account and never sent to anyone else.
    pub fn is_account_control_kind(kind: &str) -> bool {
        matches!(
            kind,
            kind::CONVERSATION_STATE
                | kind::READ_POSITION
                | kind::DELETE_FOR_ME
                | kind::VIEW_ONCE_OPENED
                | kind::STICKER_SAVED
                | kind::STICKER_REMOVED
                | kind::DISAPPEARING_EXPIRY_START
        )
    }

    /// For a same-account control kind: whether the typed body is valid.
    /// `None` for any other kind.
    pub fn account_control_is_valid(&self) -> Option<bool> {
        match self.kind.as_str() {
            kind::CONVERSATION_STATE => Some(self.as_conversation_state().is_some()),
            kind::READ_POSITION => Some(self.as_read_position().is_some()),
            kind::DELETE_FOR_ME => Some(self.as_delete_for_me().is_some()),
            kind::VIEW_ONCE_OPENED => Some(self.as_view_once_opened().is_some()),
            kind::STICKER_SAVED => Some(self.as_sticker_saved().is_some()),
            kind::STICKER_REMOVED => Some(self.as_sticker_removed().is_some()),
            kind::DISAPPEARING_EXPIRY_START => Some(self.as_disappearing_expiry_start().is_some()),
            _ => None,
        }
    }

    /// Kinds only this device's engine writes; they never travel.
    pub fn is_local_only_kind(kind: &str) -> bool {
        kind == kind::GROUP_UPDATE
    }

    pub fn group_update_with_id(
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        body: &GroupUpdateBody,
    ) -> Result<Self, String> {
        Self::account_control(kind::GROUP_UPDATE, message_id, sent_at, 0, body)
    }

    pub fn as_group_update(&self) -> Option<GroupUpdateBody> {
        self.as_account_control(kind::GROUP_UPDATE)
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
                    | kind::DISAPPEARING_TIMER
                    | kind::DISAPPEARING_EXPIRY_START
                    | kind::CONVERSATION_STATE
                    | kind::READ_POSITION
                    | kind::DELETE_FOR_ME
                    | kind::VIEW_ONCE_OPENED
                    | kind::STICKER_SAVED
                    | kind::STICKER_REMOVED
                    | kind::REACTION
                    | kind::POLL
                    | kind::POLL_VOTE
                    | kind::POLL_TERMINATE
                    | kind::MESSAGE_MUTATION
                    | kind::ATTACHMENT
                    | kind::GROUP_CONTROL
                    | kind::GROUP_UPDATE
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisappearingTimerBody {
    /// `None` disables the timer for future messages. Already-authenticated
    /// messages retain their own duration and cannot be resurrected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisappearingExpiryStartBody {
    pub conversation: ConversationId,
    pub target_message_id: String,
    pub started_at_ms: i64,
}

impl DisappearingExpiryStartBody {
    pub fn validate(&self) -> Result<(), String> {
        validate_control_conversation(&self.conversation, "expiry-start")?;
        validate_message_id(&self.target_message_id, "expiry-start target")?;
        if self.started_at_ms <= 0 {
            return Err("Chat expiry-start clock must be positive".into());
        }
        Ok(())
    }
}

fn validate_control_conversation(conversation: &ConversationId, what: &str) -> Result<(), String> {
    match conversation {
        ConversationId::Direct { address } => {
            let canonical = address.canonical();
            let reparsed: crate::AccountAddress = canonical
                .parse()
                .map_err(|_| format!("Chat {what} conversation is invalid"))?;
            if &reparsed != address {
                return Err(format!("Chat {what} conversation is not canonical"));
            }
        }
        ConversationId::Group { group_id } => {
            let parsed = Uuid::parse_str(group_id)
                .map_err(|_| format!("Chat {what} group must be a UUID"))?;
            if parsed.is_nil() || parsed.to_string() != *group_id {
                return Err(format!(
                    "Chat {what} group must be a canonical non-nil UUID"
                ));
            }
        }
    }
    Ok(())
}

fn validate_message_id(message_id: &str, what: &str) -> Result<(), String> {
    let parsed = Uuid::parse_str(message_id).map_err(|_| format!("Chat {what} must be a UUID"))?;
    if parsed.is_nil() || parsed.to_string() != message_id {
        return Err(format!("Chat {what} must be a canonical non-nil UUID"));
    }
    Ok(())
}

/// The largest integer a JavaScript client holds exactly; "muted forever"
/// is this value, as in Signal Desktop.
pub const MAX_SAFE_CLOCK_MS: i64 = (1 << 53) - 1;

/// One conversation's list state on this account, replaced as a whole.
/// `revision` is one more than the highest this device has seen for the
/// conversation; equal revisions from two devices tie-break by
/// `source_device_id`, so every device converges on the same record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversationStateBody {
    pub conversation: ConversationId,
    pub revision: u32,
    pub source_device_id: u32,
    pub updated_at_ms: i64,
    #[serde(default)]
    pub pinned: bool,
    #[serde(default)]
    pub archived: bool,
    /// Notifications are off until this time; [`MAX_SAFE_CLOCK_MS`] means
    /// until turned back on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub muted_until_ms: Option<i64>,
    #[serde(default)]
    pub marked_unread: bool,
}

impl ConversationStateBody {
    pub fn validate(&self) -> Result<(), String> {
        validate_control_conversation(&self.conversation, "conversation-state")?;
        if self.revision == 0 || self.source_device_id == 0 {
            return Err("Chat conversation-state revision and device must be positive".into());
        }
        if self.updated_at_ms <= 0 || self.updated_at_ms > MAX_SAFE_CLOCK_MS {
            return Err("Chat conversation-state clock is out of range".into());
        }
        if self
            .muted_until_ms
            .is_some_and(|until| until <= 0 || until > MAX_SAFE_CLOCK_MS)
        {
            return Err("Chat conversation-state mute deadline is out of range".into());
        }
        Ok(())
    }

    /// Convergent order: the record that sorts last wins.
    pub fn order(&self) -> (u32, u32) {
        (self.revision, self.source_device_id)
    }
}

/// Everything in `conversation` up to and including `through_message_id`
/// has been read on one of this account's devices. The message is the
/// anchor because each device orders by its own arrival time;
/// `read_through_ms` (the reading device's clock for that message) places the
/// position when the anchor is missing here (not arrived yet, or deleted).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadPositionBody {
    pub conversation: ConversationId,
    pub through_message_id: String,
    pub read_through_ms: i64,
}

impl ReadPositionBody {
    pub fn validate(&self) -> Result<(), String> {
        validate_control_conversation(&self.conversation, "read-position")?;
        validate_message_id(&self.through_message_id, "read-position anchor")?;
        if self.read_through_ms <= 0 || self.read_through_ms > MAX_SAFE_CLOCK_MS {
            return Err("Chat read-position clock is out of range".into());
        }
        Ok(())
    }
}

/// One visible change an applied group Commit made. Members are canonical
/// account addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type", deny_unknown_fields)]
pub enum GroupUpdateChange {
    #[serde(rename_all = "camelCase")]
    NameChanged {
        name: String,
    },
    /// Empty when the description was removed.
    #[serde(rename_all = "camelCase")]
    DescriptionChanged {
        description: String,
    },
    #[serde(rename_all = "camelCase")]
    PictureChanged {
        removed: bool,
    },
    #[serde(rename_all = "camelCase")]
    MemberAdded {
        member: String,
    },
    #[serde(rename_all = "camelCase")]
    MemberRemoved {
        member: String,
    },
    /// A removal the member asked for.
    #[serde(rename_all = "camelCase")]
    MemberLeft {
        member: String,
    },
    #[serde(rename_all = "camelCase")]
    AdminGranted {
        member: String,
    },
    #[serde(rename_all = "camelCase")]
    AdminRevoked {
        member: String,
    },
    #[serde(rename_all = "camelCase")]
    OwnerAdded {
        member: String,
    },
    #[serde(rename_all = "camelCase")]
    OwnerRemoved {
        member: String,
    },
    #[serde(rename_all = "camelCase")]
    SendersChanged {
        administrators_only: bool,
    },
    #[serde(rename_all = "camelCase")]
    EditorsChanged {
        administrators_only: bool,
    },
    Closed,
}

/// Who made an applied group change, and what it changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupUpdateBody {
    pub actor: String,
    pub changes: Vec<GroupUpdateChange>,
}

/// A sticker in this account's collection: its id, the emoji it stands for,
/// and the image (WebP or PNG, at most 48 KiB, inline so it syncs and is
/// backed up with the account's other state).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StickerSavedBody {
    pub sticker_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub emoji: String,
    pub content_type: String,
    /// Standard base64.
    pub data: String,
}

impl StickerSavedBody {
    pub const MAX_IMAGE_BYTES: usize = 48 * 1024;

    pub fn validate(&self) -> Result<(), String> {
        use base64::Engine as _;
        validate_message_id(&self.sticker_id, "sticker")?;
        if self.emoji.chars().count() > 8 || self.emoji.chars().any(char::is_control) {
            return Err("a Chat sticker emoji is at most 8 characters".into());
        }
        if !matches!(self.content_type.as_str(), "image/webp" | "image/png") {
            return Err("a Chat sticker is a WebP or PNG image".into());
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.data)
            .map_err(|_| "a Chat sticker image must be base64".to_string())?;
        if bytes.is_empty()
            || bytes.len() > Self::MAX_IMAGE_BYTES
            || base64::engine::general_purpose::STANDARD.encode(&bytes) != self.data
        {
            return Err("a Chat sticker image is at most 48 KiB of canonical base64".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StickerRemovedBody {
    pub sticker_id: String,
}

/// A view-once photo or video was opened on one of this account's devices.
/// Like a delete-for-me of `message_id`, plus what the "Viewed" placeholder
/// shows in its place: who sent it, when (the opening device's clock), and
/// whether it was a photo or a video.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ViewOnceOpenedBody {
    pub conversation: ConversationId,
    pub message_id: String,
    /// Canonical address of the sender.
    pub sender: String,
    pub timestamp_ms: i64,
    pub video: bool,
}

impl ViewOnceOpenedBody {
    pub fn validate(&self) -> Result<(), String> {
        validate_control_conversation(&self.conversation, "view-once")?;
        validate_message_id(&self.message_id, "view-once message")?;
        let sender: crate::AccountAddress = self
            .sender
            .parse()
            .map_err(|_| "Chat view-once sender is invalid".to_string())?;
        if sender.server.is_none() || sender.canonical() != self.sender {
            return Err("Chat view-once sender must be canonical".into());
        }
        if self.timestamp_ms <= 0 || self.timestamp_ms > MAX_SAFE_CLOCK_MS {
            return Err("Chat view-once clock is out of range".into());
        }
        Ok(())
    }
}

/// Remove these messages from this account's history on every one of its
/// devices. Nobody else's copy changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteForMeBody {
    pub conversation: ConversationId,
    pub message_ids: Vec<String>,
}

impl DeleteForMeBody {
    pub const MAX_MESSAGES: usize = 64;

    pub fn validate(&self) -> Result<(), String> {
        validate_control_conversation(&self.conversation, "delete-for-me")?;
        if self.message_ids.is_empty() || self.message_ids.len() > Self::MAX_MESSAGES {
            return Err("Chat delete-for-me must name 1 to 64 messages".into());
        }
        let mut unique = std::collections::BTreeSet::new();
        for message_id in &self.message_ids {
            validate_message_id(message_id, "delete-for-me message")?;
            if !unique.insert(message_id) {
                return Err("Chat delete-for-me messages must be unique".into());
            }
        }
        Ok(())
    }
}

impl DisappearingTimerBody {
    pub fn validate(&self) -> Result<(), String> {
        match self.duration_seconds {
            Some(seconds) => validate_disappearing_seconds(seconds),
            None => Ok(()),
        }
    }
}

fn validate_disappearing_seconds(seconds: u32) -> Result<(), String> {
    if (ChatContent::MIN_DISAPPEARING_SECONDS..=ChatContent::MAX_DISAPPEARING_SECONDS)
        .contains(&seconds)
    {
        Ok(())
    } else {
        Err("Chat disappearing duration must be between 30 seconds and 30 days".into())
    }
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
    fn disappearing_timer_and_per_message_duration_are_strict_and_authenticated() {
        let timer = ChatContent::disappearing_timer_with_id(
            "018f8ad5-d7db-7c7c-8c4b-4f53467f4432",
            "2026-08-10T11:00:00Z",
            47,
            Some(86_400),
        )
        .unwrap();
        assert_eq!(
            timer.as_disappearing_timer(),
            Some(DisappearingTimerBody {
                duration_seconds: Some(86_400),
            })
        );
        assert!(timer.is_known_kind());

        let message = ChatContent::text_with_id(
            "018f8ad5-d7db-7c7c-8c4b-4f53467f4433",
            "2026-08-10T11:00:01Z",
            48,
            "temporary",
        )
        .with_disappearing_after(86_400)
        .unwrap();
        let value = serde_json::to_value(&message).unwrap();
        assert_eq!(value["expiresAfterSeconds"], 86_400);
        assert_eq!(message.disappearing_after_seconds().unwrap(), Some(86_400));

        assert!(ChatContent::text("t", 1, "too short")
            .with_disappearing_after(29)
            .is_err());
        assert!(ChatContent::typing_with_id("id", "t", 1, true)
            .with_disappearing_after(60)
            .is_err());
        assert!(ChatContent::disappearing_timer_with_id("id", "t", 1, Some(0)).is_err());
        assert_eq!(
            ChatContent::disappearing_timer_with_id("id", "t", 1, None)
                .unwrap()
                .as_disappearing_timer(),
            Some(DisappearingTimerBody {
                duration_seconds: None,
            })
        );

        let mut malformed = message;
        malformed
            .extra
            .insert("expiresAfterSeconds".into(), serde_json::json!(2_592_001));
        assert!(malformed.disappearing_after_seconds().is_err());

        let conversation = ConversationId::Group {
            group_id: "11111111-1111-4111-8111-111111111111".into(),
        };
        let start = ChatContent::disappearing_expiry_start_with_id(
            "22222222-2222-4222-8222-222222222222",
            "2026-08-10T11:00:01Z",
            49,
            conversation.clone(),
            "33333333-3333-4333-8333-333333333333",
            1_775_992_401_000,
        )
        .unwrap();
        assert_eq!(
            start.as_disappearing_expiry_start(),
            Some(DisappearingExpiryStartBody {
                conversation,
                target_message_id: "33333333-3333-4333-8333-333333333333".into(),
                started_at_ms: 1_775_992_401_000,
            })
        );
        assert!(start.is_known_kind());
        assert!(ChatContent::disappearing_expiry_start_with_id(
            "22222222-2222-4222-8222-222222222222",
            "t",
            1,
            ConversationId::Group {
                group_id: "not-a-group".into(),
            },
            "33333333-3333-4333-8333-333333333333",
            1,
        )
        .is_err());
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

    const MESSAGE: &str = "0b0f6a8e-35f5-4a8e-9f5a-0a8f3c2d1e4b";
    const OTHER: &str = "6c1d7e2f-9a3b-4c5d-8e7f-1a2b3c4d5e6f";

    fn direct(address: &str) -> ConversationId {
        ConversationId::direct(address.parse().unwrap())
    }

    #[test]
    fn conversation_state_round_trips_and_bounds_its_fields() {
        let body = ConversationStateBody {
            conversation: direct("bob@example.org"),
            revision: 3,
            source_device_id: 2,
            updated_at_ms: 1_000,
            pinned: true,
            archived: false,
            muted_until_ms: Some(MAX_SAFE_CLOCK_MS),
            marked_unread: true,
        };
        let content = ChatContent::conversation_state_with_id(
            MESSAGE,
            "2026-09-25T10:00:00Z",
            1,
            body.clone(),
        )
        .unwrap();
        assert!(content.is_known_kind());
        assert_eq!(content.as_conversation_state(), Some(body.clone()));
        assert_eq!(content.account_control_is_valid(), Some(true));
        assert!(ChatContent::is_account_control_kind(&content.kind));

        for invalid in [
            ConversationStateBody {
                revision: 0,
                ..body.clone()
            },
            ConversationStateBody {
                source_device_id: 0,
                ..body.clone()
            },
            ConversationStateBody {
                updated_at_ms: 0,
                ..body.clone()
            },
            ConversationStateBody {
                muted_until_ms: Some(MAX_SAFE_CLOCK_MS + 1),
                ..body.clone()
            },
            ConversationStateBody {
                conversation: ConversationId::Group {
                    group_id: uuid::Uuid::nil().to_string(),
                },
                ..body.clone()
            },
        ] {
            assert!(ChatContent::conversation_state_with_id(MESSAGE, "t", 1, invalid).is_err());
        }
    }

    #[test]
    fn conversation_state_rejects_unknown_fields_and_a_missing_message_id() {
        let mut content = ChatContent::conversation_state_with_id(
            MESSAGE,
            "t",
            1,
            ConversationStateBody {
                conversation: direct("bob@example.org"),
                revision: 1,
                source_device_id: 1,
                updated_at_ms: 1,
                pinned: false,
                archived: true,
                muted_until_ms: None,
                marked_unread: false,
            },
        )
        .unwrap();
        let mut unknown = content.clone();
        unknown.body["colour"] = serde_json::json!("red");
        assert_eq!(unknown.as_conversation_state(), None);
        assert_eq!(unknown.account_control_is_valid(), Some(false));
        content.message_id = None;
        assert_eq!(content.as_conversation_state(), None);
    }

    #[test]
    fn read_position_needs_a_canonical_anchor() {
        let body = ReadPositionBody {
            conversation: ConversationId::Group {
                group_id: OTHER.into(),
            },
            through_message_id: MESSAGE.into(),
            read_through_ms: 5_000,
        };
        let content = ChatContent::read_position_with_id(OTHER, "t", 2, body.clone()).unwrap();
        assert_eq!(content.as_read_position(), Some(body.clone()));
        assert!(ChatContent::read_position_with_id(
            OTHER,
            "t",
            2,
            ReadPositionBody {
                through_message_id: MESSAGE.to_uppercase(),
                ..body.clone()
            },
        )
        .is_err());
        assert!(ChatContent::read_position_with_id(
            OTHER,
            "t",
            2,
            ReadPositionBody {
                read_through_ms: 0,
                ..body
            },
        )
        .is_err());
    }

    #[test]
    fn delete_for_me_names_one_to_64_unique_messages() {
        let body = DeleteForMeBody {
            conversation: direct("bob@example.org"),
            message_ids: vec![MESSAGE.into(), OTHER.into()],
        };
        let content = ChatContent::delete_for_me_with_id(OTHER, "t", 3, body.clone()).unwrap();
        assert_eq!(content.as_delete_for_me(), Some(body.clone()));
        for message_ids in [
            vec![],
            vec![MESSAGE.to_string(), MESSAGE.to_string()],
            (0..65).map(|_| uuid::Uuid::new_v4().to_string()).collect(),
        ] {
            assert!(ChatContent::delete_for_me_with_id(
                OTHER,
                "t",
                3,
                DeleteForMeBody {
                    message_ids,
                    ..body.clone()
                },
            )
            .is_err());
        }
    }
}
