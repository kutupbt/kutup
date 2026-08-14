//! Typed wire and encrypted-plaintext structures for `docs/chat-media.md`.

use std::str::FromStr as _;

use base64::Engine as _;
use kutup_crypto::chat_attachment_ledger::{self, MAX_CHAT_ATTACHMENT_LEDGER_PLAINTEXT_BYTES};
use kutup_crypto::chat_media::{
    object_ciphertext_size, ChatMediaSuiteId, MAX_CHAT_MEDIA_PLAINTEXT_BYTES,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AccountAddress;

pub const CHAT_MEDIA_PROTOCOL_VERSION: u16 = 1;
pub const CHAT_ATTACHMENT_VERSION: u16 = 1;
pub const CHAT_ATTACHMENT_LEDGER_ENTRY_VERSION: u16 = 1;
pub const MAX_CHAT_MEDIA_FILENAME_BYTES: usize = 1024;
pub const MAX_CHAT_MEDIA_MIME_BYTES: usize = 255;
pub const MAX_CHAT_MEDIA_CAPTION_BYTES: usize = 4096;
pub const MAX_CHAT_MEDIA_PREVIEW_BYTES: usize = 32 * 1024;
pub const MAX_CHAT_MEDIA_CONVERSATION_REF_BYTES: usize = 512;
pub const MAX_CHAT_MEDIA_DISPLAY_NAME_BYTES: usize = 1024;
pub const MAX_CHAT_ATTACHMENT_LEDGER_PAGE_ENTITIES: usize = 256;

const LEDGER_ENTRY_MAGIC: &[u8; 8] = b"KUTPCE1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum ChatMediaClassV1 {
    File = 1,
    Photo = 2,
    Video = 3,
    Audio = 4,
}

impl ChatMediaClassV1 {
    const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for ChatMediaClassV1 {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::File),
            2 => Ok(Self::Photo),
            3 => Ok(Self::Video),
            4 => Ok(Self::Audio),
            _ => Err(format!("unknown Chat media class {value}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatMediaPreviewV1 {
    pub mime_type: String,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatAttachmentDescriptorV1 {
    pub version: u16,
    #[cfg_attr(feature = "openapi", schema(value_type = u16))]
    pub suite: ChatMediaSuiteId,
    pub attachment_id: String,
    pub origin_domain: String,
    /// Canonical base64 32-byte, recipient/destination/object-bound token.
    pub retrieval_token: String,
    pub ciphertext_bytes: u64,
    pub ciphertext_sha256: String,
    /// Canonical base64 32-byte random attachment key, protected by the outer
    /// libsignal or MLS application ciphertext.
    pub attachment_key: String,
    pub plaintext_bytes: u64,
    pub filename: String,
    pub mime_type: String,
    pub media_class: ChatMediaClassV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caption: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<ChatMediaPreviewV1>,
    /// Opaque locator for the independently encrypted continuous-history copy.
    /// It is present only in backup display records, never required for live delivery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_media_id: Option<String>,
}

impl ChatAttachmentDescriptorV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != CHAT_ATTACHMENT_VERSION {
            return Err("unsupported Chat attachment descriptor version".into());
        }
        require_canonical_uuid("attachmentId", &self.attachment_id)?;
        kutup_federation_proto::validate_server_name(&self.origin_domain)
            .map_err(|error| error.to_string())?;
        decode_canonical_base64::<32>("retrievalToken", &self.retrieval_token)?;
        decode_canonical_base64::<32>("attachmentKey", &self.attachment_key)?;
        validate_sha256("ciphertextSha256", &self.ciphertext_sha256)?;
        if self.plaintext_bytes > MAX_CHAT_MEDIA_PLAINTEXT_BYTES
            || self.ciphertext_bytes
                != object_ciphertext_size(self.plaintext_bytes)
                    .map_err(|error| error.to_string())?
        {
            return Err("Chat attachment length does not match its suite framing".into());
        }
        validate_display_name(&self.filename, MAX_CHAT_MEDIA_FILENAME_BYTES, "filename")?;
        validate_mime(&self.mime_type)?;
        if let Some(caption) = &self.caption {
            if caption.is_empty()
                || caption.len() > MAX_CHAT_MEDIA_CAPTION_BYTES
                || caption.as_bytes().contains(&0)
            {
                return Err("Chat attachment caption is invalid".into());
            }
        }
        match (self.width, self.height) {
            (Some(width), Some(height)) if width > 0 && height > 0 => {}
            (None, None) => {}
            _ => return Err("Chat attachment dimensions must be a non-zero pair".into()),
        }
        if self.duration_ms == Some(0) {
            return Err("Chat attachment duration must be non-zero".into());
        }
        if let Some(preview) = &self.preview {
            validate_mime(&preview.mime_type)?;
            let decoded = decode_canonical_base64_vec("preview", &preview.data)?;
            if decoded.is_empty() || decoded.len() > MAX_CHAT_MEDIA_PREVIEW_BYTES {
                return Err("Chat attachment preview length is invalid".into());
            }
        }
        if let Some(media_id) = &self.backup_media_id {
            validate_sha256("backupMediaId", media_id)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatMediaCapabilitiesV1 {
    pub protocol_version: u16,
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<u16>))]
    pub suites: Vec<ChatMediaSuiteId>,
    pub maximum_plaintext_bytes: u64,
}

impl ChatMediaCapabilitiesV1 {
    pub fn v1(maximum_plaintext_bytes: u64) -> Result<Self, String> {
        if maximum_plaintext_bytes == 0 || maximum_plaintext_bytes > MAX_CHAT_MEDIA_PLAINTEXT_BYTES
        {
            return Err("Chat media capability limit is outside V1".into());
        }
        Ok(Self {
            protocol_version: CHAT_MEDIA_PROTOCOL_VERSION,
            suites: vec![ChatMediaSuiteId::XChaCha20Poly1305SecretStreamV1],
            maximum_plaintext_bytes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatMediaDeliveryOfferV1 {
    pub version: u16,
    pub origin_domain: String,
    pub destination_domain: String,
    pub recipient: String,
    pub operation_id: String,
    pub attachment_id: String,
    #[cfg_attr(feature = "openapi", schema(value_type = u16))]
    pub suite: ChatMediaSuiteId,
    pub ciphertext_bytes: u64,
    pub ciphertext_sha256: String,
    pub retrieval_token: String,
    /// Canonical base64 16-byte contacts/group delivery capability.
    pub delivery_capability: String,
    pub expires_at: i64,
}

impl ChatMediaDeliveryOfferV1 {
    pub fn validate(&self, expected_destination: &str, now_unix: i64) -> Result<(), String> {
        if self.version != CHAT_MEDIA_PROTOCOL_VERSION {
            return Err("unsupported Chat media offer version".into());
        }
        kutup_federation_proto::validate_server_name(&self.origin_domain)
            .map_err(|error| error.to_string())?;
        kutup_federation_proto::validate_server_name(&self.destination_domain)
            .map_err(|error| error.to_string())?;
        if self.destination_domain != expected_destination {
            return Err("Chat media offer destination does not match".into());
        }
        let recipient = AccountAddress::from_str(&self.recipient)
            .map_err(|error| format!("invalid Chat media recipient: {error}"))?;
        if recipient.canonical() != self.recipient
            || recipient.server.as_deref() != Some(self.destination_domain.as_str())
        {
            return Err("Chat media offer recipient is not canonical for destination".into());
        }
        require_canonical_uuid("operationId", &self.operation_id)?;
        require_canonical_uuid("attachmentId", &self.attachment_id)?;
        validate_sha256("ciphertextSha256", &self.ciphertext_sha256)?;
        decode_canonical_base64::<32>("retrievalToken", &self.retrieval_token)?;
        decode_canonical_base64::<16>("deliveryCapability", &self.delivery_capability)?;
        if self.ciphertext_bytes == 0
            || self.ciphertext_bytes > kutup_crypto::chat_media::max_object_ciphertext_bytes()
        {
            return Err("Chat media offer ciphertext length is invalid".into());
        }
        if self.expires_at <= now_unix || self.expires_at > now_unix.saturating_add(30 * 86_400) {
            return Err("Chat media offer expiry is invalid".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ChatMediaDeliveryStatusV1 {
    Stored,
    AlreadyStored,
    /// The origin durably queued a federated transfer. The encrypted message
    /// may proceed; the origin retry worker keeps the exact offer immutable.
    Queued,
    StorageFull,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatMediaOfferResponseV1 {
    pub operation_id: String,
    pub status: ChatMediaDeliveryStatusV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_reference_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatAttachmentLedgerPutRequestV1 {
    pub operation_id: String,
    pub envelope: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatAttachmentLedgerPutReceiptV1 {
    pub entity_id: String,
    pub revision: String,
    pub envelope_digest: String,
    pub cursor: String,
    pub idempotent: bool,
}

impl ChatAttachmentLedgerPutReceiptV1 {
    pub fn validate(&self) -> Result<(), String> {
        require_canonical_uuid("entityId", &self.entity_id)?;
        parse_canonical_u64("revision", &self.revision, false)?;
        validate_sha256("envelopeDigest", &self.envelope_digest)?;
        parse_canonical_u64("cursor", &self.cursor, false)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatAttachmentLedgerWireEntityV1 {
    pub entity_id: String,
    pub revision: String,
    pub envelope_digest: String,
    pub envelope: String,
    pub cursor: String,
}

impl ChatAttachmentLedgerWireEntityV1 {
    pub fn validate(&self) -> Result<(), String> {
        require_canonical_uuid("entityId", &self.entity_id)?;
        let revision = parse_canonical_u64("revision", &self.revision, false)?;
        validate_sha256("envelopeDigest", &self.envelope_digest)?;
        let _ = parse_canonical_u64("cursor", &self.cursor, false)?;
        let envelope = chat_attachment_ledger::decode_canonical_b64(&self.envelope)
            .map_err(|error| error.to_string())?;
        let header =
            chat_attachment_ledger::inspect(&envelope).map_err(|error| error.to_string())?;
        if Uuid::from_bytes(header.context.entity_id)
            .hyphenated()
            .to_string()
            != self.entity_id
            || header.context.revision != revision
            || chat_attachment_ledger::envelope_digest(&envelope)
                .map_err(|error| error.to_string())?
                != self.envelope_digest
        {
            return Err("Chat attachment ledger entity differs from its envelope".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatAttachmentLedgerDiffPageV1 {
    pub entities: Vec<ChatAttachmentLedgerWireEntityV1>,
    pub next_cursor: String,
    pub more: bool,
}

impl ChatAttachmentLedgerDiffPageV1 {
    pub fn validate(&self, after_cursor: &str) -> Result<(), String> {
        if self.entities.len() > MAX_CHAT_ATTACHMENT_LEDGER_PAGE_ENTITIES {
            return Err("Chat attachment ledger page is too large".into());
        }
        let mut previous = parse_canonical_u64("after cursor", after_cursor, true)?;
        for entity in &self.entities {
            entity.validate()?;
            let cursor = parse_canonical_u64("entity cursor", &entity.cursor, false)?;
            if cursor <= previous {
                return Err("Chat attachment ledger page is reordered or duplicated".into());
            }
            previous = cursor;
        }
        let next = parse_canonical_u64("next cursor", &self.next_cursor, true)?;
        if next != previous {
            return Err("Chat attachment ledger page next cursor is inconsistent".into());
        }
        if self.more && self.entities.len() != MAX_CHAT_ATTACHMENT_LEDGER_PAGE_ENTITIES {
            return Err("Chat attachment ledger continuation is not a full page".into());
        }
        Ok(())
    }
}

/// Sender-free signed server-to-server transaction. The authenticated
/// federation request carries the origin identity; this structure binds it to
/// a contiguous feature sequence and the exact recipient capability offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedChatMediaTransactionV1 {
    pub version: u16,
    pub origin_domain: String,
    pub origin_sequence: u64,
    pub offer: ChatMediaDeliveryOfferV1,
}

impl FederatedChatMediaTransactionV1 {
    pub fn validate(&self, expected_destination: &str, now_unix: i64) -> Result<(), String> {
        if self.version != CHAT_MEDIA_PROTOCOL_VERSION || self.origin_sequence == 0 {
            return Err("invalid federated Chat media transaction version or sequence".into());
        }
        kutup_federation_proto::validate_server_name(&self.origin_domain)
            .map_err(|error| error.to_string())?;
        self.offer.validate(expected_destination, now_unix)?;
        if self.offer.origin_domain != self.origin_domain {
            return Err("federated Chat media origin does not match its offer".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum ChatMediaConversationKindV1 {
    Direct = 1,
    MlsGroup = 2,
    NoteToSelf = 3,
}

impl ChatMediaConversationKindV1 {
    const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for ChatMediaConversationKindV1 {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Direct),
            2 => Ok(Self::MlsGroup),
            3 => Ok(Self::NoteToSelf),
            _ => Err(format!("unknown Chat media conversation kind {value}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum ChatAttachmentLedgerStateV1 {
    Active = 1,
    Cleared = 2,
    SavedToDrive = 3,
    Expired = 4,
}

impl ChatAttachmentLedgerStateV1 {
    const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for ChatAttachmentLedgerStateV1 {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Active),
            2 => Ok(Self::Cleared),
            3 => Ok(Self::SavedToDrive),
            4 => Ok(Self::Expired),
            _ => Err(format!("unknown Chat attachment ledger state {value}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatAttachmentLedgerEntryV1 {
    pub version: u16,
    pub conversation_kind: ChatMediaConversationKindV1,
    pub conversation_reference: String,
    pub message_id: String,
    pub attachment_id: String,
    pub storage_reference_id: String,
    pub ciphertext_bytes: u64,
    pub state: ChatAttachmentLedgerStateV1,
    pub media_class: ChatMediaClassV1,
    pub display_name: String,
    pub updated_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drive_file_id: Option<String>,
}

impl ChatAttachmentLedgerEntryV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != CHAT_ATTACHMENT_LEDGER_ENTRY_VERSION {
            return Err("unsupported Chat attachment ledger-entry version".into());
        }
        if self.conversation_reference.is_empty()
            || self.conversation_reference.len() > MAX_CHAT_MEDIA_CONVERSATION_REF_BYTES
            || self.conversation_reference.as_bytes().contains(&0)
        {
            return Err("Chat attachment conversation reference is invalid".into());
        }
        match self.conversation_kind {
            ChatMediaConversationKindV1::Direct | ChatMediaConversationKindV1::NoteToSelf => {
                let address = AccountAddress::from_str(&self.conversation_reference)
                    .map_err(|error| error.to_string())?;
                if address.server.is_none() || address.canonical() != self.conversation_reference {
                    return Err("Chat attachment account reference is not canonical".into());
                }
            }
            ChatMediaConversationKindV1::MlsGroup => {
                require_canonical_uuid("conversationReference", &self.conversation_reference)?;
            }
        }
        require_canonical_uuid("messageId", &self.message_id)?;
        require_canonical_uuid("attachmentId", &self.attachment_id)?;
        require_canonical_uuid("storageReferenceId", &self.storage_reference_id)?;
        if self.ciphertext_bytes == 0
            || self.ciphertext_bytes > kutup_crypto::chat_media::max_object_ciphertext_bytes()
        {
            return Err("Chat attachment ledger byte count is invalid".into());
        }
        validate_display_name(
            &self.display_name,
            MAX_CHAT_MEDIA_DISPLAY_NAME_BYTES,
            "displayName",
        )?;
        if self.updated_at_ms <= 0 {
            return Err("Chat attachment ledger update time is invalid".into());
        }
        match (self.state, &self.drive_file_id) {
            (ChatAttachmentLedgerStateV1::SavedToDrive, Some(id)) => {
                require_canonical_uuid("driveFileId", id)?;
            }
            (ChatAttachmentLedgerStateV1::SavedToDrive, None) => {
                return Err("saved Chat attachment requires a Drive file id".into())
            }
            (_, Some(_)) => return Err("only a saved Chat attachment may carry a Drive id".into()),
            (_, None) => {}
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut out =
            Vec::with_capacity(192 + self.conversation_reference.len() + self.display_name.len());
        out.extend_from_slice(LEDGER_ENTRY_MAGIC);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.conversation_kind.as_u8());
        out.push(self.state.as_u8());
        out.push(self.media_class.as_u8());
        out.push(0);
        push_string(
            &mut out,
            "conversationReference",
            &self.conversation_reference,
        )?;
        push_uuid(&mut out, "messageId", &self.message_id)?;
        push_uuid(&mut out, "attachmentId", &self.attachment_id)?;
        push_uuid(&mut out, "storageReferenceId", &self.storage_reference_id)?;
        out.extend_from_slice(&self.ciphertext_bytes.to_be_bytes());
        out.extend_from_slice(&self.updated_at_ms.to_be_bytes());
        push_string(&mut out, "displayName", &self.display_name)?;
        match &self.drive_file_id {
            Some(id) => {
                out.push(1);
                push_uuid(&mut out, "driveFileId", id)?;
            }
            None => out.push(0),
        }
        if out.len() > MAX_CHAT_ATTACHMENT_LEDGER_PLAINTEXT_BYTES {
            return Err("Chat attachment ledger entry is too large".into());
        }
        Ok(out)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 8 + 2 + 4 || bytes.get(..8) != Some(LEDGER_ENTRY_MAGIC) {
            return Err("Chat attachment ledger entry is too short".into());
        }
        if bytes.len() > MAX_CHAT_ATTACHMENT_LEDGER_PLAINTEXT_BYTES {
            return Err("Chat attachment ledger entry is too large".into());
        }
        let mut cursor = 8usize;
        let version = read_u16(bytes, &mut cursor)?;
        let conversation_kind =
            ChatMediaConversationKindV1::try_from(read_u8(bytes, &mut cursor)?)?;
        let state = ChatAttachmentLedgerStateV1::try_from(read_u8(bytes, &mut cursor)?)?;
        let media_class = ChatMediaClassV1::try_from(read_u8(bytes, &mut cursor)?)?;
        if read_u8(bytes, &mut cursor)? != 0 {
            return Err("Chat attachment ledger entry reserved byte is non-zero".into());
        }
        let conversation_reference = read_string(bytes, &mut cursor, "conversationReference")?;
        let message_id = read_uuid(bytes, &mut cursor)?;
        let attachment_id = read_uuid(bytes, &mut cursor)?;
        let storage_reference_id = read_uuid(bytes, &mut cursor)?;
        let ciphertext_bytes = read_u64(bytes, &mut cursor)?;
        let updated_at_ms = read_i64(bytes, &mut cursor)?;
        let display_name = read_string(bytes, &mut cursor, "displayName")?;
        let drive_file_id = match read_u8(bytes, &mut cursor)? {
            0 => None,
            1 => Some(read_uuid(bytes, &mut cursor)?),
            _ => return Err("Chat attachment ledger Drive-id flag is invalid".into()),
        };
        if cursor != bytes.len() {
            return Err("Chat attachment ledger entry has trailing bytes".into());
        }
        let entry = Self {
            version,
            conversation_kind,
            conversation_reference,
            message_id,
            attachment_id,
            storage_reference_id,
            ciphertext_bytes,
            state,
            media_class,
            display_name,
            updated_at_ms,
            drive_file_id,
        };
        entry.validate()?;
        if entry.canonical_bytes()? != bytes {
            return Err("Chat attachment ledger entry is not canonical".into());
        }
        Ok(entry)
    }
}

fn require_canonical_uuid(field: &str, value: &str) -> Result<(), String> {
    let parsed = Uuid::parse_str(value).map_err(|_| format!("{field} must be a UUID"))?;
    if parsed.hyphenated().to_string() != value {
        return Err(format!("{field} must be a canonical lowercase UUID"));
    }
    Ok(())
}

fn decode_canonical_base64_vec(field: &str, value: &str) -> Result<Vec<u8>, String> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| format!("{field} must be canonical base64"))?;
    if base64::engine::general_purpose::STANDARD.encode(&decoded) != value {
        return Err(format!("{field} must be canonical base64"));
    }
    Ok(decoded)
}

fn decode_canonical_base64<const N: usize>(field: &str, value: &str) -> Result<[u8; N], String> {
    let decoded = decode_canonical_base64_vec(field, value)?;
    decoded
        .try_into()
        .map_err(|_| format!("{field} must decode to {N} bytes"))
}

fn validate_sha256(field: &str, value: &str) -> Result<(), String> {
    let decoded = hex::decode(value).map_err(|_| format!("{field} must be lowercase hex"))?;
    if decoded.len() != 32 || hex::encode(decoded) != value {
        return Err(format!("{field} must be canonical SHA-256 hex"));
    }
    Ok(())
}

fn parse_canonical_u64(field: &str, value: &str, allow_zero: bool) -> Result<u64, String> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!("{field} must be a canonical u64"));
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{field} must be a canonical u64"))?;
    if !allow_zero && parsed == 0 {
        return Err(format!("{field} must be non-zero"));
    }
    Ok(parsed)
}

fn validate_display_name(value: &str, max: usize, field: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > max
        || value.as_bytes().contains(&0)
        || value.contains('/')
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        return Err(format!("Chat attachment {field} is invalid"));
    }
    Ok(())
}

fn validate_mime(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_CHAT_MEDIA_MIME_BYTES
        || value.matches('/').count() != 1
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'/' | b'+' | b'-' | b'.')
        })
    {
        return Err("Chat attachment MIME type is not canonical".into());
    }
    Ok(())
}

fn push_string(out: &mut Vec<u8>, field: &str, value: &str) -> Result<(), String> {
    let len = u16::try_from(value.len()).map_err(|_| format!("{field} is too long"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_uuid(out: &mut Vec<u8>, field: &str, value: &str) -> Result<(), String> {
    require_canonical_uuid(field, value)?;
    out.extend_from_slice(Uuid::parse_str(value).expect("validated UUID").as_bytes());
    Ok(())
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8], String> {
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| "Chat attachment ledger length overflow".to_string())?;
    let value = bytes
        .get(*cursor..end)
        .ok_or_else(|| "Chat attachment ledger entry is truncated".to_string())?;
    *cursor = end;
    Ok(value)
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, String> {
    Ok(take(bytes, cursor, 1)?[0])
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, String> {
    Ok(u16::from_be_bytes(
        take(bytes, cursor, 2)?.try_into().expect("two-byte slice"),
    ))
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, String> {
    Ok(u64::from_be_bytes(
        take(bytes, cursor, 8)?
            .try_into()
            .expect("eight-byte slice"),
    ))
}

fn read_i64(bytes: &[u8], cursor: &mut usize) -> Result<i64, String> {
    Ok(i64::from_be_bytes(
        take(bytes, cursor, 8)?
            .try_into()
            .expect("eight-byte slice"),
    ))
}

fn read_string(bytes: &[u8], cursor: &mut usize, field: &str) -> Result<String, String> {
    let len = usize::from(read_u16(bytes, cursor)?);
    let value = std::str::from_utf8(take(bytes, cursor, len)?)
        .map_err(|_| format!("{field} is not UTF-8"))?;
    Ok(value.to_string())
}

fn read_uuid(bytes: &[u8], cursor: &mut usize) -> Result<String, String> {
    let raw: [u8; 16] = take(bytes, cursor, 16)?
        .try_into()
        .expect("sixteen-byte slice");
    Ok(Uuid::from_bytes(raw).hyphenated().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> ChatAttachmentDescriptorV1 {
        ChatAttachmentDescriptorV1 {
            version: 1,
            suite: ChatMediaSuiteId::XChaCha20Poly1305SecretStreamV1,
            attachment_id: "11111111-1111-4111-8111-111111111111".into(),
            origin_domain: "a.example".into(),
            retrieval_token: base64::engine::general_purpose::STANDARD.encode([1; 32]),
            ciphertext_bytes: object_ciphertext_size(7).unwrap(),
            ciphertext_sha256: "22".repeat(32),
            attachment_key: base64::engine::general_purpose::STANDARD.encode([3; 32]),
            plaintext_bytes: 7,
            filename: "cat.jpg".into(),
            mime_type: "image/jpeg".into(),
            media_class: ChatMediaClassV1::Photo,
            caption: Some("cat".into()),
            width: Some(10),
            height: Some(20),
            duration_ms: None,
            preview: None,
            backup_media_id: None,
        }
    }

    fn ledger_entry() -> ChatAttachmentLedgerEntryV1 {
        ChatAttachmentLedgerEntryV1 {
            version: 1,
            conversation_kind: ChatMediaConversationKindV1::Direct,
            conversation_reference: "bob@example.org".into(),
            message_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            attachment_id: "11111111-1111-4111-8111-111111111111".into(),
            storage_reference_id: "22222222-2222-4222-8222-222222222222".into(),
            ciphertext_bytes: object_ciphertext_size(7).unwrap(),
            state: ChatAttachmentLedgerStateV1::Active,
            media_class: ChatMediaClassV1::Photo,
            display_name: "cat.jpg".into(),
            updated_at_ms: 1_700_000_000_000,
            drive_file_id: None,
        }
    }

    fn ledger_wire_entity(cursor: u64) -> ChatAttachmentLedgerWireEntityV1 {
        let entity_id = "99999999-9999-4999-8999-999999999999";
        let context = chat_attachment_ledger::ChatAttachmentLedgerContextV1::new(
            &"aa".repeat(32),
            entity_id,
            1,
            None,
        )
        .unwrap();
        let envelope = chat_attachment_ledger::seal_with_nonce(
            &ledger_entry().canonical_bytes().unwrap(),
            &[8; 32],
            context,
            &[9; 24],
        )
        .unwrap();
        ChatAttachmentLedgerWireEntityV1 {
            entity_id: entity_id.into(),
            revision: "1".into(),
            envelope_digest: chat_attachment_ledger::envelope_digest(&envelope).unwrap(),
            envelope: base64::engine::general_purpose::STANDARD.encode(&envelope),
            cursor: cursor.to_string(),
        }
    }

    #[test]
    fn descriptor_is_strict_and_context_complete() {
        descriptor().validate().unwrap();
        let mut bad = descriptor();
        bad.filename = "../cat.jpg".into();
        assert!(bad.validate().is_err());
        let mut bad = descriptor();
        bad.ciphertext_bytes += 1;
        assert!(bad.validate().is_err());
        let mut bad = descriptor();
        bad.width = None;
        assert!(bad.validate().is_err());
        let mut value = serde_json::to_value(descriptor()).unwrap();
        value["sender"] = serde_json::Value::String("alice@a.example".into());
        assert!(serde_json::from_value::<ChatAttachmentDescriptorV1>(value).is_err());
    }

    #[test]
    fn ledger_entry_canonical_vector_round_trips() {
        let entry = ledger_entry();
        let bytes = entry.canonical_bytes().unwrap();
        assert_eq!(
            hex::encode(&bytes),
            "4b55545043453100000101010200000f626f62406578616d706c652e6f7267aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa1111111111114111811111111111111122222222222242228222222222222222000000000000004c0000018bcfe5680000076361742e6a706700"
        );
        assert_eq!(
            ChatAttachmentLedgerEntryV1::from_canonical_bytes(&bytes).unwrap(),
            entry
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert!(ChatAttachmentLedgerEntryV1::from_canonical_bytes(&trailing).is_err());
    }

    #[test]
    fn ledger_receipt_and_diff_page_are_strict_ordered_and_envelope_bound() {
        let entity = ledger_wire_entity(7);
        entity.validate().unwrap();
        let request = ChatAttachmentLedgerPutRequestV1 {
            operation_id: "88888888-8888-4888-8888-888888888888".into(),
            envelope: entity.envelope.clone(),
        };
        let mut request_json = serde_json::to_value(&request).unwrap();
        request_json["unknown"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<ChatAttachmentLedgerPutRequestV1>(request_json).is_err());
        ChatAttachmentLedgerPutReceiptV1 {
            entity_id: entity.entity_id.clone(),
            revision: entity.revision.clone(),
            envelope_digest: entity.envelope_digest.clone(),
            cursor: entity.cursor.clone(),
            idempotent: false,
        }
        .validate()
        .unwrap();
        ChatAttachmentLedgerDiffPageV1 {
            entities: vec![entity.clone()],
            next_cursor: "7".into(),
            more: false,
        }
        .validate("0")
        .unwrap();

        let mut bad = entity.clone();
        bad.envelope_digest = "11".repeat(32);
        assert!(bad.validate().is_err());
        let mut bad = entity.clone();
        bad.revision = "2".into();
        assert!(bad.validate().is_err());
        assert!(ChatAttachmentLedgerDiffPageV1 {
            entities: vec![entity.clone()],
            next_cursor: "6".into(),
            more: false,
        }
        .validate("0")
        .is_err());
        assert!(ChatAttachmentLedgerDiffPageV1 {
            entities: vec![entity],
            next_cursor: "7".into(),
            more: true,
        }
        .validate("0")
        .is_err());
    }

    #[test]
    fn delivery_offer_has_no_sender_field_and_is_destination_bound() {
        let offer = ChatMediaDeliveryOfferV1 {
            version: 1,
            origin_domain: "a.example".into(),
            destination_domain: "b.example".into(),
            recipient: "bob@b.example".into(),
            operation_id: "33333333-3333-4333-8333-333333333333".into(),
            attachment_id: "11111111-1111-4111-8111-111111111111".into(),
            suite: ChatMediaSuiteId::XChaCha20Poly1305SecretStreamV1,
            ciphertext_bytes: object_ciphertext_size(7).unwrap(),
            ciphertext_sha256: "44".repeat(32),
            retrieval_token: base64::engine::general_purpose::STANDARD.encode([5; 32]),
            delivery_capability: base64::engine::general_purpose::STANDARD.encode([6; 16]),
            expires_at: 1_800,
        };
        offer.validate("b.example", 1_000).unwrap();
        let json = serde_json::to_value(&offer).unwrap();
        assert!(json.get("sender").is_none());
        assert!(json.get("senderDevice").is_none());
        assert!(offer.validate("c.example", 1_000).is_err());

        let transaction = FederatedChatMediaTransactionV1 {
            version: 1,
            origin_domain: "a.example".into(),
            origin_sequence: 7,
            offer,
        };
        transaction.validate("b.example", 1_000).unwrap();
        assert_eq!(
            String::from_utf8(serde_json::to_vec(&transaction).unwrap()).unwrap(),
            concat!(
                "{\"version\":1,\"originDomain\":\"a.example\",\"originSequence\":7,",
                "\"offer\":{\"version\":1,\"originDomain\":\"a.example\",",
                "\"destinationDomain\":\"b.example\",\"recipient\":\"bob@b.example\",",
                "\"operationId\":\"33333333-3333-4333-8333-333333333333\",",
                "\"attachmentId\":\"11111111-1111-4111-8111-111111111111\",",
                "\"suite\":1,\"ciphertextBytes\":76,\"ciphertextSha256\":\"",
                "4444444444444444444444444444444444444444444444444444444444444444\",",
                "\"retrievalToken\":\"BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=\",",
                "\"deliveryCapability\":\"BgYGBgYGBgYGBgYGBgYGBg==\",\"expiresAt\":1800}}"
            )
        );
        let mut wrong_origin = transaction.clone();
        wrong_origin.origin_domain = "evil.example".into();
        assert!(wrong_origin.validate("b.example", 1_000).is_err());
        let mut zero_sequence = transaction;
        zero_sequence.origin_sequence = 0;
        assert!(zero_sequence.validate("b.example", 1_000).is_err());
    }

    #[test]
    fn delivery_offer_rejects_expiry_size_and_routing_boundaries() {
        let mut offer = ChatMediaDeliveryOfferV1 {
            version: 1,
            origin_domain: "a.example".into(),
            destination_domain: "b.example".into(),
            recipient: "bob@b.example".into(),
            operation_id: "33333333-3333-4333-8333-333333333333".into(),
            attachment_id: "11111111-1111-4111-8111-111111111111".into(),
            suite: ChatMediaSuiteId::XChaCha20Poly1305SecretStreamV1,
            ciphertext_bytes: object_ciphertext_size(0).unwrap(),
            ciphertext_sha256: "44".repeat(32),
            retrieval_token: base64::engine::general_purpose::STANDARD.encode([5; 32]),
            delivery_capability: base64::engine::general_purpose::STANDARD.encode([6; 16]),
            expires_at: 1_001,
        };
        offer.validate("b.example", 1_000).unwrap();

        offer.expires_at = 1_000;
        assert!(offer.validate("b.example", 1_000).is_err());
        offer.expires_at = 1_000 + 30 * 86_400 + 1;
        assert!(offer.validate("b.example", 1_000).is_err());
        offer.expires_at = 1_001;
        offer.ciphertext_bytes = 0;
        assert!(offer.validate("b.example", 1_000).is_err());
        offer.ciphertext_bytes = kutup_crypto::chat_media::max_object_ciphertext_bytes() + 1;
        assert!(offer.validate("b.example", 1_000).is_err());
        offer.ciphertext_bytes = object_ciphertext_size(0).unwrap();
        offer.recipient = "Bob@b.example".into();
        assert!(offer.validate("b.example", 1_000).is_err());
        offer.recipient = "bob@b.example".into();
        offer.destination_domain = "c.example".into();
        assert!(offer.validate("b.example", 1_000).is_err());
    }
}
