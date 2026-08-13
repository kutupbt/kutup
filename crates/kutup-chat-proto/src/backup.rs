//! Versioned opaque wire contract for continuous E2EE Chat history.
//!
//! The server validates authorization, public framing, ordering, digests, and
//! quota. Conversation identifiers, senders, message kinds, filenames, and
//! archive plaintext exist only inside [`kutup_crypto::chat_backup`] objects.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use kutup_crypto::chat_backup::{ChatBackupProtectionDomainV1, ChatBackupSuiteId};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::ConversationId;

pub const CHAT_BACKUP_PROTOCOL_VERSION: u16 = 1;
pub const DEFAULT_CHAT_STORAGE_QUOTA_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const CHAT_DELIVERY_MEDIA_RETENTION_DAYS: u32 = 45;
pub const MAX_CHAT_BACKUP_SEGMENT_CIPHERTEXT_BYTES: u32 = 256 * 1024 + 1024;
pub const MAX_CHAT_BACKUP_BASE_CIPHERTEXT_BYTES: u64 = 128 * 1024 * 1024 + 1024;
pub const MAX_CHAT_BACKUP_PAGE_SEGMENTS: u16 = 256;
pub const MAX_CHAT_BACKUP_ROOT_ENVELOPE_BYTES: usize = 1024;
pub const MAX_CHAT_BACKUP_SIGNER_AUTHORIZATION_BYTES: usize = 4096;
pub const MAX_CHAT_BACKUP_RECORDS_PER_SEGMENT: usize = 1024;
pub const MAX_CHAT_BACKUP_MEDIA_REFERENCES_PER_PAGE: usize = 1000;

const SIGNER_AUTHORIZATION_DOMAIN: &[u8] = b"kutup/chat-backup/signer-authorization/v1\0";
const MANIFEST_DOMAIN: &[u8] = b"kutup/chat-backup/manifest/v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatBackupCapabilitiesV1 {
    pub protocol_version: u16,
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<u16>))]
    pub suites: Vec<ChatBackupSuiteId>,
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<u8>))]
    pub protection_domains: Vec<ChatBackupProtectionDomainV1>,
    pub default_storage_quota_bytes: u64,
    pub maximum_segment_ciphertext_bytes: u32,
    pub maximum_base_ciphertext_bytes: u64,
    pub segment_page_limit: u16,
    pub delivery_media_retention_days: u32,
    pub always_enabled: bool,
}

impl ChatBackupCapabilitiesV1 {
    pub fn v1(
        default_storage_quota_bytes: u64,
        delivery_media_retention_days: u32,
    ) -> Result<Self, String> {
        if default_storage_quota_bytes == 0 {
            return Err("Chat storage quota must be positive".into());
        }
        Ok(Self {
            protocol_version: CHAT_BACKUP_PROTOCOL_VERSION,
            suites: vec![ChatBackupSuiteId::HkdfSha256XChaCha20Poly1305V1],
            protection_domains: vec![ChatBackupProtectionDomainV1::StandardChat],
            default_storage_quota_bytes,
            maximum_segment_ciphertext_bytes: MAX_CHAT_BACKUP_SEGMENT_CIPHERTEXT_BYTES,
            maximum_base_ciphertext_bytes: MAX_CHAT_BACKUP_BASE_CIPHERTEXT_BYTES,
            segment_page_limit: MAX_CHAT_BACKUP_PAGE_SEGMENTS,
            delivery_media_retention_days,
            always_enabled: true,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatBackupSignerAuthorizationV1 {
    pub version: u16,
    pub backup_incarnation_id: String,
    pub account_incarnation_id: String,
    #[cfg_attr(feature = "openapi", schema(value_type = u16))]
    pub suite: ChatBackupSuiteId,
    #[cfg_attr(feature = "openapi", schema(value_type = u8))]
    pub protection_domain: ChatBackupProtectionDomainV1,
    pub manifest_signing_public_key: String,
    pub account_authority_key_id: String,
    pub created_at_unix: i64,
    pub account_authority_signature: String,
}

impl ChatBackupSignerAuthorizationV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        require_version(self.version)?;
        let backup_id = require_uuid("backupIncarnationId", &self.backup_incarnation_id)?;
        let account_incarnation =
            require_hash("accountIncarnationId", &self.account_incarnation_id)?;
        let signing_key = decode_base64_exact::<32>(
            "manifestSigningPublicKey",
            &self.manifest_signing_public_key,
        )?;
        let authority_key_id =
            require_hash("accountAuthorityKeyId", &self.account_authority_key_id)?;
        if self.created_at_unix <= 0 {
            return Err("backup signer authorization time is invalid".into());
        }
        let mut out = Vec::with_capacity(180);
        out.extend_from_slice(SIGNER_AUTHORIZATION_DOMAIN);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(backup_id.as_bytes());
        out.extend_from_slice(&account_incarnation);
        out.extend_from_slice(&self.suite.as_u16().to_be_bytes());
        out.push(self.protection_domain.as_u8());
        out.extend_from_slice(&signing_key);
        out.extend_from_slice(&authority_key_id);
        out.extend_from_slice(&self.created_at_unix.to_be_bytes());
        Ok(out)
    }

    pub fn verify(&self, account_authority_public_key: &[u8; 32]) -> Result<(), String> {
        let public_key = VerifyingKey::from_bytes(account_authority_public_key)
            .map_err(|_| "account authority public key is invalid")?;
        let signature = Signature::from_bytes(&decode_base64_exact::<64>(
            "accountAuthoritySignature",
            &self.account_authority_signature,
        )?);
        public_key
            .verify(&self.signing_bytes()?, &signature)
            .map_err(|_| "backup signer authorization signature is invalid".into())
    }

    pub fn digest(&self) -> Result<String, String> {
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        ensure_canonical_json(self, &bytes)?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatBackupManifestV1 {
    pub version: u16,
    pub backup_incarnation_id: String,
    #[cfg_attr(feature = "openapi", schema(value_type = u16))]
    pub suite: ChatBackupSuiteId,
    #[cfg_attr(feature = "openapi", schema(value_type = u8))]
    pub protection_domain: ChatBackupProtectionDomainV1,
    pub generation: u64,
    pub previous_manifest_digest: String,
    pub base_object_id: String,
    pub base_ciphertext_bytes: u64,
    pub base_ciphertext_sha256: String,
    pub covered_cursor: u64,
    pub media_reference_set_digest: String,
    pub signer_authorization_digest: String,
    pub created_at_unix: i64,
    pub signature: String,
}

impl ChatBackupManifestV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        require_version(self.version)?;
        let backup_id = require_uuid("backupIncarnationId", &self.backup_incarnation_id)?;
        if self.generation == 0 {
            return Err("backup manifest generation must be positive".into());
        }
        let previous = require_hash("previousManifestDigest", &self.previous_manifest_digest)?;
        if self.generation == 1 && previous != [0u8; 32] {
            return Err("first backup manifest must use the zero previous digest".into());
        }
        if self.generation > 1 && previous == [0u8; 32] {
            return Err("later backup manifest must chain its predecessor".into());
        }
        let base_id = require_uuid("baseObjectId", &self.base_object_id)?;
        if self.base_ciphertext_bytes == 0
            || self.base_ciphertext_bytes > MAX_CHAT_BACKUP_BASE_CIPHERTEXT_BYTES
        {
            return Err("backup base ciphertext length is invalid".into());
        }
        let base_digest = require_hash("baseCiphertextSha256", &self.base_ciphertext_sha256)?;
        let media_digest =
            require_hash("mediaReferenceSetDigest", &self.media_reference_set_digest)?;
        let authorization_digest = require_hash(
            "signerAuthorizationDigest",
            &self.signer_authorization_digest,
        )?;
        if self.created_at_unix <= 0 {
            return Err("backup manifest creation time is invalid".into());
        }
        let mut out = Vec::with_capacity(320);
        out.extend_from_slice(MANIFEST_DOMAIN);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(backup_id.as_bytes());
        out.extend_from_slice(&self.suite.as_u16().to_be_bytes());
        out.push(self.protection_domain.as_u8());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&previous);
        out.extend_from_slice(base_id.as_bytes());
        out.extend_from_slice(&self.base_ciphertext_bytes.to_be_bytes());
        out.extend_from_slice(&base_digest);
        out.extend_from_slice(&self.covered_cursor.to_be_bytes());
        out.extend_from_slice(&media_digest);
        out.extend_from_slice(&authorization_digest);
        out.extend_from_slice(&self.created_at_unix.to_be_bytes());
        Ok(out)
    }

    pub fn verify(&self, authorization: &ChatBackupSignerAuthorizationV1) -> Result<(), String> {
        if self.backup_incarnation_id != authorization.backup_incarnation_id
            || self.suite != authorization.suite
            || self.protection_domain != authorization.protection_domain
            || self.signer_authorization_digest != authorization.digest()?
        {
            return Err("backup manifest signer binding differs from authorization".into());
        }
        let public_key = VerifyingKey::from_bytes(&decode_base64_exact::<32>(
            "manifestSigningPublicKey",
            &authorization.manifest_signing_public_key,
        )?)
        .map_err(|_| "backup manifest signing public key is invalid")?;
        let signature =
            Signature::from_bytes(&decode_base64_exact::<64>("signature", &self.signature)?);
        public_key
            .verify(&self.signing_bytes()?, &signature)
            .map_err(|_| "backup manifest signature is invalid".into())
    }

    pub fn digest(&self) -> Result<String, String> {
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        ensure_canonical_json(self, &bytes)?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatBackupDisplayRecordV1 {
    pub version: u16,
    pub record_id: String,
    pub mutation_sequence: u64,
    pub conversation: ConversationId,
    pub sender: String,
    pub sender_device_id: u32,
    pub outgoing: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<serde_json::Value>,
    pub timestamp_ms: i64,
    pub delivered: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub absolute_expiry_ms: Option<i64>,
    pub tombstone: bool,
}

impl ChatBackupDisplayRecordV1 {
    pub fn validate(&self) -> Result<(), String> {
        require_version(self.version)?;
        require_uuid("recordId", &self.record_id)?;
        if self.mutation_sequence == 0 || self.timestamp_ms <= 0 || self.sender_device_id == 0 {
            return Err("backup display record ordering metadata is invalid".into());
        }
        if self.sender.is_empty() || self.sender.len() > 320 || self.sender.as_bytes().contains(&0)
        {
            return Err("backup display record sender is invalid".into());
        }
        if self.tombstone == self.content.is_some() {
            return Err("backup display record must contain content or a tombstone".into());
        }
        if let Some(content) = &self.content {
            let object = content
                .as_object()
                .ok_or_else(|| "backup display content must be an object".to_string())?;
            let version = object.get("version").and_then(serde_json::Value::as_u64);
            let kind = object.get("kind").and_then(serde_json::Value::as_str);
            let sent_at = object.get("sentAt").and_then(serde_json::Value::as_str);
            let sequence = object.get("seq").and_then(serde_json::Value::as_str);
            if version.is_none_or(|value| value == 0 || value > u64::from(u16::MAX))
                || kind.is_none_or(|value| value.is_empty() || value.len() > 128)
                || sent_at.is_none_or(|value| value.is_empty() || value.len() > 64)
                || sequence.is_none_or(|value| {
                    value.is_empty()
                        || value.len() > 20
                        || !value.bytes().all(|byte| byte.is_ascii_digit())
                })
                || !object.contains_key("body")
                || serde_json::to_vec(content)
                    .map_err(|error| error.to_string())?
                    .len()
                    > 128 * 1024
            {
                return Err("backup display content is invalid".into());
            }
        }
        if self.absolute_expiry_ms.is_some_and(|value| value <= 0) {
            return Err("backup display record expiry is invalid".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatBackupSegmentPlaintextV1 {
    pub version: u16,
    pub records: Vec<ChatBackupDisplayRecordV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatBackupBasePlaintextV1 {
    pub version: u16,
    pub covered_cursor: u64,
    pub records: Vec<ChatBackupDisplayRecordV1>,
}

impl ChatBackupBasePlaintextV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        require_version(self.version)?;
        validate_record_set(&self.records)?;
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty()
            || bytes.len() > kutup_crypto::chat_backup::MAX_CHAT_BACKUP_BASE_PLAINTEXT_BYTES
        {
            return Err("backup base plaintext length is invalid".into());
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid backup base plaintext: {error}"))?;
        if value.canonical_bytes()? != bytes {
            return Err("backup base plaintext is not canonical JSON".into());
        }
        Ok(value)
    }
}

impl ChatBackupSegmentPlaintextV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        require_version(self.version)?;
        if self.records.is_empty() || self.records.len() > MAX_CHAT_BACKUP_RECORDS_PER_SEGMENT {
            return Err("backup segment record count is invalid".into());
        }
        validate_record_set(&self.records)?;
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty()
            || bytes.len() > kutup_crypto::chat_backup::MAX_CHAT_BACKUP_SEGMENT_PLAINTEXT_BYTES
        {
            return Err("backup segment plaintext length is invalid".into());
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid backup segment plaintext: {error}"))?;
        if value.canonical_bytes()? != bytes {
            return Err("backup segment plaintext is not canonical JSON".into());
        }
        Ok(value)
    }
}

fn validate_record_set(records: &[ChatBackupDisplayRecordV1]) -> Result<(), String> {
    let mut record_ids = std::collections::HashSet::with_capacity(records.len());
    for record in records {
        record.validate()?;
        if !record_ids.insert(record.record_id.as_str()) {
            return Err("duplicate backup display record".into());
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProvisionChatBackupRequestV1 {
    pub operation_id: String,
    pub root_envelope: String,
    pub signer_authorization: ChatBackupSignerAuthorizationV1,
}

impl ProvisionChatBackupRequestV1 {
    pub fn validate(&self) -> Result<(), String> {
        require_uuid("operationId", &self.operation_id)?;
        if self.root_envelope.is_empty()
            || self.root_envelope.len() > MAX_CHAT_BACKUP_ROOT_ENVELOPE_BYTES
        {
            return Err("backup root envelope length is invalid".into());
        }
        if serde_json::to_vec(&self.signer_authorization)
            .map_err(|error| error.to_string())?
            .len()
            > MAX_CHAT_BACKUP_SIGNER_AUTHORIZATION_BYTES
        {
            return Err("backup signer authorization is too large".into());
        }
        self.signer_authorization.signing_bytes()?;
        decode_base64_exact::<64>(
            "accountAuthoritySignature",
            &self.signer_authorization.account_authority_signature,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppendChatBackupSegmentRequestV1 {
    pub operation_id: String,
    pub backup_incarnation_id: String,
    pub source_device_id: u32,
    pub device_sequence: u64,
    pub previous_segment_digest: String,
    pub account_manifest_sequence: u64,
    pub ciphertext_bytes: u32,
    pub ciphertext_sha256: String,
    pub ciphertext: String,
}

impl AppendChatBackupSegmentRequestV1 {
    pub fn validate(&self) -> Result<Vec<u8>, String> {
        require_uuid("operationId", &self.operation_id)?;
        require_uuid("backupIncarnationId", &self.backup_incarnation_id)?;
        if self.source_device_id == 0
            || self.device_sequence == 0
            || self.account_manifest_sequence == 0
        {
            return Err("backup segment sequence metadata is invalid".into());
        }
        require_hash("previousSegmentDigest", &self.previous_segment_digest)?;
        let expected_digest = require_hash("ciphertextSha256", &self.ciphertext_sha256)?;
        if self.ciphertext_bytes == 0
            || self.ciphertext_bytes > MAX_CHAT_BACKUP_SEGMENT_CIPHERTEXT_BYTES
        {
            return Err("backup segment ciphertext length is invalid".into());
        }
        let ciphertext = decode_canonical_base64("ciphertext", &self.ciphertext)?;
        if ciphertext.len() != self.ciphertext_bytes as usize
            || Sha256::digest(&ciphertext).as_slice() != expected_digest
        {
            return Err("backup segment ciphertext binding is invalid".into());
        }
        Ok(ciphertext)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatBackupSegmentReceiptV1 {
    pub operation_id: String,
    pub cursor: u64,
    pub acknowledged_at_unix: i64,
    pub already_stored: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatBackupWireSegmentV1 {
    pub operation_id: String,
    pub cursor: u64,
    pub source_device_id: u32,
    pub device_sequence: u64,
    pub previous_segment_digest: String,
    pub ciphertext_bytes: u32,
    pub ciphertext_sha256: String,
    pub ciphertext: String,
    pub acknowledged_at_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatBackupSegmentPageV1 {
    pub segments: Vec<ChatBackupWireSegmentV1>,
    pub current_cursor: u64,
    pub more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StageChatBackupBaseRequestV1 {
    pub backup_incarnation_id: String,
    pub object_id: String,
    pub generation: u64,
    pub covered_cursor: u64,
    pub ciphertext_bytes: u64,
    pub ciphertext_sha256: String,
}

impl StageChatBackupBaseRequestV1 {
    pub fn validate(&self) -> Result<(), String> {
        require_uuid("backupIncarnationId", &self.backup_incarnation_id)?;
        require_uuid("objectId", &self.object_id)?;
        if self.generation == 0
            || self.ciphertext_bytes == 0
            || self.ciphertext_bytes > MAX_CHAT_BACKUP_BASE_CIPHERTEXT_BYTES
        {
            return Err("backup base metadata is invalid".into());
        }
        require_hash("ciphertextSha256", &self.ciphertext_sha256)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatBackupBaseReceiptV1 {
    pub object_id: String,
    pub already_stored: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommitChatBackupManifestRequestV1 {
    pub expected_generation: u64,
    pub expected_cursor: u64,
    pub expected_manifest_digest: String,
    pub manifest: ChatBackupManifestV1,
}

impl CommitChatBackupManifestRequestV1 {
    pub fn validate(&self) -> Result<(), String> {
        require_hash("expectedManifestDigest", &self.expected_manifest_digest)?;
        self.manifest.signing_bytes()?;
        decode_base64_exact::<64>("signature", &self.manifest.signature)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatBackupManifestCommitReceiptV1 {
    pub generation: u64,
    pub covered_cursor: u64,
    pub manifest_digest: String,
    pub committed_at_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CopyChatBackupMediaRequestV1 {
    pub operation_id: String,
    pub backup_incarnation_id: String,
    pub source_attachment_id: String,
    pub media_id: String,
    pub reference_id: String,
    pub outer_encryption_key: String,
}

impl CopyChatBackupMediaRequestV1 {
    pub fn validate(&self) -> Result<[u8; 32], String> {
        require_uuid("operationId", &self.operation_id)?;
        require_uuid("backupIncarnationId", &self.backup_incarnation_id)?;
        require_uuid("sourceAttachmentId", &self.source_attachment_id)?;
        require_uuid("referenceId", &self.reference_id)?;
        require_hash("mediaId", &self.media_id)?;
        decode_base64_exact::<32>("outerEncryptionKey", &self.outer_encryption_key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UploadChatBackupMediaRequestV1 {
    pub backup_incarnation_id: String,
    pub media_id: String,
    pub reference_id: String,
    pub source_ciphertext_bytes: u64,
    pub ciphertext_bytes: u64,
    pub ciphertext_sha256: String,
}

impl UploadChatBackupMediaRequestV1 {
    pub fn validate(&self) -> Result<(), String> {
        require_uuid("backupIncarnationId", &self.backup_incarnation_id)?;
        require_uuid("referenceId", &self.reference_id)?;
        require_hash("mediaId", &self.media_id)?;
        require_hash("ciphertextSha256", &self.ciphertext_sha256)?;
        if self.source_ciphertext_bytes == 0 || self.ciphertext_bytes == 0 {
            return Err("backup media lengths must be positive".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatBackupMediaReceiptV1 {
    pub media_id: String,
    pub ciphertext_bytes: u64,
    pub ciphertext_sha256: String,
    pub already_stored: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatBackupMediaReferenceV1 {
    pub reference_id: String,
    pub media_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReconcileChatBackupMediaRequestV1 {
    pub operation_id: String,
    pub target_generation: u64,
    pub reference_set_digest: String,
    pub page_index: u32,
    pub final_page: bool,
    pub references: Vec<ChatBackupMediaReferenceV1>,
}

impl ReconcileChatBackupMediaRequestV1 {
    pub fn validate(&self) -> Result<(), String> {
        require_uuid("operationId", &self.operation_id)?;
        require_hash("referenceSetDigest", &self.reference_set_digest)?;
        if self.target_generation == 0
            || self.references.len() > MAX_CHAT_BACKUP_MEDIA_REFERENCES_PER_PAGE
            || (!self.final_page && self.references.is_empty())
        {
            return Err("backup media reconciliation page is invalid".into());
        }
        let mut previous: Option<Uuid> = None;
        for reference in &self.references {
            let id = require_uuid("referenceId", &reference.reference_id)?;
            require_hash("mediaId", &reference.media_id)?;
            if previous.is_some_and(|value| value >= id) {
                return Err("backup media references must be strictly UUID-sorted".into());
            }
            previous = Some(id);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatBackupMediaReconciliationReceiptV1 {
    pub operation_id: String,
    pub next_page: u32,
    pub completed: bool,
}

pub fn chat_backup_media_reference_set_digest(
    references: &[ChatBackupMediaReferenceV1],
) -> Result<String, String> {
    let mut sorted = references.to_vec();
    sorted.sort_by(|left, right| left.reference_id.cmp(&right.reference_id));
    let mut digest = Sha256::new();
    digest.update(b"kutup/chat-backup/media-reference-set/v1\0");
    digest.update((sorted.len() as u64).to_be_bytes());
    let mut previous: Option<Uuid> = None;
    for reference in sorted {
        let reference_id = require_uuid("referenceId", &reference.reference_id)?;
        if previous == Some(reference_id) {
            return Err("duplicate backup media reference".into());
        }
        previous = Some(reference_id);
        digest.update(reference_id.as_bytes());
        digest.update(require_hash("mediaId", &reference.media_id)?);
    }
    Ok(hex::encode(digest.finalize()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatBackupStorageUsageV1 {
    pub quota_bytes: u64,
    pub used_bytes: u64,
    pub message_bytes: u64,
    pub delivery_media_bytes: u64,
    pub history_media_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatBackupStatusV1 {
    pub provisioned: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_envelope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_authorization: Option<ChatBackupSignerAuthorizationV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<ChatBackupManifestV1>,
    pub current_cursor: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_protected_at_unix: Option<i64>,
    pub storage: ChatBackupStorageUsageV1,
}

fn require_version(version: u16) -> Result<(), String> {
    if version == CHAT_BACKUP_PROTOCOL_VERSION {
        Ok(())
    } else {
        Err("unsupported Chat backup version".into())
    }
}

fn require_uuid(field: &str, value: &str) -> Result<Uuid, String> {
    let parsed = Uuid::parse_str(value).map_err(|_| format!("{field} must be a UUID"))?;
    if parsed.is_nil() || parsed.hyphenated().to_string() != value {
        return Err(format!("{field} must be a canonical non-nil UUID"));
    }
    Ok(parsed)
}

fn require_hash(field: &str, value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{field} must be lowercase SHA-256 hex"));
    }
    let decoded = hex::decode(value).map_err(|_| format!("{field} must be SHA-256 hex"))?;
    decoded
        .try_into()
        .map_err(|_| format!("{field} must be 32 bytes"))
}

fn decode_canonical_base64(field: &str, value: &str) -> Result<Vec<u8>, String> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| format!("{field} must be canonical base64"))?;
    if STANDARD.encode(&decoded) != value {
        return Err(format!("{field} must be canonical base64"));
    }
    Ok(decoded)
}

fn decode_base64_exact<const N: usize>(field: &str, value: &str) -> Result<[u8; N], String> {
    decode_canonical_base64(field, value)?
        .try_into()
        .map_err(|_| format!("{field} must be {N} bytes"))
}

fn ensure_canonical_json<T: Serialize>(value: &T, bytes: &[u8]) -> Result<(), String> {
    if serde_json::to_vec(value).map_err(|error| error.to_string())? != bytes {
        return Err("backup JSON is not canonical".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    #[test]
    fn capabilities_advertise_the_admin_media_retention_exactly() {
        let capabilities =
            ChatBackupCapabilitiesV1::v1(DEFAULT_CHAT_STORAGE_QUOTA_BYTES, 0).unwrap();
        assert_eq!(capabilities.delivery_media_retention_days, 0);
        assert!(capabilities.always_enabled);
        assert!(ChatBackupCapabilitiesV1::v1(0, 45).is_err());
    }

    fn authorization(
        authority: &SigningKey,
        signer: &SigningKey,
    ) -> ChatBackupSignerAuthorizationV1 {
        let mut value = ChatBackupSignerAuthorizationV1 {
            version: 1,
            backup_incarnation_id: "11111111-1111-4111-8111-111111111111".into(),
            account_incarnation_id: "22".repeat(32),
            suite: ChatBackupSuiteId::HkdfSha256XChaCha20Poly1305V1,
            protection_domain: ChatBackupProtectionDomainV1::StandardChat,
            manifest_signing_public_key: STANDARD.encode(signer.verifying_key().to_bytes()),
            account_authority_key_id: hex::encode(Sha256::digest(
                authority.verifying_key().to_bytes(),
            )),
            created_at_unix: 1_800_000_000,
            account_authority_signature: String::new(),
        };
        value.account_authority_signature =
            STANDARD.encode(authority.sign(&value.signing_bytes().unwrap()).to_bytes());
        value
    }

    fn display_record() -> ChatBackupDisplayRecordV1 {
        ChatBackupDisplayRecordV1 {
            version: 1,
            record_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            mutation_sequence: 1,
            conversation: ConversationId::direct("alice@example.test".parse().unwrap()),
            sender: "alice@example.test".into(),
            sender_device_id: 1,
            outgoing: false,
            content: Some(serde_json::json!({
                "version": 1,
                "kind": "text",
                "sentAt": "1800000000",
                "seq": "1",
                "body": { "text": "opaque to the server" }
            })),
            timestamp_ms: 1_800_000_000_000,
            delivered: true,
            absolute_expiry_ms: None,
            tombstone: false,
        }
    }

    #[test]
    fn signer_and_manifest_signatures_are_context_bound() {
        let authority = SigningKey::from_bytes(&[3u8; 32]);
        let signer = SigningKey::from_bytes(&[4u8; 32]);
        let authorization = authorization(&authority, &signer);
        authorization
            .verify(&authority.verifying_key().to_bytes())
            .unwrap();

        let mut manifest = ChatBackupManifestV1 {
            version: 1,
            backup_incarnation_id: authorization.backup_incarnation_id.clone(),
            suite: authorization.suite,
            protection_domain: authorization.protection_domain,
            generation: 1,
            previous_manifest_digest: "00".repeat(32),
            base_object_id: "33333333-3333-4333-8333-333333333333".into(),
            base_ciphertext_bytes: 1024,
            base_ciphertext_sha256: "44".repeat(32),
            covered_cursor: 8,
            media_reference_set_digest: "55".repeat(32),
            signer_authorization_digest: authorization.digest().unwrap(),
            created_at_unix: 1_800_000_001,
            signature: String::new(),
        };
        manifest.signature =
            STANDARD.encode(signer.sign(&manifest.signing_bytes().unwrap()).to_bytes());
        manifest.verify(&authorization).unwrap();
        manifest.covered_cursor += 1;
        assert!(manifest.verify(&authorization).is_err());
    }

    #[test]
    fn append_rejects_digest_length_and_noncanonical_base64() {
        let ciphertext = vec![1u8; 64];
        let mut request = AppendChatBackupSegmentRequestV1 {
            operation_id: "11111111-1111-4111-8111-111111111111".into(),
            backup_incarnation_id: "22222222-2222-4222-8222-222222222222".into(),
            source_device_id: 1,
            device_sequence: 1,
            previous_segment_digest: "00".repeat(32),
            account_manifest_sequence: 1,
            ciphertext_bytes: ciphertext.len() as u32,
            ciphertext_sha256: hex::encode(Sha256::digest(&ciphertext)),
            ciphertext: STANDARD.encode(&ciphertext),
        };
        assert_eq!(request.validate().unwrap(), ciphertext);
        request.ciphertext_bytes += 1;
        assert!(request.validate().is_err());
    }

    #[test]
    fn archives_reject_duplicates_invalid_mutations_and_noncanonical_wrappers() {
        let record = display_record();
        let duplicate = ChatBackupSegmentPlaintextV1 {
            version: 1,
            records: vec![record.clone(), record.clone()],
        };
        assert!(duplicate.canonical_bytes().is_err());

        let mut invalid_mutation = record.clone();
        invalid_mutation.mutation_sequence = 0;
        assert!(ChatBackupSegmentPlaintextV1 {
            version: 1,
            records: vec![invalid_mutation],
        }
        .canonical_bytes()
        .is_err());

        let canonical = ChatBackupSegmentPlaintextV1 {
            version: 1,
            records: vec![record],
        }
        .canonical_bytes()
        .unwrap();
        let mut noncanonical = b" ".to_vec();
        noncanonical.extend(canonical);
        assert!(ChatBackupSegmentPlaintextV1::from_canonical_bytes(&noncanonical).is_err());

        // V1 is deliberately uncompressed. A wrapper/flag is an unknown field,
        // not an invitation to allocate or invoke a decompressor.
        let compressed = br#"{"version":1,"compression":"gzip","records":[]}"#;
        assert!(ChatBackupSegmentPlaintextV1::from_canonical_bytes(compressed).is_err());
    }
}
