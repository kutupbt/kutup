//! Browser bindings for `kutup-crypto`.
//!
//! This crate contains no cryptographic construction or policy. It converts
//! JS transport values and delegates to the canonical Rust implementation.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use kutup_chat_proto::{
    ChatAttachmentLedgerEntryV1, ChatBackupBasePlaintextV1, ChatBackupManifestV1,
    ChatBackupSegmentPlaintextV1, ChatBackupSignerAuthorizationV1,
};
use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
use kutup_crypto::chat_attachment_ledger::{self, ChatAttachmentLedgerContextV1};
use kutup_crypto::chat_backup::{
    self, ChatBackupContextV1, ChatBackupObjectContextV1, ChatBackupObjectPurposeV1,
    ChatBackupProtectionDomainV1, ChatBackupSuiteId,
};
use kutup_crypto::chat_media::{self, ChatMediaObjectContextV1};
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};
use kutup_crypto::drive_object::{self, DriveFileBlobContextV1};
use kutup_crypto::envelope::{self, CollabFrameContextV1};
use kutup_crypto::kdf::{self, AccountProtectionParameters, AccountProtectionSuiteId};
use kutup_crypto::local_state::{self, LocalStatePurpose};
use kutup_crypto::thumbnail::{self, Thumbnail, ThumbnailFormat, ThumbnailVariant};
use serde::Serialize;
use uuid::Uuid;
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountProtectionKeysView {
    key_encryption_key: String,
    login_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountIdentityKeysView {
    authority_public_key: String,
    authority_key_id: String,
    incarnation_id: String,
    drive_hpke_public_key: String,
    drive_hpke_private_key: String,
    drive_signing_public_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DriveFileBlobPreparationView {
    object_header: String,
    stream_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChatMediaObjectPreparationView {
    object_header: String,
    stream_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChatBackupMediaPreparationView {
    media_id: String,
    outer_encryption_key: String,
    object_header: String,
    padded_plaintext_bytes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenedChatBackupMediaHeaderView {
    outer_encryption_key: String,
    source_ciphertext_bytes: u64,
    padded_plaintext_bytes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifiedChatBackupMetadataView {
    signer_authorization_digest: String,
    manifest_digest: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChatAttachmentLedgerHeaderView {
    suite: u16,
    account_incarnation_id: String,
    entity_id: String,
    revision: String,
    previous_envelope_digest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenedCollabFrameView {
    kind: u8,
    key_generation: u32,
    doc_key_id: u32,
    sender_device_id: String,
    sequence: String,
    plaintext: String,
}

fn chat_backup_context(
    account_incarnation_id: &str,
    backup_incarnation_id: &str,
) -> Result<ChatBackupContextV1, JsValue> {
    let account = hex::decode(account_incarnation_id)
        .ok()
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| js_error("account incarnation must be lowercase 32-byte hex"))?;
    if hex::encode(account) != account_incarnation_id {
        return Err(js_error(
            "account incarnation must be canonical lowercase hex",
        ));
    }
    let backup = Uuid::parse_str(backup_incarnation_id)
        .ok()
        .filter(|value| !value.is_nil() && value.hyphenated().to_string() == backup_incarnation_id)
        .ok_or_else(|| js_error("backup incarnation must be a canonical non-nil UUID"))?;
    Ok(ChatBackupContextV1 {
        account_incarnation_id: account,
        backup_incarnation_id: *backup.as_bytes(),
        protection_domain: ChatBackupProtectionDomainV1::StandardChat,
    })
}

/// The local-state purposes a web page may use. `CliSession` stays CLI-only.
fn web_local_state_purpose(purpose: u8) -> Result<LocalStatePurpose, JsValue> {
    match LocalStatePurpose::try_from(purpose).map_err(|error| js_error(&error.to_string()))? {
        p @ (LocalStatePurpose::SessionFork | LocalStatePurpose::WebSession) => Ok(p),
        LocalStatePurpose::CliSession => Err(js_error(
            "local-state purpose is not available to web clients",
        )),
    }
}

/// Seal a session-fork payload (purpose 2) or a persisted web session (3).
/// Returns the canonical base64 envelope; the nonce is random.
#[wasm_bindgen(js_name = sealLocalState)]
pub fn seal_local_state(
    plaintext_base64: &str,
    key_base64: &str,
    purpose: u8,
    profile: &str,
) -> Result<String, JsValue> {
    let purpose = web_local_state_purpose(purpose)?;
    let plaintext = decode_canonical_base64(plaintext_base64, "local-state plaintext")?;
    let key = decode_canonical_base64(key_base64, "local-state key")?;
    let envelope = local_state::seal(&plaintext, &key, purpose, profile)
        .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(envelope))
}

/// Open an envelope sealed by `sealLocalState` (or the Rust equivalent);
/// fails closed on a wrong key, purpose or profile.
#[wasm_bindgen(js_name = openLocalState)]
pub fn open_local_state(
    envelope_base64: &str,
    key_base64: &str,
    purpose: u8,
    profile: &str,
) -> Result<String, JsValue> {
    let purpose = web_local_state_purpose(purpose)?;
    let envelope = decode_canonical_base64(envelope_base64, "local-state envelope")?;
    let key = decode_canonical_base64(key_base64, "local-state key")?;
    let plaintext = local_state::open(&envelope, &key, purpose, profile)
        .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(plaintext))
}

#[wasm_bindgen(js_name = createChatBackupSignerAuthorization)]
pub fn create_chat_backup_signer_authorization(
    master_key_base64: &str,
    backup_root_base64: &str,
    backup_incarnation_id: &str,
    created_at_unix: i64,
) -> Result<JsValue, JsValue> {
    let master_key: [u8; 32] = decode_canonical_base64(master_key_base64, "master key")?
        .try_into()
        .map_err(|_| js_error("master key must be 32 bytes"))?;
    let root: [u8; 32] = decode_canonical_base64(backup_root_base64, "backup root")?
        .try_into()
        .map_err(|_| js_error("backup root must be 32 bytes"))?;
    if created_at_unix <= 0 {
        return Err(js_error("backup authorization time is invalid"));
    }
    let identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(&master_key)
        .map_err(|error| js_error(&error.to_string()))?;
    let context = chat_backup_context(&identity.incarnation_id(), backup_incarnation_id)?;
    let signer_seed = chat_backup::derive_manifest_signing_seed(&root, context)
        .map_err(|error| js_error(&error.to_string()))?;
    let signer = SigningKey::from_bytes(&signer_seed);
    let mut authorization = ChatBackupSignerAuthorizationV1 {
        version: 1,
        backup_incarnation_id: backup_incarnation_id.into(),
        account_incarnation_id: identity.incarnation_id(),
        suite: ChatBackupSuiteId::HkdfSha256XChaCha20Poly1305V1,
        protection_domain: ChatBackupProtectionDomainV1::StandardChat,
        manifest_signing_public_key: STANDARD.encode(signer.verifying_key().to_bytes()),
        account_authority_key_id: identity.authority_key_id(),
        created_at_unix,
        account_authority_signature: String::new(),
    };
    authorization.account_authority_signature = STANDARD.encode(
        identity
            .authority_signing_key()
            .sign(
                &authorization
                    .signing_bytes()
                    .map_err(|error| js_error(&error))?,
            )
            .to_bytes(),
    );
    serde_wasm_bindgen::to_value(&authorization)
        .map_err(|error| js_error(&format!("encode backup authorization: {error}")))
}

/// Verify the complete account-authority -> backup-signer -> manifest chain
/// against keys derived locally from the recovered account master key.
#[wasm_bindgen(js_name = verifyChatBackupMetadata)]
pub fn verify_chat_backup_metadata(
    signer_authorization: JsValue,
    manifest: JsValue,
    master_key_base64: &str,
    backup_root_base64: &str,
    expected_backup_incarnation_id: &str,
) -> Result<JsValue, JsValue> {
    let master_key: [u8; 32] = decode_canonical_base64(master_key_base64, "master key")?
        .try_into()
        .map_err(|_| js_error("master key must be 32 bytes"))?;
    let root: [u8; 32] = decode_canonical_base64(backup_root_base64, "backup root")?
        .try_into()
        .map_err(|_| js_error("backup root must be 32 bytes"))?;
    let authorization: ChatBackupSignerAuthorizationV1 =
        serde_wasm_bindgen::from_value(signer_authorization)
            .map_err(|error| js_error(&format!("decode backup authorization: {error}")))?;
    let identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(&master_key)
        .map_err(|error| js_error(&error.to_string()))?;
    let context = chat_backup_context(&identity.incarnation_id(), expected_backup_incarnation_id)?;
    if authorization.backup_incarnation_id != expected_backup_incarnation_id
        || authorization.account_incarnation_id != identity.incarnation_id()
        || authorization.account_authority_key_id != identity.authority_key_id()
        || authorization.suite != ChatBackupSuiteId::HkdfSha256XChaCha20Poly1305V1
        || authorization.protection_domain != ChatBackupProtectionDomainV1::StandardChat
    {
        return Err(js_error("backup signer authorization context mismatch"));
    }
    authorization
        .verify(&identity.authority_public_key())
        .map_err(|error| js_error(&error))?;
    let signer_seed = chat_backup::derive_manifest_signing_seed(&root, context)
        .map_err(|error| js_error(&error.to_string()))?;
    if authorization.manifest_signing_public_key
        != STANDARD.encode(
            SigningKey::from_bytes(&signer_seed)
                .verifying_key()
                .to_bytes(),
        )
    {
        return Err(js_error(
            "backup manifest signer does not match the backup root",
        ));
    }
    let authorization_digest = authorization.digest().map_err(|error| js_error(&error))?;
    let manifest_digest = if manifest.is_null() || manifest.is_undefined() {
        None
    } else {
        let manifest: ChatBackupManifestV1 = serde_wasm_bindgen::from_value(manifest)
            .map_err(|error| js_error(&format!("decode backup manifest: {error}")))?;
        manifest
            .verify(&authorization)
            .map_err(|error| js_error(&error))?;
        Some(manifest.digest().map_err(|error| js_error(&error))?)
    };
    serde_wasm_bindgen::to_value(&VerifiedChatBackupMetadataView {
        signer_authorization_digest: authorization_digest,
        manifest_digest,
    })
    .map_err(|error| js_error(&format!("encode verified backup metadata: {error}")))
}

/// Serialize archive plaintext through the canonical Rust protocol types.
#[wasm_bindgen(js_name = encodeChatBackupPlaintext)]
pub fn encode_chat_backup_plaintext(value: JsValue, purpose: u8) -> Result<String, JsValue> {
    let bytes = match ChatBackupObjectPurposeV1::try_from(purpose)
        .map_err(|error| js_error(&error.to_string()))?
    {
        ChatBackupObjectPurposeV1::BaseSnapshot => {
            let value: ChatBackupBasePlaintextV1 = serde_wasm_bindgen::from_value(value)
                .map_err(|error| js_error(&format!("decode backup base plaintext: {error}")))?;
            value.canonical_bytes().map_err(|error| js_error(&error))?
        }
        ChatBackupObjectPurposeV1::EventSegment => {
            let value: ChatBackupSegmentPlaintextV1 = serde_wasm_bindgen::from_value(value)
                .map_err(|error| js_error(&format!("decode backup segment plaintext: {error}")))?;
            value.canonical_bytes().map_err(|error| js_error(&error))?
        }
    };
    Ok(STANDARD.encode(bytes))
}

/// Authenticate canonical archive structure before any record reaches the
/// isolated display-history store.
#[wasm_bindgen(js_name = decodeChatBackupPlaintext)]
pub fn decode_chat_backup_plaintext(
    plaintext_base64: &str,
    purpose: u8,
) -> Result<JsValue, JsValue> {
    let bytes = decode_canonical_base64(plaintext_base64, "backup plaintext")?;
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
    match ChatBackupObjectPurposeV1::try_from(purpose)
        .map_err(|error| js_error(&error.to_string()))?
    {
        ChatBackupObjectPurposeV1::BaseSnapshot => {
            let value = ChatBackupBasePlaintextV1::from_canonical_bytes(&bytes)
                .map_err(|error| js_error(&error))?;
            value
                .serialize(&serializer)
                .map_err(|error| js_error(&format!("encode backup base plaintext: {error}")))
        }
        ChatBackupObjectPurposeV1::EventSegment => {
            let value = ChatBackupSegmentPlaintextV1::from_canonical_bytes(&bytes)
                .map_err(|error| js_error(&error))?;
            value
                .serialize(&serializer)
                .map_err(|error| js_error(&format!("encode backup segment plaintext: {error}")))
        }
    }
}

#[wasm_bindgen(js_name = sealChatBackupObject)]
#[allow(clippy::too_many_arguments)]
pub fn seal_chat_backup_object(
    plaintext_base64: &str,
    backup_root_base64: &str,
    account_incarnation_id: &str,
    backup_incarnation_id: &str,
    purpose: u8,
    object_id: &str,
    source_device_id: u32,
    device_sequence: u64,
    previous_segment_digest: &str,
) -> Result<String, JsValue> {
    let plaintext = decode_canonical_base64(plaintext_base64, "backup plaintext")?;
    let root = decode_canonical_base64(backup_root_base64, "backup root")?;
    let backup = chat_backup_context(account_incarnation_id, backup_incarnation_id)?;
    let purpose = ChatBackupObjectPurposeV1::try_from(purpose)
        .map_err(|error| js_error(&error.to_string()))?;
    let object_id = Uuid::parse_str(object_id)
        .ok()
        .filter(|value| !value.is_nil() && value.hyphenated().to_string() == object_id)
        .ok_or_else(|| js_error("backup object id must be a canonical non-nil UUID"))?;
    let previous: [u8; 32] = hex::decode(previous_segment_digest)
        .ok()
        .and_then(|value| value.try_into().ok())
        .filter(|value: &[u8; 32]| hex::encode(value) == previous_segment_digest)
        .ok_or_else(|| js_error("previous segment digest must be lowercase 32-byte hex"))?;
    let object = chat_backup::seal_object(
        &plaintext,
        &root,
        ChatBackupObjectContextV1 {
            backup,
            purpose,
            object_id: *object_id.as_bytes(),
            source_device_id,
            device_sequence,
            previous_segment_digest: previous,
        },
    )
    .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(object))
}

#[wasm_bindgen(js_name = openChatBackupObject)]
#[allow(clippy::too_many_arguments)]
pub fn open_chat_backup_object(
    object_base64: &str,
    backup_root_base64: &str,
    account_incarnation_id: &str,
    backup_incarnation_id: &str,
    purpose: u8,
    object_id: &str,
    source_device_id: u32,
    device_sequence: u64,
    previous_segment_digest: &str,
) -> Result<String, JsValue> {
    let object = decode_canonical_base64(object_base64, "backup object")?;
    let root = decode_canonical_base64(backup_root_base64, "backup root")?;
    let backup = chat_backup_context(account_incarnation_id, backup_incarnation_id)?;
    let purpose = ChatBackupObjectPurposeV1::try_from(purpose)
        .map_err(|error| js_error(&error.to_string()))?;
    let object_id = Uuid::parse_str(object_id)
        .ok()
        .filter(|value| !value.is_nil() && value.hyphenated().to_string() == object_id)
        .ok_or_else(|| js_error("backup object id must be a canonical non-nil UUID"))?;
    let previous: [u8; 32] = hex::decode(previous_segment_digest)
        .ok()
        .and_then(|value| value.try_into().ok())
        .filter(|value: &[u8; 32]| hex::encode(value) == previous_segment_digest)
        .ok_or_else(|| js_error("previous segment digest must be lowercase 32-byte hex"))?;
    let plaintext = chat_backup::open_object(
        &object,
        &root,
        ChatBackupObjectContextV1 {
            backup,
            purpose,
            object_id: *object_id.as_bytes(),
            source_device_id,
            device_sequence,
            previous_segment_digest: previous,
        },
    )
    .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(plaintext))
}

#[wasm_bindgen(js_name = signChatBackupManifest)]
pub fn sign_chat_backup_manifest(
    unsigned_manifest: JsValue,
    backup_root_base64: &str,
    account_incarnation_id: &str,
    backup_incarnation_id: &str,
) -> Result<JsValue, JsValue> {
    let root = decode_canonical_base64(backup_root_base64, "backup root")?;
    let context = chat_backup_context(account_incarnation_id, backup_incarnation_id)?;
    let mut manifest: ChatBackupManifestV1 = serde_wasm_bindgen::from_value(unsigned_manifest)
        .map_err(|error| js_error(&format!("decode backup manifest: {error}")))?;
    manifest.signature.clear();
    let signer_seed = chat_backup::derive_manifest_signing_seed(&root, context)
        .map_err(|error| js_error(&error.to_string()))?;
    let signer = SigningKey::from_bytes(&signer_seed);
    manifest.signature = STANDARD.encode(
        signer
            .sign(&manifest.signing_bytes().map_err(|error| js_error(&error))?)
            .to_bytes(),
    );
    serde_wasm_bindgen::to_value(&manifest)
        .map_err(|error| js_error(&format!("encode backup manifest: {error}")))
}

#[wasm_bindgen(js_name = prepareChatBackupMedia)]
pub fn prepare_chat_backup_media(
    backup_root_base64: &str,
    account_incarnation_id: &str,
    backup_incarnation_id: &str,
    stable_source_binding: &str,
    source_ciphertext_bytes: u64,
) -> Result<JsValue, JsValue> {
    if stable_source_binding.is_empty() {
        return Err(js_error("backup media source binding is empty"));
    }
    let root = decode_canonical_base64(backup_root_base64, "backup root")?;
    let context = chat_backup_context(account_incarnation_id, backup_incarnation_id)?;
    let media_id = chat_backup::derive_media_id(&root, context, stable_source_binding.as_bytes())
        .map_err(|error| js_error(&error.to_string()))?;
    let key = chat_backup::derive_media_encryption_key(&root, context, &media_id)
        .map_err(|error| js_error(&error.to_string()))?;
    let header = kutup_crypto::chat_backup_media::build_media_header(
        kutup_crypto::chat_backup_media::ChatBackupMediaContextV1 {
            account_incarnation_id: context.account_incarnation_id,
            backup_incarnation_id: context.backup_incarnation_id,
            protection_domain: context.protection_domain,
            media_id,
        },
        source_ciphertext_bytes,
    )
    .map_err(|error| js_error(&error.to_string()))?;
    let parsed = kutup_crypto::chat_backup_media::inspect_media_header(&header)
        .map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&ChatBackupMediaPreparationView {
        media_id: hex::encode(media_id),
        outer_encryption_key: STANDARD.encode(key.as_slice()),
        object_header: STANDARD.encode(header),
        padded_plaintext_bytes: parsed.padded_plaintext_bytes,
    })
    .map_err(|error| js_error(&format!("encode backup media preparation: {error}")))
}

#[wasm_bindgen(js_name = openChatBackupMediaHeader)]
pub fn open_chat_backup_media_header(
    header_base64: &str,
    backup_root_base64: &str,
    expected_account_incarnation_id: &str,
    expected_backup_incarnation_id: &str,
    expected_media_id: &str,
) -> Result<JsValue, JsValue> {
    let header = decode_canonical_base64(header_base64, "backup media header")?;
    let root = decode_canonical_base64(backup_root_base64, "backup root")?;
    let expected = chat_backup_context(
        expected_account_incarnation_id,
        expected_backup_incarnation_id,
    )?;
    let media_id: [u8; 32] = hex::decode(expected_media_id)
        .ok()
        .and_then(|value| value.try_into().ok())
        .filter(|value: &[u8; 32]| hex::encode(value) == expected_media_id)
        .ok_or_else(|| js_error("backup media id must be lowercase 32-byte hex"))?;
    let parsed = kutup_crypto::chat_backup_media::inspect_media_header(&header)
        .map_err(|error| js_error(&error.to_string()))?;
    if parsed.context.account_incarnation_id != expected.account_incarnation_id
        || parsed.context.backup_incarnation_id != expected.backup_incarnation_id
        || parsed.context.protection_domain != expected.protection_domain
        || parsed.context.media_id != media_id
    {
        return Err(js_error("backup media header context mismatch"));
    }
    let key = chat_backup::derive_media_encryption_key(&root, expected, &media_id)
        .map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&OpenedChatBackupMediaHeaderView {
        outer_encryption_key: STANDARD.encode(key.as_slice()),
        source_ciphertext_bytes: parsed.source_ciphertext_bytes,
        padded_plaintext_bytes: parsed.padded_plaintext_bytes,
    })
    .map_err(|error| js_error(&format!("encode opened backup media header: {error}")))
}

/// Run the one expensive V1 Argon2id derivation and expand its two
/// purpose-separated account subkeys.
#[wasm_bindgen(js_name = deriveAccountProtectionKeys)]
pub fn derive_account_protection_keys(
    password: &str,
    salt_base64: &str,
    suite: u16,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<JsValue, JsValue> {
    AccountProtectionSuiteId::try_from(suite).map_err(|error| js_error(&error.to_string()))?;
    let keys = kdf::derive_account_protection_keys_b64(
        password,
        salt_base64,
        AccountProtectionParameters {
            memory_kib,
            iterations,
            parallelism,
        },
    )
    .map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&AccountProtectionKeysView {
        key_encryption_key: STANDARD.encode(keys.key_encryption_key.as_slice()),
        login_key: STANDARD.encode(keys.login_key.as_slice()),
    })
    .map_err(|error| js_error(&format!("encode account keys: {error}")))
}

/// Derive the recovery authorization proof sent to the server. Raw recovery
/// entropy stays in the browser and continues to open only the recovery wrap.
#[wasm_bindgen(js_name = deriveRecoveryAuthProof)]
pub fn derive_recovery_auth_proof(
    recovery_entropy_base64: &str,
    login_email: &str,
) -> Result<String, JsValue> {
    let entropy = STANDARD
        .decode(recovery_entropy_base64)
        .map_err(|_| js_error("recovery entropy must be canonical base64"))?;
    if STANDARD.encode(&entropy) != recovery_entropy_base64 {
        return Err(js_error("recovery entropy must be canonical base64"));
    }
    let proof = kdf::derive_recovery_auth_proof(&entropy, login_email)
        .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(proof.as_slice()))
}

/// Derive the purpose-separated V1 account identity. The Drive private key is
/// returned only so the existing account-private wrap can be created during
/// the pre-tag format cutover; it is never sent in plaintext to the server.
#[wasm_bindgen(js_name = deriveAccountIdentityKeys)]
pub fn derive_account_identity_keys(master_key_base64: &str) -> Result<JsValue, JsValue> {
    let master_key = STANDARD
        .decode(master_key_base64)
        .map_err(|_| js_error("master key must be canonical base64"))?;
    if STANDARD.encode(&master_key) != master_key_base64 {
        return Err(js_error("master key must be canonical base64"));
    }
    let master_key: [u8; 32] = master_key
        .try_into()
        .map_err(|_| js_error("master key must be 32 bytes"))?;
    let identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(&master_key)
        .map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&AccountIdentityKeysView {
        authority_public_key: STANDARD.encode(identity.authority_public_key()),
        authority_key_id: identity.authority_key_id(),
        incarnation_id: identity.incarnation_id(),
        drive_hpke_public_key: STANDARD.encode(identity.drive_hpke_public_key()),
        drive_hpke_private_key: STANDARD.encode(identity.drive_hpke_private_key()),
        drive_signing_public_key: STANDARD.encode(identity.drive_signing_public_key()),
    })
    .map_err(|error| js_error(&format!("encode account identity: {error}")))
}

/// Seal one account secret into the canonical, suite-bearing V1 envelope.
#[wasm_bindgen(js_name = sealAccountEnvelope)]
pub fn seal_account_envelope(
    plaintext_base64: &str,
    key_base64: &str,
    purpose: u8,
    login_email: &str,
) -> Result<String, JsValue> {
    let plaintext = decode_canonical_base64(plaintext_base64, "plaintext")?;
    let key = decode_canonical_base64(key_base64, "key")?;
    let purpose = generic_account_purpose(purpose)?;
    account_envelope::seal_b64(&plaintext, &key, purpose, login_email)
        .map_err(|error| js_error(&error.to_string()))
}

/// Open one account secret only when its purpose and login-email binding match.
#[wasm_bindgen(js_name = openAccountEnvelope)]
pub fn open_account_envelope(
    envelope_base64: &str,
    key_base64: &str,
    expected_purpose: u8,
    login_email: &str,
) -> Result<String, JsValue> {
    let key = decode_canonical_base64(key_base64, "key")?;
    let purpose = generic_account_purpose(expected_purpose)?;
    let plaintext = account_envelope::open_b64(envelope_base64, &key, purpose, login_email)
        .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(plaintext))
}

/// Mail address keys have typed exports (`generateMailAddressKey`), so the
/// generic account-envelope path cannot hand their secret key to JavaScript.
fn generic_account_purpose(value: u8) -> Result<AccountEnvelopePurpose, JsValue> {
    match AccountEnvelopePurpose::try_from(value).map_err(|error| js_error(&error.to_string()))? {
        AccountEnvelopePurpose::MailAddressPrivateKey => Err(js_error(
            "this account envelope purpose has its own typed export",
        )),
        purpose => Ok(purpose),
    }
}

/// The purposes whose context is two plain UUIDs. Whiteboard assets and
/// thumbnails derive their parent id and have typed exports
/// (`sealWhiteboardAsset`, `sealThumbnail`); the generic path refuses them so
/// their bindings cannot be bypassed.
fn generic_drive_purpose(value: u8) -> Result<DriveEnvelopePurpose, JsValue> {
    match DriveEnvelopePurpose::try_from(value).map_err(|error| js_error(&error.to_string()))? {
        DriveEnvelopePurpose::WhiteboardAsset
        | DriveEnvelopePurpose::Thumbnail
        | DriveEnvelopePurpose::PreviousCollectionKey
        | DriveEnvelopePurpose::PreviousFileKey => Err(js_error(
            "this Drive envelope purpose has its own typed export",
        )),
        purpose => Ok(purpose),
    }
}

#[wasm_bindgen(js_name = sealDriveEnvelope)]
#[allow(clippy::too_many_arguments)]
pub fn seal_drive_envelope(
    plaintext_base64: &str,
    root_key_base64: &str,
    purpose: u8,
    epoch: u32,
    revision: u64,
    object_id: &str,
    parent_id: &str,
) -> Result<String, JsValue> {
    let plaintext = decode_canonical_base64(plaintext_base64, "plaintext")?;
    let root_key = decode_canonical_base64(root_key_base64, "root key")?;
    let context = DriveEnvelopeContextV1::new(
        generic_drive_purpose(purpose)?,
        epoch,
        revision,
        object_id,
        parent_id,
    )
    .map_err(|error| js_error(&error.to_string()))?;
    drive_envelope::seal_b64(&plaintext, &root_key, context)
        .map_err(|error| js_error(&error.to_string()))
}

#[wasm_bindgen(js_name = openDriveEnvelope)]
#[allow(clippy::too_many_arguments)]
pub fn open_drive_envelope(
    envelope_base64: &str,
    root_key_base64: &str,
    expected_purpose: u8,
    expected_epoch: u32,
    expected_revision: u64,
    expected_object_id: &str,
    expected_parent_id: &str,
) -> Result<String, JsValue> {
    let root_key = decode_canonical_base64(root_key_base64, "root key")?;
    let context = DriveEnvelopeContextV1::new(
        generic_drive_purpose(expected_purpose)?,
        expected_epoch,
        expected_revision,
        expected_object_id,
        expected_parent_id,
    )
    .map_err(|error| js_error(&error.to_string()))?;
    let plaintext = drive_envelope::open_b64(envelope_base64, &root_key, context)
        .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(plaintext))
}

#[wasm_bindgen(js_name = sealWhiteboardAsset)]
pub fn seal_whiteboard_asset(
    plaintext_base64: &str,
    file_key_base64: &str,
    file_id: &str,
    asset_id: &str,
    generation: u32,
) -> Result<String, JsValue> {
    let plaintext = decode_canonical_base64(plaintext_base64, "whiteboard asset")?;
    let file_key = decode_canonical_base64(file_key_base64, "file key")?;
    let context = DriveEnvelopeContextV1::whiteboard_asset(file_id, asset_id, generation)
        .map_err(|error| js_error(&error.to_string()))?;
    drive_envelope::seal_b64(&plaintext, &file_key, context)
        .map_err(|error| js_error(&error.to_string()))
}

#[wasm_bindgen(js_name = openWhiteboardAsset)]
pub fn open_whiteboard_asset(
    envelope_base64: &str,
    file_key_base64: &str,
    expected_file_id: &str,
    expected_asset_id: &str,
    expected_generation: u32,
) -> Result<String, JsValue> {
    let file_key = decode_canonical_base64(file_key_base64, "file key")?;
    let context = DriveEnvelopeContextV1::whiteboard_asset(
        expected_file_id,
        expected_asset_id,
        expected_generation,
    )
    .map_err(|error| js_error(&error.to_string()))?;
    let plaintext = drive_envelope::open_b64(envelope_base64, &file_key, context)
        .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(plaintext))
}

/// A thumbnail as JavaScript sees it; `image` is canonical base64.
#[derive(Serialize)]
struct ThumbnailView {
    format: u8,
    width: u16,
    height: u16,
    image: String,
}

fn thumbnail_variant(value: &str) -> Result<ThumbnailVariant, JsValue> {
    ThumbnailVariant::try_from(value).map_err(|error| js_error(&error.to_string()))
}

/// Frame, pad and seal a thumbnail under the file key
/// (docs/plans/drive-thumbnails.md). `format`: 1 JPEG, 2 WebP, 3 PNG.
#[wasm_bindgen(js_name = sealThumbnail)]
#[allow(clippy::too_many_arguments)]
pub fn seal_thumbnail(
    image_base64: &str,
    format: u8,
    width: u16,
    height: u16,
    variant: &str,
    file_key_base64: &str,
    file_id: &str,
    generation: u32,
) -> Result<String, JsValue> {
    let thumbnail = Thumbnail {
        format: ThumbnailFormat::try_from(format).map_err(|error| js_error(&error.to_string()))?,
        width,
        height,
        image: decode_canonical_base64(image_base64, "thumbnail image")?,
    };
    let file_key = decode_canonical_base64(file_key_base64, "file key")?;
    let envelope = thumbnail::seal(
        &thumbnail,
        thumbnail_variant(variant)?,
        &file_key,
        file_id,
        generation,
    )
    .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(envelope))
}

/// Open a thumbnail of exactly this file, variant and key generation.
#[wasm_bindgen(js_name = openThumbnail)]
pub fn open_thumbnail(
    envelope_base64: &str,
    variant: &str,
    file_key_base64: &str,
    expected_file_id: &str,
    expected_generation: u32,
) -> Result<JsValue, JsValue> {
    let envelope = decode_canonical_base64(envelope_base64, "thumbnail envelope")?;
    let file_key = decode_canonical_base64(file_key_base64, "file key")?;
    let opened = thumbnail::open(
        &envelope,
        thumbnail_variant(variant)?,
        &file_key,
        expected_file_id,
        expected_generation,
    )
    .map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&ThumbnailView {
        format: opened.format as u8,
        width: opened.width,
        height: opened.height,
        image: STANDARD.encode(opened.image),
    })
    .map_err(|error| js_error(&error.to_string()))
}

#[wasm_bindgen(js_name = prepareDriveFileBlob)]
pub fn prepare_drive_file_blob(
    file_key_base64: &str,
    file_id: &str,
    generation: u32,
) -> Result<JsValue, JsValue> {
    let file_key = decode_canonical_base64(file_key_base64, "file key")?;
    let context = DriveFileBlobContextV1::new(file_id, generation)
        .map_err(|error| js_error(&error.to_string()))?;
    let object_header = drive_object::file_blob_header(context);
    let stream_key = drive_object::derive_file_blob_key(&file_key, context)
        .map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&DriveFileBlobPreparationView {
        object_header: STANDARD.encode(object_header),
        stream_key: STANDARD.encode(stream_key.as_slice()),
    })
    .map_err(|error| js_error(&format!("encode Drive file-blob preparation: {error}")))
}

#[wasm_bindgen(js_name = openDriveFileBlobHeader)]
pub fn open_drive_file_blob_header(
    object_header_base64: &str,
    file_key_base64: &str,
    expected_file_id: &str,
    expected_generation: u32,
) -> Result<String, JsValue> {
    let object_header = decode_canonical_base64(object_header_base64, "object header")?;
    let file_key = decode_canonical_base64(file_key_base64, "file key")?;
    let expected = DriveFileBlobContextV1::new(expected_file_id, expected_generation)
        .map_err(|error| js_error(&error.to_string()))?;
    drive_object::validate_file_blob_header(&object_header, expected)
        .map_err(|error| js_error(&error.to_string()))?;
    let stream_key = drive_object::derive_file_blob_key(&file_key, expected)
        .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(stream_key.as_slice()))
}

/// Return the canonical Chat-media header and its purpose-derived stream key.
/// JS owns only bounded secretstream I/O, exactly as for Drive file blobs.
#[wasm_bindgen(js_name = prepareChatMediaObject)]
pub fn prepare_chat_media_object(
    attachment_key_base64: &str,
    attachment_id: &str,
) -> Result<JsValue, JsValue> {
    let attachment_key = decode_canonical_base64(attachment_key_base64, "attachment key")?;
    let context = ChatMediaObjectContextV1::new(attachment_id)
        .map_err(|error| js_error(&error.to_string()))?;
    let object_header = chat_media::object_header(context);
    let stream_key = chat_media::derive_object_key(&attachment_key, context)
        .map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&ChatMediaObjectPreparationView {
        object_header: STANDARD.encode(object_header),
        stream_key: STANDARD.encode(stream_key.as_slice()),
    })
    .map_err(|error| js_error(&format!("encode Chat-media preparation: {error}")))
}

#[wasm_bindgen(js_name = openChatMediaObjectHeader)]
pub fn open_chat_media_object_header(
    object_header_base64: &str,
    attachment_key_base64: &str,
    expected_attachment_id: &str,
) -> Result<String, JsValue> {
    let object_header = decode_canonical_base64(object_header_base64, "object header")?;
    let attachment_key = decode_canonical_base64(attachment_key_base64, "attachment key")?;
    let expected = ChatMediaObjectContextV1::new(expected_attachment_id)
        .map_err(|error| js_error(&error.to_string()))?;
    chat_media::validate_object_header(&object_header, expected)
        .map_err(|error| js_error(&error.to_string()))?;
    let stream_key = chat_media::derive_object_key(&attachment_key, expected)
        .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(stream_key.as_slice()))
}

#[wasm_bindgen(js_name = sealChatAttachmentLedger)]
#[allow(clippy::too_many_arguments)]
pub fn seal_chat_attachment_ledger(
    plaintext_base64: &str,
    ledger_key_base64: &str,
    account_incarnation_id: &str,
    entity_id: &str,
    revision: u64,
    previous_envelope_digest: &str,
) -> Result<String, JsValue> {
    let plaintext = decode_canonical_base64(plaintext_base64, "ledger plaintext")?;
    let ledger_key = decode_canonical_base64(ledger_key_base64, "ledger key")?;
    let context = ChatAttachmentLedgerContextV1::new(
        account_incarnation_id,
        entity_id,
        revision,
        (!previous_envelope_digest.is_empty()).then_some(previous_envelope_digest),
    )
    .map_err(|error| js_error(&error.to_string()))?;
    chat_attachment_ledger::seal_b64(&plaintext, &ledger_key, context)
        .map_err(|error| js_error(&error.to_string()))
}

#[wasm_bindgen(js_name = deriveChatAttachmentLedgerKey)]
pub fn derive_chat_attachment_ledger_key(master_key_base64: &str) -> Result<String, JsValue> {
    let master_key = decode_canonical_base64(master_key_base64, "master key")?;
    let key = chat_attachment_ledger::derive_account_ledger_key(&master_key)
        .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(key.as_slice()))
}

#[wasm_bindgen(js_name = openChatAttachmentLedger)]
#[allow(clippy::too_many_arguments)]
pub fn open_chat_attachment_ledger(
    envelope_base64: &str,
    ledger_key_base64: &str,
    expected_account_incarnation_id: &str,
    expected_entity_id: &str,
    expected_revision: u64,
    expected_previous_envelope_digest: &str,
) -> Result<String, JsValue> {
    let envelope = chat_attachment_ledger::decode_canonical_b64(envelope_base64)
        .map_err(|error| js_error(&error.to_string()))?;
    let ledger_key = decode_canonical_base64(ledger_key_base64, "ledger key")?;
    let expected = ChatAttachmentLedgerContextV1::new(
        expected_account_incarnation_id,
        expected_entity_id,
        expected_revision,
        (!expected_previous_envelope_digest.is_empty())
            .then_some(expected_previous_envelope_digest),
    )
    .map_err(|error| js_error(&error.to_string()))?;
    let plaintext = chat_attachment_ledger::open(&envelope, &ledger_key, expected)
        .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(plaintext))
}

#[wasm_bindgen(js_name = chatAttachmentLedgerEnvelopeDigest)]
pub fn chat_attachment_ledger_envelope_digest(envelope_base64: &str) -> Result<String, JsValue> {
    let envelope = chat_attachment_ledger::decode_canonical_b64(envelope_base64)
        .map_err(|error| js_error(&error.to_string()))?;
    chat_attachment_ledger::envelope_digest(&envelope).map_err(|error| js_error(&error.to_string()))
}

#[wasm_bindgen(js_name = inspectChatAttachmentLedgerEnvelope)]
pub fn inspect_chat_attachment_ledger_envelope(envelope_base64: &str) -> Result<JsValue, JsValue> {
    let envelope = chat_attachment_ledger::decode_canonical_b64(envelope_base64)
        .map_err(|error| js_error(&error.to_string()))?;
    let header =
        chat_attachment_ledger::inspect(&envelope).map_err(|error| js_error(&error.to_string()))?;
    let view = ChatAttachmentLedgerHeaderView {
        suite: header.suite.as_u16(),
        account_incarnation_id: hex::encode(header.context.account_incarnation_id),
        entity_id: uuid::Uuid::from_bytes(header.context.entity_id)
            .hyphenated()
            .to_string(),
        revision: header.context.revision.to_string(),
        previous_envelope_digest: hex::encode(header.context.previous_envelope_digest),
    };
    serde_wasm_bindgen::to_value(&view)
        .map_err(|error| js_error(&format!("encode Chat attachment ledger header: {error}")))
}

#[wasm_bindgen(js_name = encodeChatAttachmentLedgerEntry)]
pub fn encode_chat_attachment_ledger_entry(entry: JsValue) -> Result<String, JsValue> {
    let entry: ChatAttachmentLedgerEntryV1 = serde_wasm_bindgen::from_value(entry)
        .map_err(|error| js_error(&format!("decode Chat attachment ledger entry: {error}")))?;
    let bytes = entry.canonical_bytes().map_err(|error| js_error(&error))?;
    Ok(STANDARD.encode(bytes))
}

#[wasm_bindgen(js_name = decodeChatAttachmentLedgerEntry)]
pub fn decode_chat_attachment_ledger_entry(entry_base64: &str) -> Result<JsValue, JsValue> {
    let bytes = decode_canonical_base64(entry_base64, "Chat attachment ledger entry")?;
    let entry = ChatAttachmentLedgerEntryV1::from_canonical_bytes(&bytes)
        .map_err(|error| js_error(&error))?;
    serde_wasm_bindgen::to_value(&entry)
        .map_err(|error| js_error(&format!("encode Chat attachment ledger entry: {error}")))
}

#[wasm_bindgen(js_name = sealCollabFrame)]
#[allow(clippy::too_many_arguments)]
pub fn seal_collab_frame(
    plaintext_base64: &str,
    file_key_base64: &str,
    kind: u8,
    key_generation: u32,
    doc_key_id: u32,
    file_id: &str,
    sender_device_id: &str,
    sequence: &str,
) -> Result<String, JsValue> {
    let plaintext = decode_canonical_base64(plaintext_base64, "collaboration plaintext")?;
    let file_key = decode_canonical_base64(file_key_base64, "file key")?;
    let sender_device_id = sender_device_id
        .parse::<u64>()
        .map_err(|_| js_error("sender device id must be canonical u64"))?;
    let sequence = sequence
        .parse::<u64>()
        .map_err(|_| js_error("sequence must be canonical u64"))?;
    let context = CollabFrameContextV1::new(
        kind,
        key_generation,
        doc_key_id,
        file_id,
        sender_device_id,
        sequence,
    )
    .map_err(|error| js_error(&error.to_string()))?;
    envelope::seal_unsigned(&plaintext, &file_key, context)
        .map(|packed| STANDARD.encode(packed))
        .map_err(|error| js_error(&error.to_string()))
}

#[wasm_bindgen(js_name = collabFrameSigningBytes)]
pub fn collab_frame_signing_bytes(frame_base64: &str) -> Result<String, JsValue> {
    let frame = decode_canonical_base64(frame_base64, "collaboration frame")?;
    envelope::signing_bytes(&frame)
        .map(|bytes| STANDARD.encode(bytes))
        .map_err(|error| js_error(&error.to_string()))
}

#[wasm_bindgen(js_name = attachCollabFrameSignature)]
pub fn attach_collab_frame_signature(
    frame_base64: &str,
    signature_base64: &str,
) -> Result<String, JsValue> {
    let frame = decode_canonical_base64(frame_base64, "collaboration frame")?;
    let signature = decode_canonical_base64(signature_base64, "collaboration signature")?;
    envelope::attach_signature(&frame, &signature)
        .map(|packed| STANDARD.encode(packed))
        .map_err(|error| js_error(&error.to_string()))
}

#[wasm_bindgen(js_name = openCollabFrame)]
pub fn open_collab_frame(
    frame_base64: &str,
    file_key_base64: &str,
    expected_file_id: &str,
    expected_key_generation: u32,
) -> Result<JsValue, JsValue> {
    let frame = decode_canonical_base64(frame_base64, "collaboration frame")?;
    let file_key = decode_canonical_base64(file_key_base64, "file key")?;
    let (parsed, plaintext) =
        envelope::open(&frame, &file_key, expected_file_id, expected_key_generation)
            .map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&OpenedCollabFrameView {
        kind: parsed.kind,
        key_generation: parsed.key_generation,
        doc_key_id: parsed.doc_key_id,
        sender_device_id: parsed.sender_device_id.to_string(),
        sequence: parsed.sequence.to_string(),
        plaintext: STANDARD.encode(plaintext),
    })
    .map_err(|error| js_error(&format!("encode collaboration frame: {error}")))
}

/// The file-key generation a frame names in its public header, so a
/// client replaying older log frames can pick that generation's key.
/// Opening still checks it (`openCollabFrame` with the same generation).
#[wasm_bindgen(js_name = collabFrameKeyGeneration)]
pub fn collab_frame_key_generation(frame_base64: &str) -> Result<u32, JsValue> {
    let frame = decode_canonical_base64(frame_base64, "collaboration frame")?;
    envelope::Frame::unpack(&frame)
        .map(|parsed| parsed.key_generation)
        .map_err(|error| js_error(&error.to_string()))
}

#[wasm_bindgen(js_name = createCollectionEpochStatement)]
#[allow(clippy::too_many_arguments)]
pub fn create_collection_epoch_statement(
    master_key_base64: &str,
    collection_key_base64: &str,
    collection_id: &str,
    owner_user_id: &str,
    epoch: u32,
    previous_statement_hash: &str,
) -> Result<String, JsValue> {
    let master_key = decode_canonical_base64(master_key_base64, "master key")?;
    let master_key: [u8; 32] = master_key
        .try_into()
        .map_err(|_| js_error("master key must be 32 bytes"))?;
    let collection_key = decode_canonical_base64(collection_key_base64, "collection key")?;
    let identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(&master_key)
        .map_err(|error| js_error(&error.to_string()))?;
    let statement = kutup_crypto::collection_epoch::CollectionEpochStatementV1::create(
        collection_id,
        owner_user_id,
        epoch,
        (!previous_statement_hash.is_empty()).then_some(previous_statement_hash),
        &collection_key,
        identity.authority_signing_key(),
    )
    .map_err(|error| js_error(&error.to_string()))?;
    Ok(statement.encode_b64())
}

#[wasm_bindgen(js_name = verifyCollectionEpochStatement)]
#[allow(clippy::too_many_arguments)]
pub fn verify_collection_epoch_statement(
    statement_base64: &str,
    authority_public_key_base64: &str,
    collection_key_base64: &str,
    expected_collection_id: &str,
    expected_owner_user_id: &str,
    expected_epoch: u32,
    expected_previous_statement_hash: &str,
) -> Result<String, JsValue> {
    let authority = decode_canonical_base64(authority_public_key_base64, "authority public key")?;
    let collection_key = decode_canonical_base64(collection_key_base64, "collection key")?;
    let statement =
        kutup_crypto::collection_epoch::CollectionEpochStatementV1::decode_b64(statement_base64)
            .map_err(|error| js_error(&error.to_string()))?;
    statement
        .verify_authority(&authority)
        .and_then(|()| {
            if expected_previous_statement_hash.is_empty() && expected_epoch > 1 {
                statement.verify_current_binding(
                    expected_collection_id,
                    expected_owner_user_id,
                    expected_epoch,
                )
            } else {
                statement.verify_binding(
                    expected_collection_id,
                    expected_owner_user_id,
                    expected_epoch,
                    (!expected_previous_statement_hash.is_empty())
                        .then_some(expected_previous_statement_hash),
                )
            }
        })
        .and_then(|()| statement.verify_collection_key(&collection_key))
        .map_err(|error| js_error(&error.to_string()))?;
    Ok(statement.statement_hash())
}

/// The previous epoch's folder key sealed under this epoch's, for the
/// rotation record (docs/plans/drive-share-revocation.md).
#[wasm_bindgen(js_name = sealPreviousCollectionKey)]
pub fn seal_previous_collection_key(
    previous_key_base64: &str,
    key_base64: &str,
    collection_id: &str,
    owner_user_id: &str,
    epoch: u32,
) -> Result<String, JsValue> {
    let previous = decode_canonical_base64(previous_key_base64, "previous collection key")?;
    let key = decode_canonical_base64(key_base64, "collection key")?;
    kutup_crypto::collection_keyring::seal_previous_key(
        &previous,
        &key,
        collection_id,
        owner_user_id,
        epoch,
    )
    .map_err(|error| js_error(&error.to_string()))
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct EpochLinkJson {
    epoch: u32,
    epoch_statement: String,
    previous_key_envelope: Option<String>,
}

/// Every key of a folder, oldest first, as an array of base64 strings, from
/// its current key and complete signed history (`chain`: the
/// `GET /api/collections/{id}/epochs` array). Fails unless every statement
/// is the owner's, chained, and every key matches its commitment.
#[wasm_bindgen(js_name = unlockCollectionKeyring)]
pub fn unlock_collection_keyring(
    current_key_base64: &str,
    collection_id: &str,
    owner_user_id: &str,
    owner_authority_public_key_base64: &str,
    chain: JsValue,
) -> Result<JsValue, JsValue> {
    let current = decode_canonical_base64(current_key_base64, "collection key")?;
    let authority =
        decode_canonical_base64(owner_authority_public_key_base64, "authority public key")?;
    let links: Vec<EpochLinkJson> = serde_wasm_bindgen::from_value(chain)
        .map_err(|error| js_error(&format!("collection key history: {error}")))?;
    let chain: Vec<kutup_crypto::collection_keyring::EpochLinkV1> = links
        .into_iter()
        .map(|link| kutup_crypto::collection_keyring::EpochLinkV1 {
            epoch: link.epoch,
            statement: link.epoch_statement,
            previous_key_envelope: link.previous_key_envelope,
        })
        .collect();
    let keys = kutup_crypto::collection_keyring::unlock(
        &current,
        collection_id,
        owner_user_id,
        &authority,
        &chain,
    )
    .map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(
        &keys
            .iter()
            .map(|key| STANDARD.encode(key.as_slice()))
            .collect::<Vec<_>>(),
    )
    .map_err(|error| js_error(&error.to_string()))
}

/// The file key of `generation − 1` sealed under that of `generation`, for a
/// re-key (docs/plans/drive-move.md).
#[wasm_bindgen(js_name = sealPreviousFileKey)]
pub fn seal_previous_file_key(
    previous_key_base64: &str,
    key_base64: &str,
    file_id: &str,
    generation: u32,
) -> Result<String, JsValue> {
    let previous = decode_canonical_base64(previous_key_base64, "previous file key")?;
    let key = decode_canonical_base64(key_base64, "file key")?;
    kutup_crypto::file_keyring::seal_previous_key(&previous, &key, file_id, generation)
        .map_err(|error| js_error(&error.to_string()))
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileKeyLinkJson {
    generation: u32,
    previous_key_envelope: String,
}

/// The file key of generation `wanted`, base64, from the current key of
/// `generation` and the file's history (`chain`: the listing's
/// `keyHistory`, generations 2 to `generation` in order).
#[wasm_bindgen(js_name = fileKeyAt)]
pub fn file_key_at(
    current_key_base64: &str,
    file_id: &str,
    generation: u32,
    chain: JsValue,
    wanted: u32,
) -> Result<String, JsValue> {
    let current = decode_canonical_base64(current_key_base64, "file key")?;
    let links: Vec<FileKeyLinkJson> = serde_wasm_bindgen::from_value(chain)
        .map_err(|error| js_error(&format!("file key history: {error}")))?;
    let chain: Vec<kutup_crypto::file_keyring::FileKeyLinkV1> = links
        .into_iter()
        .map(|link| kutup_crypto::file_keyring::FileKeyLinkV1 {
            generation: link.generation,
            previous_key_envelope: link.previous_key_envelope,
        })
        .collect();
    kutup_crypto::file_keyring::key_at(&current, file_id, generation, &chain, wanted)
        .map(|key| STANDARD.encode(key.as_slice()))
        .map_err(|error| js_error(&error.to_string()))
}

#[wasm_bindgen(js_name = sealNamedShareEnvelope)]
#[allow(clippy::too_many_arguments)]
pub fn seal_named_share_envelope(
    collection_key_base64: &str,
    sender_master_key_base64: &str,
    recipient_hpke_public_key_base64: &str,
    collection_id: &str,
    epoch: u32,
    sender_account: &str,
    sender_incarnation_id: &str,
    recipient_account: &str,
    recipient_incarnation_id: &str,
) -> Result<String, JsValue> {
    let collection_key = decode_canonical_base64(collection_key_base64, "collection key")?;
    let sender_master_key = decode_canonical_base64(sender_master_key_base64, "master key")?;
    let sender_master_key: [u8; 32] = sender_master_key
        .try_into()
        .map_err(|_| js_error("master key must be 32 bytes"))?;
    let recipient_public_key = decode_canonical_base64(
        recipient_hpke_public_key_base64,
        "recipient HPKE public key",
    )?;
    let sender_identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(&sender_master_key)
        .map_err(|error| js_error(&error.to_string()))?;
    kutup_crypto::named_share::NamedShareEnvelopeV1::seal(
        &collection_key,
        collection_id,
        epoch,
        sender_account,
        sender_incarnation_id,
        sender_identity.drive_signing_key(),
        recipient_account,
        recipient_incarnation_id,
        &recipient_public_key,
    )
    .and_then(|envelope| envelope.encode_b64())
    .map_err(|error| js_error(&error.to_string()))
}

#[wasm_bindgen(js_name = openNamedShareEnvelope)]
#[allow(clippy::too_many_arguments)]
pub fn open_named_share_envelope(
    envelope_base64: &str,
    sender_signing_public_key_base64: &str,
    recipient_hpke_private_key_base64: &str,
    expected_collection_id: &str,
    expected_epoch: u32,
    expected_sender_account: &str,
    expected_sender_incarnation_id: &str,
    expected_recipient_account: &str,
    expected_recipient_incarnation_id: &str,
) -> Result<String, JsValue> {
    let sender_signing_public_key = decode_canonical_base64(
        sender_signing_public_key_base64,
        "sender signing public key",
    )?;
    let recipient_private_key = decode_canonical_base64(
        recipient_hpke_private_key_base64,
        "recipient HPKE private key",
    )?;
    let envelope = kutup_crypto::named_share::NamedShareEnvelopeV1::decode_b64(envelope_base64)
        .map_err(|error| js_error(&error.to_string()))?;
    let collection_key = envelope
        .open(
            expected_collection_id,
            expected_epoch,
            expected_sender_account,
            expected_sender_incarnation_id,
            &sender_signing_public_key,
            expected_recipient_account,
            expected_recipient_incarnation_id,
            &recipient_private_key,
        )
        .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(collection_key))
}

/// A single file's key for someone it is shared with
/// (docs/plans/drive-file-sharing.md), sealed to them and signed by the owner.
#[wasm_bindgen(js_name = sealFileShareEnvelope)]
#[allow(clippy::too_many_arguments)]
pub fn seal_file_share_envelope(
    file_key_base64: &str,
    sender_master_key_base64: &str,
    recipient_hpke_public_key_base64: &str,
    file_id: &str,
    generation: u32,
    sender_account: &str,
    sender_incarnation_id: &str,
    recipient_account: &str,
    recipient_incarnation_id: &str,
) -> Result<String, JsValue> {
    let file_key = decode_canonical_base64(file_key_base64, "file key")?;
    let sender_master_key = decode_canonical_base64(sender_master_key_base64, "master key")?;
    let sender_master_key: [u8; 32] = sender_master_key
        .try_into()
        .map_err(|_| js_error("master key must be 32 bytes"))?;
    let recipient_public_key = decode_canonical_base64(
        recipient_hpke_public_key_base64,
        "recipient HPKE public key",
    )?;
    let sender_identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(&sender_master_key)
        .map_err(|error| js_error(&error.to_string()))?;
    kutup_crypto::named_share::FileShareEnvelopeV1::seal(
        &file_key,
        file_id,
        generation,
        sender_account,
        sender_incarnation_id,
        sender_identity.drive_signing_key(),
        recipient_account,
        recipient_incarnation_id,
        &recipient_public_key,
    )
    .and_then(|envelope| envelope.encode_b64())
    .map_err(|error| js_error(&error.to_string()))
}

#[wasm_bindgen(js_name = openFileShareEnvelope)]
#[allow(clippy::too_many_arguments)]
pub fn open_file_share_envelope(
    envelope_base64: &str,
    sender_signing_public_key_base64: &str,
    recipient_hpke_private_key_base64: &str,
    expected_file_id: &str,
    expected_generation: u32,
    expected_sender_account: &str,
    expected_sender_incarnation_id: &str,
    expected_recipient_account: &str,
    expected_recipient_incarnation_id: &str,
) -> Result<String, JsValue> {
    let sender_signing_public_key = decode_canonical_base64(
        sender_signing_public_key_base64,
        "sender signing public key",
    )?;
    let recipient_private_key = decode_canonical_base64(
        recipient_hpke_private_key_base64,
        "recipient HPKE private key",
    )?;
    let envelope = kutup_crypto::named_share::FileShareEnvelopeV1::decode_b64(envelope_base64)
        .map_err(|error| js_error(&error.to_string()))?;
    let file_key = envelope
        .open(
            expected_file_id,
            expected_generation,
            expected_sender_account,
            expected_sender_incarnation_id,
            &sender_signing_public_key,
            expected_recipient_account,
            expected_recipient_incarnation_id,
            &recipient_private_key,
        )
        .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(file_key))
}

/// Your profile key for someone you share Drive folders with
/// (docs/plans/unified-profile.md), sealed to them and signed by you.
#[wasm_bindgen(js_name = sealProfileKeyEnvelope)]
pub fn seal_profile_key_envelope(
    profile_key_base64: &str,
    sender_master_key_base64: &str,
    recipient_hpke_public_key_base64: &str,
    sender_account: &str,
    sender_incarnation_id: &str,
    recipient_account: &str,
    recipient_incarnation_id: &str,
) -> Result<String, JsValue> {
    let profile_key = decode_canonical_base64(profile_key_base64, "profile key")?;
    let sender_master_key: [u8; 32] =
        decode_canonical_base64(sender_master_key_base64, "master key")?
            .try_into()
            .map_err(|_| js_error("master key must be 32 bytes"))?;
    let recipient_public_key = decode_canonical_base64(
        recipient_hpke_public_key_base64,
        "recipient HPKE public key",
    )?;
    let sender_identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(&sender_master_key)
        .map_err(|error| js_error(&error.to_string()))?;
    kutup_crypto::profile_key_share::ProfileKeyEnvelopeV1::seal(
        &profile_key,
        &kutup_crypto::profile_key_share::ProfileKeyParties {
            sender_account,
            sender_incarnation_id,
            recipient_account,
            recipient_incarnation_id,
        },
        sender_identity.drive_signing_key(),
        &recipient_public_key,
    )
    .and_then(|envelope| envelope.encode_b64())
    .map_err(|error| js_error(&error.to_string()))
}

/// Someone's profile key, after checking it is from them, to you.
#[wasm_bindgen(js_name = openProfileKeyEnvelope)]
pub fn open_profile_key_envelope(
    envelope_base64: &str,
    sender_signing_public_key_base64: &str,
    recipient_hpke_private_key_base64: &str,
    expected_sender_account: &str,
    expected_sender_incarnation_id: &str,
    expected_recipient_account: &str,
    expected_recipient_incarnation_id: &str,
) -> Result<String, JsValue> {
    let sender_signing_public_key = decode_canonical_base64(
        sender_signing_public_key_base64,
        "sender signing public key",
    )?;
    let recipient_private_key = decode_canonical_base64(
        recipient_hpke_private_key_base64,
        "recipient HPKE private key",
    )?;
    let envelope =
        kutup_crypto::profile_key_share::ProfileKeyEnvelopeV1::decode_b64(envelope_base64)
            .map_err(|error| js_error(&error.to_string()))?;
    let key = envelope
        .open(
            &kutup_crypto::profile_key_share::ProfileKeyParties {
                sender_account: expected_sender_account,
                sender_incarnation_id: expected_sender_incarnation_id,
                recipient_account: expected_recipient_account,
                recipient_incarnation_id: expected_recipient_incarnation_id,
            },
            &sender_signing_public_key,
            &recipient_private_key,
        )
        .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(key))
}

fn live_location_inputs(
    key_base64: &str,
    stream_id_hex: &str,
) -> Result<(Vec<u8>, Vec<u8>), JsValue> {
    let key = decode_canonical_base64(key_base64, "live location key")?;
    let stream_id = hex::decode(stream_id_hex)
        .ok()
        .filter(|bytes| hex::encode(bytes) == stream_id_hex)
        .ok_or_else(|| js_error("live location stream id must be lowercase hex"))?;
    Ok((key, stream_id))
}

fn whole_number(value: f64, field: &str) -> Result<u64, JsValue> {
    if value.fract() != 0.0 || !(1.0..=9_007_199_254_740_991.0).contains(&value) {
        return Err(js_error(&format!(
            "{field} must be a positive whole number"
        )));
    }
    Ok(value as u64)
}

/// Seal update number `counter` of a live-location stream
/// (docs/plans/maps.md); standard base64 of the 88-byte update.
#[wasm_bindgen(js_name = liveLocationSeal)]
pub fn live_location_seal(
    key_base64: &str,
    stream_id_hex: &str,
    counter: f64,
    lat: f64,
    lon: f64,
    accuracy_m: u32,
    at_ms: f64,
) -> Result<String, JsValue> {
    let (key, stream_id) = live_location_inputs(key_base64, stream_id_hex)?;
    let point = kutup_crypto::live_location::LiveLocationPoint {
        lat,
        lon,
        accuracy_m,
        at_ms: whole_number(at_ms, "time")?,
    };
    kutup_crypto::live_location::seal(&key, &stream_id, whole_number(counter, "counter")?, &point)
        .map(|sealed| STANDARD.encode(sealed))
        .map_err(|error| js_error(&error.to_string()))
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct LiveLocationUpdateJson {
    counter: f64,
    lat: f64,
    lon: f64,
    accuracy_m: u32,
    at_ms: f64,
}

/// Open a live-location update: `{counter, lat, lon, accuracyM, atMs}`.
#[wasm_bindgen(js_name = liveLocationOpen)]
pub fn live_location_open(
    key_base64: &str,
    stream_id_hex: &str,
    envelope_base64: &str,
) -> Result<JsValue, JsValue> {
    let (key, stream_id) = live_location_inputs(key_base64, stream_id_hex)?;
    let envelope = decode_canonical_base64(envelope_base64, "live location update")?;
    let (counter, point) = kutup_crypto::live_location::open(&key, &stream_id, &envelope)
        .map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&LiveLocationUpdateJson {
        counter: counter as f64,
        lat: point.lat,
        lon: point.lon,
        accuracy_m: point.accuracy_m,
        at_ms: point.at_ms as f64,
    })
    .map_err(|error| js_error(&error.to_string()))
}

fn decode_canonical_base64(value: &str, field: &str) -> Result<Vec<u8>, JsValue> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| js_error(&format!("{field} must be canonical base64")))?;
    if STANDARD.encode(&decoded) != value {
        return Err(js_error(&format!("{field} must be canonical base64")));
    }
    Ok(decoded)
}

fn js_error(message: &str) -> JsValue {
    JsValue::from_str(message)
}

/// A Drive file's metadata (name, type, size, photo details), checked and
/// written canonically (docs/plans/photos.md): JSON text in, the exact JSON
/// text to seal out. Opening metadata runs it through here too, so every
/// client refuses the same things.
#[wasm_bindgen(js_name = canonicalFileMetadata)]
pub fn canonical_file_metadata(json: &str) -> Result<String, JsValue> {
    let metadata = kutup_crypto::file_metadata::decode(json.as_bytes())
        .map_err(|error| js_error(&error.to_string()))?;
    let bytes = kutup_crypto::file_metadata::encode(&metadata)
        .map_err(|error| js_error(&error.to_string()))?;
    String::from_utf8(bytes).map_err(|_| js_error("file metadata is not UTF-8"))
}

/// A photo's content hash, fed chunk by chunk as the file is read.
#[wasm_bindgen(js_name = ContentHasher)]
pub struct ContentHasherJs(Option<kutup_crypto::file_metadata::ContentHasher>);

#[wasm_bindgen(js_class = ContentHasher)]
impl ContentHasherJs {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self(Some(kutup_crypto::file_metadata::ContentHasher::new()))
    }

    pub fn update(&mut self, chunk: &[u8]) -> Result<(), JsValue> {
        self.0
            .as_mut()
            .ok_or_else(|| js_error("content hash already finished"))?
            .update(chunk);
        Ok(())
    }

    /// Canonical base64 of the SHA-256; the hasher is spent.
    pub fn finish(&mut self) -> Result<String, JsValue> {
        self.0
            .take()
            .map(|hasher| hasher.finish())
            .ok_or_else(|| js_error("content hash already finished"))
    }
}

impl Default for ContentHasherJs {
    fn default() -> Self {
        Self::new()
    }
}

/// A folder's hash key (`kutup_crypto::drive_names`), from its first (epoch 1) key.
#[wasm_bindgen(js_name = driveFolderHashKey)]
pub fn drive_folder_hash_key(
    first_folder_key_base64: &str,
    collection_id: &str,
) -> Result<String, JsValue> {
    let key = decode_canonical_base64(first_folder_key_base64, "folder key")?;
    kutup_crypto::drive_names::folder_hash_key(&key, collection_id)
        .map(|key| STANDARD.encode(key))
        .map_err(|error| js_error(&error.to_string()))
}

/// The hash key for an account's top-level folders, from its master key.
#[wasm_bindgen(js_name = driveTopLevelHashKey)]
pub fn drive_top_level_hash_key(master_key_base64: &str) -> Result<String, JsValue> {
    let key = decode_canonical_base64(master_key_base64, "master key")?;
    kutup_crypto::drive_names::top_level_hash_key(&key)
        .map(|key| STANDARD.encode(key))
        .map_err(|error| js_error(&error.to_string()))
}

/// The hash a name is kept unique by in its folder (lowercase hex).
#[wasm_bindgen(js_name = driveNameHash)]
pub fn drive_name_hash(hash_key_base64: &str, name: &str) -> Result<String, JsValue> {
    let key = decode_canonical_base64(hash_key_base64, "folder hash key")?;
    kutup_crypto::drive_names::name_hash(&key, name).map_err(|error| js_error(&error.to_string()))
}

/// The hash a file's content is recognised by in its folder, from the
/// SHA-256 of its plaintext (base64, as `ContentHasher` gives it).
#[wasm_bindgen(js_name = driveContentHash)]
pub fn drive_content_hash(
    hash_key_base64: &str,
    content_sha256_base64: &str,
) -> Result<String, JsValue> {
    let key = decode_canonical_base64(hash_key_base64, "folder hash key")?;
    let digest = decode_canonical_base64(content_sha256_base64, "content digest")?;
    kutup_crypto::drive_names::content_hash(&key, &digest)
        .map_err(|error| js_error(&error.to_string()))
}

/// The form two names are compared in (case and composition aside).
#[wasm_bindgen(js_name = driveCanonicalName)]
pub fn drive_canonical_name(name: &str) -> String {
    kutup_crypto::drive_names::canonical_name(name)
}

/// The Photos library record's key (docs/plans/photos.md), from the master key.
#[wasm_bindgen(js_name = photosLibraryKey)]
pub fn photos_library_key(master_key_base64: &str) -> Result<String, JsValue> {
    let master = decode_canonical_base64(master_key_base64, "master key")?;
    kutup_crypto::photos_library::derive_photos_library_key(&master)
        .map(|key| STANDARD.encode(key.as_slice()))
        .map_err(|error| js_error(&error.to_string()))
}

fn photos_library_context(
    account_incarnation_id: &str,
    revision: f64,
    previous_digest: Option<String>,
) -> Result<kutup_crypto::photos_library::PhotosLibraryContextV1, JsValue> {
    kutup_crypto::photos_library::PhotosLibraryContextV1::new(
        account_incarnation_id,
        whole_number(revision, "revision")?,
        previous_digest.as_deref(),
    )
    .map_err(|error| js_error(&error.to_string()))
}

#[derive(Serialize)]
struct SealedPhotosLibrary {
    envelope: String,
    digest: String,
}

/// Seal the library (JSON `{favourites, archived, hidden}`, put in canonical
/// order here) as `revision`, after the record whose digest is given (none
/// for revision 1). Returns `{ envelope, digest }`.
#[wasm_bindgen(js_name = sealPhotosLibrary)]
pub fn seal_photos_library(
    library_json: &str,
    key_base64: &str,
    account_incarnation_id: &str,
    revision: f64,
    previous_digest: Option<String>,
) -> Result<JsValue, JsValue> {
    use kutup_crypto::photos_library;
    let library: photos_library::PhotosLibraryV1 =
        serde_json::from_str(library_json).map_err(|_| js_error("Photos library is not valid"))?;
    let library = library
        .canonicalize()
        .map_err(|error| js_error(&error.to_string()))?;
    let plaintext =
        photos_library::encode_library(&library).map_err(|error| js_error(&error.to_string()))?;
    let key = decode_canonical_base64(key_base64, "Photos library key")?;
    let context = photos_library_context(account_incarnation_id, revision, previous_digest)?;
    let envelope = photos_library::seal(&plaintext, &key, context)
        .map_err(|error| js_error(&error.to_string()))?;
    let digest =
        photos_library::envelope_digest(&envelope).map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&SealedPhotosLibrary {
        envelope: STANDARD.encode(envelope),
        digest,
    })
    .map_err(|_| js_error("encode sealed library"))
}

/// Open a library record as exactly the revision expected; its JSON text.
#[wasm_bindgen(js_name = openPhotosLibrary)]
pub fn open_photos_library(
    envelope_base64: &str,
    key_base64: &str,
    account_incarnation_id: &str,
    revision: f64,
    previous_digest: Option<String>,
) -> Result<String, JsValue> {
    use kutup_crypto::photos_library;
    let envelope = photos_library::decode_canonical_b64(envelope_base64)
        .map_err(|error| js_error(&error.to_string()))?;
    let key = decode_canonical_base64(key_base64, "Photos library key")?;
    let context = photos_library_context(account_incarnation_id, revision, previous_digest)?;
    let plaintext = photos_library::open(&envelope, &key, context)
        .map_err(|error| js_error(&error.to_string()))?;
    let library =
        photos_library::decode_library(&plaintext).map_err(|error| js_error(&error.to_string()))?;
    serde_json::to_string(&library).map_err(|_| js_error("encode library"))
}

/// A record's digest (its successor's predecessor), lowercase hex.
#[wasm_bindgen(js_name = photosLibraryDigest)]
pub fn photos_library_digest(envelope_base64: &str) -> Result<String, JsValue> {
    use kutup_crypto::photos_library;
    let envelope = photos_library::decode_canonical_b64(envelope_base64)
        .map_err(|error| js_error(&error.to_string()))?;
    photos_library::envelope_digest(&envelope).map_err(|error| js_error(&error.to_string()))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PhotosLibraryHeaderJson {
    account_incarnation_id: String,
    revision: f64,
    /// Absent for revision 1.
    previous_digest: Option<String>,
}

/// A library record's public header: whose, which revision, after which one.
#[wasm_bindgen(js_name = inspectPhotosLibrary)]
pub fn inspect_photos_library(envelope_base64: &str) -> Result<JsValue, JsValue> {
    use kutup_crypto::photos_library;
    let envelope = photos_library::decode_canonical_b64(envelope_base64)
        .map_err(|error| js_error(&error.to_string()))?;
    let header =
        photos_library::inspect(&envelope).map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&PhotosLibraryHeaderJson {
        account_incarnation_id: hex::encode(header.account_incarnation_id),
        revision: header.revision as f64,
        previous_digest: (header.revision > 1)
            .then(|| hex::encode(header.previous_envelope_digest)),
    })
    .map_err(|_| js_error("encode header"))
}

// --- mail address keys (docs/plans/mail-address-keys.md) ---------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MailAddressKeyView {
    /// Binary OpenPGP public key, base64.
    public_key: String,
    /// The secret key sealed under the master key, base64. The secret key
    /// itself never leaves WASM.
    envelope: String,
    fingerprint: String,
    sha256_fingerprint: String,
}

fn master_key_32(master_key_base64: &str) -> Result<[u8; 32], JsValue> {
    decode_canonical_base64(master_key_base64, "master key")?
        .try_into()
        .map_err(|_| js_error("master key must be 32 bytes"))
}

/// Generates an address key and seals its secret part under the master key.
#[wasm_bindgen(js_name = generateMailAddressKey)]
pub fn generate_mail_address_key(
    master_key_base64: &str,
    login_email: &str,
    address: &str,
    created_at_secs: u32,
) -> Result<JsValue, JsValue> {
    let master_key = master_key_32(master_key_base64)?;
    let key = kutup_crypto::mail_key::generate_address_key(address, created_at_secs)
        .map_err(|error| js_error(&error.to_string()))?;
    let envelope = kutup_crypto::mail_key::seal_address_key(
        &master_key,
        login_email,
        address,
        &key.secret_key,
    )
    .map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&MailAddressKeyView {
        public_key: STANDARD.encode(&key.public_key),
        envelope: STANDARD.encode(envelope),
        fingerprint: hex::encode(key.fingerprint),
        sha256_fingerprint: hex::encode(key.sha256_fingerprint),
    })
    .map_err(|error| js_error(&format!("encode mail address key: {error}")))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MailPublicKeyView {
    fingerprint: String,
    sha256_fingerprint: String,
    created_at: u32,
}

/// Checks that a public key is a Kutup address key for `address`.
#[wasm_bindgen(js_name = inspectMailAddressPublicKey)]
pub fn inspect_mail_address_public_key(
    public_key_base64: &str,
    address: &str,
) -> Result<JsValue, JsValue> {
    let public_key = decode_canonical_base64(public_key_base64, "public key")?;
    let info = kutup_crypto::mail_key::inspect_address_public_key(&public_key, address)
        .map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&MailPublicKeyView {
        fingerprint: hex::encode(info.fingerprint),
        sha256_fingerprint: hex::encode(info.sha256_fingerprint),
        created_at: info.created_at_secs,
    })
    .map_err(|error| js_error(&format!("encode public key: {error}")))
}

fn open_mail_secret(
    master_key_base64: &str,
    login_email: &str,
    address: &str,
    envelope_base64: &str,
    fingerprint_hex: &str,
) -> Result<zeroize::Zeroizing<Vec<u8>>, JsValue> {
    let master_key = master_key_32(master_key_base64)?;
    let envelope = decode_canonical_base64(envelope_base64, "envelope")?;
    let fingerprint: [u8; 20] = hex::decode(fingerprint_hex)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| js_error("fingerprint must be 40 hex digits"))?;
    kutup_crypto::mail_key::open_address_key(
        &envelope,
        &master_key,
        login_email,
        address,
        &fingerprint,
    )
    .map_err(|error| js_error(&error.to_string()))
}

/// A message opened with an address key (docs/plans/mail.md).
#[wasm_bindgen(js_name = OpenedMail)]
pub struct OpenedMailJs {
    data: Vec<u8>,
    signed: bool,
    verified: bool,
}

#[wasm_bindgen(js_class = OpenedMail)]
impl OpenedMailJs {
    /// The message as sent: RFC 5322 bytes.
    #[wasm_bindgen(getter)]
    pub fn data(&self) -> Vec<u8> {
        self.data.clone()
    }

    /// Whether the message carried an OpenPGP signature.
    #[wasm_bindgen(getter)]
    pub fn signed(&self) -> bool {
        self.signed
    }

    /// Whether that signature is valid for the sender key given.
    #[wasm_bindgen(getter)]
    pub fn verified(&self) -> bool {
        self.verified
    }
}

/// Opens a stored message with the address key sealed in `envelope`; the
/// secret key never leaves WASM. With `sender_public_key_base64`, checks the
/// message's signature against it.
#[wasm_bindgen(js_name = openMailMessage)]
#[allow(clippy::too_many_arguments)]
pub fn open_mail_message(
    master_key_base64: &str,
    login_email: &str,
    address: &str,
    envelope_base64: &str,
    fingerprint_hex: &str,
    message: &[u8],
    sender_public_key_base64: Option<String>,
) -> Result<OpenedMailJs, JsValue> {
    let secret = open_mail_secret(
        master_key_base64,
        login_email,
        address,
        envelope_base64,
        fingerprint_hex,
    )?;
    let sender = sender_public_key_base64
        .map(|key| decode_canonical_base64(&key, "sender public key"))
        .transpose()?;
    let opened = kutup_crypto::mail_key::decrypt(&secret, message, sender.as_deref())
        .map_err(|error| js_error(&error.to_string()))?;
    Ok(OpenedMailJs {
        data: opened.data.to_vec(),
        signed: opened.signed,
        verified: opened.verified,
    })
}

/// A message encrypted once for several recipients and split into key
/// packets and a shared data packet.
#[wasm_bindgen(js_name = SealedMail)]
pub struct SealedMailJs {
    key_packets: Vec<String>,
    data_packet: Vec<u8>,
}

#[wasm_bindgen(js_class = SealedMail)]
impl SealedMailJs {
    /// One base64 key packet per recipient key, in the order given.
    #[wasm_bindgen(getter, js_name = keyPackets)]
    pub fn key_packets(&self) -> Vec<String> {
        self.key_packets.clone()
    }

    #[wasm_bindgen(getter, js_name = dataPacket)]
    pub fn data_packet(&self) -> Vec<u8> {
        self.data_packet.clone()
    }
}

/// Encrypts `plaintext` to every key in `recipient_public_keys` (base64,
/// include your own for your copy), signed with the address key sealed in
/// `envelope`.
#[wasm_bindgen(js_name = encryptMailMessage)]
#[allow(clippy::too_many_arguments)]
pub fn encrypt_mail_message(
    master_key_base64: &str,
    login_email: &str,
    address: &str,
    envelope_base64: &str,
    fingerprint_hex: &str,
    recipient_public_keys: Vec<String>,
    plaintext: &[u8],
) -> Result<SealedMailJs, JsValue> {
    let secret = open_mail_secret(
        master_key_base64,
        login_email,
        address,
        envelope_base64,
        fingerprint_hex,
    )?;
    let keys = recipient_public_keys
        .iter()
        .map(|key| decode_canonical_base64(key, "recipient public key"))
        .collect::<Result<Vec<_>, _>>()?;
    let refs: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
    let split = kutup_crypto::mail_key::encrypt_split(&refs, &secret, plaintext)
        .map_err(|error| js_error(&error.to_string()))?;
    Ok(SealedMailJs {
        key_packets: split
            .key_packets
            .iter()
            .map(|p| STANDARD.encode(p))
            .collect(),
        data_packet: split.data_packet,
    })
}

/// An ASCII-armored public key, for "Download public key".
#[wasm_bindgen(js_name = armorMailPublicKey)]
pub fn armor_mail_public_key(public_key_base64: &str) -> Result<String, JsValue> {
    let public_key = decode_canonical_base64(public_key_base64, "public key")?;
    kutup_crypto::mail_key::armor_public_key(&public_key)
        .map_err(|error| js_error(&error.to_string()))
}

#[derive(serde::Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct MailKeyEntryView {
    fingerprint: String,
    sha256_fingerprint: String,
    primary: bool,
    flags: u32,
}

#[derive(serde::Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct MailKeyListInput {
    account: String,
    address: String,
    sequence: u64,
    #[serde(default)]
    previous_hash: Option<String>,
    issued_at: String,
    keys: Vec<MailKeyEntryView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedMailKeyListView {
    data: String,
    signature: String,
    hash: String,
    account: String,
    address: String,
    sequence: u64,
    previous_hash: Option<String>,
    issued_at: String,
    keys: Vec<MailKeyEntryView>,
}

fn hex_array<const N: usize>(value: &str, field: &str) -> Result<[u8; N], JsValue> {
    let decoded =
        hex::decode(value).map_err(|_| js_error(&format!("{field} must be lowercase hex")))?;
    if hex::encode(&decoded) != value {
        return Err(js_error(&format!("{field} must be lowercase hex")));
    }
    decoded
        .try_into()
        .map_err(|_| js_error(&format!("{field} has the wrong length")))
}

fn signed_list_view(signed: &kutup_crypto::mail_key::SignedMailKeyListV1) -> SignedMailKeyListView {
    let list = &signed.list;
    SignedMailKeyListView {
        data: STANDARD.encode(&signed.data),
        signature: STANDARD.encode(signed.signature),
        hash: hex::encode(signed.hash()),
        account: list.account.clone(),
        address: list.address.clone(),
        sequence: list.sequence,
        previous_hash: list.previous_hash.map(hex::encode),
        issued_at: list.issued_at.clone(),
        keys: list
            .keys
            .iter()
            .map(|key| MailKeyEntryView {
                fingerprint: hex::encode(key.fingerprint),
                sha256_fingerprint: hex::encode(key.sha256_fingerprint),
                primary: key.primary,
                flags: key.flags,
            })
            .collect(),
    }
}

/// Signs an address's key list with the account authority derived from the
/// master key; the authority and incarnation ids are filled in here.
#[wasm_bindgen(js_name = signMailKeyList)]
pub fn sign_mail_key_list(master_key_base64: &str, list: JsValue) -> Result<JsValue, JsValue> {
    let master_key = master_key_32(master_key_base64)?;
    let input: MailKeyListInput = serde_wasm_bindgen::from_value(list)
        .map_err(|error| js_error(&format!("key list: {error}")))?;
    let identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(&master_key)
        .map_err(|error| js_error(&error.to_string()))?;
    let mut keys = Vec::with_capacity(input.keys.len());
    for key in &input.keys {
        keys.push(kutup_crypto::mail_key::MailKeyEntryV1 {
            fingerprint: hex_array(&key.fingerprint, "fingerprint")?,
            sha256_fingerprint: hex_array(&key.sha256_fingerprint, "sha256Fingerprint")?,
            primary: key.primary,
            flags: key.flags,
        });
    }
    let list = kutup_crypto::mail_key::MailKeyListV1 {
        account: input.account,
        incarnation_id: hex_array(&identity.incarnation_id(), "incarnation")?,
        authority_key_id: hex_array(&identity.authority_key_id(), "authority key id")?,
        address: input.address,
        sequence: input.sequence,
        previous_hash: match &input.previous_hash {
            Some(hash) => Some(hex_array(hash, "previousHash")?),
            None => None,
        },
        issued_at: input.issued_at,
        keys,
    };
    let signed = list
        .sign(identity.authority_signing_key())
        .map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&signed_list_view(&signed))
        .map_err(|error| js_error(&format!("encode key list: {error}")))
}

/// Verifies a signed key list against the account authority (from the
/// account's verified manifest) and, when given, that it directly follows
/// `previous`.
#[wasm_bindgen(js_name = verifyMailKeyList)]
pub fn verify_mail_key_list(
    data_base64: &str,
    signature_base64: &str,
    authority_public_key_base64: &str,
    previous_data_base64: Option<String>,
    previous_signature_base64: Option<String>,
) -> Result<JsValue, JsValue> {
    use kutup_crypto::mail_key::SignedMailKeyListV1;
    let authority: [u8; 32] =
        decode_canonical_base64(authority_public_key_base64, "authority key")?
            .try_into()
            .map_err(|_| js_error("authority key must be 32 bytes"))?;
    let verify = |data: &str, signature: &str| -> Result<SignedMailKeyListV1, JsValue> {
        SignedMailKeyListV1::verify(
            &decode_canonical_base64(data, "key list")?,
            &decode_canonical_base64(signature, "key list signature")?,
            &authority,
        )
        .map_err(|error| js_error(&error.to_string()))
    };
    let signed = verify(data_base64, signature_base64)?;
    match (previous_data_base64, previous_signature_base64) {
        (Some(data), Some(signature)) => verify(&data, &signature)?
            .check_successor(&signed)
            .map_err(|error| js_error(&error.to_string()))?,
        (None, None) => {}
        _ => return Err(js_error("previous key list needs both data and signature")),
    }
    serde_wasm_bindgen::to_value(&signed_list_view(&signed))
        .map_err(|error| js_error(&format!("encode key list: {error}")))
}

// --- contacts (docs/plans/contacts.md) ---------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedContactSummaryView {
    /// The canonical summary JSON, exactly as signed and stored.
    summary: String,
    signature: String,
}

/// Canonicalizes and signs a contact summary (JSON text) with the account
/// authority derived from the master key.
#[wasm_bindgen(js_name = signContactSummary)]
pub fn sign_contact_summary(
    master_key_base64: &str,
    account: &str,
    summary_json: &str,
) -> Result<JsValue, JsValue> {
    let master_key = master_key_32(master_key_base64)?;
    let summary: kutup_crypto::contact_card::ContactSummaryV1 = serde_json::from_str(summary_json)
        .map_err(|error| js_error(&format!("contact summary: {error}")))?;
    let identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(&master_key)
        .map_err(|error| js_error(&error.to_string()))?;
    let (bytes, signature) = kutup_crypto::contact_card::sign_summary(
        &summary,
        account,
        identity.authority_signing_key(),
    )
    .map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&SignedContactSummaryView {
        summary: String::from_utf8(bytes).map_err(|_| js_error("summary is not UTF-8"))?,
        signature: STANDARD.encode(signature),
    })
    .map_err(|error| js_error(&format!("encode summary: {error}")))
}

/// Verifies a stored contact summary against the account authority and
/// returns it parsed.
#[wasm_bindgen(js_name = verifyContactSummary)]
pub fn verify_contact_summary(
    summary: &str,
    signature_base64: &str,
    account: &str,
    authority_public_key_base64: &str,
) -> Result<JsValue, JsValue> {
    let authority: [u8; 32] =
        decode_canonical_base64(authority_public_key_base64, "authority key")?
            .try_into()
            .map_err(|_| js_error("authority key must be 32 bytes"))?;
    let signature = decode_canonical_base64(signature_base64, "signature")?;
    let parsed = kutup_crypto::contact_card::verify_summary(
        summary.as_bytes(),
        &signature,
        account,
        &authority,
    )
    .map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&parsed)
        .map_err(|error| js_error(&format!("encode summary: {error}")))
}

/// Seals a contact's vCard text under the contacts key, bound to its UID.
#[wasm_bindgen(js_name = sealContactCard)]
pub fn seal_contact_card(
    master_key_base64: &str,
    account: &str,
    uid: &str,
    vcard: &str,
) -> Result<String, JsValue> {
    let master_key = master_key_32(master_key_base64)?;
    let key = kutup_crypto::contact_card::derive_contacts_key(&master_key)
        .map_err(|error| js_error(&error.to_string()))?;
    let sealed = kutup_crypto::contact_card::seal_card(&key, account, uid, vcard.as_bytes())
        .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(sealed))
}

/// Opens a sealed contact card and returns its vCard text.
#[wasm_bindgen(js_name = openContactCard)]
pub fn open_contact_card(
    master_key_base64: &str,
    account: &str,
    uid: &str,
    sealed_base64: &str,
) -> Result<String, JsValue> {
    let master_key = master_key_32(master_key_base64)?;
    let key = kutup_crypto::contact_card::derive_contacts_key(&master_key)
        .map_err(|error| js_error(&error.to_string()))?;
    let sealed = decode_canonical_base64(sealed_base64, "card")?;
    let vcard = kutup_crypto::contact_card::open_card(&key, account, uid, &sealed)
        .map_err(|error| js_error(&error.to_string()))?;
    String::from_utf8(vcard.to_vec()).map_err(|_| js_error("contact card is not UTF-8"))
}
