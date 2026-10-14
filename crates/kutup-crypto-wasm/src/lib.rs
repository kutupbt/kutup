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
    binding: &str,
) -> Result<String, JsValue> {
    let entropy = STANDARD
        .decode(recovery_entropy_base64)
        .map_err(|_| js_error("recovery entropy must be canonical base64"))?;
    if STANDARD.encode(&entropy) != recovery_entropy_base64 {
        return Err(js_error("recovery entropy must be canonical base64"));
    }
    let proof = kdf::derive_recovery_auth_proof(&entropy, binding)
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
    binding: &str,
) -> Result<String, JsValue> {
    let plaintext = decode_canonical_base64(plaintext_base64, "plaintext")?;
    let key = decode_canonical_base64(key_base64, "key")?;
    let purpose = generic_account_purpose(purpose)?;
    account_envelope::seal_b64(&plaintext, &key, purpose, binding)
        .map_err(|error| js_error(&error.to_string()))
}

/// Open one account secret only when its purpose and login-email binding match.
#[wasm_bindgen(js_name = openAccountEnvelope)]
pub fn open_account_envelope(
    envelope_base64: &str,
    key_base64: &str,
    expected_purpose: u8,
    binding: &str,
) -> Result<String, JsValue> {
    let key = decode_canonical_base64(key_base64, "key")?;
    let purpose = generic_account_purpose(expected_purpose)?;
    let plaintext = account_envelope::open_b64(envelope_base64, &key, purpose, binding)
        .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(plaintext))
}

/// Checks an account envelope's shape (suite, purpose, object, revision and
/// padded length) without a key, as the server does before storing one;
/// throws when it is malformed. Returns the purpose.
#[wasm_bindgen(js_name = inspectAccountEnvelope)]
pub fn inspect_account_envelope(envelope_base64: &str) -> Result<u8, JsValue> {
    let envelope = account_envelope::decode_canonical_b64(envelope_base64)
        .map_err(|error| js_error(&error.to_string()))?;
    account_envelope::inspect(&envelope)
        .map(|header| header.purpose.as_u8())
        .map_err(|error| js_error(&error.to_string()))
}

/// Mail address keys have typed exports (`generateMailAddressKey`), so the
/// generic account-envelope path cannot hand their secret key to JavaScript.
fn generic_account_purpose(value: u8) -> Result<AccountEnvelopePurpose, JsValue> {
    match AccountEnvelopePurpose::try_from(value).map_err(|error| js_error(&error.to_string()))? {
        AccountEnvelopePurpose::MailAddressPrivateKey | AccountEnvelopePurpose::PassVaultSecret => {
            Err(js_error(
                "this account envelope purpose has its own typed export",
            ))
        }
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

/// A 32-byte key from canonical base64, wiped when dropped (as is the decoded
/// copy).
fn master_key_32(master_key_base64: &str) -> Result<zeroize::Zeroizing<[u8; 32]>, JsValue> {
    let decoded =
        zeroize::Zeroizing::new(decode_canonical_base64(master_key_base64, "master key")?);
    let key: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| js_error("master key must be 32 bytes"))?;
    Ok(zeroize::Zeroizing::new(key))
}

/// Generates an address key and seals its secret part under the master key.
#[wasm_bindgen(js_name = generateMailAddressKey)]
pub fn generate_mail_address_key(
    master_key_base64: &str,
    binding: &str,
    address: &str,
    created_at_secs: u32,
) -> Result<JsValue, JsValue> {
    let master_key = master_key_32(master_key_base64)?;
    let key = kutup_crypto::mail_key::generate_address_key(address, created_at_secs)
        .map_err(|error| js_error(&error.to_string()))?;
    let envelope = kutup_crypto::mail_key::seal_address_key(
        &master_key[..],
        binding,
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

/// An address key as an OpenPGP file locked with `passphrase` (armored),
/// to keep or to use in another OpenPGP program.
#[wasm_bindgen(js_name = exportMailAddressKey)]
pub fn export_mail_address_key(
    master_key_base64: &str,
    binding: &str,
    address: &str,
    envelope_base64: &str,
    fingerprint_hex: &str,
    passphrase: &str,
) -> Result<String, JsValue> {
    let secret = open_mail_secret(
        master_key_base64,
        binding,
        address,
        envelope_base64,
        fingerprint_hex,
    )?;
    kutup_crypto::mail_key::export_address_secret_key(&secret, passphrase)
        .map(|armored| armored.to_string())
        .map_err(|error| js_error(&error.to_string()))
}

/// Imports an address key from an OpenPGP secret key file (unlocked with
/// `passphrase`), sealed under the master key like a generated one. Errors
/// with `wrong passphrase` when the passphrase does not open it.
#[wasm_bindgen(js_name = importMailAddressKey)]
pub fn import_mail_address_key(
    master_key_base64: &str,
    binding: &str,
    address: &str,
    file: &[u8],
    passphrase: &str,
) -> Result<JsValue, JsValue> {
    let master_key = master_key_32(master_key_base64)?;
    let key = kutup_crypto::mail_key::import_address_secret_key(file, passphrase, address)
        .map_err(|error| match error {
            kutup_crypto::CryptoError::AuthFailed => js_error("wrong passphrase"),
            error => js_error(&error.to_string()),
        })?;
    let envelope = kutup_crypto::mail_key::seal_address_key(
        &master_key[..],
        binding,
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
    binding: &str,
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
        &master_key[..],
        binding,
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
    binding: &str,
    address: &str,
    envelope_base64: &str,
    fingerprint_hex: &str,
    message: &[u8],
    sender_public_key_base64: Option<String>,
) -> Result<OpenedMailJs, JsValue> {
    let secret = open_mail_secret(
        master_key_base64,
        binding,
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
    binding: &str,
    address: &str,
    envelope_base64: &str,
    fingerprint_hex: &str,
    recipient_public_keys: Vec<String>,
    plaintext: &[u8],
) -> Result<SealedMailJs, JsValue> {
    let secret = open_mail_secret(
        master_key_base64,
        binding,
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

// --- Shared mailboxes (docs/plans/mail-groups.md, G1b) ---------------------
//
// A shared mailbox has its own address key. Its secret part reaches each
// member as a share: an OpenPGP message encrypted to the member's address
// key. Like address keys, it is opened only here and never handed to JS.

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MailGroupKeyView {
    public_key: String,
    fingerprint: String,
    sha256_fingerprint: String,
    /// One share per member public key, in the order given.
    shares: Vec<String>,
}

fn group_fingerprint(fingerprint_hex: &str) -> Result<[u8; 20], JsValue> {
    hex::decode(fingerprint_hex)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| js_error("group fingerprint must be 40 hex digits"))
}

fn seal_shares(group_secret: &[u8], member_public_keys: &[String]) -> Result<Vec<String>, JsValue> {
    member_public_keys
        .iter()
        .map(|key| {
            let key = decode_canonical_base64(key, "member public key")?;
            kutup_crypto::mail_key::seal_group_key_share(&key, group_secret)
                .map(|share| STANDARD.encode(share))
                .map_err(|error| js_error(&error.to_string()))
        })
        .collect()
}

/// The group key's secret, opened from the caller's share with their own
/// address key (sealed in `envelope`).
#[allow(clippy::too_many_arguments)]
fn open_group_secret(
    master_key_base64: &str,
    binding: &str,
    address: &str,
    envelope_base64: &str,
    fingerprint_hex: &str,
    share_base64: &str,
    group_fingerprint_hex: &str,
) -> Result<zeroize::Zeroizing<Vec<u8>>, JsValue> {
    let member = open_mail_secret(
        master_key_base64,
        binding,
        address,
        envelope_base64,
        fingerprint_hex,
    )?;
    let share = decode_canonical_base64(share_base64, "share")?;
    kutup_crypto::mail_key::open_group_key_share(
        &member,
        &share,
        &group_fingerprint(group_fingerprint_hex)?,
    )
    .map_err(|error| js_error(&error.to_string()))
}

/// Makes a shared mailbox's key for `group_address`, with a share for each
/// member public key (base64).
#[wasm_bindgen(js_name = generateMailGroupKey)]
pub fn generate_mail_group_key(
    group_address: &str,
    created_at_secs: u32,
    member_public_keys: Vec<String>,
) -> Result<JsValue, JsValue> {
    let key = kutup_crypto::mail_key::generate_address_key(group_address, created_at_secs)
        .map_err(|error| js_error(&error.to_string()))?;
    let shares = seal_shares(&key.secret_key, &member_public_keys)?;
    serde_wasm_bindgen::to_value(&MailGroupKeyView {
        public_key: STANDARD.encode(&key.public_key),
        fingerprint: hex::encode(key.fingerprint),
        sha256_fingerprint: hex::encode(key.sha256_fingerprint),
        shares,
    })
    .map_err(|error| js_error(&format!("encode group key: {error}")))
}

/// Shares a group key the caller holds with more members (one share per
/// member public key, in order).
#[wasm_bindgen(js_name = reshareMailGroupKey)]
#[allow(clippy::too_many_arguments)]
pub fn reshare_mail_group_key(
    master_key_base64: &str,
    binding: &str,
    address: &str,
    envelope_base64: &str,
    fingerprint_hex: &str,
    share_base64: &str,
    group_fingerprint_hex: &str,
    member_public_keys: Vec<String>,
) -> Result<Vec<String>, JsValue> {
    let secret = open_group_secret(
        master_key_base64,
        binding,
        address,
        envelope_base64,
        fingerprint_hex,
        share_base64,
        group_fingerprint_hex,
    )?;
    seal_shares(&secret, &member_public_keys)
}

/// Opens a message of a shared mailbox with the group key, checking its
/// signature with `sender_public_key_base64` when given.
#[wasm_bindgen(js_name = openMailGroupMessage)]
#[allow(clippy::too_many_arguments)]
pub fn open_mail_group_message(
    master_key_base64: &str,
    binding: &str,
    address: &str,
    envelope_base64: &str,
    fingerprint_hex: &str,
    share_base64: &str,
    group_fingerprint_hex: &str,
    message: &[u8],
    sender_public_key_base64: Option<String>,
) -> Result<OpenedMailJs, JsValue> {
    let secret = open_group_secret(
        master_key_base64,
        binding,
        address,
        envelope_base64,
        fingerprint_hex,
        share_base64,
        group_fingerprint_hex,
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

/// [`encrypt_mail_message`] signed by a shared mailbox's key: a member
/// writing as the group.
fn decode_keys(recipient_public_keys: &[String]) -> Result<Vec<Vec<u8>>, JsValue> {
    recipient_public_keys
        .iter()
        .map(|key| decode_canonical_base64(key, "recipient public key"))
        .collect()
}

/// [`encrypt_mail_message`] without a signature, for a message whose sender
/// turned Sign off (docs/plans/mail-encrypt-sign.md). Needs no key.
#[wasm_bindgen(js_name = encryptMailMessageUnsigned)]
pub fn encrypt_mail_message_unsigned(
    recipient_public_keys: Vec<String>,
    plaintext: &[u8],
) -> Result<SealedMailJs, JsValue> {
    let keys = decode_keys(&recipient_public_keys)?;
    let refs: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
    let split = kutup_crypto::mail_key::encrypt_split_unsigned(&refs, plaintext)
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

/// An armored PGP message to outside keys without a signature (Sign off).
#[wasm_bindgen(js_name = encryptMailPgpUnsigned)]
pub fn encrypt_mail_pgp_unsigned(
    recipient_public_keys: Vec<String>,
    plaintext: &[u8],
) -> Result<String, JsValue> {
    let keys = decode_keys(&recipient_public_keys)?;
    let refs: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
    kutup_crypto::mail_key::encrypt_armored(&refs, None, plaintext, now_secs())
        .map_err(|error| js_error(&error.to_string()))
}

/// A detached, armored signature over a MIME part with the address key, for
/// a signed but unencrypted message (RFC 3156 `multipart/signed`).
#[wasm_bindgen(js_name = signMailDetached)]
pub fn sign_mail_detached(
    master_key_base64: &str,
    binding: &str,
    address: &str,
    envelope_base64: &str,
    fingerprint_hex: &str,
    content: &[u8],
) -> Result<String, JsValue> {
    let secret = open_mail_secret(
        master_key_base64,
        binding,
        address,
        envelope_base64,
        fingerprint_hex,
    )?;
    kutup_crypto::mail_key::sign_detached(&secret, content)
        .map_err(|error| js_error(&error.to_string()))
}

/// A cleartext signature of `text` with the address key: the body of an
/// Inline PGP message that is signed but not encrypted.
#[wasm_bindgen(js_name = signMailCleartext)]
pub fn sign_mail_cleartext(
    master_key_base64: &str,
    binding: &str,
    address: &str,
    envelope_base64: &str,
    fingerprint_hex: &str,
    text: &str,
) -> Result<String, JsValue> {
    let secret = open_mail_secret(
        master_key_base64,
        binding,
        address,
        envelope_base64,
        fingerprint_hex,
    )?;
    kutup_crypto::mail_key::sign_cleartext(&secret, text)
        .map_err(|error| js_error(&error.to_string()))
}

/// [`sign_mail_cleartext`] with a shared mailbox's key.
#[wasm_bindgen(js_name = signMailCleartextAsGroup)]
#[allow(clippy::too_many_arguments)]
pub fn sign_mail_cleartext_as_group(
    master_key_base64: &str,
    binding: &str,
    address: &str,
    envelope_base64: &str,
    fingerprint_hex: &str,
    share_base64: &str,
    group_fingerprint_hex: &str,
    text: &str,
) -> Result<String, JsValue> {
    let secret = open_group_secret(
        master_key_base64,
        binding,
        address,
        envelope_base64,
        fingerprint_hex,
        share_base64,
        group_fingerprint_hex,
    )?;
    kutup_crypto::mail_key::sign_cleartext(&secret, text)
        .map_err(|error| js_error(&error.to_string()))
}

/// [`sign_mail_detached`] with a shared mailbox's key.
#[wasm_bindgen(js_name = signMailDetachedAsGroup)]
#[allow(clippy::too_many_arguments)]
pub fn sign_mail_detached_as_group(
    master_key_base64: &str,
    binding: &str,
    address: &str,
    envelope_base64: &str,
    fingerprint_hex: &str,
    share_base64: &str,
    group_fingerprint_hex: &str,
    content: &[u8],
) -> Result<String, JsValue> {
    let secret = open_group_secret(
        master_key_base64,
        binding,
        address,
        envelope_base64,
        fingerprint_hex,
        share_base64,
        group_fingerprint_hex,
    )?;
    kutup_crypto::mail_key::sign_detached(&secret, content)
        .map_err(|error| js_error(&error.to_string()))
}

#[wasm_bindgen(js_name = encryptMailMessageAsGroup)]
#[allow(clippy::too_many_arguments)]
pub fn encrypt_mail_message_as_group(
    master_key_base64: &str,
    binding: &str,
    address: &str,
    envelope_base64: &str,
    fingerprint_hex: &str,
    share_base64: &str,
    group_fingerprint_hex: &str,
    recipient_public_keys: Vec<String>,
    plaintext: &[u8],
) -> Result<SealedMailJs, JsValue> {
    let secret = open_group_secret(
        master_key_base64,
        binding,
        address,
        envelope_base64,
        fingerprint_hex,
        share_base64,
        group_fingerprint_hex,
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

/// [`encrypt_mail_pgp`] signed by a shared mailbox's key.
#[wasm_bindgen(js_name = encryptMailPgpAsGroup)]
#[allow(clippy::too_many_arguments)]
pub fn encrypt_mail_pgp_as_group(
    master_key_base64: &str,
    binding: &str,
    address: &str,
    envelope_base64: &str,
    fingerprint_hex: &str,
    share_base64: &str,
    group_fingerprint_hex: &str,
    recipient_public_keys: Vec<String>,
    plaintext: &[u8],
) -> Result<String, JsValue> {
    let secret = open_group_secret(
        master_key_base64,
        binding,
        address,
        envelope_base64,
        fingerprint_hex,
        share_base64,
        group_fingerprint_hex,
    )?;
    let keys = recipient_public_keys
        .iter()
        .map(|key| decode_canonical_base64(key, "recipient public key"))
        .collect::<Result<Vec<_>, _>>()?;
    let refs: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
    kutup_crypto::mail_key::encrypt_armored_signed(&refs, &secret, plaintext, now_secs())
        .map_err(|error| js_error(&error.to_string()))
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = Date, js_name = now)]
    fn date_now() -> f64;
}

/// The browser's clock, for key expiry checks.
fn now_secs() -> u64 {
    (date_now() / 1000.0) as u64
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExternalMailKeyView {
    /// The key, binary, base64.
    public_key: String,
    fingerprint: String,
    created_at: u32,
}

/// Checks an outside correspondent's key for `address` (docs/plans/mail.md,
/// C3): self-signed, not revoked or expired, a user ID for the address and
/// an encryption subkey. Armored or binary (base64) in.
#[wasm_bindgen(js_name = inspectExternalMailKey)]
pub fn inspect_external_mail_key(public_key: &[u8], address: &str) -> Result<JsValue, JsValue> {
    let info = kutup_crypto::mail_key::inspect_external_public_key(public_key, address, now_secs())
        .map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&ExternalMailKeyView {
        public_key: STANDARD.encode(&info.public_key),
        fingerprint: info.fingerprint,
        created_at: info.created_at_secs,
    })
    .map_err(|error| js_error(&format!("encode key: {error}")))
}

/// An outside key as it is, unchecked (a contact's pinned key, perhaps
/// expired): binary base64, fingerprint and creation time.
#[wasm_bindgen(js_name = describeExternalMailKey)]
pub fn describe_external_mail_key(public_key: &[u8]) -> Result<JsValue, JsValue> {
    let info = kutup_crypto::mail_key::describe_external_public_key(public_key)
        .map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&ExternalMailKeyView {
        public_key: STANDARD.encode(&info.public_key),
        fingerprint: info.fingerprint,
        created_at: info.created_at_secs,
    })
    .map_err(|error| js_error(&format!("encode key: {error}")))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExternalMailKeyDetailsView {
    public_key: String,
    fingerprint: String,
    created_at: u32,
    expires_at: Option<u64>,
    algorithm: String,
    /// `usable`, `expired`, `revoked`, `otherAddress` or `cannotEncrypt`.
    state: &'static str,
}

/// An outside key as a contact's key table lists it (Proton's
/// `ContactKeysTable`): type, expiry, and where it stands for `address`
/// now; an expired or revoked key is described, not refused.
#[wasm_bindgen(js_name = describeExternalMailKeyDetails)]
pub fn describe_external_mail_key_details(
    public_key: &[u8],
    address: &str,
) -> Result<JsValue, JsValue> {
    let details =
        kutup_crypto::mail_key::describe_external_key_details(public_key, address, now_secs())
            .map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&ExternalMailKeyDetailsView {
        public_key: STANDARD.encode(&details.info.public_key),
        fingerprint: details.info.fingerprint,
        created_at: details.info.created_at_secs,
        expires_at: details.expires_at_secs,
        algorithm: details.algorithm,
        state: details.state.as_str(),
    })
    .map_err(|error| js_error(&format!("encode key: {error}")))
}

/// Encrypts `plaintext` to outside keys and the sender's own (base64),
/// signed inside with the address key sealed in `envelope`: the armored
/// message for a PGP/MIME `multipart/encrypted` part.
#[wasm_bindgen(js_name = encryptMailPgp)]
#[allow(clippy::too_many_arguments)]
pub fn encrypt_mail_pgp(
    master_key_base64: &str,
    binding: &str,
    address: &str,
    envelope_base64: &str,
    fingerprint_hex: &str,
    recipient_public_keys: Vec<String>,
    plaintext: &[u8],
) -> Result<String, JsValue> {
    let secret = open_mail_secret(
        master_key_base64,
        binding,
        address,
        envelope_base64,
        fingerprint_hex,
    )?;
    let keys = recipient_public_keys
        .iter()
        .map(|key| decode_canonical_base64(key, "recipient public key"))
        .collect::<Result<Vec<_>, _>>()?;
    let refs: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
    kutup_crypto::mail_key::encrypt_armored_signed(&refs, &secret, plaintext, now_secs())
        .map_err(|error| js_error(&error.to_string()))
}

/// Whether a `multipart/signed` signature (armored or binary) signs
/// `content` with `signer_public_key` (base64).
#[wasm_bindgen(js_name = verifyMailDetachedSignature)]
pub fn verify_mail_detached_signature(
    signature: &[u8],
    content: &[u8],
    signer_public_key_base64: &str,
) -> Result<bool, JsValue> {
    let signer = decode_canonical_base64(signer_public_key_base64, "signer public key")?;
    kutup_crypto::mail_key::verify_detached(signature, content, &signer)
        .map_err(|error| js_error(&error.to_string()))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CleartextView {
    text: String,
    verified: bool,
}

/// A cleartext-signed message's text, and whether it verifies against the
/// signer's key (base64) when given.
#[wasm_bindgen(js_name = verifyMailCleartext)]
pub fn verify_mail_cleartext(
    message: &str,
    signer_public_key_base64: Option<String>,
) -> Result<JsValue, JsValue> {
    let signer = signer_public_key_base64
        .map(|key| decode_canonical_base64(&key, "signer public key"))
        .transpose()?;
    let (text, verified) = kutup_crypto::mail_key::verify_cleartext(message, signer.as_deref())
        .map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&CleartextView { text, verified })
        .map_err(|error| js_error(&format!("encode cleartext: {error}")))
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

// --- Drive identity (docs/plans/drive-identity-pins.md) ------------------------

fn public_key_32(value: &str, what: &str) -> Result<[u8; 32], JsValue> {
    decode_canonical_base64(value, what)?
        .try_into()
        .map_err(|_| js_error(&format!("{what} must be 32 bytes")))
}

/// The account's Drive key binding: its authority vouching for its Drive keys.
#[wasm_bindgen(js_name = signDriveKeyBinding)]
pub fn sign_drive_key_binding(master_key_base64: &str, account: &str) -> Result<String, JsValue> {
    let master_key = master_key_32(master_key_base64)?;
    let identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(&master_key)
        .map_err(|error| js_error(&error.to_string()))?;
    let signature = kutup_crypto::drive_key_binding::sign(&identity, account)
        .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(signature))
}

/// Whether `authority` vouches for these Drive keys of `account`.
#[wasm_bindgen(js_name = verifyDriveKeyBinding)]
pub fn verify_drive_key_binding(
    account: &str,
    authority_public_key_base64: &str,
    drive_hpke_public_key_base64: &str,
    drive_signing_public_key_base64: &str,
    binding_base64: &str,
) -> bool {
    let check = || -> Result<(), JsValue> {
        let signature = decode_canonical_base64(binding_base64, "binding")?;
        kutup_crypto::drive_key_binding::verify(
            account,
            &public_key_32(authority_public_key_base64, "authority key")?,
            &public_key_32(drive_hpke_public_key_base64, "Drive HPKE key")?,
            &public_key_32(drive_signing_public_key_base64, "Drive signing key")?,
            &signature,
        )
        .map_err(|error| js_error(&error.to_string()))
    };
    check().is_ok()
}

/// The incarnation id an authority key stands for.
#[wasm_bindgen(js_name = incarnationIdOfAuthority)]
pub fn incarnation_id_of_authority(authority_public_key_base64: &str) -> Result<String, JsValue> {
    Ok(
        kutup_crypto::identity::incarnation_id_from_authority_public(&public_key_32(
            authority_public_key_base64,
            "authority key",
        )?),
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SafetyNumberView {
    fingerprint: String,
    qr_payload: String,
}

/// The safety number of two accounts, given their authority keys (the same
/// one Chat shows; no address, so a rename keeps it).
#[wasm_bindgen(js_name = deriveSafetyNumber)]
pub fn derive_safety_number(
    local_authority_base64: &str,
    peer_authority_base64: &str,
) -> Result<JsValue, JsValue> {
    let number = kutup_crypto::safety_number::derive(
        &public_key_32(local_authority_base64, "local authority key")?,
        &public_key_32(peer_authority_base64, "peer authority key")?,
    )
    .map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&SafetyNumberView {
        fingerprint: number.fingerprint,
        qr_payload: number.qr_payload,
    })
    .map_err(|error| js_error(&format!("encode safety number: {error}")))
}

/// Whether a scanned safety QR is exactly the one for these two authorities.
#[wasm_bindgen(js_name = safetyQrMatches)]
pub fn safety_qr_matches(
    local_authority_base64: &str,
    peer_authority_base64: &str,
    scanned: &str,
) -> bool {
    let (Ok(local), Ok(peer)) = (
        public_key_32(local_authority_base64, "local authority key"),
        public_key_32(peer_authority_base64, "peer authority key"),
    ) else {
        return false;
    };
    kutup_crypto::safety_number::derive(&local, &peer)
        .is_ok_and(|number| kutup_crypto::safety_number::matches_qr_payload(&number, scanned))
}

/// A revision from JavaScript: a positive safe integer (unix milliseconds
/// for contacts, mail names and identity pins).
fn revision_arg(revision: f64) -> Result<u64, JsValue> {
    if revision.fract() != 0.0 || !(1.0..=9_007_199_254_740_991.0).contains(&revision) {
        return Err(js_error("revision must be a positive safe integer"));
    }
    Ok(revision as u64)
}

/// Seals the account's identity pin list (canonical JSON) at `revision`,
/// bound to the account's key binding.
#[wasm_bindgen(js_name = sealIdentityPins)]
pub fn seal_identity_pins(
    master_key_base64: &str,
    binding: &str,
    revision: f64,
    pins_json: &str,
) -> Result<String, JsValue> {
    let master_key = master_key_32(master_key_base64)?;
    let list: kutup_crypto::identity_pins::IdentityPinsV1 = serde_json::from_str(pins_json)
        .map_err(|error| js_error(&format!("identity pins: {error}")))?;
    let key = kutup_crypto::identity_pins::derive_key(&master_key)
        .map_err(|error| js_error(&error.to_string()))?;
    let sealed = kutup_crypto::identity_pins::seal(&key, binding, revision_arg(revision)?, &list)
        .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(sealed))
}

/// A sealed value opened, with the revision it was sealed at (a number:
/// unix milliseconds stay below 2^53).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Revisioned<T: Serialize> {
    value: T,
    revision: f64,
}

fn revisioned<T: Serialize>(value: T, revision: u64) -> Result<JsValue, JsValue> {
    if revision > 9_007_199_254_740_991 {
        return Err(js_error("revision is past a safe integer"));
    }
    serde_wasm_bindgen::to_value(&Revisioned {
        value,
        revision: revision as f64,
    })
    .map_err(|error| js_error(&format!("encode: {error}")))
}

/// Opens the identity pin list of the account whose key binding is
/// `binding`: `{ value: its JSON, revision }`.
#[wasm_bindgen(js_name = openIdentityPins)]
pub fn open_identity_pins(
    master_key_base64: &str,
    binding: &str,
    sealed_base64: &str,
) -> Result<JsValue, JsValue> {
    let master_key = master_key_32(master_key_base64)?;
    let key = kutup_crypto::identity_pins::derive_key(&master_key)
        .map_err(|error| js_error(&error.to_string()))?;
    let sealed = decode_canonical_base64(sealed_base64, "identity pins")?;
    let (list, revision) = kutup_crypto::identity_pins::open(&key, binding, &sealed)
        .map_err(|error| js_error(&error.to_string()))?;
    let json = String::from_utf8(
        kutup_crypto::identity_pins::encode(&list).map_err(|error| js_error(&error.to_string()))?,
    )
    .map_err(|_| js_error("identity pins are not UTF-8"))?;
    revisioned(json, revision)
}

fn pins_arg(pins_json: &str) -> Result<kutup_crypto::identity_pins::IdentityPinsV1, JsValue> {
    let list: kutup_crypto::identity_pins::IdentityPinsV1 = serde_json::from_str(pins_json)
        .map_err(|error| js_error(&format!("identity pins: {error}")))?;
    list.validate()
        .map_err(|error| js_error(&error.to_string()))?;
    Ok(list)
}

fn pins_json(list: &kutup_crypto::identity_pins::IdentityPinsV1) -> Result<String, JsValue> {
    String::from_utf8(
        kutup_crypto::identity_pins::encode(list).map_err(|error| js_error(&error.to_string()))?,
    )
    .map_err(|_| js_error("identity pins are not UTF-8"))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PinsChanged<T: Serialize> {
    /// The list after, canonical JSON.
    pins: String,
    #[serde(flatten)]
    result: T,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordedJs {
    /// Whether the list differs from before (save it then).
    changed: bool,
    result: kutup_crypto::identity_pins::Recorded,
}

/// Records what a client learned about `account` (`update`: `firstSeen`,
/// `accepted` or `verified`), by the rules every app shares:
/// `{ pins, changed, result: { kind: "pinned" | "unchanged" |
/// "formerAddressTaken" | "knownElsewhere", … } }`.
#[wasm_bindgen(js_name = recordIdentityPin)]
pub fn record_identity_pin(
    pins_json_text: &str,
    account: &str,
    authority_public_base64: &str,
    update: &str,
    since: &str,
) -> Result<JsValue, JsValue> {
    let mut list = pins_arg(pins_json_text)?;
    let before = list.clone();
    let update: kutup_crypto::identity_pins::PinUpdate =
        serde_json::from_value(serde_json::Value::String(update.to_owned()))
            .map_err(|_| js_error("unknown pin update"))?;
    let result = kutup_crypto::identity_pins::record(
        &mut list,
        account,
        authority_public_base64,
        update,
        since,
    )
    .map_err(|error| js_error(&error.to_string()))?;
    PinsChanged {
        pins: pins_json(&list)?,
        result: RecordedJs {
            changed: list != before,
            result,
        },
    }
    .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
    .map_err(|error| js_error(&format!("encode: {error}")))
}

/// What the pin list says about `address`, given the authority its server
/// publishes now (absent: nobody, or not looked up): `{ kind: "pinned" |
/// "renamed" | "moved" | "new", pin?, sameAuthority? }`.
#[wasm_bindgen(js_name = lookupIdentityPin)]
pub fn lookup_identity_pin(
    pins_json_text: &str,
    address: &str,
    published_authority_base64: Option<String>,
) -> Result<JsValue, JsValue> {
    let list = pins_arg(pins_json_text)?;
    let found =
        kutup_crypto::identity_pins::lookup(&list, address, published_authority_base64.as_deref());
    found
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|error| js_error(&format!("encode: {error}")))
}

/// Follows a rename chain of the account whose authority is given: its pin
/// moves to the chain's current address, with its trust and history.
/// `{ pins, from, to, changed, displaced }`; throws for a chain that does not
/// verify, concerns no pinned account, or rolls back the one pinned.
#[wasm_bindgen(js_name = applyAccountRenameToPins)]
pub fn apply_account_rename_to_pins(
    pins_json_text: &str,
    authority_public_base64: &str,
    chain_json: &str,
) -> Result<JsValue, JsValue> {
    let mut list = pins_arg(pins_json_text)?;
    let authority = public_key_32(authority_public_base64, "authority key")?;
    let chain: Vec<kutup_crypto::account_rename::AccountRenameV1> =
        serde_json::from_str(chain_json).map_err(|_| js_error("invalid rename chain"))?;
    let applied = kutup_crypto::identity_pins::apply_rename(&mut list, &authority, &chain)
        .map_err(|error| js_error(&error.to_string()))?;
    PinsChanged {
        pins: pins_json(&list)?,
        result: applied,
    }
    .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
    .map_err(|error| js_error(&format!("encode: {error}")))
}

// --- contacts (docs/plans/contacts.md) ---------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedContactSummaryView {
    /// The canonical summary JSON, exactly as signed and stored.
    summary: String,
    signature: String,
}

/// Canonicalizes and signs revision `revision` of a contact summary (JSON
/// text) with the account authority derived from the master key, bound to
/// the account's key binding.
#[wasm_bindgen(js_name = signContactSummary)]
pub fn sign_contact_summary(
    master_key_base64: &str,
    binding: &str,
    revision: f64,
    summary_json: &str,
) -> Result<JsValue, JsValue> {
    let master_key = master_key_32(master_key_base64)?;
    let summary: kutup_crypto::contact_card::ContactSummaryV1 = serde_json::from_str(summary_json)
        .map_err(|error| js_error(&format!("contact summary: {error}")))?;
    let identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(&master_key)
        .map_err(|error| js_error(&error.to_string()))?;
    let (bytes, signature) = kutup_crypto::contact_card::sign_summary(
        &summary,
        binding,
        revision_arg(revision)?,
        identity.authority_signing_key(),
    )
    .map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&SignedContactSummaryView {
        summary: String::from_utf8(bytes).map_err(|_| js_error("summary is not UTF-8"))?,
        signature: STANDARD.encode(signature),
    })
    .map_err(|error| js_error(&format!("encode summary: {error}")))
}

/// Verifies a stored contact summary against the account authority, for
/// revision `revision` (its card's), and returns it parsed.
#[wasm_bindgen(js_name = verifyContactSummary)]
pub fn verify_contact_summary(
    summary: &str,
    signature_base64: &str,
    binding: &str,
    revision: f64,
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
        binding,
        revision_arg(revision)?,
        &authority,
    )
    .map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&parsed)
        .map_err(|error| js_error(&format!("encode summary: {error}")))
}

/// Seals revision `revision` of a contact's vCard text under the contacts
/// key, bound to its UID.
#[wasm_bindgen(js_name = sealContactCard)]
pub fn seal_contact_card(
    master_key_base64: &str,
    binding: &str,
    uid: &str,
    revision: f64,
    vcard: &str,
) -> Result<String, JsValue> {
    let master_key = master_key_32(master_key_base64)?;
    let key = kutup_crypto::contact_card::derive_contacts_key(&master_key)
        .map_err(|error| js_error(&error.to_string()))?;
    let sealed = kutup_crypto::contact_card::seal_card(
        &key,
        binding,
        uid,
        revision_arg(revision)?,
        vcard.as_bytes(),
    )
    .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(sealed))
}

type MailNameParts = (
    zeroize::Zeroizing<[u8; 32]>,
    kutup_crypto::mail_names::MailNameKind,
    [u8; 16],
);

fn mail_name_parts(
    master_key_base64: &str,
    kind: &str,
    id: &str,
) -> Result<MailNameParts, JsValue> {
    let master_key = master_key_32(master_key_base64)?;
    let key = kutup_crypto::mail_names::derive_names_key(&master_key)
        .map_err(|error| js_error(&error.to_string()))?;
    let kind = kutup_crypto::mail_names::MailNameKind::parse(kind)
        .map_err(|error| js_error(&error.to_string()))?;
    let id = Uuid::parse_str(id).map_err(|_| js_error("mail name id is not a UUID"))?;
    Ok((key, kind, *id.as_bytes()))
}

/// Seals the name of a mail folder, label or filter (`kind`) with id `id`
/// (a UUID) for the account whose key binding is `binding`
/// (docs/plans/mail-filters.md).
#[wasm_bindgen(js_name = sealMailName)]
pub fn seal_mail_name(
    master_key_base64: &str,
    binding: &str,
    kind: &str,
    id: &str,
    revision: f64,
    name: &str,
) -> Result<String, JsValue> {
    let (key, kind, id) = mail_name_parts(master_key_base64, kind, id)?;
    let sealed = kutup_crypto::mail_names::seal_name(
        &key,
        binding,
        kind,
        &id,
        revision_arg(revision)?,
        name,
    )
    .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(sealed))
}

/// Opens a sealed mail folder, label or filter name: `{ value: the name,
/// revision }`.
#[wasm_bindgen(js_name = openMailName)]
pub fn open_mail_name(
    master_key_base64: &str,
    binding: &str,
    kind: &str,
    id: &str,
    sealed_base64: &str,
) -> Result<JsValue, JsValue> {
    let (key, kind, id) = mail_name_parts(master_key_base64, kind, id)?;
    let sealed = decode_canonical_base64(sealed_base64, "name")?;
    let (name, revision) = kutup_crypto::mail_names::open_name(&key, binding, kind, &id, &sealed)
        .map_err(|error| js_error(&error.to_string()))?;
    revisioned(name, revision)
}

/// Opens a sealed contact card: `{ value: its vCard text, revision }`.
#[wasm_bindgen(js_name = openContactCard)]
pub fn open_contact_card(
    master_key_base64: &str,
    binding: &str,
    uid: &str,
    sealed_base64: &str,
) -> Result<JsValue, JsValue> {
    let master_key = master_key_32(master_key_base64)?;
    let key = kutup_crypto::contact_card::derive_contacts_key(&master_key)
        .map_err(|error| js_error(&error.to_string()))?;
    let sealed = decode_canonical_base64(sealed_base64, "card")?;
    let (vcard, revision) = kutup_crypto::contact_card::open_card(&key, binding, uid, &sealed)
        .map_err(|error| js_error(&error.to_string()))?;
    let text =
        String::from_utf8(vcard.to_vec()).map_err(|_| js_error("contact card is not UTF-8"))?;
    revisioned(text, revision)
}

/// The account's keys for its store of revisions seen: entry names that do
/// not reveal what they are about, and revisions sealed to their entry.
#[wasm_bindgen]
pub struct RevisionGuardKeys {
    keys: kutup_crypto::revision_guard::GuardKeys,
}

#[wasm_bindgen]
impl RevisionGuardKeys {
    #[wasm_bindgen(constructor)]
    pub fn new(master_key_base64: &str) -> Result<RevisionGuardKeys, JsValue> {
        let master_key = master_key_32(master_key_base64)?;
        Ok(Self {
            keys: kutup_crypto::revision_guard::GuardKeys::derive(&master_key)
                .map_err(|error| js_error(&error.to_string()))?,
        })
    }

    /// The store's name for `scope`/`id`.
    #[wasm_bindgen(js_name = entryId)]
    pub fn entry_id(&self, scope: &str, id: &str) -> Result<String, JsValue> {
        self.keys
            .entry_id(scope, id)
            .map_err(|error| js_error(&error.to_string()))
    }

    /// `revision` sealed for `entry` (base64).
    #[wasm_bindgen(js_name = sealSeen)]
    pub fn seal_seen(&self, entry: &str, revision: f64) -> Result<String, JsValue> {
        let sealed = self
            .keys
            .seal_seen(entry, revision_arg(revision)?)
            .map_err(|error| js_error(&error.to_string()))?;
        Ok(STANDARD.encode(sealed))
    }

    /// The revision sealed for `entry`; throws when it was moved or altered.
    #[wasm_bindgen(js_name = openSeen)]
    pub fn open_seen(&self, entry: &str, sealed_base64: &str) -> Result<f64, JsValue> {
        let sealed = decode_canonical_base64(sealed_base64, "revision")?;
        let revision = self
            .keys
            .open_seen(entry, &sealed)
            .map_err(|error| js_error(&error.to_string()))?;
        if revision > 9_007_199_254_740_991 {
            return Err(js_error("revision is past a safe integer"));
        }
        Ok(revision as f64)
    }
}

// --- OPAQUE sign-in (docs/plans/opaque.md) -----------------------------------
// The client's state, the password and the export key stay inside these
// objects: JavaScript passes messages in and out, and gets the master key
// once the account's envelope opens.

fn opaque_error(error: kutup_crypto::error::CryptoError) -> JsValue {
    match error {
        kutup_crypto::error::CryptoError::AuthFailed => js_error("opaque: authentication failed"),
        other => js_error(&other.to_string()),
    }
}

/// A registration (sign-up, password change, recovery) in progress.
#[wasm_bindgen]
pub struct OpaqueRegistration {
    state: Option<kutup_crypto::opaque::ClientRegistering>,
    request: String,
    export: Option<kutup_crypto::opaque::ExportKey>,
}

#[wasm_bindgen]
impl OpaqueRegistration {
    /// Starts registering `password`; send `request` to the server.
    pub fn start(password: &str) -> Result<OpaqueRegistration, JsValue> {
        let (state, request) =
            kutup_crypto::opaque::client_registration_start(password).map_err(opaque_error)?;
        Ok(Self {
            state: Some(state),
            request: STANDARD.encode(request),
            export: None,
        })
    }

    /// The registration request (canonical base64).
    #[wasm_bindgen(getter)]
    pub fn request(&self) -> String {
        self.request.clone()
    }

    /// Finishes with the server's response: the record to upload. Once.
    pub fn finish(&mut self, response_base64: &str) -> Result<String, JsValue> {
        let state = self
            .state
            .take()
            .ok_or_else(|| js_error("opaque: the registration is already finished"))?;
        let response = decode_canonical_base64(response_base64, "registration response")?;
        let done = state.finish(&response).map_err(opaque_error)?;
        self.export = Some(done.export_key);
        Ok(STANDARD.encode(done.record))
    }

    /// Seals the account's master key for this password: the password envelope.
    #[wasm_bindgen(js_name = sealMasterKey)]
    pub fn seal_master_key(
        &mut self,
        master_key_base64: &str,
        key_binding: &str,
    ) -> Result<String, JsValue> {
        // Once: the export key is wiped afterwards, sealed or not.
        let export = self
            .export
            .take()
            .ok_or_else(|| js_error("opaque: the registration is not finished"))?;
        export
            .seal_master_key(&*master_key_32(master_key_base64)?, key_binding)
            .map_err(opaque_error)
    }

    /// Ends the registration: its state and export key are wiped.
    pub fn close(&mut self) {
        self.state = None;
        self.export = None;
    }
}

/// A sign-in (or reauthentication) in progress.
#[wasm_bindgen]
pub struct OpaqueLogin {
    state: Option<kutup_crypto::opaque::ClientSigningIn>,
    request: String,
    export: Option<kutup_crypto::opaque::ExportKey>,
}

#[wasm_bindgen]
impl OpaqueLogin {
    /// Starts signing in with `password`; send `request` to the server.
    pub fn start(password: &str) -> Result<OpaqueLogin, JsValue> {
        let (state, request) =
            kutup_crypto::opaque::client_login_start(password).map_err(opaque_error)?;
        Ok(Self {
            state: Some(state),
            request: STANDARD.encode(request),
            export: None,
        })
    }

    /// The credential request (canonical base64).
    #[wasm_bindgen(getter)]
    pub fn request(&self) -> String {
        self.request.clone()
    }

    /// Finishes with the server's response: the finalization to send. Throws
    /// "opaque: authentication failed" for a wrong password (or an unknown
    /// name, or a server other than the one registered with). Once.
    pub fn finish(&mut self, response_base64: &str) -> Result<String, JsValue> {
        let state = self
            .state
            .take()
            .ok_or_else(|| js_error("opaque: the sign-in is already finished"))?;
        let response = decode_canonical_base64(response_base64, "credential response")?;
        let done = state.finish(&response).map_err(opaque_error)?;
        self.export = Some(done.export_key);
        Ok(STANDARD.encode(done.finalization))
    }

    /// Opens the account's password envelope (sent once the server accepted
    /// the finalization): the master key, canonical base64, as the session
    /// layer holds it. Once it opens, the export key is wiped.
    #[wasm_bindgen(js_name = openMasterKey)]
    pub fn open_master_key(
        &mut self,
        envelope: &str,
        key_binding: &str,
    ) -> Result<String, JsValue> {
        let export = self
            .export
            .as_ref()
            .ok_or_else(|| js_error("opaque: the sign-in is not finished"))?;
        let master_key = export
            .open_master_key(envelope, key_binding)
            .map_err(opaque_error)?;
        // Opened: the export key is no longer needed.
        self.export = None;
        Ok(STANDARD.encode(master_key.as_slice()))
    }

    /// Ends the sign-in: its state and export key are wiped (a reauth, which
    /// opens nothing, or a sign-in given up).
    pub fn close(&mut self) {
        self.state = None;
        self.export = None;
    }
}

/// The server's half, for tests and tools (servers use kutup-crypto directly):
/// a sealed setup opened under its key.
#[wasm_bindgen]
pub struct OpaqueServer {
    secrets: kutup_crypto::opaque::ServerSecrets,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OpaqueServerLoginJs {
    state: String,
    response: String,
}

#[wasm_bindgen]
impl OpaqueServer {
    /// Opens a setup sealed under `key` (canonical base64) for `key_id`.
    pub fn open(
        sealed_base64: &str,
        key_base64: &str,
        key_id: u16,
    ) -> Result<OpaqueServer, JsValue> {
        let sealed = decode_canonical_base64(sealed_base64, "sealed setup")?;
        let secrets =
            kutup_crypto::opaque::open_server_setup(&sealed, &*master_key_32(key_base64)?, key_id)
                .map_err(opaque_error)?;
        Ok(Self { secrets })
    }

    #[wasm_bindgen(js_name = registrationResponse)]
    pub fn registration_response(
        &self,
        request_base64: &str,
        key_binding: &str,
    ) -> Result<String, JsValue> {
        let request = decode_canonical_base64(request_base64, "registration request")?;
        kutup_crypto::opaque::server_registration_response(&self.secrets, &request, key_binding)
            .map(|response| STANDARD.encode(response))
            .map_err(opaque_error)
    }

    /// The record to store from a client's upload.
    pub fn record(upload_base64: &str) -> Result<String, JsValue> {
        let upload = decode_canonical_base64(upload_base64, "registration upload")?;
        kutup_crypto::opaque::server_registration_record(&upload)
            .map(|record| STANDARD.encode(record))
            .map_err(opaque_error)
    }

    /// Answers a sign-in request for the account with `key_binding` (its
    /// `record`), or, with no record, for the unknown `name`.
    #[wasm_bindgen(js_name = loginStart)]
    pub fn login_start(
        &self,
        record_base64: Option<String>,
        request_base64: &str,
        key_binding_or_name: &str,
    ) -> Result<JsValue, JsValue> {
        let request = decode_canonical_base64(request_base64, "credential request")?;
        let record = record_base64
            .map(|record| decode_canonical_base64(&record, "record"))
            .transpose()?;
        let credential = if record.is_some() {
            kutup_crypto::opaque::credential_identifier(key_binding_or_name)
                .map_err(opaque_error)?
        } else {
            kutup_crypto::opaque::unknown_credential_identifier(
                &kutup_crypto::opaque::CanonicalName::parse(key_binding_or_name)
                    .map_err(opaque_error)?,
            )
        };
        let started = kutup_crypto::opaque::server_login_start(
            &self.secrets,
            record.as_deref(),
            &request,
            &credential,
        )
        .map_err(opaque_error)?;
        serde_wasm_bindgen::to_value(&OpaqueServerLoginJs {
            state: STANDARD.encode(started.state),
            response: STANDARD.encode(started.response),
        })
        .map_err(|error| js_error(&format!("encode: {error}")))
    }

    /// Checks a client's finalization against the kept state.
    #[wasm_bindgen(js_name = loginFinish)]
    pub fn login_finish(state_base64: &str, finalization_base64: &str) -> Result<(), JsValue> {
        let state = decode_canonical_base64(state_base64, "login state")?;
        let finalization = decode_canonical_base64(finalization_base64, "finalization")?;
        kutup_crypto::opaque::server_login_finish(&state, &finalization).map_err(opaque_error)
    }
}

// --- the account head (docs/plans/rollback-protection.md) ---------------------

fn head_err(error: kutup_crypto::error::CryptoError) -> JsValue {
    js_error(&error.to_string())
}

fn index_arg(index_json: &str) -> Result<Vec<(String, u64)>, JsValue> {
    serde_json::from_str(index_json).map_err(|_| js_error("account head: invalid index"))
}

fn sealed_head(sealed_base64: &str) -> Result<Vec<u8>, JsValue> {
    decode_canonical_base64(sealed_base64, "account head")
}

fn anchor_arg(
    anchor_json: Option<String>,
) -> Result<Option<kutup_crypto::account_head::Anchor>, JsValue> {
    anchor_json
        .map(|json| {
            serde_json::from_str(&json).map_err(|_| js_error("account head: invalid anchor"))
        })
        .transpose()
}

fn segment_arg(segment_json: Option<String>) -> Result<Option<Vec<Vec<u8>>>, JsValue> {
    segment_json
        .map(|json| {
            let list: Vec<String> = serde_json::from_str(&json)
                .map_err(|_| js_error("account head: invalid segment"))?;
            list.iter()
                .map(|sealed| sealed_head(sealed))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()
}

fn js_json<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|error| js_error(&format!("encode: {error}")))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalAdvancedJs<'a> {
    state: &'a kutup_crypto::account_head::LocalHeadStateV1,
    changed: bool,
}

fn local_state_arg(
    state_json: &str,
    incarnation_id: &str,
) -> Result<kutup_crypto::account_head::LocalHeadStateV1, JsValue> {
    let state: kutup_crypto::account_head::LocalHeadStateV1 = serde_json::from_str(state_json)
        .map_err(|_| js_error("account head: invalid local state"))?;
    if state.incarnation_id != incarnation_id {
        return Err(js_error(
            "account head: the local state is another incarnation's",
        ));
    }
    Ok(state)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HeadCheckJs<'a> {
    status: &'a kutup_crypto::account_head::HeadStatus,
    /// What to remember now (a trusted head).
    anchor: Option<&'a kutup_crypto::account_head::Anchor>,
}

/// The account's head keys and the head this page has verified, for one
/// account (master key, key binding, incarnation), made once per session. The
/// keys never leave WASM; an index is checked, and a next head written, only
/// against the head a check (or a re-anchoring) verified here.
#[wasm_bindgen]
pub struct AccountHeadKeys {
    keys: kutup_crypto::account_head::HeadKeys,
    binding: String,
    incarnation_id: String,
    verified: Option<kutup_crypto::account_head::VerifiedHead>,
}

#[wasm_bindgen]
impl AccountHeadKeys {
    #[wasm_bindgen(constructor)]
    pub fn new(
        master_key_base64: &str,
        binding: &str,
        incarnation_id: &str,
    ) -> Result<AccountHeadKeys, JsValue> {
        let master_key = master_key_32(master_key_base64)?;
        Ok(Self {
            keys: kutup_crypto::account_head::HeadKeys::derive(&master_key).map_err(head_err)?,
            binding: binding.to_owned(),
            incarnation_id: incarnation_id.to_owned(),
            verified: None,
        })
    }

    /// The name this device stores its state under, for this account and
    /// incarnation (hex).
    #[wasm_bindgen(js_name = localStateName)]
    pub fn local_state_name(&self) -> Result<String, JsValue> {
        self.keys
            .local_state_name(&self.incarnation_id)
            .map_err(head_err)
    }

    /// A device's state before it has seen any head, with a new random device id.
    #[wasm_bindgen(js_name = newLocalState)]
    pub fn new_local_state(&self) -> Result<JsValue, JsValue> {
        js_json(
            &kutup_crypto::account_head::LocalHeadStateV1::new(&self.incarnation_id)
                .map_err(head_err)?,
        )
    }

    /// Opens this device's sealed state (canonical base64); throws when it
    /// does not open (altered, another account's or incarnation's).
    #[wasm_bindgen(js_name = openLocalState)]
    pub fn open_local_state(&self, sealed_base64: &str) -> Result<JsValue, JsValue> {
        let sealed = decode_canonical_base64(sealed_base64, "local head state")?;
        js_json(
            &kutup_crypto::account_head::open_local_state(
                &self.keys,
                &self.binding,
                &self.incarnation_id,
                &sealed,
            )
            .map_err(head_err)?,
        )
    }

    /// Seals this device's state (JSON) for storing: canonical base64.
    #[wasm_bindgen(js_name = sealLocalState)]
    pub fn seal_local_state(&self, state_json: &str) -> Result<String, JsValue> {
        let state = local_state_arg(state_json, &self.incarnation_id)?;
        let sealed =
            kutup_crypto::account_head::seal_local_state(&self.keys, &self.binding, &state)
                .map_err(head_err)?;
        Ok(STANDARD.encode(sealed))
    }

    /// Moves the state's anchor to this page's verified head (never back):
    /// `{ state, changed }`. Throws when no head is verified.
    #[wasm_bindgen(js_name = advanceLocalState)]
    pub fn advance_local_state(&self, state_json: &str, at_ms: f64) -> Result<JsValue, JsValue> {
        let verified = self
            .verified
            .as_ref()
            .ok_or_else(|| js_error("account head: no verified head"))?;
        let mut state = local_state_arg(state_json, &self.incarnation_id)?;
        let changed = state.advance(verified, at_ms as u64);
        js_json(&LocalAdvancedJs {
            state: &state,
            changed,
        })
    }

    /// After `reanchor`: the state moves to its record's head, and logs it.
    #[wasm_bindgen(js_name = reanchoredLocalState)]
    pub fn reanchored_local_state(
        &self,
        state_json: &str,
        record_json: &str,
    ) -> Result<JsValue, JsValue> {
        let mut state = local_state_arg(state_json, &self.incarnation_id)?;
        let record: kutup_crypto::account_head::Reanchored = serde_json::from_str(record_json)
            .map_err(|_| js_error("account head: invalid re-anchoring record"))?;
        // Only onto the head this page verified by re-anchoring.
        if self.verified.as_ref().map(|verified| verified.anchor()) != Some(&record.to) {
            return Err(js_error(
                "account head: the record is not this page's re-anchoring",
            ));
        }
        state.reanchored(&record);
        js_json(&state)
    }

    /// The server has no head at all and the person confirmed going on with
    /// its data: the state's anchor is dropped, and logged.
    #[wasm_bindgen(js_name = forgottenLocalState)]
    pub fn forgotten_local_state(&self, state_json: &str, at_ms: f64) -> Result<JsValue, JsValue> {
        let mut state = local_state_arg(state_json, &self.incarnation_id)?;
        state.forgotten(at_ms as u64);
        js_json(&state)
    }

    /// This device's writer tag in the heads it writes (hex).
    pub fn writer(&self, device_id: &str) -> Result<String, JsValue> {
        self.keys.writer(device_id).map_err(head_err)
    }

    /// A scope's entry for its whole index, `[[id, revision], …]` (JSON).
    pub fn scope(&self, scope: &str, index_json: &str) -> Result<JsValue, JsValue> {
        js_json(
            &self
                .keys
                .scope_digest(scope, &index_arg(index_json)?)
                .map_err(head_err)?,
        )
    }

    /// Checks the current head against `anchor_json` (absent: nothing
    /// remembered), given the chain segment from the anchor to it (JSON list
    /// of sealed heads; absent: the server did not show it):
    /// `{ status: { kind }, anchor? }`. A trusted head (`fresh`, `current`,
    /// `extends`) becomes this page's verified head, and `anchor` is what to
    /// remember; the others leave none verified.
    pub fn check(
        &mut self,
        anchor_json: Option<String>,
        current_base64: &str,
        segment_json: Option<String>,
    ) -> Result<JsValue, JsValue> {
        // Whatever this check finds, the head verified before it no longer
        // counts: a check that fails or does not trust leaves none.
        self.verified = None;
        let segment = segment_arg(segment_json)?;
        let checked = kutup_crypto::account_head::check(
            &self.keys,
            &self.binding,
            &self.incarnation_id,
            anchor_arg(anchor_json)?.as_ref(),
            &sealed_head(current_base64)?,
            segment.as_deref(),
        )
        .map_err(head_err)?;
        self.verified = checked.verified;
        js_json(&HeadCheckJs {
            status: &checked.status,
            anchor: self.verified.as_ref().map(|verified| verified.anchor()),
        })
    }

    /// Re-anchors after a check did not trust the head: `tooOld` always,
    /// `rollback` and `fork` only when the person `confirmed` it. Runs the
    /// check again itself. Returns the record to log; the head becomes this
    /// page's verified one.
    pub fn reanchor(
        &mut self,
        anchor_json: &str,
        current_base64: &str,
        segment_json: Option<String>,
        confirmed: bool,
        at_ms: f64,
    ) -> Result<JsValue, JsValue> {
        // As in `check`: a re-anchoring that fails leaves no verified head.
        self.verified = None;
        let anchor = anchor_arg(Some(anchor_json.to_owned()))?.expect("given");
        let segment = segment_arg(segment_json)?;
        let (record, verified) = kutup_crypto::account_head::reanchor(
            &self.keys,
            &self.binding,
            &self.incarnation_id,
            &anchor,
            &sealed_head(current_base64)?,
            segment.as_deref(),
            confirmed,
            at_ms as u64,
        )
        .map_err(head_err)?;
        self.verified = Some(verified);
        js_json(&record)
    }

    /// Whether a scope's index (`[[id, revision], …]`) matches the verified
    /// head: `"matches"`, or `"uncovered"` (the head does not cover the scope
    /// yet); throws if it differs, or if no head is verified.
    #[wasm_bindgen(js_name = checkIndex)]
    pub fn check_index(&self, scope: &str, index_json: &str) -> Result<JsValue, JsValue> {
        let verified = self
            .verified
            .as_ref()
            .ok_or_else(|| js_error("account head: no verified head"))?;
        let checked = kutup_crypto::account_head::check_index(
            &self.keys,
            verified,
            scope,
            &index_arg(index_json)?,
        )
        .map_err(head_err)?;
        js_json(&checked)
    }

    /// The next head, sealed, on top of the verified one (or the account's
    /// first when none exists yet: `first`), written by `writer`, with the
    /// scope entries in `scopes_json` replaced.
    pub fn next(&self, writer: &str, scopes_json: &str) -> Result<String, JsValue> {
        let verified = self
            .verified
            .as_ref()
            .ok_or_else(|| js_error("account head: no verified head"))?;
        let scopes = serde_json::from_str(scopes_json)
            .map_err(|_| js_error("account head: invalid scopes"))?;
        let head = verified.next(writer, scopes).map_err(head_err)?;
        kutup_crypto::account_head::seal(&self.keys, &self.binding, &head)
            .map(|sealed| STANDARD.encode(sealed))
            .map_err(head_err)
    }

    /// The account's first head (the server has none), sealed; it becomes the
    /// verified head once the server stores it (`committed`).
    pub fn first(&mut self, writer: &str, scopes_json: &str) -> Result<String, JsValue> {
        let scopes = serde_json::from_str(scopes_json)
            .map_err(|_| js_error("account head: invalid scopes"))?;
        let (sealed, _) = kutup_crypto::account_head::first(
            &self.keys,
            &self.binding,
            &self.incarnation_id,
            writer,
            scopes,
        )
        .map_err(head_err)?;
        Ok(STANDARD.encode(sealed))
    }

    /// After the server stored `sealed` (this page's next or first head): it
    /// becomes the verified head; returns what to remember.
    pub fn committed(&mut self, sealed_base64: &str) -> Result<JsValue, JsValue> {
        let sealed = sealed_head(sealed_base64)?;
        let verified = match &self.verified {
            Some(verified) => verified
                .committed(&self.keys, &self.binding, &sealed)
                .map_err(head_err)?,
            None => {
                let checked = kutup_crypto::account_head::check(
                    &self.keys,
                    &self.binding,
                    &self.incarnation_id,
                    None,
                    &sealed,
                    None,
                )
                .map_err(head_err)?;
                let head = checked.verified.expect("a fresh head is verified");
                if head.head().sequence != 1 {
                    return Err(js_error("account head: not the account's first head"));
                }
                head
            }
        };
        let anchor = js_json(verified.anchor())?;
        self.verified = Some(verified);
        Ok(anchor)
    }

    /// The verified head (JSON), for reading which scopes it covers.
    #[wasm_bindgen(js_name = verifiedHead)]
    pub fn verified_head(&self) -> Result<JsValue, JsValue> {
        match &self.verified {
            Some(verified) => js_json(verified.head()),
            None => Ok(JsValue::NULL),
        }
    }
}

/// The account's statement for a collaboration device key
/// (docs/plans/device-registration.md): the authority (from the master key)
/// signs the incarnation, the server, the account, the device key, its
/// purpose, the server's one-time challenge and the time. Returns the
/// canonical base64 signature.
#[wasm_bindgen(js_name = signDeviceRegistration)]
pub fn sign_device_registration(
    master_key_base64: &str,
    server: &str,
    user_id: &str,
    device_public_base64: &str,
    challenge_base64: &str,
    issued_at_ms: f64,
) -> Result<String, JsValue> {
    let master = master_key_32(master_key_base64)?;
    let identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(&master)
        .map_err(|error| js_error(&error.to_string()))?;
    let device = public_key_32(device_public_base64, "device key")?;
    let challenge = public_key_32(challenge_base64, "challenge")?;
    let statement = kutup_crypto::device_registration::DeviceStatement {
        server,
        user_id,
        device_public: &device,
        purpose: kutup_crypto::device_registration::PURPOSE_COLLAB_FRAMES,
        challenge: &challenge,
        issued_at_ms: millis(issued_at_ms)?,
    };
    kutup_crypto::device_registration::sign(&identity, &statement)
        .map_err(|error| js_error(&error.to_string()))
}

/// The account's revocation of a device key, signed with its authority.
/// Returns the canonical base64 signature.
#[wasm_bindgen(js_name = signDeviceRevocation)]
pub fn sign_device_revocation(
    master_key_base64: &str,
    server: &str,
    device_public_base64: &str,
    revoked_at_ms: f64,
) -> Result<String, JsValue> {
    let master = master_key_32(master_key_base64)?;
    let identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(&master)
        .map_err(|error| js_error(&error.to_string()))?;
    let device = public_key_32(device_public_base64, "device key")?;
    kutup_crypto::device_registration::sign_revocation(
        &identity,
        server,
        &device,
        millis(revoked_at_ms)?,
    )
    .map_err(|error| js_error(&error.to_string()))
}

/// A time from JavaScript: positive whole milliseconds.
fn millis(value: f64) -> Result<i64, JsValue> {
    if value.fract() != 0.0 || !(1.0..=9_007_199_254_740_991.0).contains(&value) {
        return Err(js_error("time must be positive whole milliseconds"));
    }
    Ok(value as i64)
}

/// The Yjs client id a file's first content is made under, from the file id
/// and that content's update made under client id 0
/// (`kutup_crypto::yjs_seed`). A whole number below 2^53.
#[wasm_bindgen(js_name = yjsSeedClientId)]
pub fn yjs_seed_client_id(file_id: &str, content: &[u8]) -> f64 {
    kutup_crypto::yjs_seed::seed_client_id(file_id, content) as f64
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RenameChainJs {
    incarnation_id: String,
    first: String,
    current: String,
    addresses: Vec<String>,
    sequence: u64,
    /// One hex digest per statement: what a client keeps of a verified chain.
    digests: Vec<String>,
}

/// One rename, signed with the account authority derived from the master key
/// (docs/plans/username-renames.md). Returns the statement as JSON.
#[wasm_bindgen(js_name = signAccountRename)]
pub fn sign_account_rename(
    master_key_base64: &str,
    sequence: f64,
    previous: &str,
    current: &str,
    issued_at_ms: f64,
) -> Result<String, JsValue> {
    let master = master_key_32(master_key_base64)?;
    let identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(&master)
        .map_err(|error| js_error(&error.to_string()))?;
    if sequence.fract() != 0.0 || !(1.0..=1000.0).contains(&sequence) {
        return Err(js_error("invalid rename sequence"));
    }
    if issued_at_ms.fract() != 0.0 || !issued_at_ms.is_finite() {
        return Err(js_error("invalid rename time"));
    }
    let statement = kutup_crypto::account_rename::sign(
        &identity,
        sequence as u64,
        previous,
        current,
        issued_at_ms as i64,
    )
    .map_err(|error| js_error(&error.to_string()))?;
    serde_json::to_string(&statement).map_err(|error| js_error(&error.to_string()))
}

/// Verifies an account's rename chain (JSON array) against its authority key.
/// With `known_digests_json` (the digests of a chain verified before, a JSON
/// array of hex), the chain must extend it: a server cannot roll a rename
/// back. Returns where the account is and every address it has had.
#[wasm_bindgen(js_name = verifyAccountRenameChain)]
pub fn verify_account_rename_chain(
    authority_public_base64: &str,
    chain_json: &str,
    known_digests_json: Option<String>,
) -> Result<JsValue, JsValue> {
    let authority = public_key_32(authority_public_base64, "authority key")?;
    let chain: Vec<kutup_crypto::account_rename::AccountRenameV1> =
        serde_json::from_str(chain_json).map_err(|_| js_error("invalid rename chain"))?;
    let view = kutup_crypto::account_rename::verify_chain(&authority, &chain)
        .map_err(|error| js_error(&error.to_string()))?;
    let digests: Vec<String> = view.digests.iter().map(hex::encode).collect();
    if let Some(known) = known_digests_json {
        let known: Vec<String> =
            serde_json::from_str(&known).map_err(|_| js_error("invalid known digests"))?;
        if known.len() > digests.len() || digests[..known.len()] != known[..] {
            return Err(js_error(
                "the rename chain does not extend the one seen before",
            ));
        }
    }
    serde_wasm_bindgen::to_value(&RenameChainJs {
        incarnation_id: view.incarnation_id,
        first: view.first,
        current: view.current,
        addresses: view.addresses,
        sequence: view.sequence,
        digests,
    })
    .map_err(|error| js_error(&format!("encode rename chain: {error}")))
}
