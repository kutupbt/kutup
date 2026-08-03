//! Browser bindings for `kutup-crypto`.
//!
//! This crate contains no cryptographic construction or policy. It converts
//! JS transport values and delegates to the canonical Rust implementation.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};
use kutup_crypto::drive_object::{self, DriveFileBlobContextV1};
use kutup_crypto::envelope::{self, CollabFrameContextV1};
use kutup_crypto::kdf::{self, AccountProtectionParameters, AccountProtectionSuiteId};
use serde::Serialize;
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
struct OpenedCollabFrameView {
    kind: u8,
    key_epoch: u32,
    doc_key_id: u32,
    sender_device_id: String,
    sequence: String,
    plaintext: String,
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
    let purpose =
        AccountEnvelopePurpose::try_from(purpose).map_err(|error| js_error(&error.to_string()))?;
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
    let purpose = AccountEnvelopePurpose::try_from(expected_purpose)
        .map_err(|error| js_error(&error.to_string()))?;
    let plaintext = account_envelope::open_b64(envelope_base64, &key, purpose, login_email)
        .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(plaintext))
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
        DriveEnvelopePurpose::try_from(purpose).map_err(|error| js_error(&error.to_string()))?,
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
        DriveEnvelopePurpose::try_from(expected_purpose)
            .map_err(|error| js_error(&error.to_string()))?,
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
    collection_key_base64: &str,
    file_id: &str,
    collection_id: &str,
    asset_id: &str,
    epoch: u32,
) -> Result<String, JsValue> {
    let plaintext = decode_canonical_base64(plaintext_base64, "whiteboard asset")?;
    let collection_key = decode_canonical_base64(collection_key_base64, "collection key")?;
    let context = DriveEnvelopeContextV1::whiteboard_asset(file_id, collection_id, asset_id, epoch)
        .map_err(|error| js_error(&error.to_string()))?;
    drive_envelope::seal_b64(&plaintext, &collection_key, context)
        .map_err(|error| js_error(&error.to_string()))
}

#[wasm_bindgen(js_name = openWhiteboardAsset)]
pub fn open_whiteboard_asset(
    envelope_base64: &str,
    collection_key_base64: &str,
    expected_file_id: &str,
    expected_collection_id: &str,
    expected_asset_id: &str,
    expected_epoch: u32,
) -> Result<String, JsValue> {
    let collection_key = decode_canonical_base64(collection_key_base64, "collection key")?;
    let context = DriveEnvelopeContextV1::whiteboard_asset(
        expected_file_id,
        expected_collection_id,
        expected_asset_id,
        expected_epoch,
    )
    .map_err(|error| js_error(&error.to_string()))?;
    let plaintext = drive_envelope::open_b64(envelope_base64, &collection_key, context)
        .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(plaintext))
}

#[wasm_bindgen(js_name = prepareDriveFileBlob)]
pub fn prepare_drive_file_blob(
    file_key_base64: &str,
    file_id: &str,
    collection_id: &str,
    epoch: u32,
) -> Result<JsValue, JsValue> {
    let file_key = decode_canonical_base64(file_key_base64, "file key")?;
    let context = DriveFileBlobContextV1::new(file_id, collection_id, epoch)
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
    expected_collection_id: &str,
    expected_epoch: u32,
) -> Result<String, JsValue> {
    let object_header = decode_canonical_base64(object_header_base64, "object header")?;
    let file_key = decode_canonical_base64(file_key_base64, "file key")?;
    let expected =
        DriveFileBlobContextV1::new(expected_file_id, expected_collection_id, expected_epoch)
            .map_err(|error| js_error(&error.to_string()))?;
    drive_object::validate_file_blob_header(&object_header, expected)
        .map_err(|error| js_error(&error.to_string()))?;
    let stream_key = drive_object::derive_file_blob_key(&file_key, expected)
        .map_err(|error| js_error(&error.to_string()))?;
    Ok(STANDARD.encode(stream_key.as_slice()))
}

#[wasm_bindgen(js_name = sealCollabFrame)]
#[allow(clippy::too_many_arguments)]
pub fn seal_collab_frame(
    plaintext_base64: &str,
    collection_key_base64: &str,
    kind: u8,
    key_epoch: u32,
    doc_key_id: u32,
    file_id: &str,
    collection_id: &str,
    sender_device_id: &str,
    sequence: &str,
) -> Result<String, JsValue> {
    let plaintext = decode_canonical_base64(plaintext_base64, "collaboration plaintext")?;
    let collection_key = decode_canonical_base64(collection_key_base64, "collection key")?;
    let sender_device_id = sender_device_id
        .parse::<u64>()
        .map_err(|_| js_error("sender device id must be canonical u64"))?;
    let sequence = sequence
        .parse::<u64>()
        .map_err(|_| js_error("sequence must be canonical u64"))?;
    let context = CollabFrameContextV1::new(
        kind,
        key_epoch,
        doc_key_id,
        file_id,
        collection_id,
        sender_device_id,
        sequence,
    )
    .map_err(|error| js_error(&error.to_string()))?;
    envelope::seal_unsigned(&plaintext, &collection_key, context)
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
    collection_key_base64: &str,
    expected_file_id: &str,
    expected_collection_id: &str,
    expected_key_epoch: u32,
) -> Result<JsValue, JsValue> {
    let frame = decode_canonical_base64(frame_base64, "collaboration frame")?;
    let collection_key = decode_canonical_base64(collection_key_base64, "collection key")?;
    let (parsed, plaintext) = envelope::open(
        &frame,
        &collection_key,
        expected_file_id,
        expected_collection_id,
        expected_key_epoch,
    )
    .map_err(|error| js_error(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&OpenedCollabFrameView {
        kind: parsed.kind,
        key_epoch: parsed.key_epoch,
        doc_key_id: parsed.doc_key_id,
        sender_device_id: parsed.sender_device_id.to_string(),
        sequence: parsed.sequence.to_string(),
        plaintext: STANDARD.encode(plaintext),
    })
    .map_err(|error| js_error(&format!("encode collaboration frame: {error}")))
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
