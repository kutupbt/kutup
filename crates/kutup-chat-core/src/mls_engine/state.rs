//! Canonical durable snapshot for OpenMLS provider and Kutup metadata.
//!
//! The snapshot is one authenticated database value. OpenMLS storage, pending
//! Commit retry bytes, anonymous-delivery key material, and unlinkable
//! group-control keys therefore advance atomically.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::RwLock;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use openmls::prelude::{BasicCredential, CredentialWithKey};
use openmls_basic_credential::SignatureKeyPair;
use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::types::SignatureScheme;
use openmls_traits::OpenMlsProvider;
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use serde::{Deserialize, Serialize};

use super::{
    decode_canonical_base64, validate_group_id, validate_metadata, validate_pending_commit,
    LocalMlsConversationRecord, MlsDevicePublicMaterial, PendingMlsCommit, MAX_PENDING_COMMITS,
    MAX_STATE_BYTES, MAX_STATE_RECORDS, MAX_STATE_RECORD_BYTES,
    MLS_CIPHERSUITE_P256_AES128GCM_SHA256_P256, STATE_FORMAT_VERSION,
};
use crate::error::{ChatError, Result};

#[derive(Default, Debug)]
pub(super) struct KutupMlsProvider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl OpenMlsProvider for KutupMlsProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

pub(super) struct SnapshotMetadata {
    pub(super) credential_identity: String,
    pub(super) credential_public_key: Vec<u8>,
    pub(super) anonymous_delivery_private_key: Vec<u8>,
    pub(super) pending_commits: BTreeMap<String, PendingMlsCommit>,
    pub(super) group_control_private_keys: BTreeMap<String, Vec<u8>>,
    pub(super) group_owner_private_keys: BTreeMap<String, Vec<u8>>,
    pub(super) conversations: BTreeMap<String, LocalMlsConversationRecord>,
}

impl SnapshotMetadata {
    pub(super) fn credential(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.credential_identity.as_bytes().to_vec()).into(),
            signature_key: self.credential_public_key.clone().into(),
        }
    }

    pub(super) fn read_signer(&self, provider: &KutupMlsProvider) -> Result<SignatureKeyPair> {
        SignatureKeyPair::read(
            provider.storage(),
            &self.credential_public_key,
            SignatureScheme::ECDSA_SECP256R1_SHA256,
        )
        .ok_or_else(|| {
            ChatError::MissingKeyMaterial("MLS device signing key is unavailable".into())
        })
    }

    pub(super) fn public_material(&self) -> Result<MlsDevicePublicMaterial> {
        let secret = p256::SecretKey::from_slice(&self.anonymous_delivery_private_key)
            .map_err(|_| ChatError::Db("invalid durable anonymous-delivery private key".into()))?;
        Ok(MlsDevicePublicMaterial {
            credential_public_key: self.credential_public_key.clone(),
            anonymous_delivery_public_key: secret
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistedMlsStateV3 {
    format_version: u16,
    ciphersuite: u16,
    credential_identity: String,
    credential_public_key: String,
    anonymous_delivery_private_key: String,
    pending_commits: Vec<PendingMlsCommit>,
    group_control_keys: Vec<PersistedMlsGroupControlKeyV1>,
    group_owner_keys: Vec<PersistedMlsGroupOwnerKeyV1>,
    conversations: Vec<LocalMlsConversationRecord>,
    records: Vec<PersistedMlsRecordV1>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistedMlsGroupControlKeyV1 {
    group_id: String,
    private_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistedMlsGroupOwnerKeyV1 {
    group_id: String,
    private_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistedMlsRecordV1 {
    key: String,
    value: String,
}

pub(super) fn snapshot_provider(
    provider: &KutupMlsProvider,
    metadata: &SnapshotMetadata,
) -> Result<Vec<u8>> {
    validate_metadata(metadata)?;
    let values = provider
        .storage
        .values
        .read()
        .map_err(|_| ChatError::Db("OpenMLS storage lock is poisoned".into()))?;
    if values.len() > MAX_STATE_RECORDS {
        return Err(ChatError::Db("OpenMLS state has too many records".into()));
    }
    let mut entries = values.iter().collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(right.0));
    let mut records = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        if key.len() > MAX_STATE_RECORD_BYTES || value.len() > MAX_STATE_RECORD_BYTES {
            return Err(ChatError::Db(
                "OpenMLS state record exceeds its bound".into(),
            ));
        }
        records.push(PersistedMlsRecordV1 {
            key: BASE64.encode(key),
            value: BASE64.encode(value),
        });
    }
    let state = PersistedMlsStateV3 {
        format_version: STATE_FORMAT_VERSION,
        ciphersuite: MLS_CIPHERSUITE_P256_AES128GCM_SHA256_P256,
        credential_identity: metadata.credential_identity.clone(),
        credential_public_key: BASE64.encode(&metadata.credential_public_key),
        anonymous_delivery_private_key: BASE64.encode(&metadata.anonymous_delivery_private_key),
        pending_commits: metadata.pending_commits.values().cloned().collect(),
        group_control_keys: metadata
            .group_control_private_keys
            .iter()
            .map(|(group_id, private_key)| PersistedMlsGroupControlKeyV1 {
                group_id: group_id.clone(),
                private_key: BASE64.encode(private_key),
            })
            .collect(),
        group_owner_keys: metadata
            .group_owner_private_keys
            .iter()
            .map(|(group_id, private_key)| PersistedMlsGroupOwnerKeyV1 {
                group_id: group_id.clone(),
                private_key: BASE64.encode(private_key),
            })
            .collect(),
        conversations: metadata.conversations.values().cloned().collect(),
        records,
    };
    let encoded = serde_json::to_vec(&state).map_err(|error| ChatError::Db(error.to_string()))?;
    if encoded.len() > MAX_STATE_BYTES {
        return Err(ChatError::Db("OpenMLS state exceeds 64 MiB".into()));
    }
    Ok(encoded)
}

pub(super) fn provider_from_snapshot(bytes: &[u8]) -> Result<(KutupMlsProvider, SnapshotMetadata)> {
    if bytes.is_empty() || bytes.len() > MAX_STATE_BYTES {
        return Err(ChatError::Db("OpenMLS state size is invalid".into()));
    }
    let state: PersistedMlsStateV3 =
        serde_json::from_slice(bytes).map_err(|error| ChatError::Db(error.to_string()))?;
    if state.format_version != STATE_FORMAT_VERSION
        || state.ciphersuite != MLS_CIPHERSUITE_P256_AES128GCM_SHA256_P256
        || state.records.len() > MAX_STATE_RECORDS
        || state.pending_commits.len() > MAX_PENDING_COMMITS
        || state.group_control_keys.len() > MAX_PENDING_COMMITS
        || state.group_owner_keys.len() > MAX_PENDING_COMMITS
        || state.conversations.len() > MAX_PENDING_COMMITS
    {
        return Err(ChatError::Db(
            "unsupported or oversized OpenMLS state snapshot".into(),
        ));
    }
    let canonical = serde_json::to_vec(&state).map_err(|error| ChatError::Db(error.to_string()))?;
    if canonical != bytes {
        return Err(ChatError::Db(
            "OpenMLS state snapshot is not canonically encoded".into(),
        ));
    }

    let mut pending_commits = BTreeMap::new();
    let mut previous_pending_key: Option<String> = None;
    for pending in state.pending_commits {
        validate_pending_commit(&pending)?;
        let key = BASE64.encode(&pending.mls_group_id);
        if previous_pending_key
            .as_ref()
            .is_some_and(|previous| key <= *previous)
        {
            return Err(ChatError::Db(
                "OpenMLS pending Commit records are not strictly ordered".into(),
            ));
        }
        previous_pending_key = Some(key.clone());
        if pending_commits.insert(key, pending).is_some() {
            return Err(ChatError::Db(
                "OpenMLS state contains duplicate pending Commit material".into(),
            ));
        }
    }
    let mut group_control_private_keys = BTreeMap::new();
    let mut previous_control_group: Option<String> = None;
    for entry in state.group_control_keys {
        let group_id = decode_canonical_base64("MLS control group id", &entry.group_id, 0)?;
        validate_group_id(&group_id)?;
        let expected_group_key = BASE64.encode(&group_id);
        if expected_group_key != entry.group_id
            || previous_control_group
                .as_ref()
                .is_some_and(|previous| entry.group_id <= *previous)
        {
            return Err(ChatError::Db(
                "MLS group control keys are not canonically ordered".into(),
            ));
        }
        previous_control_group = Some(entry.group_id.clone());
        let private_key =
            decode_canonical_base64("MLS group control private key", &entry.private_key, 32)?;
        P256SigningKey::from_slice(&private_key)
            .map_err(|_| ChatError::Db("invalid durable MLS group control key".into()))?;
        if group_control_private_keys
            .insert(entry.group_id, private_key)
            .is_some()
        {
            return Err(ChatError::Db(
                "OpenMLS state contains a duplicate group control key".into(),
            ));
        }
    }
    let mut group_owner_private_keys = BTreeMap::new();
    let mut previous_owner_group: Option<String> = None;
    for entry in state.group_owner_keys {
        let group_id = decode_canonical_base64("MLS owner group id", &entry.group_id, 0)?;
        validate_group_id(&group_id)?;
        let expected_group_key = BASE64.encode(&group_id);
        if expected_group_key != entry.group_id
            || previous_owner_group
                .as_ref()
                .is_some_and(|previous| entry.group_id <= *previous)
        {
            return Err(ChatError::Db(
                "MLS group owner keys are not canonically ordered".into(),
            ));
        }
        previous_owner_group = Some(entry.group_id.clone());
        let private_key =
            decode_canonical_base64("MLS group owner private key", &entry.private_key, 32)?;
        let private_key_array: [u8; 32] = private_key
            .as_slice()
            .try_into()
            .map_err(|_| ChatError::Db("invalid durable MLS group owner key".into()))?;
        ed25519_dalek::SigningKey::from_bytes(&private_key_array);
        if group_owner_private_keys
            .insert(entry.group_id, private_key)
            .is_some()
        {
            return Err(ChatError::Db(
                "OpenMLS state contains a duplicate group owner key".into(),
            ));
        }
    }
    let mut conversations = BTreeMap::new();
    let mut previous_conversation: Option<String> = None;
    for conversation in state.conversations {
        let key = conversation.request.genesis.conversation_id.to_string();
        if previous_conversation
            .as_ref()
            .is_some_and(|previous| key <= *previous)
        {
            return Err(ChatError::Db(
                "MLS conversation records are not canonically ordered".into(),
            ));
        }
        previous_conversation = Some(key.clone());
        if conversations.insert(key, conversation).is_some() {
            return Err(ChatError::Db(
                "OpenMLS state contains a duplicate conversation record".into(),
            ));
        }
    }
    let metadata = SnapshotMetadata {
        credential_identity: state.credential_identity,
        credential_public_key: decode_canonical_base64(
            "MLS credential public key",
            &state.credential_public_key,
            65,
        )?,
        anonymous_delivery_private_key: decode_canonical_base64(
            "anonymous-delivery private key",
            &state.anonymous_delivery_private_key,
            32,
        )?,
        pending_commits,
        group_control_private_keys,
        group_owner_private_keys,
        conversations,
    };
    validate_metadata(&metadata)?;

    let mut values = HashMap::with_capacity(state.records.len());
    let mut previous_key: Option<Vec<u8>> = None;
    let mut encoded_keys = HashSet::with_capacity(state.records.len());
    for record in state.records {
        if !encoded_keys.insert(record.key.clone()) {
            return Err(ChatError::Db(
                "OpenMLS state contains a duplicate record".into(),
            ));
        }
        let key = decode_canonical_base64("OpenMLS storage key", &record.key, 0)?;
        let value = decode_canonical_base64("OpenMLS storage value", &record.value, 0)?;
        if key.is_empty()
            || key.len() > MAX_STATE_RECORD_BYTES
            || value.len() > MAX_STATE_RECORD_BYTES
            || previous_key
                .as_ref()
                .is_some_and(|previous| key <= *previous)
        {
            return Err(ChatError::Db(
                "OpenMLS state records are invalid or not strictly ordered".into(),
            ));
        }
        previous_key = Some(key.clone());
        values.insert(key, value);
    }
    let provider = KutupMlsProvider {
        crypto: RustCrypto::default(),
        storage: MemoryStorage {
            values: RwLock::new(values),
        },
    };
    metadata.read_signer(&provider)?;
    Ok((provider, metadata))
}
