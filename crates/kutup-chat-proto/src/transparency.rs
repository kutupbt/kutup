//! Wire primitives and verifier for the append-only device-manifest log.
//!
//! Hashing follows RFC 6962's domain separation: `0x00 || leaf` for leaves and
//! `0x01 || left || right` for interior nodes. The leaf encoding itself is a
//! Kutup-owned, versioned canonical record so all clients derive one root.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{ChatTransparencyPolicyV1, DeviceManifest};

pub type TransparencyHash = [u8; 32];

const LEAF_DOMAIN: &[u8] = b"kutup-chat-transparency-leaf-v1\0";
const MAP_KEY_DOMAIN: &[u8] = b"kutup-chat-transparency-map-key-v1\0";
const MAP_LEAF_DOMAIN: &[u8] = b"kutup-chat-transparency-map-leaf-v1\0";
const MAP_EMPTY_DOMAIN: &[u8] = b"kutup-chat-transparency-map-empty-v1\0";
const MAP_CHECKPOINT_DOMAIN: &[u8] = b"kutup-chat-transparency-map-checkpoint-v1\0";
const SIGNED_CHECKPOINT_DOMAIN: &[u8] = b"kutup-chat-transparency-signed-checkpoint-v1\0";
const WITNESS_ATTESTATION_DOMAIN: &[u8] = b"kutup-chat-transparency-witness-v1\0";
const WITNESS_VIEW_DOMAIN: &[u8] = b"kutup-chat-transparency-witness-view-v1\0";

pub const MAX_MANIFEST_RANGE_PAGE_ENTRIES: usize = 64;
pub const MAX_WITNESS_VIEW_STATEMENTS: usize = 64;

/// Purpose-scoped operator signing interface. Provider/HSM implementations can
/// sign canonical checkpoint bytes without exposing private key material.
pub trait TransparencyOperatorSigner {
    fn public_key_bytes(&self) -> [u8; 32];
    fn sign_transparency_checkpoint(&self, message: &[u8]) -> Result<[u8; 64], String>;
}

impl TransparencyOperatorSigner for SigningKey {
    fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key().to_bytes()
    }

    fn sign_transparency_checkpoint(&self, message: &[u8]) -> Result<[u8; 64], String> {
        Ok(self.sign(message).to_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ManifestTransparencyLeaf {
    /// Username inside this log's homeserver namespace (never a display name).
    pub username: String,
    pub manifest_version: u64,
    pub manifest_hash: String,
    pub authority_key_id: String,
}

impl ManifestTransparencyLeaf {
    pub fn from_manifest(
        username: impl Into<String>,
        manifest: &DeviceManifest,
    ) -> Result<Self, String> {
        Ok(Self {
            username: username.into(),
            manifest_version: manifest.version,
            manifest_hash: manifest.manifest_hash()?,
            authority_key_id: manifest.authority_key_id.clone(),
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        if self.username.is_empty() || self.username.len() > 255 {
            return Err("transparency username must be 1-255 bytes".into());
        }
        if self.manifest_version == 0 {
            return Err("transparency manifest version must be positive".into());
        }
        let manifest_hash = decode_hash("manifestHash", &self.manifest_hash)?;
        let authority_key_id = decode_hash("authorityKeyId", &self.authority_key_id)?;
        let mut out = Vec::with_capacity(LEAF_DOMAIN.len() + self.username.len() + 74);
        out.extend_from_slice(LEAF_DOMAIN);
        let username_len =
            u16::try_from(self.username.len()).map_err(|_| "transparency username is too long")?;
        out.extend_from_slice(&username_len.to_be_bytes());
        out.extend_from_slice(self.username.as_bytes());
        out.extend_from_slice(&self.manifest_version.to_be_bytes());
        out.extend_from_slice(&manifest_hash);
        out.extend_from_slice(&authority_key_id);
        Ok(out)
    }

    pub fn hash(&self) -> Result<TransparencyHash, String> {
        let canonical = self.canonical_bytes()?;
        let mut hasher = Sha256::new();
        hasher.update([0]);
        hasher.update(canonical);
        Ok(hasher.finalize().into())
    }

    pub fn matches_manifest(
        &self,
        username: &str,
        manifest: &DeviceManifest,
    ) -> Result<(), String> {
        if self.username != username
            || self.manifest_version != manifest.version
            || self.manifest_hash != manifest.manifest_hash()?
            || self.authority_key_id != manifest.authority_key_id
        {
            return Err("transparency leaf does not match the served manifest".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct TransparencyCheckpoint {
    /// Stable random identifier for one homeserver log database.
    pub log_id: String,
    pub tree_size: u64,
    pub root_hash: String,
}

impl TransparencyCheckpoint {
    pub fn validate(&self) -> Result<TransparencyHash, String> {
        decode_hash("logId", &self.log_id)?;
        decode_hash("rootHash", &self.root_hash)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ManifestTransparencyProof {
    /// Zero-based position of `leaf` in the append-only log.
    pub leaf_index: u64,
    pub leaf: ManifestTransparencyLeaf,
    pub checkpoint: TransparencyCheckpoint,
    /// Inclusion audit path, deepest sibling first, as lowercase SHA-256 hex.
    pub inclusion: Vec<String>,
    /// Tree size whose pinned root the consistency proof starts from. Zero is
    /// the first-observation sentinel and requires an empty proof.
    pub consistency_from: u64,
    /// RFC 6962 consistency path from `consistencyFrom` to `checkpoint.treeSize`.
    pub consistency: Vec<String>,
    /// Proof that this manifest is the account's current value in the sparse
    /// account map committed by the final leaf of `checkpoint`.
    pub map: ManifestTransparencyMapProof,
    /// Stable operator signature plus independently verifiable witness
    /// attestations for this exact log/map checkpoint.
    pub authentication: TransparencyCheckpointAuthentication,
}

impl ManifestTransparencyProof {
    pub fn verify_inclusion(&self) -> Result<(), String> {
        let root = self.checkpoint.validate()?;
        let path = decode_path("inclusion", &self.inclusion)?;
        verify_inclusion(
            self.leaf.hash()?,
            self.leaf_index,
            self.checkpoint.tree_size,
            &path,
            root,
        )
    }

    pub fn verify_consistency_from(
        &self,
        prior: Option<&TransparencyCheckpoint>,
    ) -> Result<(), String> {
        let new_root = self.checkpoint.validate()?;
        let proof = decode_path("consistency", &self.consistency)?;
        match prior {
            None => {
                if self.consistency_from != 0 || !proof.is_empty() {
                    return Err("first transparency checkpoint must start at size zero".into());
                }
                Ok(())
            }
            Some(prior) => {
                let old_root = prior.validate()?;
                if prior.log_id != self.checkpoint.log_id {
                    return Err("transparency log identity changed".into());
                }
                if self.consistency_from != prior.tree_size {
                    return Err(
                        "transparency consistency proof starts at the wrong tree size".into(),
                    );
                }
                verify_consistency(
                    prior.tree_size,
                    self.checkpoint.tree_size,
                    old_root,
                    new_root,
                    &proof,
                )
            }
        }
    }

    pub fn verify_current_map(&self) -> Result<(), String> {
        self.map.verify(&self.leaf, &self.checkpoint)
    }

    pub fn verify_authentication(&self) -> Result<(), String> {
        self.authentication
            .verify(&self.checkpoint, &self.map.root_hash)
    }
}

/// Operator signature and optional independent observations of one exact
/// transparency checkpoint. Witness public keys are carried for routing and
/// first-observation UX only; a client enforcing a quorum MUST compare them to
/// keys supplied by its own trusted policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct TransparencyCheckpointAuthentication {
    /// Unix epoch seconds. Persisted with the checkpoint, so every client sees
    /// the same signed object rather than a freshly timestamped response.
    pub issued_at: i64,
    pub operator_key_id: String,
    pub operator_public_key: String,
    pub operator_signature: String,
    #[serde(default)]
    pub witnesses: Vec<TransparencyWitnessAttestation>,
}

impl TransparencyCheckpointAuthentication {
    pub fn sign(
        checkpoint: &TransparencyCheckpoint,
        map_root: &str,
        issued_at: i64,
        signing_key: &impl TransparencyOperatorSigner,
    ) -> Result<Self, String> {
        if issued_at <= 0 {
            return Err("transparency checkpoint issuedAt must be positive".into());
        }
        let verifying_key = VerifyingKey::from_bytes(&signing_key.public_key_bytes())
            .map_err(|_| "transparency signer returned an invalid public key".to_string())?;
        let operator_key_id = transparency_signing_key_id(&verifying_key);
        let bytes = signed_checkpoint_bytes(checkpoint, map_root, issued_at, &operator_key_id)?;
        Ok(Self {
            issued_at,
            operator_key_id,
            operator_public_key: STANDARD.encode(verifying_key.as_bytes()),
            operator_signature: STANDARD.encode(signing_key.sign_transparency_checkpoint(&bytes)?),
            witnesses: Vec::new(),
        })
    }

    pub fn verify(
        &self,
        checkpoint: &TransparencyCheckpoint,
        map_root: &str,
    ) -> Result<(), String> {
        if self.issued_at <= 0 {
            return Err("transparency checkpoint issuedAt must be positive".into());
        }
        let public = decode_verifying_key("operatorPublicKey", &self.operator_public_key)?;
        if transparency_signing_key_id(&public) != self.operator_key_id {
            return Err("transparency operator key id does not match its public key".into());
        }
        let signature = decode_signature("operatorSignature", &self.operator_signature)?;
        let bytes =
            signed_checkpoint_bytes(checkpoint, map_root, self.issued_at, &self.operator_key_id)?;
        public
            .verify(&bytes, &signature)
            .map_err(|_| "invalid transparency operator signature".to_string())?;

        let mut witnesses = BTreeMap::new();
        for witness in &self.witnesses {
            witness.verify(self, checkpoint, map_root)?;
            if witnesses
                .insert(witness.witness_id.as_str(), witness.key_id.as_str())
                .is_some()
            {
                return Err("transparency checkpoint repeats a witness id".into());
            }
        }
        Ok(())
    }

    pub fn add_witness(
        &mut self,
        checkpoint: &TransparencyCheckpoint,
        map_root: &str,
        witness_id: impl Into<String>,
        observed_at: i64,
        signing_key: &SigningKey,
    ) -> Result<(), String> {
        let witness = TransparencyWitnessAttestation::sign(
            self,
            checkpoint,
            map_root,
            witness_id,
            observed_at,
            signing_key,
        )?;
        if self
            .witnesses
            .iter()
            .any(|existing| existing.witness_id == witness.witness_id)
        {
            return Err("transparency checkpoint repeats a witness id".into());
        }
        self.witnesses.push(witness);
        self.witnesses
            .sort_by(|left, right| left.witness_id.cmp(&right.witness_id));
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct TransparencyWitnessAttestation {
    /// Stable deployment identity selected by client policy, such as a DNS
    /// name. It is not trusted merely because it appears in this response.
    pub witness_id: String,
    pub observed_at: i64,
    pub key_id: String,
    pub public_key: String,
    pub signature: String,
}

/// Public identity selected outside the log server and pinned by clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct TransparencyVerifierKey {
    pub witness_id: String,
    pub key_id: String,
    pub public_key: String,
}

impl TransparencyVerifierKey {
    pub fn validate(&self) -> Result<(), String> {
        validate_witness_id(&self.witness_id)?;
        let key = decode_verifying_key("witness publicKey", &self.public_key)?;
        if transparency_signing_key_id(&key) != self.key_id {
            return Err("transparency witness key id does not match its public key".into());
        }
        Ok(())
    }

    pub fn matches(&self, attestation: &TransparencyWitnessAttestation) -> bool {
        self.witness_id == attestation.witness_id
            && self.key_id == attestation.key_id
            && self.public_key == attestation.public_key
    }
}

/// Public monitoring response used by clients and independently deployed
/// witnesses without consuming a user's prekeys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct TransparencyCheckpointResponse {
    pub checkpoint: TransparencyCheckpoint,
    pub map_root: String,
    pub authentication: TransparencyCheckpointAuthentication,
    pub consistency_from: u64,
    pub consistency: Vec<String>,
}

/// Shared server/client/auditor verification of a checkpoint against an
/// authenticated feature policy. Status labels supplied by a server are never
/// inputs to this decision.
pub fn verify_checkpoint_against_policy(
    policy: &ChatTransparencyPolicyV1,
    response: &TransparencyCheckpointResponse,
    prior: Option<&TransparencyCheckpoint>,
    now: i64,
) -> Result<(), String> {
    policy.validate()?;
    response.verify(prior)?;
    if response.checkpoint.log_id != policy.log_id
        || response.authentication.operator_key_id != policy.operator_key_id
        || response.authentication.operator_public_key != policy.operator_public_key
    {
        return Err("transparency checkpoint does not match authenticated policy".into());
    }
    let minimum_time = now.saturating_sub(policy.maximum_checkpoint_age_seconds as i64);
    let maximum_time = now.saturating_add(policy.maximum_clock_skew_seconds as i64);
    if response.authentication.issued_at < minimum_time
        || response.authentication.issued_at > maximum_time
    {
        return Err("transparency checkpoint is stale or from the future".into());
    }
    let mut observed = BTreeMap::new();
    for trusted in &policy.witnesses {
        if let Some(attestation) = response.authentication.witnesses.iter().find(|candidate| {
            candidate.witness_id == trusted.witness_id
                && candidate.key_id == trusted.key_id
                && candidate.public_key == trusted.public_key
        }) {
            attestation.verify(
                &response.authentication,
                &response.checkpoint,
                &response.map_root,
            )?;
            observed.insert(
                &trusted.witness_id,
                (attestation.observed_at, &trusted.key_id),
            );
        }
    }
    if observed.len() < usize::from(policy.required_quorum) {
        return Err(format!(
            "transparency checkpoint has {} authenticated policy witnesses; {} required",
            observed.len(),
            policy.required_quorum
        ));
    }
    Ok(())
}

impl TransparencyCheckpointResponse {
    pub fn verify(&self, prior: Option<&TransparencyCheckpoint>) -> Result<(), String> {
        self.authentication
            .verify(&self.checkpoint, &self.map_root)?;
        let new_root = self.checkpoint.validate()?;
        let proof = decode_path("consistency", &self.consistency)?;
        match prior {
            None => {
                if self.consistency_from != 0 || !proof.is_empty() {
                    return Err("first transparency checkpoint must start at size zero".into());
                }
                Ok(())
            }
            Some(prior) => {
                let old_root = prior.validate()?;
                if prior.log_id != self.checkpoint.log_id {
                    return Err("transparency log identity changed".into());
                }
                if self.consistency_from != prior.tree_size {
                    return Err(
                        "transparency consistency proof starts at the wrong tree size".into(),
                    );
                }
                verify_consistency(
                    prior.tree_size,
                    self.checkpoint.tree_size,
                    old_root,
                    new_root,
                    &proof,
                )
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct SubmitTransparencyWitnessRequest {
    pub tree_size: u64,
    pub attestation: TransparencyWitnessAttestation,
}

/// One complete account update and its individual RFC 6962 inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestUpdateRangeEntryV1 {
    pub manifest: DeviceManifest,
    pub leaf_index: u64,
    pub leaf: ManifestTransparencyLeaf,
    pub inclusion: Vec<String>,
}

/// A page from one immutable checkpoint snapshot. `fromVersion` and
/// `toVersion` name the complete requested interval; page bounds name the
/// exact records present in this response. A cursor is valid only for the
/// checkpoint and next version encoded in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestUpdateRangeProofV1 {
    pub account: String,
    pub from_version: u64,
    pub to_version: u64,
    pub page_from_version: u64,
    pub page_to_version: u64,
    pub entries: Vec<ManifestUpdateRangeEntryV1>,
    pub checkpoint: TransparencyCheckpoint,
    pub authentication: TransparencyCheckpointAuthentication,
    pub consistency_from: u64,
    pub consistency: Vec<String>,
    /// Current map leaf at the fixed checkpoint. It must describe `toVersion`.
    pub latest_leaf: ManifestTransparencyLeaf,
    pub latest_map: ManifestTransparencyMapProof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl ManifestUpdateRangeProofV1 {
    pub fn verify_page(
        &self,
        expected_account: &str,
        expected_from_version: u64,
        prior_manifest: Option<&DeviceManifest>,
        prior_checkpoint: Option<&TransparencyCheckpoint>,
    ) -> Result<(), String> {
        if self.account != expected_account
            || self.from_version != expected_from_version
            || self.from_version == 0
            || self.to_version < self.from_version
            || self.entries.is_empty()
            || self.entries.len() > MAX_MANIFEST_RANGE_PAGE_ENTRIES
            || self.page_from_version
                != self.from_version.max(
                    prior_manifest
                        .map(|manifest| manifest.version.saturating_add(1))
                        .unwrap_or(self.from_version),
                )
            || self.page_to_version < self.page_from_version
        {
            return Err("manifest range page has invalid account or version bounds".into());
        }
        let username = expected_account
            .split_once('@')
            .map(|(username, _)| username)
            .unwrap_or(expected_account);
        let mut expected_version = self.page_from_version;
        let mut prior = prior_manifest;
        for entry in &self.entries {
            if entry.manifest.version != expected_version
                || entry.leaf.manifest_version != expected_version
            {
                return Err("manifest range page is missing, duplicated, or reordered".into());
            }
            entry.manifest.verify()?;
            entry.leaf.matches_manifest(username, &entry.manifest)?;
            let root = self.checkpoint.validate()?;
            let path = decode_path("range inclusion", &entry.inclusion)?;
            verify_inclusion(
                entry.leaf.hash()?,
                entry.leaf_index,
                self.checkpoint.tree_size,
                &path,
                root,
            )?;
            if let Some(previous) = prior {
                if entry.manifest.authority_key_id != previous.authority_key_id
                    || entry.manifest.self_authority_key != previous.self_authority_key
                    || entry.manifest.previous_hash.as_deref()
                        != Some(previous.manifest_hash()?.as_str())
                {
                    return Err(
                        "manifest range breaks account authority or previousHash continuity".into(),
                    );
                }
            } else if entry.manifest.version != 1 || entry.manifest.previous_hash.is_some() {
                return Err("first-observation manifest history must begin at version 1".into());
            }
            prior = Some(&entry.manifest);
            expected_version = expected_version
                .checked_add(1)
                .ok_or_else(|| "manifest version overflow".to_string())?;
        }
        if expected_version.saturating_sub(1) != self.page_to_version {
            return Err("manifest range page bounds do not match its entries".into());
        }
        self.authentication
            .verify(&self.checkpoint, &self.latest_map.root_hash)?;
        verify_checkpoint_consistency(
            &self.checkpoint,
            self.consistency_from,
            &self.consistency,
            prior_checkpoint,
        )?;
        if self.latest_leaf.manifest_version != self.to_version
            || self.latest_leaf.username != username
        {
            return Err("manifest range latest map leaf does not match the requested range".into());
        }
        self.latest_map
            .verify(&self.latest_leaf, &self.checkpoint)?;
        let expected_next = if self.page_to_version < self.to_version {
            Some(manifest_range_cursor(
                &self.account,
                self.from_version,
                self.to_version,
                self.page_to_version + 1,
                &self.checkpoint,
            )?)
        } else {
            None
        };
        if self.next_cursor != expected_next {
            return Err("manifest range pagination cursor is not bound to the checkpoint".into());
        }
        Ok(())
    }
}

pub fn manifest_range_cursor(
    account: &str,
    from_version: u64,
    to_version: u64,
    next_version: u64,
    checkpoint: &TransparencyCheckpoint,
) -> Result<String, String> {
    if account.is_empty()
        || from_version == 0
        || next_version < from_version
        || next_version > to_version
    {
        return Err("invalid manifest range cursor coordinates".into());
    }
    let mut bytes = Vec::with_capacity(160);
    bytes.extend_from_slice(b"kutup-chat-manifest-range-cursor-v1\0");
    bytes.extend_from_slice(&(account.len() as u32).to_be_bytes());
    bytes.extend_from_slice(account.as_bytes());
    bytes.extend_from_slice(&from_version.to_be_bytes());
    bytes.extend_from_slice(&to_version.to_be_bytes());
    bytes.extend_from_slice(&next_version.to_be_bytes());
    bytes.extend_from_slice(&decode_hash("logId", &checkpoint.log_id)?);
    bytes.extend_from_slice(&checkpoint.tree_size.to_be_bytes());
    bytes.extend_from_slice(&decode_hash("rootHash", &checkpoint.root_hash)?);
    Ok(STANDARD.encode(bytes))
}

/// Exact operator statement. The contained authentication retains the
/// original operator signature and any original witness attestations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransparencySignedStatementV1 {
    pub checkpoint: TransparencyCheckpoint,
    pub map_root: String,
    pub authentication: TransparencyCheckpointAuthentication,
}

impl TransparencySignedStatementV1 {
    pub fn verify(&self) -> Result<(), String> {
        decode_hash("mapRoot", &self.map_root)?;
        self.checkpoint.validate()?;
        self.authentication.verify(&self.checkpoint, &self.map_root)
    }
}

/// Bounded, witness-signed history used for independent cross-view auditing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WitnessViewV1 {
    pub version: u16,
    pub witness_id: String,
    pub issued_at: i64,
    pub key_id: String,
    pub public_key: String,
    pub statements: Vec<TransparencySignedStatementV1>,
    pub signature: String,
}

impl WitnessViewV1 {
    pub fn sign(
        witness_id: impl Into<String>,
        issued_at: i64,
        statements: Vec<TransparencySignedStatementV1>,
        signing_key: &SigningKey,
    ) -> Result<Self, String> {
        let public = signing_key.verifying_key();
        let mut view = Self {
            version: 1,
            witness_id: witness_id.into(),
            issued_at,
            key_id: transparency_signing_key_id(&public),
            public_key: STANDARD.encode(public.as_bytes()),
            statements,
            signature: String::new(),
        };
        let bytes = view.signing_bytes()?;
        view.signature = STANDARD.encode(signing_key.sign(&bytes).to_bytes());
        view.verify()?;
        Ok(view)
    }

    pub fn verify(&self) -> Result<(), String> {
        let public = decode_verifying_key("witness view publicKey", &self.public_key)?;
        if transparency_signing_key_id(&public) != self.key_id {
            return Err("witness view key id does not match its public key".into());
        }
        let signature = decode_signature("witness view signature", &self.signature)?;
        public
            .verify(&self.signing_bytes()?, &signature)
            .map_err(|_| "invalid witness view signature".to_string())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        if self.version != 1
            || self.issued_at <= 0
            || self.statements.is_empty()
            || self.statements.len() > MAX_WITNESS_VIEW_STATEMENTS
        {
            return Err("witness view version, time, or statement count is invalid".into());
        }
        validate_witness_id(&self.witness_id)?;
        let public = decode_verifying_key("witness view publicKey", &self.public_key)?;
        if transparency_signing_key_id(&public) != self.key_id {
            return Err("witness view key id does not match its public key".into());
        }
        let mut out = Vec::with_capacity(512 * self.statements.len());
        out.extend_from_slice(WITNESS_VIEW_DOMAIN);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&(self.witness_id.len() as u16).to_be_bytes());
        out.extend_from_slice(self.witness_id.as_bytes());
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&decode_hash("witness view keyId", &self.key_id)?);
        out.extend_from_slice(&(self.statements.len() as u16).to_be_bytes());
        let mut previous = None;
        for statement in &self.statements {
            statement.verify()?;
            if let Some((log_id, tree_size)) = &previous {
                if statement.checkpoint.log_id != *log_id
                    || statement.checkpoint.tree_size <= *tree_size
                {
                    return Err(
                        "witness view history regresses, changes logs, or is reordered".into(),
                    );
                }
            }
            let witness = statement
                .authentication
                .witnesses
                .iter()
                .find(|attestation| {
                    attestation.witness_id == self.witness_id
                        && attestation.key_id == self.key_id
                        && attestation.public_key == self.public_key
                })
                .ok_or_else(|| {
                    "witness view statement lacks its original witness attestation".to_string()
                })?;
            witness.verify(
                &statement.authentication,
                &statement.checkpoint,
                &statement.map_root,
            )?;
            let encoded = serde_json::to_vec(statement).map_err(|error| error.to_string())?;
            out.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
            out.extend_from_slice(&encoded);
            previous = Some((
                statement.checkpoint.log_id.clone(),
                statement.checkpoint.tree_size,
            ));
        }
        Ok(out)
    }
}

/// Immutable cryptographic contradiction. Both fields are the original signed
/// statements; no trust is placed in the auditor's conclusion alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransparencyForkEvidenceV1 {
    pub version: u16,
    pub domain: String,
    pub detected_at: i64,
    pub operator_statement: TransparencySignedStatementV1,
    pub witness_statement: TransparencySignedStatementV1,
}

impl TransparencyForkEvidenceV1 {
    pub fn verify_contradiction(&self) -> Result<(), String> {
        if self.version != 1 || self.detected_at <= 0 {
            return Err("fork evidence version or detection time is invalid".into());
        }
        kutup_federation_proto::validate_server_name(&self.domain)
            .map_err(|error| error.to_string())?;
        self.operator_statement.verify()?;
        self.witness_statement.verify()?;
        let left = &self.operator_statement;
        let right = &self.witness_statement;
        let contradictory = left.checkpoint.log_id != right.checkpoint.log_id
            || (left.checkpoint.tree_size == right.checkpoint.tree_size
                && (left.checkpoint.root_hash != right.checkpoint.root_hash
                    || left.map_root != right.map_root));
        if !contradictory {
            return Err("statements do not contain an independently verifiable fork".into());
        }
        Ok(())
    }
}

/// Shared server/auditor comparison. `Ok(None)` means the signed views contain
/// no directly provable contradiction; availability gaps and missing
/// cross-size consistency proofs are intentionally not upgraded to forks.
pub fn audit_operator_witness_view(
    domain: &str,
    detected_at: i64,
    operator: &TransparencySignedStatementV1,
    witness: &WitnessViewV1,
) -> Result<Option<TransparencyForkEvidenceV1>, String> {
    kutup_federation_proto::validate_server_name(domain).map_err(|error| error.to_string())?;
    if detected_at <= 0 {
        return Err("audit detection time must be positive".into());
    }
    operator.verify()?;
    witness.verify()?;
    for statement in &witness.statements {
        if statements_contradict(operator, statement) {
            let evidence = TransparencyForkEvidenceV1 {
                version: 1,
                domain: domain.to_string(),
                detected_at,
                operator_statement: operator.clone(),
                witness_statement: statement.clone(),
            };
            evidence.verify_contradiction()?;
            return Ok(Some(evidence));
        }
    }
    Ok(None)
}

/// Compare two independently witness-signed histories for equivocation. The
/// returned evidence retains the original operator statements and therefore
/// remains verifiable without trusting this function's conclusion.
pub fn audit_witness_views(
    domain: &str,
    detected_at: i64,
    left: &WitnessViewV1,
    right: &WitnessViewV1,
) -> Result<Option<TransparencyForkEvidenceV1>, String> {
    kutup_federation_proto::validate_server_name(domain).map_err(|error| error.to_string())?;
    if detected_at <= 0 {
        return Err("audit detection time must be positive".into());
    }
    left.verify()?;
    right.verify()?;
    for left_statement in &left.statements {
        for right_statement in &right.statements {
            if statements_contradict(left_statement, right_statement) {
                let evidence = TransparencyForkEvidenceV1 {
                    version: 1,
                    domain: domain.to_string(),
                    detected_at,
                    operator_statement: left_statement.clone(),
                    witness_statement: right_statement.clone(),
                };
                evidence.verify_contradiction()?;
                return Ok(Some(evidence));
            }
        }
    }
    Ok(None)
}

fn statements_contradict(
    left: &TransparencySignedStatementV1,
    right: &TransparencySignedStatementV1,
) -> bool {
    left.checkpoint.log_id != right.checkpoint.log_id
        || (left.checkpoint.tree_size == right.checkpoint.tree_size
            && (left.checkpoint.root_hash != right.checkpoint.root_hash
                || left.map_root != right.map_root))
}

fn verify_checkpoint_consistency(
    checkpoint: &TransparencyCheckpoint,
    consistency_from: u64,
    consistency: &[String],
    prior: Option<&TransparencyCheckpoint>,
) -> Result<(), String> {
    let proof = decode_path("range consistency", consistency)?;
    match prior {
        None => {
            if consistency_from != 0 || !proof.is_empty() {
                return Err("first manifest range proof must start at tree size zero".into());
            }
            Ok(())
        }
        Some(prior) => {
            if prior.log_id != checkpoint.log_id || consistency_from != prior.tree_size {
                return Err(
                    "manifest range consistency proof starts from the wrong checkpoint".into(),
                );
            }
            verify_consistency(
                prior.tree_size,
                checkpoint.tree_size,
                prior.validate()?,
                checkpoint.validate()?,
                &proof,
            )
        }
    }
}

impl TransparencyWitnessAttestation {
    pub fn sign(
        authentication: &TransparencyCheckpointAuthentication,
        checkpoint: &TransparencyCheckpoint,
        map_root: &str,
        witness_id: impl Into<String>,
        observed_at: i64,
        signing_key: &SigningKey,
    ) -> Result<Self, String> {
        let witness_id = witness_id.into();
        validate_witness_id(&witness_id)?;
        if observed_at <= 0 {
            return Err("transparency witness observedAt must be positive".into());
        }
        // Refuse to witness an invalid operator statement.
        authentication.verify(checkpoint, map_root)?;
        let verifying_key = signing_key.verifying_key();
        let key_id = transparency_signing_key_id(&verifying_key);
        let bytes = witness_attestation_bytes(
            authentication,
            checkpoint,
            map_root,
            &witness_id,
            observed_at,
            &key_id,
        )?;
        Ok(Self {
            witness_id,
            observed_at,
            key_id,
            public_key: STANDARD.encode(verifying_key.as_bytes()),
            signature: STANDARD.encode(signing_key.sign(&bytes).to_bytes()),
        })
    }

    pub fn verify(
        &self,
        authentication: &TransparencyCheckpointAuthentication,
        checkpoint: &TransparencyCheckpoint,
        map_root: &str,
    ) -> Result<(), String> {
        validate_witness_id(&self.witness_id)?;
        if self.observed_at < authentication.issued_at {
            return Err("transparency witness predates the operator checkpoint".into());
        }
        let public = decode_verifying_key("witness publicKey", &self.public_key)?;
        if transparency_signing_key_id(&public) != self.key_id {
            return Err("transparency witness key id does not match its public key".into());
        }
        let signature = decode_signature("witness signature", &self.signature)?;
        let bytes = witness_attestation_bytes(
            authentication,
            checkpoint,
            map_root,
            &self.witness_id,
            self.observed_at,
            &self.key_id,
        )?;
        public
            .verify(&bytes, &signature)
            .map_err(|_| "invalid transparency witness signature".to_string())
    }
}

pub fn transparency_signing_key_id(key: &VerifyingKey) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
}

fn signed_checkpoint_bytes(
    checkpoint: &TransparencyCheckpoint,
    map_root: &str,
    issued_at: i64,
    key_id: &str,
) -> Result<Vec<u8>, String> {
    let log_id = decode_hash("logId", &checkpoint.log_id)?;
    let root_hash = checkpoint.validate()?;
    let map_root = decode_hash("map rootHash", map_root)?;
    let key_id = decode_hash("operatorKeyId", key_id)?;
    if checkpoint.tree_size == 0 {
        return Err("signed transparency checkpoint must be non-empty".into());
    }
    let mut out = Vec::with_capacity(SIGNED_CHECKPOINT_DOMAIN.len() + 120);
    out.extend_from_slice(SIGNED_CHECKPOINT_DOMAIN);
    out.extend_from_slice(&log_id);
    out.extend_from_slice(&checkpoint.tree_size.to_be_bytes());
    out.extend_from_slice(&root_hash);
    out.extend_from_slice(&map_root);
    out.extend_from_slice(&issued_at.to_be_bytes());
    out.extend_from_slice(&key_id);
    Ok(out)
}

fn witness_attestation_bytes(
    authentication: &TransparencyCheckpointAuthentication,
    checkpoint: &TransparencyCheckpoint,
    map_root: &str,
    witness_id: &str,
    observed_at: i64,
    witness_key_id: &str,
) -> Result<Vec<u8>, String> {
    let operator = signed_checkpoint_bytes(
        checkpoint,
        map_root,
        authentication.issued_at,
        &authentication.operator_key_id,
    )?;
    let operator_signature =
        decode_signature("operatorSignature", &authentication.operator_signature)?;
    let witness_key_id = decode_hash("witness keyId", witness_key_id)?;
    let witness_id_len = u16::try_from(witness_id.len())
        .map_err(|_| "transparency witness id is too long".to_string())?;
    let mut out = Vec::with_capacity(
        WITNESS_ATTESTATION_DOMAIN.len() + operator.len() + witness_id.len() + 110,
    );
    out.extend_from_slice(WITNESS_ATTESTATION_DOMAIN);
    out.extend_from_slice(&operator);
    out.extend_from_slice(&operator_signature.to_bytes());
    out.extend_from_slice(&witness_id_len.to_be_bytes());
    out.extend_from_slice(witness_id.as_bytes());
    out.extend_from_slice(&observed_at.to_be_bytes());
    out.extend_from_slice(&witness_key_id);
    Ok(out)
}

fn validate_witness_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 255
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err("transparency witness id is invalid".into());
    }
    Ok(())
}

fn decode_verifying_key(name: &str, value: &str) -> Result<VerifyingKey, String> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| format!("{name} must be canonical base64"))?;
    if STANDARD.encode(&bytes) != value {
        return Err(format!("{name} must be canonical base64"));
    }
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("{name} must be 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| format!("{name} is not a valid Ed25519 key"))
}

fn decode_signature(name: &str, value: &str) -> Result<Signature, String> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| format!("{name} must be canonical base64"))?;
    if STANDARD.encode(&bytes) != value {
        return Err(format!("{name} must be canonical base64"));
    }
    Signature::from_slice(&bytes).map_err(|_| format!("{name} must be 64 bytes"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct TransparencyMapSibling {
    /// Zero-based bit depth in the SHA-256 account-map key (0 is the root).
    pub depth: u16,
    /// Non-default sibling hash at child depth `depth + 1`.
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ManifestTransparencyMapProof {
    /// Current sparse-map root.
    pub root_hash: String,
    /// Position of the map-root commitment in the chronological log.
    pub checkpoint_leaf_index: u64,
    /// RFC 6962 inclusion path for the map-root commitment.
    pub checkpoint_inclusion: Vec<String>,
    /// Compressed sparse-map membership path. Default empty siblings are
    /// omitted and reconstructed by the verifier.
    pub siblings: Vec<TransparencyMapSibling>,
}

impl ManifestTransparencyMapProof {
    pub fn verify(
        &self,
        leaf: &ManifestTransparencyLeaf,
        checkpoint: &TransparencyCheckpoint,
    ) -> Result<(), String> {
        let expected_root = decode_hash("map rootHash", &self.root_hash)?;
        if checkpoint.tree_size == 0
            || self.checkpoint_leaf_index.checked_add(1) != Some(checkpoint.tree_size)
        {
            return Err("current map commitment must be the checkpoint's final leaf".into());
        }

        let defaults = transparency_map_empty_hashes();
        let mut siblings = BTreeMap::new();
        for sibling in &self.siblings {
            if sibling.depth >= 256 {
                return Err("transparency map sibling depth is out of range".into());
            }
            let hash = decode_hash("map sibling", &sibling.hash)?;
            if hash == defaults[sibling.depth as usize + 1] {
                return Err("transparency map proof must omit default siblings".into());
            }
            if siblings.insert(sibling.depth, hash).is_some() {
                return Err("transparency map proof repeats a sibling depth".into());
            }
        }

        let key = transparency_map_key(&leaf.username)?;
        let mut actual = hash_transparency_map_leaf(leaf)?;
        for depth in (0..256usize).rev() {
            let sibling = siblings
                .get(&(depth as u16))
                .copied()
                .unwrap_or(defaults[depth + 1]);
            actual = if map_key_bit(&key, depth) == 0 {
                hash_transparency_node(actual, sibling)
            } else {
                hash_transparency_node(sibling, actual)
            };
        }
        if actual != expected_root {
            return Err("manifest is not the current transparency map value".into());
        }

        let log_root = checkpoint.validate()?;
        let inclusion = decode_path("map checkpoint inclusion", &self.checkpoint_inclusion)?;
        verify_inclusion(
            hash_transparency_map_checkpoint(expected_root),
            self.checkpoint_leaf_index,
            checkpoint.tree_size,
            &inclusion,
            log_root,
        )
    }
}

pub fn transparency_map_key(username: &str) -> Result<TransparencyHash, String> {
    if username.is_empty() || username.len() > 255 {
        return Err("transparency username must be 1-255 bytes".into());
    }
    let mut hasher = Sha256::new();
    hasher.update(MAP_KEY_DOMAIN);
    hasher.update((username.len() as u16).to_be_bytes());
    hasher.update(username.as_bytes());
    Ok(hasher.finalize().into())
}

pub fn hash_transparency_map_leaf(
    leaf: &ManifestTransparencyLeaf,
) -> Result<TransparencyHash, String> {
    let key = transparency_map_key(&leaf.username)?;
    let manifest_hash = decode_hash("manifestHash", &leaf.manifest_hash)?;
    let authority_key_id = decode_hash("authorityKeyId", &leaf.authority_key_id)?;
    if leaf.manifest_version == 0 {
        return Err("transparency manifest version must be positive".into());
    }
    let mut hasher = Sha256::new();
    hasher.update(MAP_LEAF_DOMAIN);
    hasher.update(key);
    hasher.update(leaf.manifest_version.to_be_bytes());
    hasher.update(manifest_hash);
    hasher.update(authority_key_id);
    Ok(hasher.finalize().into())
}

pub fn hash_transparency_map_checkpoint(map_root: TransparencyHash) -> TransparencyHash {
    let mut hasher = Sha256::new();
    hasher.update([0]);
    hasher.update(MAP_CHECKPOINT_DOMAIN);
    hasher.update(map_root);
    hasher.finalize().into()
}

pub fn transparency_map_empty_hashes() -> Vec<TransparencyHash> {
    let mut hashes = vec![[0; 32]; 257];
    hashes[256] = Sha256::digest(MAP_EMPTY_DOMAIN).into();
    for depth in (0..256).rev() {
        hashes[depth] = hash_transparency_node(hashes[depth + 1], hashes[depth + 1]);
    }
    hashes
}

pub fn map_key_bit(key: &TransparencyHash, depth: usize) -> u8 {
    (key[depth / 8] >> (7 - (depth % 8))) & 1
}

pub fn empty_transparency_root() -> TransparencyHash {
    Sha256::digest([]).into()
}

pub fn hash_transparency_node(left: TransparencyHash, right: TransparencyHash) -> TransparencyHash {
    let mut hasher = Sha256::new();
    hasher.update([1]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

pub(crate) fn largest_power_of_two_less_than(value: u64) -> u64 {
    debug_assert!(value > 1);
    1u64 << (63 - (value - 1).leading_zeros())
}

fn verify_inclusion(
    leaf_hash: TransparencyHash,
    leaf_index: u64,
    tree_size: u64,
    proof: &[TransparencyHash],
    expected_root: TransparencyHash,
) -> Result<(), String> {
    if tree_size == 0 || leaf_index >= tree_size || proof.len() > 64 {
        return Err("invalid transparency inclusion coordinates".into());
    }
    fn rebuild(
        leaf: TransparencyHash,
        index: u64,
        size: u64,
        proof: &[TransparencyHash],
        cursor: &mut usize,
    ) -> Result<TransparencyHash, String> {
        if size == 1 {
            return Ok(leaf);
        }
        let split = largest_power_of_two_less_than(size);
        if index < split {
            let left = rebuild(leaf, index, split, proof, cursor)?;
            let right = *proof
                .get(*cursor)
                .ok_or_else(|| "transparency inclusion proof is truncated".to_string())?;
            *cursor += 1;
            Ok(hash_transparency_node(left, right))
        } else {
            let right = rebuild(leaf, index - split, size - split, proof, cursor)?;
            let left = *proof
                .get(*cursor)
                .ok_or_else(|| "transparency inclusion proof is truncated".to_string())?;
            *cursor += 1;
            Ok(hash_transparency_node(left, right))
        }
    }
    let mut cursor = 0;
    let actual = rebuild(leaf_hash, leaf_index, tree_size, proof, &mut cursor)?;
    if cursor != proof.len() || actual != expected_root {
        return Err("transparency inclusion proof does not match the checkpoint".into());
    }
    Ok(())
}

fn verify_consistency(
    old_size: u64,
    new_size: u64,
    old_root: TransparencyHash,
    new_root: TransparencyHash,
    proof: &[TransparencyHash],
) -> Result<(), String> {
    if old_size == 0 || old_size > new_size || proof.len() > 64 {
        return Err("invalid transparency consistency coordinates".into());
    }
    if old_size == new_size {
        return if proof.is_empty() && old_root == new_root {
            Ok(())
        } else {
            Err("same-size transparency checkpoints disagree".into())
        };
    }

    let mut old_node = old_size - 1;
    let mut new_node = new_size - 1;
    while old_node & 1 == 1 {
        old_node >>= 1;
        new_node >>= 1;
    }

    let (mut old_hash, mut new_hash, mut cursor) = if old_node == 0 {
        (old_root, old_root, 0)
    } else {
        let first = *proof
            .first()
            .ok_or_else(|| "transparency consistency proof is truncated".to_string())?;
        (first, first, 1)
    };

    while cursor < proof.len() {
        if new_node == 0 {
            return Err("transparency consistency proof has extra nodes".into());
        }
        let sibling = proof[cursor];
        cursor += 1;
        if old_node & 1 == 1 || old_node == new_node {
            old_hash = hash_transparency_node(sibling, old_hash);
            new_hash = hash_transparency_node(sibling, new_hash);
            while old_node != 0 && old_node & 1 == 0 {
                old_node >>= 1;
                new_node >>= 1;
            }
        } else {
            new_hash = hash_transparency_node(new_hash, sibling);
        }
        old_node >>= 1;
        new_node >>= 1;
    }

    if new_node != 0 || old_hash != old_root || new_hash != new_root {
        return Err("transparency consistency proof does not link the checkpoints".into());
    }
    Ok(())
}

fn decode_path(name: &str, values: &[String]) -> Result<Vec<TransparencyHash>, String> {
    if values.len() > 64 {
        return Err(format!("{name} proof is too long"));
    }
    values
        .iter()
        .map(|value| decode_hash(name, value))
        .collect()
}

fn decode_hash(name: &str, value: &str) -> Result<TransparencyHash, String> {
    let decoded =
        hex::decode(value).map_err(|_| format!("{name} must be lowercase SHA-256 hex"))?;
    if decoded.len() != 32 || hex::encode(&decoded) != value {
        return Err(format!("{name} must be lowercase SHA-256 hex"));
    }
    decoded
        .try_into()
        .map_err(|_| format!("{name} must be 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(index: u64) -> TransparencyHash {
        let mut hasher = Sha256::new();
        hasher.update([0]);
        hasher.update(index.to_be_bytes());
        hasher.finalize().into()
    }

    fn root(leaves: &[TransparencyHash]) -> TransparencyHash {
        match leaves.len() {
            0 => empty_transparency_root(),
            1 => leaves[0],
            len => {
                let split = largest_power_of_two_less_than(len as u64) as usize;
                hash_transparency_node(root(&leaves[..split]), root(&leaves[split..]))
            }
        }
    }

    fn inclusion(index: usize, leaves: &[TransparencyHash]) -> Vec<TransparencyHash> {
        if leaves.len() == 1 {
            return Vec::new();
        }
        let split = largest_power_of_two_less_than(leaves.len() as u64) as usize;
        if index < split {
            let mut proof = inclusion(index, &leaves[..split]);
            proof.push(root(&leaves[split..]));
            proof
        } else {
            let mut proof = inclusion(index - split, &leaves[split..]);
            proof.push(root(&leaves[..split]));
            proof
        }
    }

    fn consistency_subproof(
        old_size: usize,
        leaves: &[TransparencyHash],
        complete: bool,
        proof: &mut Vec<TransparencyHash>,
    ) {
        if old_size == leaves.len() {
            if !complete {
                proof.push(root(leaves));
            }
            return;
        }
        let split = largest_power_of_two_less_than(leaves.len() as u64) as usize;
        if old_size <= split {
            consistency_subproof(old_size, &leaves[..split], complete, proof);
            proof.push(root(&leaves[split..]));
        } else {
            consistency_subproof(old_size - split, &leaves[split..], false, proof);
            proof.push(root(&leaves[..split]));
        }
    }

    #[test]
    fn inclusion_and_consistency_verify_for_many_tree_shapes() {
        let leaves = (0..64).map(leaf).collect::<Vec<_>>();
        for size in 1..=leaves.len() {
            for index in 0..size {
                verify_inclusion(
                    leaves[index],
                    index as u64,
                    size as u64,
                    &inclusion(index, &leaves[..size]),
                    root(&leaves[..size]),
                )
                .unwrap();
            }
            for old_size in 1..=size {
                let mut proof = Vec::new();
                if old_size != size {
                    consistency_subproof(old_size, &leaves[..size], true, &mut proof);
                }
                verify_consistency(
                    old_size as u64,
                    size as u64,
                    root(&leaves[..old_size]),
                    root(&leaves[..size]),
                    &proof,
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn tampered_paths_and_same_size_equivocation_fail() {
        let leaves = (0..5).map(leaf).collect::<Vec<_>>();
        let mut path = inclusion(3, &leaves);
        path[0][0] ^= 1;
        assert!(verify_inclusion(leaves[3], 3, 5, &path, root(&leaves)).is_err());
        assert!(verify_consistency(5, 5, root(&leaves), leaf(99), &[]).is_err());
    }

    #[test]
    fn operator_and_witness_signatures_bind_the_exact_checkpoint() {
        let checkpoint = TransparencyCheckpoint {
            log_id: "11".repeat(32),
            tree_size: 7,
            root_hash: "22".repeat(32),
        };
        let map_root = "33".repeat(32);
        let operator = SigningKey::from_bytes(&[44; 32]);
        let witness = SigningKey::from_bytes(&[55; 32]);
        let mut authentication = TransparencyCheckpointAuthentication::sign(
            &checkpoint,
            &map_root,
            1_752_688_000,
            &operator,
        )
        .unwrap();
        authentication
            .add_witness(
                &checkpoint,
                &map_root,
                "witness.example",
                1_752_688_001,
                &witness,
            )
            .unwrap();
        authentication.verify(&checkpoint, &map_root).unwrap();

        let mut fork = checkpoint.clone();
        fork.root_hash = "23".repeat(32);
        assert!(authentication.verify(&fork, &map_root).is_err());
        let mut forged = authentication.clone();
        forged.witnesses[0].witness_id = "other.example".into();
        assert!(forged.verify(&checkpoint, &map_root).is_err());
        let mut duplicate = authentication.clone();
        duplicate.witnesses.push(duplicate.witnesses[0].clone());
        assert!(duplicate.verify(&checkpoint, &map_root).is_err());
    }

    #[test]
    fn shared_auditor_emits_only_original_signed_fork_evidence() {
        fn statement(
            root: &str,
            operator: &SigningKey,
            witness_id: &str,
            witness: &SigningKey,
        ) -> TransparencySignedStatementV1 {
            let checkpoint = TransparencyCheckpoint {
                log_id: "11".repeat(32),
                tree_size: 9,
                root_hash: root.repeat(32),
            };
            let map_root = "33".repeat(32);
            let mut authentication = TransparencyCheckpointAuthentication::sign(
                &checkpoint,
                &map_root,
                1_752_688_000,
                operator,
            )
            .unwrap();
            authentication
                .add_witness(&checkpoint, &map_root, witness_id, 1_752_688_001, witness)
                .unwrap();
            TransparencySignedStatementV1 {
                checkpoint,
                map_root,
                authentication,
            }
        }

        let operator = SigningKey::from_bytes(&[61; 32]);
        let witness = SigningKey::from_bytes(&[62; 32]);
        let operator_view = statement("22", &operator, "witness.example", &witness);
        let forked = statement("44", &operator, "witness.example", &witness);
        let witness_view = WitnessViewV1::sign(
            "witness.example",
            1_752_688_010,
            vec![forked.clone()],
            &witness,
        )
        .unwrap();
        let evidence = audit_operator_witness_view(
            "chat.example",
            1_752_688_020,
            &operator_view,
            &witness_view,
        )
        .unwrap()
        .expect("same-size roots conflict");
        evidence.verify_contradiction().unwrap();
        assert_eq!(evidence.operator_statement, operator_view);
        assert_eq!(evidence.witness_statement, forked);
    }

    #[test]
    fn current_map_proof_binds_the_latest_manifest_to_the_log_head() {
        let manifest_leaf = ManifestTransparencyLeaf {
            username: "alice".into(),
            manifest_version: 3,
            manifest_hash: "11".repeat(32),
            authority_key_id: "22".repeat(32),
        };
        let key = transparency_map_key("alice").unwrap();
        let defaults = transparency_map_empty_hashes();
        let mut map_root = hash_transparency_map_leaf(&manifest_leaf).unwrap();
        for depth in (0..256).rev() {
            map_root = if map_key_bit(&key, depth) == 0 {
                hash_transparency_node(map_root, defaults[depth + 1])
            } else {
                hash_transparency_node(defaults[depth + 1], map_root)
            };
        }
        let log_root = hash_transparency_map_checkpoint(map_root);
        let checkpoint = TransparencyCheckpoint {
            log_id: "33".repeat(32),
            tree_size: 1,
            root_hash: hex::encode(log_root),
        };
        let proof = ManifestTransparencyMapProof {
            root_hash: hex::encode(map_root),
            checkpoint_leaf_index: 0,
            checkpoint_inclusion: Vec::new(),
            siblings: Vec::new(),
        };
        proof.verify(&manifest_leaf, &checkpoint).unwrap();

        let mut tampered = manifest_leaf.clone();
        tampered.manifest_version += 1;
        assert!(proof.verify(&tampered, &checkpoint).is_err());
        let mut stale = proof.clone();
        stale.checkpoint_leaf_index = 1;
        assert!(stale.verify(&manifest_leaf, &checkpoint).is_err());
    }

    #[test]
    fn sparse_current_map_proves_many_accounts_and_rejects_omission() {
        fn prefix(key: &TransparencyHash, depth: usize) -> TransparencyHash {
            let mut path = *key;
            let bytes = depth / 8;
            let bits = depth % 8;
            if bits == 0 {
                path[bytes..].fill(0);
            } else {
                path[bytes] &= 0xff << (8 - bits);
                path[bytes + 1..].fill(0);
            }
            path
        }
        fn sibling_prefix(key: &TransparencyHash, depth: usize) -> TransparencyHash {
            let mut path = prefix(key, depth + 1);
            path[depth / 8] ^= 1 << (7 - depth % 8);
            path
        }
        fn build(
            leaves: &[ManifestTransparencyLeaf],
            target: &ManifestTransparencyLeaf,
        ) -> (TransparencyHash, Vec<TransparencyMapSibling>) {
            let defaults = transparency_map_empty_hashes();
            let mut nodes = BTreeMap::new();
            for leaf in leaves {
                let key = transparency_map_key(&leaf.username).unwrap();
                let mut node = hash_transparency_map_leaf(leaf).unwrap();
                nodes.insert((256usize, key), node);
                for depth in (0..256).rev() {
                    let sibling = nodes
                        .get(&(depth + 1, sibling_prefix(&key, depth)))
                        .copied()
                        .unwrap_or(defaults[depth + 1]);
                    node = if map_key_bit(&key, depth) == 0 {
                        hash_transparency_node(node, sibling)
                    } else {
                        hash_transparency_node(sibling, node)
                    };
                    nodes.insert((depth, prefix(&key, depth)), node);
                }
            }
            let root = nodes[&(0, [0; 32])];
            let key = transparency_map_key(&target.username).unwrap();
            let siblings = (0..256)
                .filter_map(|depth| {
                    nodes
                        .get(&(depth + 1, sibling_prefix(&key, depth)))
                        .copied()
                        .filter(|hash| *hash != defaults[depth + 1])
                        .map(|hash| TransparencyMapSibling {
                            depth: depth as u16,
                            hash: hex::encode(hash),
                        })
                })
                .collect();
            (root, siblings)
        }

        let leaves = (0..16)
            .map(|index| ManifestTransparencyLeaf {
                username: format!("user{index}"),
                manifest_version: index + 1,
                manifest_hash: format!("{index:02x}").repeat(32),
                authority_key_id: format!("{:02x}", index + 16).repeat(32),
            })
            .collect::<Vec<_>>();
        for target in &leaves {
            let (map_root, siblings) = build(&leaves, target);
            let checkpoint = TransparencyCheckpoint {
                log_id: "44".repeat(32),
                tree_size: 1,
                root_hash: hex::encode(hash_transparency_map_checkpoint(map_root)),
            };
            let proof = ManifestTransparencyMapProof {
                root_hash: hex::encode(map_root),
                checkpoint_leaf_index: 0,
                checkpoint_inclusion: Vec::new(),
                siblings,
            };
            proof.verify(target, &checkpoint).unwrap();
            if !proof.siblings.is_empty() {
                let mut omitted = proof.clone();
                omitted.siblings.pop();
                assert!(omitted.verify(target, &checkpoint).is_err());
            }
        }
    }
}
