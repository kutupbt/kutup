//! Account self-authority and signed device-manifest primitives.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use kutup_chat_proto::{
    AccountAddress, DeviceManifest, ManifestDevice, ManifestTransparencyProof,
    TransparencyCheckpoint, TransparencyCheckpointAuthentication, TransparencyCheckpointResponse,
    TransparencyVerifierKey, TransparencyWitnessAttestation, UserPreKeyBundlesResponse,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize as _;

use crate::db::TransparencyWitnessTrust;
use crate::db::{AuthorityTrust, ManifestTrust, TransparencyTrust};
use crate::error::{ChatError, Result};

const AUTHORITY_KDF_INFO: &[u8] = b"kutup/chat/self-authority/v1";

/// Whether unsigned legacy/dev bundle responses are permitted. Production
/// engines default to [`Required`](Self::Required); the relaxed mode must be
/// selected explicitly and still verifies any manifest that is present.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestPolicy {
    Required,
    AllowMissingForDevelopment,
}

/// Application-supplied trust roots for one transparency namespace. A log
/// response cannot add a trusted witness to this policy.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransparencyPolicy {
    #[serde(default)]
    pub scopes: Vec<TransparencyScopePolicy>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransparencyScopePolicy {
    pub scope: String,
    pub operator_key_id: String,
    pub operator_public_key: String,
    #[serde(default)]
    pub witnesses: Vec<TransparencyVerifierKey>,
    #[serde(default)]
    pub witness_quorum: u16,
}

impl TransparencyPolicy {
    pub fn validate(&self) -> Result<()> {
        let mut scopes = std::collections::BTreeSet::new();
        for policy in &self.scopes {
            if policy.scope.is_empty() || !scopes.insert(policy.scope.as_str()) {
                return Err(ChatError::Invalid(
                    "transparency policy has an empty or repeated scope".into(),
                ));
            }
            let valid_key_id = hex::decode(&policy.operator_key_id)
                .ok()
                .filter(|bytes| bytes.len() == 32 && hex::encode(bytes) == policy.operator_key_id)
                .is_some();
            let valid_public_key = STANDARD
                .decode(&policy.operator_public_key)
                .ok()
                .filter(|bytes| STANDARD.encode(bytes) == policy.operator_public_key)
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
                .is_some_and(|key| {
                    kutup_chat_proto::transparency_signing_key_id(&key) == policy.operator_key_id
                });
            if !valid_key_id || !valid_public_key {
                return Err(ChatError::Invalid(
                    "transparency policy has an invalid operator key".into(),
                ));
            }
            let mut witness_ids = std::collections::BTreeSet::new();
            for witness in &policy.witnesses {
                witness.validate().map_err(ChatError::Invalid)?;
                if !witness_ids.insert(witness.witness_id.as_str()) {
                    return Err(ChatError::Invalid(
                        "transparency policy repeats a witness id".into(),
                    ));
                }
            }
            if usize::from(policy.witness_quorum) > policy.witnesses.len() {
                return Err(ChatError::Invalid(
                    "transparency witness quorum exceeds the trusted witness set".into(),
                ));
            }
        }
        Ok(())
    }

    fn for_scope(&self, scope: &str) -> Option<&TransparencyScopePolicy> {
        self.scopes.iter().find(|policy| policy.scope == scope)
    }
}

pub(crate) struct VerifiedBundleTrust {
    pub manifest: Option<ManifestTrust>,
    pub transparency: Option<TransparencyTrust>,
}

pub(crate) fn transparency_scope(peer: &str) -> Result<String> {
    let address: AccountAddress = peer
        .parse()
        .map_err(|error: kutup_chat_proto::AddressError| ChatError::Trust(error.to_string()))?;
    Ok(address.server.unwrap_or_else(|| "local".into()))
}

pub(crate) fn verify_manifest_publication(
    expected_account: &str,
    manifest: &DeviceManifest,
    proof: &ManifestTransparencyProof,
    prior_transparency: Option<&TransparencyTrust>,
    policy: &TransparencyPolicy,
) -> Result<TransparencyTrust> {
    let address: AccountAddress = expected_account
        .parse()
        .map_err(|error: kutup_chat_proto::AddressError| ChatError::Trust(error.to_string()))?;
    proof
        .leaf
        .matches_manifest(&address.username, manifest)
        .map_err(ChatError::Trust)?;
    proof.verify_inclusion().map_err(ChatError::Trust)?;
    proof.verify_current_map().map_err(ChatError::Trust)?;
    proof.verify_authentication().map_err(ChatError::Trust)?;
    let scope = address.server.unwrap_or_else(|| "local".into());
    let prior_checkpoint = prior_checkpoint(&scope, prior_transparency)?;
    proof
        .verify_consistency_from(prior_checkpoint.as_ref())
        .map_err(ChatError::Trust)?;
    verify_authenticated_checkpoint(
        scope,
        &proof.checkpoint,
        &proof.authentication,
        prior_transparency,
        policy,
    )
}

/// Verify a monitor response against the same application policy and durable
/// pin used by manifest/bundle acceptance, without touching account/session
/// state.
pub(crate) fn verify_transparency_checkpoint_response(
    scope: &str,
    response: &TransparencyCheckpointResponse,
    prior: Option<&TransparencyTrust>,
    policy: &TransparencyPolicy,
) -> Result<TransparencyTrust> {
    let prior_checkpoint = prior_checkpoint(scope, prior)?;
    response
        .verify(prior_checkpoint.as_ref())
        .map_err(ChatError::Trust)?;
    verify_authenticated_checkpoint(
        scope.to_string(),
        &response.checkpoint,
        &response.authentication,
        prior,
        policy,
    )
}

fn prior_checkpoint(
    scope: &str,
    prior: Option<&TransparencyTrust>,
) -> Result<Option<TransparencyCheckpoint>> {
    prior
        .map(|prior| {
            if prior.scope != scope {
                return Err(ChatError::Trust(
                    "transparency checkpoint belongs to another homeserver".into(),
                ));
            }
            Ok(TransparencyCheckpoint {
                log_id: prior.log_id.clone(),
                tree_size: prior.tree_size,
                root_hash: prior.root_hash.clone(),
            })
        })
        .transpose()
}

fn verify_authenticated_checkpoint(
    scope: String,
    checkpoint: &TransparencyCheckpoint,
    authentication: &TransparencyCheckpointAuthentication,
    prior: Option<&TransparencyTrust>,
    policy: &TransparencyPolicy,
) -> Result<TransparencyTrust> {
    let scope_policy = policy.for_scope(&scope);
    if let Some(scope_policy) = scope_policy {
        if authentication.operator_key_id != scope_policy.operator_key_id
            || authentication.operator_public_key != scope_policy.operator_public_key
        {
            return Err(ChatError::Trust(
                "transparency operator does not match application policy".into(),
            ));
        }
    }
    if let Some(prior) = prior {
        if !prior.operator_key_id.is_empty()
            && (prior.operator_key_id != authentication.operator_key_id
                || prior.operator_public_key != authentication.operator_public_key)
        {
            return Err(ChatError::Trust(
                "transparency operator key changed without an authenticated transition".into(),
            ));
        }
        if authentication.issued_at < prior.checkpoint_issued_at
            || (checkpoint.tree_size == prior.tree_size
                && prior.checkpoint_issued_at != 0
                && authentication.issued_at != prior.checkpoint_issued_at)
        {
            return Err(ChatError::Trust(
                "transparency checkpoint signing time rolled back or changed in place".into(),
            ));
        }
    }
    let witnesses =
        verify_witness_policy(&authentication.witnesses, scope_policy, prior, checkpoint)?;
    Ok(TransparencyTrust {
        scope,
        log_id: checkpoint.log_id.clone(),
        tree_size: checkpoint.tree_size,
        root_hash: checkpoint.root_hash.clone(),
        operator_key_id: authentication.operator_key_id.clone(),
        operator_public_key: authentication.operator_public_key.clone(),
        checkpoint_issued_at: authentication.issued_at,
        witnesses,
    })
}

fn verify_witness_policy(
    attestations: &[TransparencyWitnessAttestation],
    policy: Option<&TransparencyScopePolicy>,
    prior: Option<&TransparencyTrust>,
    checkpoint: &TransparencyCheckpoint,
) -> Result<Vec<TransparencyWitnessTrust>> {
    let Some(policy) = policy else {
        return Ok(prior
            .map(|prior| prior.witnesses.clone())
            .unwrap_or_default());
    };
    let mut accepted = Vec::new();
    let mut observed = 0usize;
    for trusted in &policy.witnesses {
        let previous = prior.and_then(|prior| {
            prior
                .witnesses
                .iter()
                .find(|witness| witness.witness_id == trusted.witness_id)
        });
        if let Some(previous) = previous {
            if previous.key_id != trusted.key_id || previous.public_key != trusted.public_key {
                return Err(ChatError::Trust(
                    "trusted transparency witness key changed without a transition".into(),
                ));
            }
        }
        let current = attestations
            .iter()
            .find(|attestation| trusted.matches(attestation));
        if let Some(current) = current {
            if let Some(previous) = previous {
                if current.observed_at < previous.observed_at
                    || checkpoint.tree_size < previous.tree_size
                    || (checkpoint.tree_size == previous.tree_size
                        && checkpoint.root_hash != previous.root_hash)
                {
                    return Err(ChatError::Trust(
                        "transparency witness observation rolled back or equivocated".into(),
                    ));
                }
            }
            observed += 1;
            accepted.push(TransparencyWitnessTrust {
                witness_id: current.witness_id.clone(),
                key_id: current.key_id.clone(),
                public_key: current.public_key.clone(),
                tree_size: checkpoint.tree_size,
                root_hash: checkpoint.root_hash.clone(),
                observed_at: current.observed_at,
            });
        } else if let Some(previous) = previous {
            accepted.push(previous.clone());
        }
    }
    if observed < usize::from(policy.witness_quorum) {
        return Err(ChatError::Trust(format!(
            "transparency checkpoint has {observed} trusted witnesses; {} required",
            policy.witness_quorum
        )));
    }
    accepted.sort_by(|left, right| left.witness_id.cmp(&right.witness_id));
    Ok(accepted)
}

/// Verify the signed manifest and its inclusion in the homeserver's append-only
/// log. The checkpoint is global per homeserver, so fetching any peer advances
/// the same durable consistency pin.
pub(crate) fn verify_transparent_bundle_response(
    expected_peer: &str,
    response: &UserPreKeyBundlesResponse,
    policy: ManifestPolicy,
    prior_manifest: Option<&ManifestTrust>,
    prior_transparency: Option<&TransparencyTrust>,
    transparency_policy: &TransparencyPolicy,
) -> Result<VerifiedBundleTrust> {
    let mut manifest = verify_bundle_response(expected_peer, response, policy, prior_manifest)?;
    let Some(served_manifest) = response.manifest.as_ref() else {
        if response.transparency.is_some() {
            return Err(ChatError::Trust(
                "server returned transparency without a signed manifest".into(),
            ));
        }
        return Ok(VerifiedBundleTrust {
            manifest,
            transparency: prior_transparency.cloned(),
        });
    };
    let Some(proof) = response.transparency.as_ref() else {
        return match policy {
            ManifestPolicy::Required => Err(ChatError::Trust(
                "server omitted the required manifest transparency proof".into(),
            )),
            ManifestPolicy::AllowMissingForDevelopment => Ok(VerifiedBundleTrust {
                manifest,
                transparency: prior_transparency.cloned(),
            }),
        };
    };

    let next = verify_manifest_publication(
        expected_peer,
        served_manifest,
        proof,
        prior_transparency,
        transparency_policy,
    )?;
    if let Some(trust) = manifest.as_mut() {
        if let Some(prior) = prior_manifest {
            if let Some(prior_position) = prior.transparency_position {
                if served_manifest.version == prior.highest_version
                    && proof.leaf_index != prior_position
                {
                    return Err(ChatError::Trust(
                        "unchanged manifest moved to another transparency log position".into(),
                    ));
                }
                if served_manifest.version > prior.highest_version
                    && proof.leaf_index <= prior_position
                {
                    return Err(ChatError::Trust(
                        "updated manifest did not advance its transparency monitor position".into(),
                    ));
                }
            }
        }
        trust.transparency_position = Some(proof.leaf_index);
    }

    Ok(VerifiedBundleTrust {
        manifest,
        transparency: Some(next),
    })
}

/// Deterministic account authority derived from the recoverable account master
/// key. Every authenticated device recovers the same authority without storing
/// another independent long-term secret.
pub struct AccountAuthority {
    signing: SigningKey,
}

impl AccountAuthority {
    pub fn derive(master_key: &[u8; 32]) -> Result<Self> {
        let hkdf = Hkdf::<Sha256>::new(None, master_key);
        let mut seed = [0u8; 32];
        hkdf.expand(AUTHORITY_KDF_INFO, &mut seed)
            .map_err(|_| ChatError::Invalid("self-authority KDF failed".into()))?;
        let signing = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Ok(Self { signing })
    }

    pub fn public_key_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.signing.verifying_key().as_bytes())
    }

    pub fn key_id(&self) -> String {
        hex::encode(Sha256::digest(self.signing.verifying_key().as_bytes()))
    }

    pub fn sign_manifest(
        &self,
        version: u64,
        previous_hash: Option<String>,
        mut devices: Vec<ManifestDevice>,
        issued_at: impl Into<String>,
    ) -> Result<DeviceManifest> {
        devices.sort_by_key(|device| device.device_id);
        let mut manifest = DeviceManifest {
            version,
            previous_hash,
            devices,
            issued_at: issued_at.into(),
            authority_key_id: self.key_id(),
            self_authority_key: self.public_key_base64(),
            signature: String::new(),
        };
        let bytes = manifest.signing_bytes().map_err(ChatError::Invalid)?;
        manifest.signature =
            base64::engine::general_purpose::STANDARD.encode(self.signing.sign(&bytes).to_bytes());
        Ok(manifest)
    }
}

pub fn verify_manifest(manifest: &DeviceManifest) -> Result<()> {
    manifest.verify().map_err(ChatError::Protocol)
}

/// Verify one bundle response and advance the durable peer-account trust pin.
/// This is intentionally separate from libsignal's per-device identity trust:
/// the manifest authenticates *which devices belong to the account*, while
/// libsignal authenticates each session and surfaces identity replacements.
pub fn verify_bundle_response(
    expected_peer: &str,
    response: &UserPreKeyBundlesResponse,
    policy: ManifestPolicy,
    prior: Option<&ManifestTrust>,
) -> Result<Option<ManifestTrust>> {
    if response.username != expected_peer {
        return Err(ChatError::Trust(format!(
            "bundle username {} does not match requested peer {expected_peer}",
            response.username
        )));
    }
    let Some(manifest) = &response.manifest else {
        if prior.is_some() {
            return Err(ChatError::Trust(
                "server omitted a previously required signed device manifest".into(),
            ));
        }
        return match policy {
            ManifestPolicy::Required => Err(ChatError::Trust(
                "server omitted the required signed device manifest".into(),
            )),
            ManifestPolicy::AllowMissingForDevelopment => Ok(None),
        };
    };
    manifest.verify().map_err(ChatError::Trust)?;

    if response.devices.len() != manifest.devices.len() {
        return Err(ChatError::Trust(
            "bundle device count does not match signed manifest".into(),
        ));
    }
    let mut served = std::collections::BTreeMap::new();
    for bundle in &response.devices {
        if served.insert(bundle.device_id, bundle).is_some() {
            return Err(ChatError::Trust(format!(
                "bundle response repeats device {}",
                bundle.device_id
            )));
        }
    }
    for declared in &manifest.devices {
        let bundle = served.get(&declared.device_id).ok_or_else(|| {
            ChatError::Trust(format!(
                "signed device {} has no prekey bundle",
                declared.device_id
            ))
        })?;
        if bundle.registration_id != declared.registration_id
            || bundle.identity_key != declared.identity_key
        {
            return Err(ChatError::Trust(format!(
                "bundle for device {} contradicts the signed manifest",
                declared.device_id
            )));
        }
    }

    let manifest_hash = manifest.manifest_hash().map_err(ChatError::Trust)?;
    let (trust, continuity_gap) = match prior {
        None => (AuthorityTrust::Tofu, manifest.version != 1),
        Some(prior) => {
            if prior.peer != expected_peer {
                return Err(ChatError::Trust(
                    "manifest pin belongs to another peer".into(),
                ));
            }
            if prior.authority_key_id != manifest.authority_key_id
                || prior.self_authority_key != manifest.self_authority_key
            {
                return Err(ChatError::Trust(
                    "peer account authority changed; explicit recovery is required".into(),
                ));
            }
            if manifest.version < prior.highest_version {
                return Err(ChatError::Trust(format!(
                    "manifest rollback from version {} to {}",
                    prior.highest_version, manifest.version
                )));
            }
            if manifest.version == prior.highest_version {
                if manifest_hash != prior.manifest_hash {
                    return Err(ChatError::Trust(format!(
                        "manifest equivocation at version {}",
                        manifest.version
                    )));
                }
                return Ok(Some(prior.clone()));
            }

            let consecutive = manifest.version == prior.highest_version.saturating_add(1);
            if consecutive
                && manifest.previous_hash.as_deref() != Some(prior.manifest_hash.as_str())
            {
                return Err(ChatError::Trust(
                    "manifest update does not link to the previously accepted version".into(),
                ));
            }
            (prior.trust, prior.continuity_gap || !consecutive)
        }
    };

    Ok(Some(ManifestTrust {
        peer: expected_peer.to_string(),
        authority_key_id: manifest.authority_key_id.clone(),
        self_authority_key: manifest.self_authority_key.clone(),
        highest_version: manifest.version,
        manifest_hash,
        trust,
        transparency_position: prior.and_then(|prior| prior.transparency_position),
        continuity_gap,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use kutup_chat_proto::{
        hash_transparency_map_checkpoint, hash_transparency_map_leaf, hash_transparency_node,
        map_key_bit, transparency_map_empty_hashes, transparency_map_key, DevicePreKeyBundle,
        EcPreKey, KemPreKey, ManifestTransparencyLeaf, ManifestTransparencyMapProof,
        ManifestTransparencyProof, SuiteId, TransparencyCheckpoint, UserPreKeyBundlesResponse,
    };

    fn bundle(device_id: u32, registration_id: u32, identity_key: &str) -> DevicePreKeyBundle {
        DevicePreKeyBundle {
            device_id,
            registration_id,
            suite: SuiteId::PqxdhTripleRatchetV1,
            identity_key: identity_key.into(),
            signed_pre_key: EcPreKey {
                key_id: 1,
                public_key: "signed".into(),
                signature: Some("signature".into()),
            },
            kyber_pre_key: KemPreKey {
                key_id: 2,
                public_key: "kyber".into(),
                signature: "signature".into(),
            },
            one_time_pre_key: None,
        }
    }

    fn response(manifest: DeviceManifest) -> UserPreKeyBundlesResponse {
        UserPreKeyBundlesResponse {
            username: "bob".into(),
            devices: vec![bundle(1, 42, "identity")],
            manifest: Some(manifest),
            transparency: None,
        }
    }

    #[test]
    fn authority_is_deterministic_and_manifest_detects_tampering() {
        let first = AccountAuthority::derive(&[7; 32]).unwrap();
        let second = AccountAuthority::derive(&[7; 32]).unwrap();
        assert_eq!(first.public_key_base64(), second.public_key_base64());

        let manifest = first
            .sign_manifest(
                1,
                None,
                vec![ManifestDevice {
                    device_id: 1,
                    identity_key: "identity".into(),
                    registration_id: 42,
                }],
                "2026-07-15T12:00:00Z",
            )
            .unwrap();
        verify_manifest(&manifest).unwrap();

        let mut tampered = manifest;
        tampered.devices[0].registration_id += 1;
        assert!(verify_manifest(&tampered).is_err());
    }

    #[test]
    fn bundle_manifest_pins_authority_and_rejects_tampering_and_rollback() {
        let authority = AccountAuthority::derive(&[9; 32]).unwrap();
        let v1 = authority
            .sign_manifest(
                1,
                None,
                vec![ManifestDevice {
                    device_id: 1,
                    identity_key: "identity".into(),
                    registration_id: 42,
                }],
                "2026-07-15T12:00:00Z",
            )
            .unwrap();
        let first =
            verify_bundle_response("bob", &response(v1.clone()), ManifestPolicy::Required, None)
                .unwrap()
                .unwrap();
        assert_eq!(first.trust, AuthorityTrust::Tofu);
        assert!(!first.continuity_gap);

        let mut injected = response(v1.clone());
        injected.devices[0].identity_key = "server-injected".into();
        assert!(matches!(
            verify_bundle_response("bob", &injected, ManifestPolicy::Required, Some(&first)),
            Err(ChatError::Trust(_))
        ));

        let v2 = authority
            .sign_manifest(
                2,
                Some(v1.manifest_hash().unwrap()),
                v1.devices.clone(),
                "2026-07-15T12:01:00Z",
            )
            .unwrap();
        let second =
            verify_bundle_response("bob", &response(v2), ManifestPolicy::Required, Some(&first))
                .unwrap()
                .unwrap();
        assert_eq!(second.highest_version, 2);
        assert!(!second.continuity_gap);

        assert!(matches!(
            verify_bundle_response(
                "bob",
                &response(v1),
                ManifestPolicy::Required,
                Some(&second)
            ),
            Err(ChatError::Trust(_))
        ));
    }

    #[test]
    fn missing_manifest_requires_explicit_dev_mode_and_cannot_downgrade_a_pin() {
        let unsigned = UserPreKeyBundlesResponse {
            username: "bob".into(),
            devices: vec![],
            manifest: None,
            transparency: None,
        };
        assert!(verify_bundle_response("bob", &unsigned, ManifestPolicy::Required, None).is_err());
        assert!(verify_bundle_response(
            "bob",
            &unsigned,
            ManifestPolicy::AllowMissingForDevelopment,
            None
        )
        .unwrap()
        .is_none());

        let pin = ManifestTrust {
            peer: "bob".into(),
            authority_key_id: "id".into(),
            self_authority_key: "key".into(),
            highest_version: 1,
            manifest_hash: "hash".into(),
            trust: AuthorityTrust::Tofu,
            transparency_position: None,
            continuity_gap: false,
        };
        assert!(verify_bundle_response(
            "bob",
            &unsigned,
            ManifestPolicy::AllowMissingForDevelopment,
            Some(&pin)
        )
        .is_err());
    }

    #[test]
    fn production_requires_manifest_inclusion_and_pins_the_global_checkpoint() {
        let authority = AccountAuthority::derive(&[33; 32]).unwrap();
        let manifest = authority
            .sign_manifest(
                1,
                None,
                vec![ManifestDevice {
                    device_id: 1,
                    identity_key: "identity".into(),
                    registration_id: 42,
                }],
                "2026-07-16T12:00:00Z",
            )
            .unwrap();
        let mut response = response(manifest.clone());
        assert!(verify_transparent_bundle_response(
            "bob",
            &response,
            ManifestPolicy::Required,
            None,
            None,
            &TransparencyPolicy::default(),
        )
        .is_err());

        let leaf = ManifestTransparencyLeaf::from_manifest("bob", &manifest).unwrap();
        let key = transparency_map_key("bob").unwrap();
        let defaults = transparency_map_empty_hashes();
        let mut map_root = hash_transparency_map_leaf(&leaf).unwrap();
        for depth in (0..256).rev() {
            map_root = if map_key_bit(&key, depth) == 0 {
                hash_transparency_node(map_root, defaults[depth + 1])
            } else {
                hash_transparency_node(defaults[depth + 1], map_root)
            };
        }
        let event_hash = leaf.hash().unwrap();
        let map_checkpoint_hash = hash_transparency_map_checkpoint(map_root);
        let signed_checkpoint = TransparencyCheckpoint {
            log_id: "01".repeat(32),
            tree_size: 2,
            root_hash: hex::encode(hash_transparency_node(event_hash, map_checkpoint_hash)),
        };
        let map_root_hex = hex::encode(map_root);
        let authentication = kutup_chat_proto::TransparencyCheckpointAuthentication::sign(
            &signed_checkpoint,
            &map_root_hex,
            1_752_688_000,
            &SigningKey::from_bytes(&[92; 32]),
        )
        .unwrap();
        response.transparency = Some(ManifestTransparencyProof {
            leaf_index: 0,
            checkpoint: signed_checkpoint,
            leaf,
            inclusion: vec![hex::encode(map_checkpoint_hash)],
            consistency_from: 0,
            consistency: Vec::new(),
            map: ManifestTransparencyMapProof {
                root_hash: map_root_hex,
                checkpoint_leaf_index: 1,
                checkpoint_inclusion: vec![hex::encode(event_hash)],
                siblings: Vec::new(),
            },
            authentication,
        });
        let witness = SigningKey::from_bytes(&[94; 32]);
        let proof = response.transparency.as_mut().unwrap();
        proof
            .authentication
            .add_witness(
                &proof.checkpoint,
                &proof.map.root_hash,
                "audit.example",
                1_752_688_001,
                &witness,
            )
            .unwrap();
        let witness_key = witness.verifying_key();
        let policy = TransparencyPolicy {
            scopes: vec![TransparencyScopePolicy {
                scope: "local".into(),
                operator_key_id: proof.authentication.operator_key_id.clone(),
                operator_public_key: proof.authentication.operator_public_key.clone(),
                witnesses: vec![TransparencyVerifierKey {
                    witness_id: "audit.example".into(),
                    key_id: kutup_chat_proto::transparency_signing_key_id(&witness_key),
                    public_key: base64::engine::general_purpose::STANDARD
                        .encode(witness_key.as_bytes()),
                }],
                witness_quorum: 1,
            }],
        };
        policy.validate().unwrap();
        let mut mismatched_operator_policy = policy.clone();
        mismatched_operator_policy.scopes[0].operator_public_key =
            STANDARD.encode(SigningKey::from_bytes(&[93; 32]).verifying_key().as_bytes());
        assert!(mismatched_operator_policy.validate().is_err());
        let verified = verify_transparent_bundle_response(
            "bob",
            &response,
            ManifestPolicy::Required,
            None,
            None,
            &policy,
        )
        .unwrap();
        let checkpoint = verified.transparency.unwrap();
        assert_eq!(checkpoint.scope, "local");
        assert_eq!(checkpoint.tree_size, 2);
        assert_eq!(checkpoint.witnesses.len(), 1);

        let mut unwitnessed = response.clone();
        unwitnessed
            .transparency
            .as_mut()
            .unwrap()
            .authentication
            .witnesses
            .clear();
        assert!(verify_transparent_bundle_response(
            "bob",
            &unwitnessed,
            ManifestPolicy::Required,
            None,
            None,
            &policy,
        )
        .is_err());

        response.transparency.as_mut().unwrap().map.root_hash = "03".repeat(32);
        assert!(verify_transparent_bundle_response(
            "bob",
            &response,
            ManifestPolicy::Required,
            None,
            None,
            &TransparencyPolicy::default(),
        )
        .is_err());
        response.transparency.as_mut().unwrap().map.root_hash = hex::encode(map_root);
        response.transparency.as_mut().unwrap().checkpoint.root_hash = "02".repeat(32);
        assert!(verify_transparent_bundle_response(
            "bob",
            &response,
            ManifestPolicy::Required,
            None,
            None,
            &TransparencyPolicy::default(),
        )
        .is_err());
    }
}
