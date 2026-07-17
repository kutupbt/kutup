//! Account self-authority and signed device-manifest primitives.

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use hkdf::Hkdf;
use kutup_chat_proto::{
    AccountAddress, DeviceManifest, ManifestDevice, ManifestTransparencyProof,
    TransparencyCheckpoint, UserPreKeyBundlesResponse,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize as _;

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
    let scope = address.server.unwrap_or_else(|| "local".into());
    let prior_checkpoint = prior_transparency
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
        .transpose()?;
    proof
        .verify_consistency_from(prior_checkpoint.as_ref())
        .map_err(ChatError::Trust)?;
    Ok(TransparencyTrust {
        scope,
        log_id: proof.checkpoint.log_id.clone(),
        tree_size: proof.checkpoint.tree_size,
        root_hash: proof.checkpoint.root_hash.clone(),
    })
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

    let next =
        verify_manifest_publication(expected_peer, served_manifest, proof, prior_transparency)?;
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
        response.transparency = Some(ManifestTransparencyProof {
            leaf_index: 0,
            checkpoint: TransparencyCheckpoint {
                log_id: "01".repeat(32),
                tree_size: 2,
                root_hash: hex::encode(hash_transparency_node(event_hash, map_checkpoint_hash)),
            },
            leaf,
            inclusion: vec![hex::encode(map_checkpoint_hash)],
            consistency_from: 0,
            consistency: Vec::new(),
            map: ManifestTransparencyMapProof {
                root_hash: hex::encode(map_root),
                checkpoint_leaf_index: 1,
                checkpoint_inclusion: vec![hex::encode(event_hash)],
                siblings: Vec::new(),
            },
        });
        let verified = verify_transparent_bundle_response(
            "bob",
            &response,
            ManifestPolicy::Required,
            None,
            None,
        )
        .unwrap();
        let checkpoint = verified.transparency.unwrap();
        assert_eq!(checkpoint.scope, "local");
        assert_eq!(checkpoint.tree_size, 2);

        response.transparency.as_mut().unwrap().map.root_hash = "03".repeat(32);
        assert!(verify_transparent_bundle_response(
            "bob",
            &response,
            ManifestPolicy::Required,
            None,
            None,
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
        )
        .is_err());
    }
}
