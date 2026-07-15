//! Account self-authority and signed device-manifest primitives.

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use hkdf::Hkdf;
use kutup_chat_proto::{DeviceManifest, ManifestDevice, UserPreKeyBundlesResponse};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize as _;

use crate::db::{AuthorityTrust, ManifestTrust};
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
        continuity_gap,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kutup_chat_proto::{
        DevicePreKeyBundle, EcPreKey, KemPreKey, SuiteId, UserPreKeyBundlesResponse,
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
}
