//! Account self-authority and signed device-manifest primitives.

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use hkdf::Hkdf;
use kutup_chat_proto::{DeviceManifest, ManifestDevice};
use sha2::{Digest as _, Sha256};

use crate::error::{ChatError, Result};

const AUTHORITY_KDF_INFO: &[u8] = b"kutup/chat/self-authority/v1";

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
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
        })
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
