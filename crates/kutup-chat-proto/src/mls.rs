//! Canonical MLS conversation, ordering, and anonymous-delivery protocol.
//!
//! OpenMLS owns the MLS state machine in clients. These types deliberately
//! contain only authenticated control metadata and opaque ciphertext so Kutup
//! servers never receive epoch secrets or message plaintext.

use std::collections::BTreeSet;

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use p256::ecdsa::{signature::Verifier as _, Signature as P256Signature, VerifyingKey as P256Key};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{AccountAddress, DeviceManifest, ManifestTransparencyProof};

pub const MLS_PROTOCOL_VERSION: u16 = 1;
pub const MLS_ORDERING_SERVICE_POLICY_VERSION: u16 = 1;
pub const MLS_GROUP_AUTHORIZATION_POLICY_VERSION: u16 = 1;
pub const MLS_GROUP_CRYPTOGRAPHIC_POLICY_VERSION: u16 = 1;
pub const MLS_CIPHERSUITE_P256_AES128GCM_SHA256_P256: u16 = 0x0002;
/// Private-use RFC 9420 GroupContext extension carrying Kutup's
/// group-encrypted authorization/control state. Every V1 KeyPackage advertises
/// this extension and every V1 group requires it.
pub const MLS_PRIVATE_CONTROL_EXTENSION_TYPE: u16 = 0xff4b;
pub const ANONYMOUS_MLS_DELIVERY_CONTEXT: &[u8] = b"kutup/anonymous-mls-delivery/v1";
const GROUP_DELIVERY_CAPABILITY_CONTEXT: &[u8] = b"kutup/group-delivery-capability/v1";
const MAX_CANONICAL_POLICY_BYTES: usize = 256 * 1024;
const MAX_MLS_GROUP_ID_BYTES: usize = 255;
const MAX_MLS_KEY_PACKAGE_BYTES: usize = 64 * 1024;
const MAX_MLS_CONTROL_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_MLS_APPLICATION_BYTES: usize = 1024 * 1024;
const MAX_ANONYMOUS_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_ANONYMOUS_ENVELOPES: usize = 32;
const MAX_AUTHORITY_BOOTSTRAP_COMMITS_PER_PAGE: usize = 64;
const MAX_AUTHORITY_BOOTSTRAP_PAGE_BYTES: usize = 8 * 1024 * 1024;
const MAX_MEMBERSHIP_DELIVERY_BYTES: usize = 8 * 1024 * 1024;
const MAX_MEMBERSHIP_ENVELOPES: usize = 4096;

mod conversation;
pub use conversation::*;
mod control;
pub use control::*;
mod bootstrap;
pub use bootstrap::*;
use bootstrap::{replay_mls_control_history, validate_participant_domain_set};
mod recovery;
pub use recovery::*;
mod delivery;
pub use delivery::*;

fn decode_canonical<T>(bytes: &[u8], validate: fn(&T) -> Result<(), String>) -> Result<T, String>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.len() > MAX_CANONICAL_POLICY_BYTES {
        return Err("canonical MLS payload is too large".into());
    }
    let value: T = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    validate(&value)?;
    if serde_json::to_vec(&value).map_err(|error| error.to_string())? != bytes {
        return Err("MLS payload is not in canonical JSON encoding".into());
    }
    Ok(value)
}

fn validate_hash(name: &str, value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|_| format!("{name} must be lowercase SHA-256 hex"))?;
    if bytes.len() != 32 || hex::encode(&bytes) != value {
        return Err(format!("{name} must be lowercase SHA-256 hex"));
    }
    bytes
        .try_into()
        .map_err(|_| format!("{name} has the wrong length"))
}

fn validate_uncompressed_p256(name: &str, value: &str) -> Result<(), String> {
    let bytes = decode_canonical_base64(name, value, 65, 65)?;
    if bytes.first() != Some(&4) || p256::PublicKey::from_sec1_bytes(&bytes).is_err() {
        return Err(format!("{name} must be a valid uncompressed P-256 point"));
    }
    Ok(())
}

fn decode_canonical_base64(
    name: &str,
    value: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| format!("{name} must be canonical padded base64"))?;
    if bytes.len() < minimum
        || bytes.len() > maximum
        || base64::engine::general_purpose::STANDARD.encode(&bytes) != value
    {
        return Err(format!(
            "{name} must be canonical padded base64 within its size limit"
        ));
    }
    Ok(bytes)
}

fn validate_ed25519_key(name: &str, key_id: &str, encoded: &str) -> Result<(), String> {
    validate_hash(name, key_id)?;
    let bytes = decode_canonical_base64(name, encoded, 32, 32)?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("{name} must be 32 bytes"))?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|_| format!("{name} is not Ed25519"))?;
    if hex::encode(Sha256::digest(key_bytes)) != key_id {
        return Err(format!("{name} key id does not match its public key"));
    }
    Ok(())
}

fn verify_ed25519_signature(
    public_key: &str,
    message: &[u8],
    signature: &str,
    name: &str,
) -> Result<(), String> {
    let public = decode_canonical_base64(name, public_key, 32, 32)?;
    let signature = decode_canonical_base64(name, signature, 64, 64)?;
    let verifying_key = VerifyingKey::from_bytes(
        &public
            .try_into()
            .map_err(|_| format!("{name} public key must be 32 bytes"))?,
    )
    .map_err(|_| format!("{name} public key is not Ed25519"))?;
    let signature =
        Signature::from_slice(&signature).map_err(|_| format!("{name} signature is malformed"))?;
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| format!("{name} signature is invalid"))
}

fn push_string(out: &mut Vec<u8>, value: &str) -> Result<(), String> {
    let length = u32::try_from(value.len()).map_err(|_| "MLS string is too long")?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests;
