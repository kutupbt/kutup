//! Browser bindings for `kutup-crypto`.
//!
//! This crate contains no cryptographic construction or policy. It converts
//! JS transport values and delegates to the canonical Rust implementation.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::kdf::{self, AccountProtectionParameters, AccountProtectionSuiteId};
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountProtectionKeysView {
    key_encryption_key: String,
    login_key: String,
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

fn js_error(message: &str) -> JsValue {
    JsValue::from_str(message)
}
