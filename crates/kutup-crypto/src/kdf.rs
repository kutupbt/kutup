//! Purpose-separated V1 account and content key derivation.
//!
//! V1 Argon2id parameters are fixed and **must match every client exactly**:
//! opslimit (time) = 3, memlimit (memory) = 64 MiB (`64 * 1024 * 1024` bytes),
//! parallelism = 1, output = 32 bytes.
//!
//! Note on parallelism: libsodium's `crypto_pwhash` hard-codes 1 lane — the
//! "4 threads" comment in `kdf.ts` is inaccurate, which is why the Go code
//! passes `threads = 1`. All three implementations therefore agree.
//!
//! One Argon2id invocation produces an account-protection root. HKDF-SHA256
//! expands independent KEK and login subkeys. The server-visible login key can
//! therefore never decrypt the account master-key envelope.

use base64::Engine;
use dryoc::classic::crypto_pwhash::{crypto_pwhash, PasswordHashAlgorithm};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

/// Argon2id opslimit (iterations). Mirrors `argonTime` / `OPSLIMIT`.
pub const OPSLIMIT: u64 = 3;
/// Argon2id memlimit in bytes (64 MiB). Mirrors `argonMemory` (64*1024 KiB) / `MEMLIMIT`.
pub const MEMLIMIT: usize = 64 * 1024 * 1024;
/// Derived key length in bytes. Mirrors `argonKeyLen` / `KEYLEN`.
pub const KEY_LEN: usize = 32;
/// Account-protection salt length required by libsodium/dryoc Argon2id.
pub const ACCOUNT_PROTECTION_SALT_LEN: usize = 16;
/// Closed registry for the complete account-protection construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum AccountProtectionSuiteId {
    Argon2idHkdfSha256V1 = 1,
}

impl AccountProtectionSuiteId {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for AccountProtectionSuiteId {
    type Error = CryptoError;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::Argon2idHkdfSha256V1),
            _ => Err(CryptoError::InvalidInput(format!(
                "unknown account-protection suite {value}"
            ))),
        }
    }
}

const ACCOUNT_PROTECTION_HKDF_SALT: &[u8] = b"kutup/account-protection/v1\0";
const ACCOUNT_KEK_INFO: &[u8] = b"kutup/account-protection/kek/v1\0";
const ACCOUNT_LOGIN_INFO: &[u8] = b"kutup/account-protection/login/v1\0";
const RECOVERY_AUTH_SALT: &[u8] = b"kutup/account-recovery/auth-proof/v1\0";

/// HKDF salt for the per-file content key. Mirrors `kutup/file-content/v1`.
const CONTENT_KEY_SALT: &[u8] = b"kutup/file-content/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountProtectionParameters {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl AccountProtectionParameters {
    pub const V1: Self = Self {
        memory_kib: (MEMLIMIT / 1024) as u32,
        iterations: OPSLIMIT as u32,
        parallelism: 1,
    };

    pub fn validate_v1(self) -> Result<()> {
        if self != Self::V1 {
            return Err(CryptoError::InvalidInput(
                "unsupported V1 account-protection parameters".into(),
            ));
        }
        Ok(())
    }
}

pub struct AccountProtectionKeys {
    pub key_encryption_key: Zeroizing<[u8; KEY_LEN]>,
    pub login_key: Zeroizing<[u8; KEY_LEN]>,
}

fn argon2id(
    password: &[u8],
    salt: &[u8],
    parameters: AccountProtectionParameters,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    parameters.validate_v1()?;
    if salt.len() != ACCOUNT_PROTECTION_SALT_LEN {
        return Err(CryptoError::InvalidInput(format!(
            "account-protection salt must be {ACCOUNT_PROTECTION_SALT_LEN} bytes"
        )));
    }
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    crypto_pwhash(
        out.as_mut_slice(),
        password,
        salt,
        u64::from(parameters.iterations),
        parameters.memory_kib as usize * 1024,
        PasswordHashAlgorithm::Argon2id13,
    )
    .map_err(|e| CryptoError::Backend(format!("argon2id: {e}")))?;
    Ok(out)
}

/// Derive the V1 account KEK and server-facing login key from one expensive
/// password-hardened root.
pub fn derive_account_protection_keys(
    password: &str,
    salt: &[u8],
    parameters: AccountProtectionParameters,
) -> Result<AccountProtectionKeys> {
    let root = argon2id(password.as_bytes(), salt, parameters)?;
    let hkdf = Hkdf::<Sha256>::new(Some(ACCOUNT_PROTECTION_HKDF_SALT), root.as_slice());
    let mut key_encryption_key = Zeroizing::new([0u8; KEY_LEN]);
    let mut login_key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(ACCOUNT_KEK_INFO, key_encryption_key.as_mut_slice())
        .map_err(|_| CryptoError::Backend("account KEK HKDF expand".into()))?;
    hkdf.expand(ACCOUNT_LOGIN_INFO, login_key.as_mut_slice())
        .map_err(|_| CryptoError::Backend("account login HKDF expand".into()))?;
    Ok(AccountProtectionKeys {
        key_encryption_key,
        login_key,
    })
}

/// Base64-input convenience wrapper for login/CLI clients.
pub fn derive_account_protection_keys_b64(
    password: &str,
    salt_b64: &str,
    parameters: AccountProtectionParameters,
) -> Result<AccountProtectionKeys> {
    let salt = base64::engine::general_purpose::STANDARD.decode(salt_b64)?;
    derive_account_protection_keys(password, &salt, parameters)
}

/// Derive the server-visible recovery authorization proof. The 32-byte raw
/// recovery entropy continues to encrypt the recovery master-key wrap and is
/// never sent to the server.
pub fn derive_recovery_auth_proof(
    recovery_entropy: &[u8],
    login_email: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if recovery_entropy.len() != KEY_LEN {
        return Err(CryptoError::InvalidInput(
            "recovery entropy must be 32 bytes".into(),
        ));
    }
    let canonical_email = login_email.trim().to_ascii_lowercase();
    if canonical_email.is_empty() {
        return Err(CryptoError::InvalidInput(
            "recovery login email is empty".into(),
        ));
    }
    let hkdf = Hkdf::<Sha256>::new(Some(RECOVERY_AUTH_SALT), recovery_entropy);
    let mut proof = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(canonical_email.as_bytes(), proof.as_mut_slice())
        .map_err(|_| CryptoError::Backend("recovery proof HKDF expand".into()))?;
    Ok(proof)
}

/// Derives the per-file content key used for AEAD-encrypted child blobs
/// (whiteboard asset blobs at `files/{fileId}/assets/*`).
///
/// `HKDF-SHA256(ikm = collection_master, salt = "kutup/file-content/v1",
/// info = file_id)` → 32 bytes. Mirrors `DeriveContentKey` and
/// `frontend/src/collab/cryptoFrame.ts`.
pub fn derive_content_key(
    collection_master: &[u8],
    file_id: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let hk = Hkdf::<Sha256>::new(Some(CONTENT_KEY_SALT), collection_master);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(file_id.as_bytes(), out.as_mut_slice())
        .map_err(|_| CryptoError::Backend("hkdf expand".into()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_proof_is_email_normalized_and_not_raw_entropy() {
        let entropy = [9u8; 32];
        let first = derive_recovery_auth_proof(&entropy, " Alice@Example.COM ").unwrap();
        let second = derive_recovery_auth_proof(&entropy, "alice@example.com").unwrap();
        assert_eq!(first.as_slice(), second.as_slice());
        assert_ne!(first.as_slice(), entropy.as_slice());
        assert_ne!(
            first.as_slice(),
            derive_recovery_auth_proof(&entropy, "bob@example.com")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn account_parameters_and_salt_are_closed() {
        assert!(AccountProtectionParameters::V1.validate_v1().is_ok());
        assert!(AccountProtectionParameters {
            parallelism: 2,
            ..AccountProtectionParameters::V1
        }
        .validate_v1()
        .is_err());
        assert!(derive_account_protection_keys(
            "password",
            &[0u8; 15],
            AccountProtectionParameters::V1,
        )
        .is_err());
    }
}
