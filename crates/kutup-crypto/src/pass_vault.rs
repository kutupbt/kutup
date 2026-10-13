//! Kutup Pass vault secrets (docs/plans/pass.md, "Vault secrets").
//!
//! A vault is a KeePass file in Drive with its own composite key (a password,
//! a key file, or both), so KeePass apps keep opening it. Kutup Pass and
//! `kutup sync` unlock it with the Kutup sign-in, as Proton Pass does: the
//! vault's key is kept in an [`account_envelope`] under the master key
//! (purpose `PassVaultSecret`), one per person and vault, stored by the
//! server and unreadable to it. The payload binds the vault's file id, so a
//! server cannot hand one vault's secret to another vault.

use zeroize::Zeroizing;

use crate::account_envelope::{self, AccountEnvelopePurpose};
use crate::error::{CryptoError, Result};

const DOMAIN: &[u8] = b"kutup/pass-vault-secret/v1\0";
const HAS_PASSWORD: u8 = 1;
const HAS_KEY_FILE: u8 = 2;

/// The longest vault password kept, in bytes (UTF-8).
pub const MAX_PASSWORD_BYTES: usize = 1024;
/// The largest key file kept, in bytes. KeePass reduces any other file to
/// its SHA-256, which works as the same key (`kutup_pass::key_file_secret`).
pub const MAX_KEY_FILE_BYTES: usize = 2048;

/// What opens one vault.
#[derive(Clone, PartialEq, Eq)]
pub struct VaultSecretV1 {
    pub password: Option<Zeroizing<String>>,
    pub key_file: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for VaultSecretV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultSecretV1")
            .field("password", &self.password.as_ref().map(|_| "[redacted]"))
            .field("key_file", &self.key_file.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

fn invalid(message: &str) -> CryptoError {
    CryptoError::InvalidInput(format!("vault secret: {message}"))
}

fn payload(file_id: &[u8; 16], secret: &VaultSecretV1) -> Result<Zeroizing<Vec<u8>>> {
    if secret.password.is_none() && secret.key_file.is_none() {
        return Err(invalid("a vault needs a password or a key file"));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(
        DOMAIN.len() + 16 + 1 + 4 + MAX_PASSWORD_BYTES + MAX_KEY_FILE_BYTES,
    ));
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(file_id);
    let mut flags = 0;
    if secret.password.is_some() {
        flags |= HAS_PASSWORD;
    }
    if secret.key_file.is_some() {
        flags |= HAS_KEY_FILE;
    }
    out.push(flags);
    if let Some(password) = &secret.password {
        if password.len() > MAX_PASSWORD_BYTES {
            return Err(invalid("the password is too long"));
        }
        push(&mut out, password.as_bytes());
    }
    if let Some(key_file) = &secret.key_file {
        if key_file.is_empty() || key_file.len() > MAX_KEY_FILE_BYTES {
            return Err(invalid("the key file must be 1 to 2048 bytes"));
        }
        push(&mut out, key_file);
    }
    Ok(out)
}

fn push(out: &mut Vec<u8>, value: &[u8]) {
    // Both limits are far below u16::MAX.
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

fn take<'a>(rest: &mut &'a [u8], len: usize) -> Result<&'a [u8]> {
    if rest.len() < len {
        return Err(CryptoError::AuthFailed);
    }
    let (head, tail) = rest.split_at(len);
    *rest = tail;
    Ok(head)
}

fn take_value<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8]> {
    let len = u16::from_be_bytes(take(rest, 2)?.try_into().expect("two bytes")) as usize;
    take(rest, len)
}

/// Seals the secret of vault `file_id` (the Drive file's UUID bytes) under
/// the master key.
pub fn seal_vault_secret(
    master_key: &[u8],
    binding: &str,
    file_id: &[u8; 16],
    secret: &VaultSecretV1,
) -> Result<Vec<u8>> {
    account_envelope::seal_object(
        &payload(file_id, secret)?,
        master_key,
        AccountEnvelopePurpose::PassVaultSecret,
        binding,
        file_id,
    )
}

/// [`seal_vault_secret`] with a fixed nonce, for checked-in vectors only.
pub fn seal_vault_secret_with_nonce(
    master_key: &[u8],
    binding: &str,
    file_id: &[u8; 16],
    secret: &VaultSecretV1,
    nonce: &[u8],
) -> Result<Vec<u8>> {
    account_envelope::seal_suite(
        account_envelope::AccountEnvelopeSuiteId::XChaCha20Poly1305HkdfV2,
        &payload(file_id, secret)?,
        master_key,
        AccountEnvelopePurpose::PassVaultSecret,
        binding,
        file_id,
        nonce,
    )
}

/// Opens the secret of vault `file_id`; fails unless it was sealed for that
/// vault.
pub fn open_vault_secret(
    envelope: &[u8],
    master_key: &[u8],
    binding: &str,
    file_id: &[u8; 16],
) -> Result<VaultSecretV1> {
    let plain = Zeroizing::new(account_envelope::open_object(
        envelope,
        master_key,
        AccountEnvelopePurpose::PassVaultSecret,
        binding,
        file_id,
    )?);
    let mut rest = plain.strip_prefix(DOMAIN).ok_or(CryptoError::AuthFailed)?;
    if take(&mut rest, 16)? != file_id {
        return Err(CryptoError::AuthFailed);
    }
    let flags = take(&mut rest, 1)?[0];
    if flags == 0 || flags & !(HAS_PASSWORD | HAS_KEY_FILE) != 0 {
        return Err(CryptoError::AuthFailed);
    }
    let password = if flags & HAS_PASSWORD != 0 {
        let bytes = take_value(&mut rest)?;
        Some(Zeroizing::new(
            std::str::from_utf8(bytes)
                .map_err(|_| CryptoError::AuthFailed)?
                .to_owned(),
        ))
    } else {
        None
    };
    let key_file = if flags & HAS_KEY_FILE != 0 {
        Some(Zeroizing::new(take_value(&mut rest)?.to_vec()))
    } else {
        None
    };
    if !rest.is_empty() {
        return Err(CryptoError::AuthFailed);
    }
    Ok(VaultSecretV1 { password, key_file })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: [u8; 32] = [7; 32];
    const VAULT: [u8; 16] = [1; 16];

    fn secret(password: Option<&str>, key_file: Option<&[u8]>) -> VaultSecretV1 {
        VaultSecretV1 {
            password: password.map(|p| Zeroizing::new(p.to_owned())),
            key_file: key_file.map(|k| Zeroizing::new(k.to_vec())),
        }
    }

    #[test]
    fn round_trips_every_kind_of_key() {
        for s in [
            secret(Some("parola-çğ"), None),
            secret(None, Some(b"<KeyFile/>")),
            secret(Some(""), Some(&[9; 32])),
        ] {
            let sealed =
                seal_vault_secret(&MASTER, "0b9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e90", &VAULT, &s)
                    .unwrap();
            assert_eq!(
                open_vault_secret(
                    &sealed,
                    &MASTER,
                    "0b9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e90",
                    &VAULT
                )
                .unwrap(),
                s
            );
        }
    }

    #[test]
    fn bound_to_the_vault_the_account_and_the_key() {
        let sealed = seal_vault_secret(
            &MASTER,
            "0b9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e90",
            &VAULT,
            &secret(Some("p"), None),
        )
        .unwrap();
        assert!(open_vault_secret(
            &sealed,
            &MASTER,
            "0b9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e90",
            &[2; 16]
        )
        .is_err());
        assert!(open_vault_secret(
            &sealed,
            &MASTER,
            "1c9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e91",
            &VAULT
        )
        .is_err());
        assert!(open_vault_secret(
            &sealed,
            &[8; 32],
            "0b9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e90",
            &VAULT
        )
        .is_err());
    }

    #[test]
    fn refuses_empty_and_oversized_secrets() {
        let seal = |s: &VaultSecretV1| {
            seal_vault_secret(&MASTER, "0b9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e90", &VAULT, s)
        };
        assert!(seal(&secret(None, None)).is_err());
        assert!(seal(&secret(Some(&"x".repeat(MAX_PASSWORD_BYTES + 1)), None)).is_err());
        assert!(seal(&secret(None, Some(&[0; MAX_KEY_FILE_BYTES + 1]))).is_err());
        assert!(seal(&secret(None, Some(&[]))).is_err());
    }
}
