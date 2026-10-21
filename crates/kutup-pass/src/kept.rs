//! Kept vault keys (docs/plans/pass.md, "Vault secrets"): the one place that
//! turns a vault's key into the record the account keeps, and back. The
//! website (through the Pass WASM module) and the `kutup` CLI both call these;
//! nothing else builds or reads a vault secret.
//!
//! What is kept opens the vault without holding a password the person chose
//! (only its SHA-256, KeePass's password part of the composite key); a
//! password Kutup Pass generated is kept as it is, so it can be shown; a key
//! file is kept as its key element ([`key_file_secret`]). The format itself is
//! `kutup_crypto::pass_vault`.

use kutup_crypto::pass_vault::{open_vault_secret, seal_vault_secret, VaultSecret};
use zeroize::Zeroizing;

use crate::kdbx::{key_file_secret, VaultKey};

/// Why a key could not be kept or read back.
#[derive(Debug, thiserror::Error)]
pub enum KeptError {
    /// A key known only as its hash (itself opened from what is kept) has no
    /// password to keep again.
    #[error("this key cannot be kept: its password is not known here")]
    NotKeepable,
    /// A generated key needs its password.
    #[error("a generated key needs its password")]
    NoPassword,
    /// An unusual key file (its key is not 32 bytes) too large to keep.
    #[error("this key file cannot be kept")]
    KeyFileNotKeepable,
    #[error(transparent)]
    Crypto(#[from] kutup_crypto::error::CryptoError),
}

/// A kept key, opened: the key that opens the vault, and the password Kutup
/// Pass generated for it (to show), if it did.
pub struct Kept {
    pub key: VaultKey,
    pub generated_password: Option<Zeroizing<String>>,
    /// The revision it was kept at (docs/plans/sealed-revisions.md): the
    /// next keep of this vault goes on top of it.
    pub revision: u64,
}

/// Seals `key` for the account: under `master_key`, bound to `binding` and
/// the vault. It does not open the vault: callers pass a key that opened it
/// (the Pass worker keeps the key its vault was opened or made with; the CLI
/// opens the vault with the key first). A key file is kept as its key element
/// ([`key_file_secret`]), which opens the vault as the file does.
/// `generated`: its password is one Kutup Pass made, kept to be shown.
pub fn seal(
    master_key: &[u8],
    binding: &str,
    file_id: &[u8; 16],
    revision: u64,
    key: &VaultKey,
    generated: bool,
) -> Result<Vec<u8>, KeptError> {
    if key.password.is_none() && key.password_hash.is_some() {
        return Err(KeptError::NotKeepable);
    }
    let key_file = match key.key_file.as_deref() {
        Some(file) => Some(Zeroizing::new(
            key_file_secret(file).ok_or(KeptError::KeyFileNotKeepable)?,
        )),
        None => None,
    };
    let key_file = key_file.as_deref().map(Vec::as_slice);
    let secret = match (generated, key.password.as_deref()) {
        (true, Some(password)) => VaultSecret::generated(password, key_file),
        (true, None) => return Err(KeptError::NoPassword),
        (false, password) => VaultSecret::chosen(password.map(String::as_str), key_file),
    };
    Ok(seal_vault_secret(
        master_key, binding, file_id, revision, &secret,
    )?)
}

/// Opens what the account keeps for vault `file_id`.
pub fn open(
    envelope: &[u8],
    master_key: &[u8],
    binding: &str,
    file_id: &[u8; 16],
) -> Result<Kept, KeptError> {
    let (secret, revision) = open_vault_secret(envelope, master_key, binding, file_id)?;
    let mut key = VaultKey::new();
    if let Some(hash) = secret.password_element() {
        key = key.with_password_hash(&hash);
    }
    if let Some(file) = &secret.key_file {
        key = key.with_key_file(file);
    }
    Ok(Kept {
        key,
        generated_password: secret.generated_password,
        revision,
    })
}

/// Keeps what the account keeps for vault `from` for vault `to` too, at
/// `revision`: for a copy of the vault, which has the same key. The secret
/// moves as it is (a chosen password's hash, a generated password, a key
/// file's element), so neither vault is opened and no password is needed.
pub fn reseal(
    envelope: &[u8],
    master_key: &[u8],
    binding: &str,
    from: &[u8; 16],
    to: &[u8; 16],
    revision: u64,
) -> Result<Vec<u8>, KeptError> {
    let (secret, _) = open_vault_secret(envelope, master_key, binding, from)?;
    Ok(seal_vault_secret(
        master_key, binding, to, revision, &secret,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{edit::new_vault, open as open_vault, save};

    const MASTER: [u8; 32] = [7; 32];
    const VAULT: [u8; 16] = [1; 16];
    const BINDING: &str = "0b9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e90";

    fn vault_saved_with(key: &VaultKey) -> Vec<u8> {
        let now = chrono::DateTime::from_timestamp(1_790_000_000, 0)
            .unwrap()
            .naive_utc();
        save(&new_vault("Kişisel", now).unwrap(), key).unwrap()
    }

    #[test]
    fn a_kept_key_opens_its_vault_and_a_chosen_password_is_not_kept() {
        let large: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        for (key, generated) in [
            (VaultKey::new().with_password("parola-çğ"), false),
            (
                VaultKey::new().with_password("p").with_key_file(&large),
                false,
            ),
            (VaultKey::new().with_key_file(b"<KeyFile/>"), false),
            (VaultKey::new().with_password("k7m2q-9xd4t-4tpav"), true),
        ] {
            let contents = vault_saved_with(&key);
            let envelope = seal(&MASTER, BINDING, &VAULT, 5, &key, generated).unwrap();
            let kept = open(&envelope, &MASTER, BINDING, &VAULT).unwrap();
            assert_eq!(kept.revision, 5);
            assert!(open_vault(&contents, &kept.key).is_ok());
            assert_eq!(kept.key.password, None, "never the password itself");
            assert_eq!(
                kept.generated_password.as_deref().map(String::as_str),
                generated.then(|| key.password.as_deref().unwrap().as_str())
            );
        }
    }

    #[test]
    fn a_copy_keeps_the_same_secret_and_only_for_itself() {
        const COPY: [u8; 16] = [2; 16];
        for (key, generated) in [
            (VaultKey::new().with_password("parola-çğ"), false),
            (VaultKey::new().with_password("k7m2q-9xd4t-4tpav"), true),
            (
                VaultKey::new()
                    .with_password("p")
                    .with_key_file(b"<KeyFile/>"),
                false,
            ),
        ] {
            let contents = vault_saved_with(&key);
            let envelope = seal(&MASTER, BINDING, &VAULT, 5, &key, generated).unwrap();
            let copied = reseal(&envelope, &MASTER, BINDING, &VAULT, &COPY, 1).unwrap();
            let kept = open(&copied, &MASTER, BINDING, &COPY).unwrap();
            assert_eq!(kept.revision, 1);
            assert!(open_vault(&contents, &kept.key).is_ok());
            assert_eq!(
                kept.generated_password.as_deref().map(String::as_str),
                generated.then(|| key.password.as_deref().unwrap().as_str())
            );
            // Bound to the copy: it doesn't stand in for the original.
            assert!(open(&copied, &MASTER, BINDING, &VAULT).is_err());
        }
        // Only from what is kept for the vault named.
        let envelope = seal(
            &MASTER,
            BINDING,
            &VAULT,
            5,
            &VaultKey::new().with_password("p"),
            false,
        )
        .unwrap();
        assert!(reseal(&envelope, &MASTER, BINDING, &COPY, &VAULT, 1).is_err());
        assert!(reseal(&envelope, &[8; 32], BINDING, &VAULT, &COPY, 1).is_err());
    }

    #[test]
    fn a_key_known_only_by_its_hash_is_not_kept_again() {
        let key = VaultKey::new().with_password("p");
        let envelope = seal(&MASTER, BINDING, &VAULT, 5, &key, false).unwrap();
        let kept = open(&envelope, &MASTER, BINDING, &VAULT).unwrap();
        assert!(matches!(
            seal(&MASTER, BINDING, &VAULT, 5, &kept.key, false),
            Err(KeptError::NotKeepable)
        ));
        assert!(matches!(
            seal(
                &MASTER,
                BINDING,
                &VAULT,
                5,
                &VaultKey::new().with_key_file(b"k"),
                true
            ),
            Err(KeptError::NoPassword)
        ));
    }

    #[test]
    fn bound_to_the_account_and_the_vault() {
        let envelope = seal(
            &MASTER,
            BINDING,
            &VAULT,
            5,
            &VaultKey::new().with_password("p"),
            false,
        )
        .unwrap();
        assert!(open(&envelope, &MASTER, BINDING, &[2; 16]).is_err());
        assert!(open(&envelope, &[8; 32], BINDING, &VAULT).is_err());
        assert!(open(
            &envelope,
            &MASTER,
            "1c2d3e4f-0000-4000-8000-000000000000",
            &VAULT
        )
        .is_err());
    }
}
