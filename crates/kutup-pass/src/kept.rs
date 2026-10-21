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
    /// A generated key needs its password itself, not only its hash.
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

/// Whose password a kept key holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordKind {
    /// One the person chose (or none): kept only as its SHA-256, so a key
    /// that holds just that hash is kept too.
    Chosen,
    /// One Kutup Pass generated: kept as it is, to be shown, so the key must
    /// hold the password itself.
    Generated,
}

/// Seals `key` for the account: under `master_key`, bound to `binding` and
/// the vault. It does not open the vault: callers pass a key that opened it
/// (the Pass worker keeps the key its vault was opened or made with; the CLI
/// opens the vault with the key first). A key file is kept as its key element
/// ([`key_file_secret`]), which opens the vault as the file does.
/// `kind` says whose password it is (see [`PasswordKind`]).
pub fn seal(
    master_key: &[u8],
    binding: &str,
    file_id: &[u8; 16],
    revision: u64,
    key: &VaultKey,
    kind: PasswordKind,
) -> Result<Vec<u8>, KeptError> {
    let key_file = match key.key_file.as_deref() {
        Some(file) => Some(Zeroizing::new(
            key_file_secret(file).ok_or(KeptError::KeyFileNotKeepable)?,
        )),
        None => None,
    };
    let key_file = key_file.as_deref().map(Vec::as_slice);
    let secret = match (kind, key.password.as_deref(), key.password_hash.as_deref()) {
        (PasswordKind::Generated, Some(password), _) => VaultSecret::generated(password, key_file),
        (PasswordKind::Generated, None, _) => return Err(KeptError::NoPassword),
        (PasswordKind::Chosen, Some(password), _) => VaultSecret::chosen(Some(password), key_file),
        // Known only as its hash (a vault opened with its kept key, its key
        // file changed): kept as that hash, which is what a chosen password
        // is kept as anyway.
        (PasswordKind::Chosen, None, Some(hash)) => VaultSecret::chosen_hashed(hash, key_file),
        (PasswordKind::Chosen, None, None) => VaultSecret::chosen(None, key_file),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(generated: bool) -> PasswordKind {
        if generated {
            PasswordKind::Generated
        } else {
            PasswordKind::Chosen
        }
    }
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
            let envelope = seal(&MASTER, BINDING, &VAULT, 5, &key, kind(generated)).unwrap();
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
    fn a_chosen_password_known_only_by_its_hash_is_kept_as_that_hash() {
        // A vault opened with its kept key holds its password as the hash.
        let key = VaultKey::new().with_password("parola-çğ");
        let envelope = seal(&MASTER, BINDING, &VAULT, 5, &key, PasswordKind::Chosen).unwrap();
        let kept = open(&envelope, &MASTER, BINDING, &VAULT).unwrap();
        let again = seal(&MASTER, BINDING, &VAULT, 6, &kept.key, PasswordKind::Chosen).unwrap();
        let (first, _) = open_vault_secret(&envelope, &MASTER, BINDING, &VAULT).unwrap();
        let (second, revision) = open_vault_secret(&again, &MASTER, BINDING, &VAULT).unwrap();
        assert_eq!(revision, 6);
        assert_eq!(
            (
                first.password_hash,
                first.generated_password,
                first.key_file
            ),
            (
                second.password_hash,
                second.generated_password,
                second.key_file
            ),
            "the same secret as the password itself gives"
        );

        // A generated one needs the password itself: its hash, or no
        // password at all, is refused.
        for key in [kept.key.clone(), VaultKey::new().with_key_file(b"k")] {
            assert!(matches!(
                seal(&MASTER, BINDING, &VAULT, 7, &key, PasswordKind::Generated),
                Err(KeptError::NoPassword)
            ));
        }
    }

    #[test]
    fn after_only_the_key_file_changes_the_vault_opens_with_the_kept_key_and_with_password_and_file(
    ) {
        // Kept with its password; opened with the kept key (the hash); its
        // key file changed, keeping the password part; kept again.
        let first = VaultKey::new().with_password("parola");
        let envelope = seal(&MASTER, BINDING, &VAULT, 5, &first, PasswordKind::Chosen).unwrap();
        let opened = open(&envelope, &MASTER, BINDING, &VAULT).unwrap().key;
        let file = crate::kdbx::generate_key_file().unwrap();
        let changed = opened.with_key_file(&file);
        let contents = vault_saved_with(&changed);
        let envelope = seal(&MASTER, BINDING, &VAULT, 6, &changed, PasswordKind::Chosen).unwrap();
        let kept = open(&envelope, &MASTER, BINDING, &VAULT).unwrap();
        assert!(
            open_vault(&contents, &kept.key).is_ok(),
            "with the kept key"
        );
        let typed = VaultKey::new().with_password("parola").with_key_file(&file);
        assert!(
            open_vault(&contents, &typed).is_ok(),
            "with the password and the new key file"
        );
        assert!(
            open_vault(&contents, &first).is_err(),
            "not with the old key"
        );
    }

    #[test]
    fn bound_to_the_account_and_the_vault() {
        let envelope = seal(
            &MASTER,
            BINDING,
            &VAULT,
            5,
            &VaultKey::new().with_password("p"),
            PasswordKind::Chosen,
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
