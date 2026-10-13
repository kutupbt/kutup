//! Opening and saving KeePass vaults.
//!
//! Every KDBX version in use today (3.1, 4.0, 4.1) opens; vaults are always
//! saved as KDBX 4.1, the only version the library writes, as KeePassXC
//! upgrades older files on save. A vault's key is the KeePass composite key:
//! a password (or its SHA-256, the password's part of the composite key,
//! which is what Kutup Pass keeps), a key file, or both.

use keepass::config::{DatabaseVersion, InnerCipherConfig};
use keepass::error::{DatabaseKeyError, DatabaseOpenError, DatabaseSaveError};
use keepass::{Database, DatabaseKey};
use zeroize::Zeroizing;

/// The composite key of a vault: a password, a key file, or both.
#[derive(Clone, Default)]
pub struct VaultKey {
    pub(crate) password: Option<Zeroizing<String>>,
    pub(crate) password_hash: Option<Zeroizing<[u8; 32]>>,
    pub(crate) key_file: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultKey")
            .field("password", &self.password.as_ref().map(|_| "[redacted]"))
            .field(
                "password_hash",
                &self.password_hash.as_ref().map(|_| "[redacted]"),
            )
            .field("key_file", &self.key_file.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

impl VaultKey {
    /// An empty key; add a password and/or a key file.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds the vault password.
    pub fn with_password(mut self, password: &str) -> Self {
        self.password = Some(Zeroizing::new(password.to_owned()));
        self
    }

    /// Adds the vault password as its SHA-256 (the password's part of the
    /// composite key), which opens and saves the vault as the password does.
    pub fn with_password_hash(mut self, hash: &[u8; 32]) -> Self {
        self.password_hash = Some(Zeroizing::new(*hash));
        self
    }

    /// The password's hash, when that is how the key holds the password.
    pub fn password_hash(&self) -> Option<&[u8; 32]> {
        self.password_hash.as_deref()
    }

    /// The key file's contents, if the key has one.
    pub fn key_file(&self) -> Option<&[u8]> {
        self.key_file.as_deref().map(Vec::as_slice)
    }

    /// Adds the contents of a key file (any of KeePass's key file kinds).
    pub fn with_key_file(mut self, contents: &[u8]) -> Self {
        self.key_file = Some(Zeroizing::new(contents.to_vec()));
        self
    }

    fn database_key(&self) -> Result<DatabaseKey, KdbxError> {
        if self.password.is_none() && self.password_hash.is_none() && self.key_file.is_none() {
            return Err(KdbxError::EmptyKey);
        }
        let mut key = DatabaseKey::new();
        if let Some(password) = &self.password {
            key = key.with_password(password);
        } else if let Some(hash) = &self.password_hash {
            key = key.with_password_hash(hash);
        }
        if let Some(contents) = &self.key_file {
            key = key
                .with_keyfile(&mut contents.as_slice())
                .map_err(|_| KdbxError::KeyFile)?;
        }
        Ok(key)
    }
}

/// The largest key file kept as it is in a vault secret
/// (`kutup_crypto::pass_vault::MAX_KEY_FILE_BYTES`).
pub const MAX_KEPT_KEY_FILE_BYTES: usize = 2048;

/// A key file as a vault secret keeps it: small files (KeePass's XML, 32-byte
/// and hex key files) as they are; any larger file as its SHA-256, which
/// KeePass treats as the same key (it hashes files that are none of those
/// kinds, and uses a 32-byte file directly). Check that the result opens the
/// vault before keeping it.
pub fn key_file_secret(contents: &[u8]) -> Vec<u8> {
    use sha2::{Digest as _, Sha256};
    if contents.len() <= MAX_KEPT_KEY_FILE_BYTES {
        contents.to_vec()
    } else {
        Sha256::digest(contents).to_vec()
    }
}

/// Why a vault could not be opened or saved.
#[derive(Debug, thiserror::Error)]
pub enum KdbxError {
    /// A vault needs a password, a key file, or both.
    #[error("a vault needs a password or a key file")]
    EmptyKey,
    /// The key file could not be read.
    #[error("the key file could not be read")]
    KeyFile,
    /// Wrong key, a damaged file, or not a KeePass file at all.
    #[error("the vault could not be opened: {0}")]
    Open(#[from] DatabaseOpenError),
    /// The key could not be used to write the vault.
    #[error("the vault key could not be used: {0}")]
    Key(#[from] DatabaseKeyError),
    /// Writing the vault failed.
    #[error("the vault could not be saved: {0}")]
    Save(#[from] DatabaseSaveError),
}

/// Opens a vault from its file contents.
pub fn open(contents: &[u8], key: &VaultKey) -> Result<Database, KdbxError> {
    Ok(Database::open(&mut &contents[..], key.database_key()?)?)
}

/// Saves a vault as KDBX 4.1. An older vault is upgraded: version 4.1, and
/// protected values under ChaCha20, which KDBX 4 requires; its cipher, key
/// derivation and compression settings are kept.
pub fn save(vault: &Database, key: &VaultKey) -> Result<Vec<u8>, KdbxError> {
    let key = key.database_key()?;
    let mut contents = Vec::new();
    if matches!(vault.config.version, DatabaseVersion::KDB4(1))
        && matches!(
            vault.config.inner_cipher_config,
            InnerCipherConfig::ChaCha20
        )
    {
        vault.save(&mut contents, key)?;
    } else {
        let mut upgraded = vault.clone();
        upgraded.config.version = DatabaseVersion::KDB4(1);
        upgraded.config.inner_cipher_config = InnerCipherConfig::ChaCha20;
        upgraded.save(&mut contents, key)?;
    }
    Ok(contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Database {
        let mut db = Database::new();
        db.meta.database_name = Some("Personal".into());
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected("Title", "Bank");
        entry.set_unprotected("UserName", "ayse");
        entry.set_protected("Password", "çok-gizli-1");
        db
    }

    #[test]
    fn saves_and_reopens_with_a_password() {
        let db = sample();
        let key = VaultKey::new().with_password("parola");
        let bytes = save(&db, &key).unwrap();
        let reopened = open(&bytes, &key).unwrap();
        assert_eq!(reopened.root().entries().count(), 1);
        let root = reopened.root();
        let entry = root.entries().next().unwrap();
        assert_eq!(entry.get_password(), Some("çok-gizli-1"));
        assert!(entry.fields["Password"].is_protected());
    }

    #[test]
    fn the_passwords_hash_opens_and_saves_as_the_password_does() {
        use sha2::{Digest, Sha256};
        let hash: [u8; 32] = Sha256::digest("parola-çğ".as_bytes()).into();
        let file = b"a key file".to_vec();
        for (by_password, by_hash) in [
            (
                VaultKey::new().with_password("parola-çğ"),
                VaultKey::new().with_password_hash(&hash),
            ),
            (
                VaultKey::new()
                    .with_password("parola-çğ")
                    .with_key_file(&file),
                VaultKey::new()
                    .with_password_hash(&hash)
                    .with_key_file(&file),
            ),
        ] {
            let saved = save(&sample(), &by_password).unwrap();
            assert!(open(&saved, &by_hash).is_ok());
            let saved = save(&sample(), &by_hash).unwrap();
            assert!(open(&saved, &by_password).is_ok());
        }
        let wrong: [u8; 32] = Sha256::digest(b"other").into();
        let saved = save(&sample(), &VaultKey::new().with_password("parola-çğ")).unwrap();
        assert!(open(&saved, &VaultKey::new().with_password_hash(&wrong)).is_err());
    }

    #[test]
    fn a_large_key_file_is_kept_as_its_hash() {
        let large: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let key = VaultKey::new().with_password("p").with_key_file(&large);
        let bytes = save(&sample(), &key).unwrap();
        let kept = key_file_secret(&large);
        assert_eq!(kept.len(), 32);
        let reopened = VaultKey::new().with_password("p").with_key_file(&kept);
        assert!(open(&bytes, &reopened).is_ok());
        assert_eq!(key_file_secret(b"<KeyFile/>"), b"<KeyFile/>");
    }

    #[test]
    fn a_key_file_alone_or_with_a_password() {
        let db = sample();
        let file = b"any file works as a hashed key file".to_vec();
        for key in [
            VaultKey::new().with_key_file(&file),
            VaultKey::new().with_password("p").with_key_file(&file),
        ] {
            let bytes = save(&db, &key).unwrap();
            assert!(open(&bytes, &key).is_ok());
            assert!(open(&bytes, &VaultKey::new().with_password("p")).is_err());
        }
    }

    #[test]
    fn the_wrong_password_and_an_empty_key_are_refused() {
        let bytes = save(&sample(), &VaultKey::new().with_password("right")).unwrap();
        assert!(matches!(
            open(&bytes, &VaultKey::new().with_password("wrong")),
            Err(KdbxError::Open(_))
        ));
        assert!(matches!(
            open(&bytes, &VaultKey::new()),
            Err(KdbxError::EmptyKey)
        ));
        assert!(matches!(
            open(b"not a vault", &VaultKey::new().with_password("x")),
            Err(KdbxError::Open(_))
        ));
    }

    #[test]
    fn the_debug_form_hides_the_key() {
        let key = VaultKey::new()
            .with_password("secret")
            .with_key_file(b"file");
        let shown = format!("{key:?}");
        assert!(!shown.contains("secret"));
        assert_eq!(shown.matches("[redacted]").count(), 2);
    }
}
