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

    /// This key with only the parts asked for: what a key change keeps of
    /// the vault's current key (a password known only as its hash too).
    pub fn keeping(&self, password: bool, key_file: bool) -> VaultKey {
        VaultKey {
            password: self.password.clone().filter(|_| password),
            password_hash: self.password_hash.clone().filter(|_| password),
            key_file: self.key_file.clone().filter(|_| key_file),
        }
    }

    /// The password's part of the composite key (its SHA-256), whichever
    /// way the key holds it.
    pub fn password_element(&self) -> Option<Zeroizing<[u8; 32]>> {
        match (&self.password, &self.password_hash) {
            (Some(password), _) => Some(kutup_crypto::pass_vault::password_hash(password)),
            (None, Some(hash)) => Some(hash.clone()),
            (None, None) => None,
        }
    }

    /// Whether `password` is this key's password (compared by its hash).
    pub fn has_this_password(&self, password: &str) -> bool {
        self.password_element().is_some_and(|element| {
            *element == *kutup_crypto::pass_vault::password_hash(password)
        })
    }

    /// Whether the key has a password, given as it is or as its hash.
    pub fn has_password(&self) -> bool {
        self.password.is_some() || self.password_hash.is_some()
    }

    /// The key file's contents, if the key has one.
    pub fn key_file(&self) -> Option<&[u8]> {
        self.key_file.as_deref().map(Vec::as_slice)
    }

    /// Whether `other` is the same composite key: the same password part
    /// (a password and its SHA-256 are the same part) and the same key file
    /// element, so each opens what the other does.
    pub fn same_as(&self, other: &VaultKey) -> bool {
        use sha2::{Digest as _, Sha256};
        let password = |key: &VaultKey| -> Option<[u8; 32]> {
            match (&key.password, &key.password_hash) {
                (Some(password), _) => Some(Sha256::digest(password.as_bytes()).into()),
                (None, Some(hash)) => Some(**hash),
                (None, None) => None,
            }
        };
        let element = |key: &VaultKey| {
            key.key_file
                .as_deref()
                .and_then(|file| keepass::key_file_element(file))
        };
        password(self) == password(other) && element(self) == element(other)
    }

    /// Adds the contents of a key file (any of KeePass's key file kinds).
    pub fn with_key_file(mut self, contents: &[u8]) -> Self {
        self.key_file = Some(Zeroizing::new(contents.to_vec()));
        self
    }

    /// Whether the key can lock a vault: a password or a key file, and a
    /// key file KeePass reads (`KdbxError::KeyFile` otherwise).
    pub fn check(&self) -> Result<(), KdbxError> {
        self.database_key().map(|_| ())
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

/// A key file as a vault secret keeps it: the key element KeePass derives
/// from it (`keepass::key_file_element`: an XML key file's key, a 32-byte or
/// hex key file's bytes, any other file's SHA-256), which opens the vault as
/// the file does, whatever its size or padding. Kept as those 32 bytes when,
/// read back as a key file, they give the same element (a 32-byte key file
/// is used as it is); an unusual key file whose element is not 32 bytes is
/// kept as it is, if it fits. `None`: it cannot be kept.
pub fn key_file_secret(contents: &[u8]) -> Option<Vec<u8>> {
    let element = Zeroizing::new(keepass::key_file_element(contents)?);
    if element.len() == 32
        && keepass::key_file_element(&element).as_deref() == Some(element.as_slice())
    {
        return Some(element.to_vec());
    }
    (contents.len() <= MAX_KEPT_KEY_FILE_BYTES).then(|| contents.to_vec())
}

/// A new key file: 32 random bytes in KeePass's XML key file format v2,
/// written as KeePassXC writes one (`FileKey::createXMLv2`), so KeePassXC,
/// KeePass and the mobile apps open the vault with it. It never leaves the
/// device but as the person's download (and, kept, as its key element).
pub fn generate_key_file() -> Result<Zeroizing<Vec<u8>>, getrandom::Error> {
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom::fill(key.as_mut())?;
    Ok(key_file_xml(&key))
}

/// The XML v2 key file of `key`: its SHA-256's first four bytes as the
/// `Hash` check, the key in upper-case hex, eight digits a group and four
/// groups a line, indented as KeePassXC indents it.
fn key_file_xml(key: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    use sha2::{Digest, Sha256};
    let check = hex::encode_upper(&Sha256::digest(key)[..4]);
    let digits = Zeroizing::new(hex::encode_upper(key));
    let mut data = Zeroizing::new(String::with_capacity(96));
    for (i, group) in digits.as_bytes().chunks(8).enumerate() {
        data.push_str(match i {
            0 => "",
            _ if i % 4 == 0 => "\n            ",
            _ => " ",
        });
        // Hex digits: ASCII.
        data.push_str(std::str::from_utf8(group).unwrap_or_default());
    }
    Zeroizing::new(
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <KeyFile>\n    <Meta>\n        <Version>2.0</Version>\n    </Meta>\n    \
             <Key>\n        <Data Hash=\"{check}\">\n            {data}\n        </Data>\n    \
             </Key>\n</KeyFile>\n",
            data = data.as_str()
        )
        .into_bytes(),
    )
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

impl KdbxError {
    /// Why, as a code a person's message is chosen by: `wrongKey` (the key
    /// doesn't open it, which is also what a YubiKey-protected vault gives
    /// without its YubiKey), `unsupported` (a cipher or key derivation this
    /// build doesn't know), `damaged` (not a whole KeePass file), `keyFile`,
    /// `emptyKey`, or `save`.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::EmptyKey => "emptyKey",
            Self::KeyFile => "keyFile",
            Self::Open(DatabaseOpenError::Key(_)) => "wrongKey",
            Self::Open(DatabaseOpenError::UnsupportedVersion) => "unsupported",
            Self::Open(DatabaseOpenError::Format(_)) => "unsupported",
            Self::Open(_) => "damaged",
            Self::Key(_) | Self::Save(_) => "save",
        }
    }
}

/// What a file is, read from its header alone (no key): a KeePass vault
/// Kutup opens, and whether its first save upgrades it to KDBX 4.1, or why
/// it can't be opened here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultFormat {
    /// KDBX 3.1, 4.0 or 4.1; `upgrade` when it isn't 4.1 already.
    Supported { version: (u16, u16), upgrade: bool },
    /// A KeePass file of a version Kutup can't open: KeePass 1 (`.kdb`),
    /// KeePass 2's pre-releases, KDBX 3.0, or a future major version.
    Unsupported { version: (u16, u16) },
    /// Not a KeePass file.
    NotKeePass,
}

/// Reads `contents`' header: what [`open`] would make of its version.
pub fn probe(contents: &[u8]) -> VaultFormat {
    match Database::get_version(&mut &contents[..]) {
        Ok(DatabaseVersion::KDB4(minor)) if minor <= 1 => VaultFormat::Supported {
            version: (4, minor),
            upgrade: minor < 1,
        },
        Ok(DatabaseVersion::KDB3(1)) => VaultFormat::Supported {
            version: (3, 1),
            upgrade: true,
        },
        Ok(DatabaseVersion::KDB(minor)) => VaultFormat::Unsupported {
            version: (1, minor),
        },
        Ok(DatabaseVersion::KDB2(minor)) => VaultFormat::Unsupported {
            version: (2, minor),
        },
        Ok(DatabaseVersion::KDB3(minor)) => VaultFormat::Unsupported {
            version: (3, minor),
        },
        Ok(DatabaseVersion::KDB4(minor)) => VaultFormat::Unsupported {
            version: (4, minor),
        },
        Err(_) => VaultFormat::NotKeePass,
    }
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
    fn a_generated_key_file_is_keepassxcs_xml_v2_and_opens_the_vault() {
        // KeePassXC's own form, for a known key (its test vault's key file).
        let key: [u8; 32] =
            hex::decode("36057B1C35037FD962257893C0A22403EE3F8FBB504D998108B821CB00D28F89")
                .unwrap()
                .try_into()
                .unwrap();
        let xml = String::from_utf8(key_file_xml(&key).to_vec()).unwrap();
        assert_eq!(
            xml,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<KeyFile>\n    <Meta>\n        \
             <Version>2.0</Version>\n    </Meta>\n    <Key>\n        <Data Hash=\"A65F0C2D\">\n            \
             36057B1C 35037FD9 62257893 C0A22403\n            \
             EE3F8FBB 504D9981 08B821CB 00D28F89\n        </Data>\n    </Key>\n</KeyFile>\n"
        );
        assert_eq!(
            keepass::key_file_element(xml.as_bytes()).as_deref(),
            Some(&key[..])
        );

        // A random one: its key, kept as that element, opens what it saved.
        let file = generate_key_file().unwrap();
        let other = generate_key_file().unwrap();
        assert_ne!(*file, *other);
        let key = VaultKey::new().with_key_file(&file);
        let bytes = save(&sample(), &key).unwrap();
        assert!(open(&bytes, &key).is_ok());
        let kept = key_file_secret(&file).unwrap();
        assert_eq!(kept.len(), 32);
        assert!(open(&bytes, &VaultKey::new().with_key_file(&kept)).is_ok());
    }

    #[test]
    fn a_key_change_keeps_the_parts_asked_for_even_a_hashed_password() {
        let file = generate_key_file().unwrap();
        let hashed = VaultKey::new()
            .with_password_hash(&kutup_crypto::pass_vault::password_hash("parola"))
            .with_key_file(&file);
        // The password kept, a new key file: opens with the typed password
        // and the new file.
        let other = generate_key_file().unwrap();
        let changed = hashed.keeping(true, false).with_key_file(&other);
        let bytes = save(&sample(), &changed).unwrap();
        let typed = VaultKey::new()
            .with_password("parola")
            .with_key_file(&other);
        assert!(open(&bytes, &typed).is_ok());
        assert!(open(&bytes, &hashed).is_err());
        // Nothing kept and nothing new: no key.
        assert!(hashed.keeping(false, false).check().is_err());
        assert!(hashed.keeping(false, true).check().is_ok());
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
    fn the_same_key_however_it_is_held() {
        use sha2::{Digest as _, Sha256};
        let hash: [u8; 32] = Sha256::digest(b"p").into();
        let by_password = VaultKey::new().with_password("p").with_key_file(&[7; 32]);
        let by_hash = VaultKey::new()
            .with_password_hash(&hash)
            .with_key_file(&[7; 32]);
        assert!(by_password.same_as(&by_hash));
        assert!(!by_password.same_as(&VaultKey::new().with_password("q").with_key_file(&[7; 32])));
        assert!(!by_password.same_as(&VaultKey::new().with_password("p")));
        assert!(!VaultKey::new()
            .with_password("p")
            .same_as(&VaultKey::new().with_key_file(&[7; 32])));
    }

    /// Every kind of key file is kept as 32 bytes that open the vault as it does.
    #[test]
    fn a_key_file_is_kept_as_its_key_element() {
        let bare: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let xml_v2 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash=\"A65F1F33\">6E0A1A8C 6D8F4B2E 9C7A1F52 0B3D4E5F 61728394 A5B6C7D8 E9FA0B1C 2D3E4F50</Data></Key></KeyFile>\n";
        // An XML key file padded past 2048 bytes is still its 32-byte key,
        // not a hash of the whole file.
        let xml_padded = xml_v2.replace("<Meta>", &format!("<!--{}--><Meta>", " ".repeat(4000)));
        let xml_v1 = format!(
            "<KeyFile><Meta><Version>1.00</Version></Meta><Key><Data>{}</Data></Key></KeyFile>",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [9u8; 32])
        );
        let hex_file = "ab".repeat(32);
        for file in [
            bare,
            xml_v2.as_bytes().to_vec(),
            xml_padded.into_bytes(),
            xml_v1.into_bytes(),
            hex_file.into_bytes(),
            vec![7u8; 32],
            b"<KeyFile/>".to_vec(),
        ] {
            let key = VaultKey::new().with_password("p").with_key_file(&file);
            let bytes = save(&sample(), &key).unwrap();
            let kept = key_file_secret(&file).unwrap();
            assert_eq!(kept.len(), 32, "{}", String::from_utf8_lossy(&file[..20]));
            let reopened = VaultKey::new().with_password("p").with_key_file(&kept);
            assert!(open(&bytes, &reopened).is_ok());
        }
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

    #[test]
    fn a_header_says_what_a_file_is_before_any_key() {
        let key = VaultKey::new().with_password("probe");
        let saved = save(&sample(), &key).unwrap();
        assert_eq!(
            probe(&saved),
            VaultFormat::Supported {
                version: (4, 1),
                upgrade: false
            }
        );
        assert_eq!(probe(b"not a vault at all"), VaultFormat::NotKeePass);
        // KeePass 1: its own signature.
        let mut kdb = vec![
            0x03, 0xd9, 0xa2, 0x9a, 0x65, 0xfb, 0x4b, 0xb5, 0x01, 0x00, 0x03, 0x00,
        ];
        kdb.resize(124, 0);
        assert!(matches!(
            probe(&kdb),
            VaultFormat::Unsupported { version: (1, _) }
        ));
        // A wrong key is said as such.
        let wrong = open(&saved, &VaultKey::new().with_password("not it")).unwrap_err();
        assert_eq!(wrong.kind(), "wrongKey");
    }
}
