//! SSH keys kept in vault entries (docs/plans/pass.md, K3b), in the form
//! KeePassXC and Strongbox already use: a `KeeAgent.settings` attachment
//! (KeeAgent's XML) beside the key, which is an attachment of the same entry
//! (an OpenSSH private key, encrypted or not); the entry's password is the
//! key's passphrase. The `kutup` agent lists these keys and signs with them;
//! nothing here is Kutup-only, so the same entry works in KeePassXC's agent.

use keepass::db::Entry;
use keepass::Database;
use quick_xml::events::Event;
use quick_xml::Reader;
use ssh_key::private::KeypairData;
use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey, Signature};
use zeroize::Zeroizing;

use crate::view::group_in_recycle_bin;

/// The attachment holding an entry's agent settings.
pub const SETTINGS_ATTACHMENT: &str = "KeeAgent.settings";

/// The agent asks for an RSA signature with SHA-256 (`SSH_AGENT_RSA_SHA2_256`).
pub const RSA_SHA2_256: u32 = 2;
/// … or SHA-512 (`SSH_AGENT_RSA_SHA2_512`); without either, `ssh-rsa` (SHA-1),
/// which Kutup refuses.
pub const RSA_SHA2_512: u32 = 4;

/// Where an entry's key is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyLocation {
    /// An attachment of the entry, by name.
    Attachment(String),
    /// A file on the machine KeeAgent ran on, by path.
    File(String),
}

/// KeeAgent's settings for one entry (KeePassXC `KeeAgentSettings`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeeAgentSettings {
    pub allow_use: bool,
    pub add_at_open: bool,
    pub remove_at_close: bool,
    /// Ask before each use (KeePassXC passes this to the system agent).
    pub confirm: bool,
    /// Forget the key after `lifetime_secs` (when `use_lifetime`).
    pub use_lifetime: bool,
    pub lifetime_secs: u32,
    pub location: Option<KeyLocation>,
}

impl Default for KeeAgentSettings {
    fn default() -> Self {
        Self {
            allow_use: false,
            add_at_open: false,
            remove_at_close: true,
            confirm: false,
            use_lifetime: false,
            lifetime_secs: 600,
            location: None,
        }
    }
}

/// Why an entry's key cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SshError {
    #[error("the KeeAgent settings could not be read")]
    Settings,
    #[error(
        "the key is in a file outside the vault ({0}); only keys attached to the entry are used"
    )]
    KeyInFile(String),
    #[error("the entry has no key attachment named {0}")]
    MissingKey(String),
    #[error("the key is not an OpenSSH private key")]
    Unreadable,
    #[error("the entry's password does not decrypt the key")]
    WrongPassphrase,
    #[error("Kutup does not sign with {0} keys")]
    Unsupported(String),
    #[error("signing failed")]
    Sign,
}

fn decode_text(bytes: &[u8]) -> Option<String> {
    // KeePassXC writes UTF-8; KeeAgent itself writes UTF-16 with a BOM.
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8(rest.to_vec()).ok();
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        return String::from_utf16(&units).ok();
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes(*c))
            .collect();
        return String::from_utf16(&units).ok();
    }
    String::from_utf8(bytes.to_vec()).ok()
}

impl KeeAgentSettings {
    /// Reads a `KeeAgent.settings` attachment.
    pub fn parse(bytes: &[u8]) -> Result<Self, SshError> {
        let text = decode_text(bytes).ok_or(SshError::Settings)?;
        let mut reader = Reader::from_str(&text);
        reader.config_mut().trim_text(true);
        let mut settings = Self::default();
        let mut path: Vec<String> = Vec::new();
        let mut value = String::new();
        let mut selected = String::new();
        let mut attachment = String::new();
        let mut file = String::new();
        let mut saw_root = false;
        loop {
            match reader.read_event().map_err(|_| SshError::Settings)? {
                Event::Start(start) => {
                    let name = start.local_name().as_ref().to_owned();
                    if path.is_empty() {
                        if name != "EntrySettings" {
                            return Err(SshError::Settings);
                        }
                        saw_root = true;
                    }
                    path.push(name);
                    value.clear();
                }
                Event::Text(text) => value.push_str(&text.xml10_content()),
                // Entities are their own events: `&amp;`, `&#38;`.
                Event::GeneralRef(reference) => match reference
                    .resolve_char_ref()
                    .map_err(|_| SshError::Settings)?
                {
                    Some(c) => value.push(c),
                    None => value.push_str(match &*reference.xml10_content() {
                        "amp" => "&",
                        "lt" => "<",
                        "gt" => ">",
                        "quot" => "\"",
                        "apos" => "'",
                        _ => return Err(SshError::Settings),
                    }),
                },
                Event::End(_) => {
                    let flag = value.trim().eq_ignore_ascii_case("true");
                    match path
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .as_slice()
                    {
                        ["EntrySettings", "AllowUseOfSshKey"] => settings.allow_use = flag,
                        ["EntrySettings", "AddAtDatabaseOpen"] => settings.add_at_open = flag,
                        ["EntrySettings", "RemoveAtDatabaseClose"] => {
                            settings.remove_at_close = flag
                        }
                        ["EntrySettings", "UseConfirmConstraintWhenAdding"] => {
                            settings.confirm = flag
                        }
                        ["EntrySettings", "UseLifetimeConstraintWhenAdding"] => {
                            settings.use_lifetime = flag
                        }
                        ["EntrySettings", "LifetimeConstraintDuration"] => {
                            settings.lifetime_secs =
                                value.trim().parse().unwrap_or(settings.lifetime_secs)
                        }
                        ["EntrySettings", "Location", "SelectedType"] => {
                            selected = value.trim().to_owned()
                        }
                        ["EntrySettings", "Location", "AttachmentName"] => {
                            attachment = value.clone()
                        }
                        ["EntrySettings", "Location", "FileName"] => file = value.clone(),
                        _ => {}
                    }
                    path.pop();
                    value.clear();
                }
                Event::Eof => break,
                _ => {}
            }
        }
        if !saw_root {
            return Err(SshError::Settings);
        }
        settings.location = match selected.as_str() {
            "attachment" if !attachment.is_empty() => Some(KeyLocation::Attachment(attachment)),
            "file" if !file.is_empty() => Some(KeyLocation::File(file)),
            _ => None,
        };
        Ok(settings)
    }
}

/// An SSH key kept in a vault entry, as the agent lists it: its public half
/// is readable without the passphrase.
#[derive(Clone)]
pub struct SshKeyEntry {
    pub entry_id: uuid::Uuid,
    pub title: String,
    pub settings: KeeAgentSettings,
    pub public_key: PublicKey,
    /// The key as stored (OpenSSH, maybe encrypted).
    stored: PrivateKey,
    passphrase: Zeroizing<String>,
}

impl std::fmt::Debug for SshKeyEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshKeyEntry")
            .field("entry_id", &self.entry_id)
            .field("title", &self.title)
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

impl SshKeyEntry {
    /// `SHA256:…`, as `ssh-add -l` prints it.
    pub fn fingerprint(&self) -> String {
        self.public_key.fingerprint(HashAlg::Sha256).to_string()
    }

    /// The key's comment, else the entry's title.
    pub fn comment(&self) -> String {
        let comment = self.public_key.comment();
        if comment.is_empty() {
            self.title.clone()
        } else {
            comment.to_owned()
        }
    }

    /// The public key's wire encoding (the agent's key blob).
    pub fn public_blob(&self) -> Vec<u8> {
        self.public_key.to_bytes().unwrap_or_default()
    }

    /// The private key, decrypted with the entry's password when needed.
    pub fn private_key(&self) -> Result<PrivateKey, SshError> {
        if !self.stored.is_encrypted() {
            return Ok(self.stored.clone());
        }
        self.stored
            .decrypt(self.passphrase.as_bytes())
            .map_err(|_| SshError::WrongPassphrase)
    }
}

fn read_key(
    entry: &Entry,
    db: &Database,
    settings: &KeeAgentSettings,
) -> Result<PrivateKey, SshError> {
    let name = match &settings.location {
        Some(KeyLocation::Attachment(name)) => name,
        Some(KeyLocation::File(path)) => return Err(SshError::KeyInFile(path.clone())),
        None => return Err(SshError::Settings),
    };
    let bytes = crate::view::attachment(db, entry, name)
        .ok_or_else(|| SshError::MissingKey(name.clone()))?;
    PrivateKey::from_openssh(bytes).map_err(|_| SshError::Unreadable)
}

/// One entry that wanted to be an agent key but cannot be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedKey {
    pub title: String,
    pub reason: SshError,
}

/// The agent keys in a vault: entries outside the recycle bin whose KeeAgent
/// settings allow use; and those that could not be read, with why.
pub fn ssh_keys(db: &Database) -> (Vec<SshKeyEntry>, Vec<SkippedKey>) {
    let mut keys = Vec::new();
    let mut skipped = Vec::new();
    let mut entries: Vec<&Entry> = db.entries.values().collect();
    entries.sort_by_key(|e| (e.get_title().unwrap_or("").to_owned(), e.id.uuid()));
    for entry in entries {
        if group_in_recycle_bin(db, entry.parent) {
            continue;
        }
        let Some(settings_bytes) = crate::view::attachment(db, entry, SETTINGS_ATTACHMENT) else {
            continue;
        };
        let title = entry.get_title().unwrap_or("").to_owned();
        let settings = match KeeAgentSettings::parse(settings_bytes) {
            Ok(settings) => settings,
            Err(reason) => {
                skipped.push(SkippedKey { title, reason });
                continue;
            }
        };
        if !settings.allow_use {
            continue;
        }
        match read_key(entry, db, &settings) {
            Ok(stored) => keys.push(SshKeyEntry {
                entry_id: entry.id.uuid(),
                title,
                public_key: stored.public_key().clone(),
                settings,
                stored,
                passphrase: Zeroizing::new(entry.get_password().unwrap_or("").to_owned()),
            }),
            Err(reason) => skipped.push(SkippedKey { title, reason }),
        }
    }
    (keys, skipped)
}

/// The `rsa` crate's key for an SSH RSA key. Not ssh-key 0.6.7's own
/// conversion, which passes the prime `p` twice and so fails for every key.
fn rsa_private_key(key: &ssh_key::private::RsaKeypair) -> Result<rsa::RsaPrivateKey, SshError> {
    let int = |m: &ssh_key::Mpint| -> Result<rsa::BigUint, SshError> {
        Ok(rsa::BigUint::from_bytes_be(
            m.as_positive_bytes().ok_or(SshError::Sign)?,
        ))
    };
    let private = rsa::RsaPrivateKey::from_components(
        int(&key.public.n)?,
        int(&key.public.e)?,
        int(&key.private.d)?,
        vec![int(&key.private.p)?, int(&key.private.q)?],
    )
    .map_err(|_| SshError::Sign)?;
    // OpenSSH refuses RSA keys under 2048 bits; so does Kutup.
    if rsa::traits::PublicKeyParts::size(&private) * 8 < 2048 {
        return Err(SshError::Unsupported("RSA keys under 2048 bits".into()));
    }
    Ok(private)
}

/// The system's RNG (`getrandom`) for `rsa`'s blinding, through `rsa`'s own
/// `rand_core` traits.
struct SystemRng;

impl rsa::rand_core::RngCore for SystemRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }
    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::fill(dest).expect("the system's random source");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rsa::rand_core::CryptoRng for SystemRng {}

fn put_string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

/// Signs `data` as an SSH agent does (`flags` as in the sign request) and
/// returns the signature blob (`string algorithm, string signature`).
pub fn sign(key: &PrivateKey, data: &[u8], flags: u32) -> Result<Vec<u8>, SshError> {
    use signature::Signer as _;
    let signature: Signature = match key.key_data() {
        KeypairData::Rsa(rsa_key) => {
            // Blinded (the RNG's): the private-key operation's timing then
            // says little about the key (RUSTSEC-2023-0071, Marvin; deny.toml).
            // A PKCS#1 v1.5 signature is deterministic, so the bytes are
            // the same as unblinded.
            use rsa::signature::RandomizedSigner as _;
            let mut rng = SystemRng;
            let private = rsa_private_key(rsa_key)?;
            let (hash, bytes) = if flags & RSA_SHA2_512 != 0 {
                let signing = rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(private);
                (
                    HashAlg::Sha512,
                    signing
                        .try_sign_with_rng(&mut rng, data)
                        .map_err(|_| SshError::Sign)?,
                )
            } else if flags & RSA_SHA2_256 != 0 {
                let signing = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private);
                (
                    HashAlg::Sha256,
                    signing
                        .try_sign_with_rng(&mut rng, data)
                        .map_err(|_| SshError::Sign)?,
                )
            } else {
                // `ssh-rsa` signs with SHA-1, which OpenSSH itself refuses now.
                return Err(SshError::Unsupported("ssh-rsa (SHA-1)".into()));
            };
            Signature::new(
                Algorithm::Rsa { hash: Some(hash) },
                rsa::signature::SignatureEncoding::to_vec(&bytes),
            )
            .map_err(|_| SshError::Sign)?
        }
        KeypairData::Ed25519(_) | KeypairData::Ecdsa(_) => {
            key.try_sign(data).map_err(|_| SshError::Sign)?
        }
        other => {
            return Err(SshError::Unsupported(
                other
                    .algorithm()
                    .map(|a| a.as_str().to_owned())
                    .unwrap_or_else(|_| "these".into()),
            ))
        }
    };
    let mut out = Vec::new();
    put_string(&mut out, signature.algorithm().as_str().as_bytes());
    put_string(&mut out, signature.as_bytes());
    Ok(out)
}

/// A public key blob's `SHA256:…` fingerprint, if it is a key.
pub fn blob_fingerprint(blob: &[u8]) -> Option<String> {
    PublicKey::from_bytes(blob)
        .ok()
        .map(|key| key.fingerprint(HashAlg::Sha256).to_string())
}

fn take<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    if rest.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes(rest[..4].try_into().ok()?) as usize;
    let value = rest.get(4..4 + len)?;
    *rest = &rest[4 + len..];
    Some(value)
}

/// A signature blob (`string algorithm, string signature`) as ssh-key's.
pub fn parse_signature(blob: &[u8]) -> Option<Signature> {
    let mut rest = blob;
    let algorithm = std::str::from_utf8(take(&mut rest)?).ok()?;
    let data = take(&mut rest)?;
    if !rest.is_empty() {
        return None;
    }
    Signature::new(Algorithm::new(algorithm).ok()?, data.to_vec()).ok()
}

/// Checks OpenSSH's `session-bind@openssh.com`: the host proved it holds
/// `host_key` by signing `session_id`. Returns the host key's fingerprint.
pub fn verify_session_bind(host_key: &[u8], session_id: &[u8], signature: &[u8]) -> Option<String> {
    use signature::Verifier as _;
    let key = PublicKey::from_bytes(host_key).ok()?;
    let signature = parse_signature(signature)?;
    key.key_data().verify(session_id, &signature).ok()?;
    Some(key.fingerprint(HashAlg::Sha256).to_string())
}

/// The body of an agent's add-identity request for `key` (key type, key
/// fields, comment), for pushing a key into another agent (`kutup ssh-add`).
pub fn agent_identity_blob(
    key: &PrivateKey,
    comment: &str,
) -> Result<Zeroizing<Vec<u8>>, SshError> {
    use ssh_encoding::Encode as _;
    let mut out = Zeroizing::new(Vec::new());
    key.key_data()
        .encode(&mut *out)
        .map_err(|_| SshError::Sign)?;
    put_string(&mut out, comment.as_bytes());
    Ok(out)
}
