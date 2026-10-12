//! KeePass vaults (`.kdbx`) in `kutup sync` (docs/plans/pass.md, K1).
//!
//! A vault is saved as a new version of the same Drive file, conditional on
//! the version it was made from (`basedOn`), so the file keeps its id and no
//! save overwrites one it has not seen. When both sides changed, sync merges
//! them with `kutup-pass` (base, local, remote) instead of writing a
//! `.sync-conflict` copy, saves the result the same way and writes it
//! locally. Without the vault's key it falls back to the conflict copy.

use std::collections::BTreeMap;
use std::io::IsTerminal;

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use kutup_crypto::account_envelope;
use kutup_crypto::drive_object::{self, DriveFileBlobContextV1};
use kutup_crypto::pass_vault::{open_vault_secret, seal_vault_secret, VaultSecretV1};
use kutup_pass::keepass::Database;
use kutup_pass::{MergeReport, VaultKey};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::api::versions::{NewVersion, ORIGINAL};
use crate::api::{ApiError, Client, File};
use crate::keyring::Keyring;

/// How many times a save that lost a race is merged again and retried.
const SAVE_ATTEMPTS: usize = 5;
/// Password prompts per vault before sync gives up on it for this run.
const PROMPTS: usize = 3;

/// Whether `rel` is a KeePass vault.
pub(crate) fn is_vault(rel: &str) -> bool {
    rel.rsplit('/')
        .next()
        .and_then(|name| name.rsplit_once('.'))
        .is_some_and(|(stem, ext)| !stem.is_empty() && ext.eq_ignore_ascii_case("kdbx"))
}

/// A version as the sync base records it: `""` is the original upload.
pub(crate) fn based_on(recorded: &str) -> String {
    if recorded.is_empty() {
        ORIGINAL.to_owned()
    } else {
        recorded.to_owned()
    }
}

/// The recorded form of a version a server names (`original` → `""`).
pub(crate) fn recorded(version: &str) -> String {
    if version == ORIGINAL {
        String::new()
    } else {
        version.to_owned()
    }
}

/// The keys that open the vaults of one sync run (and of every pass of
/// `--watch`): the vault secret kept in the account (docs/plans/pass.md,
/// "Vault secrets"), `KUTUP_VAULT_PASSWORD` and `KUTUP_VAULT_KEY_FILE`, then
/// what the person types, remembered per vault in memory only.
pub struct VaultKeys {
    configured: Vec<VaultKey>,
    /// Combined with a typed password.
    key_file: Option<Vec<u8>>,
    interactive: bool,
    /// Per vault: the keys that opened a version of it, in the order found;
    /// `None` once the person skipped it.
    known: BTreeMap<String, Option<Vec<VaultKey>>>,
    /// What opens the account's vault secrets.
    account: Option<Account>,
    /// The account's sealed vault secrets by file id, fetched once a pass.
    stored: Option<BTreeMap<String, String>>,
}

struct Account {
    master_key: Zeroizing<Vec<u8>>,
    email: String,
}

impl VaultKeys {
    /// From the environment; prompts only when stdin and stderr are a
    /// terminal.
    pub fn from_env() -> Result<Self> {
        let password = std::env::var("KUTUP_VAULT_PASSWORD").ok();
        let key_file = match std::env::var_os("KUTUP_VAULT_KEY_FILE") {
            Some(path) => Some(std::fs::read(&path).with_context(|| {
                format!("read KUTUP_VAULT_KEY_FILE {}", path.to_string_lossy())
            })?),
            None => None,
        };
        let interactive = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
        Ok(Self::new(
            password.as_deref(),
            key_file.as_deref(),
            interactive,
        ))
    }

    /// Only the vault secrets kept in the account (after [`Self::sign_in`]):
    /// what a service started at login has.
    pub fn account_only() -> Self {
        Self::new(None, None, false)
    }

    fn new(password: Option<&str>, key_file: Option<&[u8]>, interactive: bool) -> Self {
        let mut configured = Vec::new();
        match (password, key_file) {
            (Some(password), Some(file)) => {
                configured.push(VaultKey::new().with_password(password).with_key_file(file));
                configured.push(VaultKey::new().with_password(password));
                configured.push(VaultKey::new().with_key_file(file));
            }
            (Some(password), None) => configured.push(VaultKey::new().with_password(password)),
            (None, Some(file)) => configured.push(VaultKey::new().with_key_file(file)),
            (None, None) => {}
        }
        Self {
            configured,
            key_file: key_file.map(<[u8]>::to_vec),
            interactive,
            known: BTreeMap::new(),
            account: None,
            stored: None,
        }
    }

    /// The signed-in account, whose vault secrets open vaults; read again
    /// on every pass.
    pub fn sign_in(&mut self, session: &crate::session::Session) -> Result<()> {
        self.account = Some(Account {
            master_key: Zeroizing::new(session.master_key_bytes()?),
            email: session.email.clone(),
        });
        self.stored = None;
        Ok(())
    }

    /// Opens a version of vault `rel` (Drive file `file_id`) with a key
    /// already known for it, its vault secret, a configured one, or (`ask`)
    /// one the person types. The index is which known key opened it.
    pub(crate) fn open(
        &mut self,
        client: &Client,
        rel: &str,
        file_id: &str,
        contents: &[u8],
        ask: bool,
    ) -> Option<(Database, usize)> {
        // `None`: skipped earlier in this run.
        let known = self
            .known
            .entry(rel.to_owned())
            .or_insert_with(|| Some(Vec::new()))
            .clone()?;
        for (index, key) in known.iter().enumerate() {
            if let Ok(db) = kutup_pass::open(contents, key) {
                return Some((db, index));
            }
        }
        let mut candidates: Vec<VaultKey> = self.stored_key(client, file_id).into_iter().collect();
        candidates.extend(self.configured.iter().cloned());
        for key in candidates {
            if let Ok(db) = kutup_pass::open(contents, &key) {
                return Some((db, self.remember(rel, key)));
            }
        }
        if !ask || !self.interactive {
            return None;
        }
        for attempt in 0..PROMPTS {
            let question = if attempt == 0 {
                format!("  Password for vault {rel} (empty to skip): ")
            } else {
                format!("  Wrong password for {rel}; try again (empty to skip): ")
            };
            let Ok(password) = rpassword::prompt_password(question) else {
                break;
            };
            let password = Zeroizing::new(password);
            if password.is_empty() {
                break;
            }
            let mut key = VaultKey::new().with_password(&password);
            if let Some(file) = &self.key_file {
                key = key.with_key_file(file);
            }
            if let Ok(db) = kutup_pass::open(contents, &key) {
                self.offer_to_keep(client, file_id, contents, &password);
                return Some((db, self.remember(rel, key)));
            }
        }
        self.known.insert(rel.to_owned(), None);
        None
    }

    fn remember(&mut self, rel: &str, key: VaultKey) -> usize {
        let keys = self
            .known
            .entry(rel.to_owned())
            .or_insert_with(|| Some(Vec::new()))
            .get_or_insert_with(Vec::new);
        keys.push(key);
        keys.len() - 1
    }

    fn key(&self, rel: &str, index: usize) -> Option<&VaultKey> {
        self.known.get(rel)?.as_ref()?.get(index)
    }

    /// The key in the account's vault secret for `file_id`, if one is kept.
    fn stored_key(&mut self, client: &Client, file_id: &str) -> Option<VaultKey> {
        let account = self.account.as_ref()?;
        let stored = self.stored.get_or_insert_with(|| {
            client
                .list_vault_secrets()
                .map(|rows| rows.into_iter().map(|r| (r.file_id, r.envelope)).collect())
                .unwrap_or_default()
        });
        let envelope = account_envelope::decode_canonical_b64(stored.get(file_id)?).ok()?;
        let id = Uuid::parse_str(file_id).ok()?;
        let secret = open_vault_secret(
            &envelope,
            &account.master_key,
            &account.email,
            id.as_bytes(),
        )
        .ok()?;
        let mut key = VaultKey::new();
        if let Some(password) = &secret.password {
            key = key.with_password(password);
        }
        if let Some(file) = &secret.key_file {
            key = key.with_key_file(file);
        }
        Some(key)
    }

    /// After a typed password opened the vault: offers to keep it in the
    /// account, so Kutup Pass and sync open the vault with the sign-in.
    fn offer_to_keep(&mut self, client: &Client, file_id: &str, contents: &[u8], password: &str) {
        let Some(account) = &self.account else {
            return;
        };
        eprint!(
            "  Keep this vault's key in your Kutup account, so Kutup Pass and sync \
             open it with your sign-in? [Y/n] "
        );
        let mut answer = String::new();
        if std::io::stdin().read_line(&mut answer).is_err()
            || answer.trim().to_lowercase().starts_with('n')
        {
            return;
        }
        let kept = keep_secret(
            client,
            &account.master_key,
            &account.email,
            file_id,
            contents,
            Some(password),
            self.key_file.as_deref(),
        );
        match kept {
            Ok(envelope) => {
                eprintln!("  Kept.");
                if let Some(stored) = &mut self.stored {
                    stored.insert(file_id.to_owned(), envelope);
                }
            }
            Err(error) => eprintln!("  Could not keep it: {error:#}"),
        }
    }
}

/// Keeps what opens vault `file_id` (whose current contents are `contents`)
/// in the account: checked to open the vault by itself, sealed under the
/// master key and stored. Returns the envelope (base64).
pub(crate) fn keep_secret(
    client: &Client,
    master_key: &[u8],
    email: &str,
    file_id: &str,
    contents: &[u8],
    password: Option<&str>,
    key_file: Option<&[u8]>,
) -> Result<String> {
    let key_file = key_file.map(kutup_pass::key_file_secret);
    let mut key = VaultKey::new();
    if let Some(password) = password {
        key = key.with_password(password);
    }
    if let Some(file) = &key_file {
        key = key.with_key_file(file);
    }
    kutup_pass::open(contents, &key).map_err(|_| anyhow!("this key does not open the vault"))?;
    let id = Uuid::parse_str(file_id)?;
    let secret = VaultSecretV1 {
        password: password.map(|p| Zeroizing::new(p.to_owned())),
        key_file: key_file.map(Zeroizing::new),
    };
    let sealed = seal_vault_secret(master_key, email, id.as_bytes(), &secret)?;
    let envelope = base64::engine::general_purpose::STANDARD.encode(sealed);
    client.put_vault_secret(file_id, &envelope)?;
    Ok(envelope)
}

/// Where a vault lives on Drive and what opens it there.
pub(crate) struct VaultFile<'a> {
    pub file_id: &'a str,
    pub collection_id: &'a str,
    pub folder_epoch: u32,
    pub keys: &'a Keyring,
}

/// A vault saved to Drive.
pub(crate) struct Saved {
    /// What was written: the new version's contents (or the remote's, when
    /// the merge added nothing to it).
    pub contents: Vec<u8>,
    /// The version Drive now holds, as the base records it.
    pub version: String,
    pub report: MergeReport,
    /// False when the remote already held everything: nothing was uploaded.
    pub uploaded: bool,
}

/// Saves `contents` as a version made from `based_on` (a recorded version).
/// `Ok(None)`: the file holds another version now.
pub(crate) fn save_version(
    client: &Client,
    vault: &VaultFile,
    contents: &[u8],
    based_on_version: &str,
) -> Result<Option<String>> {
    // New content goes under a key only the folder's current people hold.
    let (file, file_key) = current_file(client, vault)?;
    let (file, file_key) = crate::cryptohelpers::rekey_file_if_behind(
        client,
        file,
        file_key,
        vault.keys,
        vault.collection_id,
        vault.folder_epoch,
    )?;
    let sealed = drive_object::encrypt_file_blob(
        contents,
        &file_key,
        DriveFileBlobContextV1::new(&file.id, file.key_generation)?,
    )
    .context("encrypt vault")?;
    let stored = client.create_version(
        &file.id,
        sealed,
        &NewVersion {
            kind: "file".into(),
            seq_at_snapshot: 0,
            doc_key_id: 1,
            based_on: Some(based_on(based_on_version)),
            ..Default::default()
        },
    );
    match stored {
        Ok(row) => Ok(Some(row.id)),
        Err(error) if version_conflict(&error).is_some() => Ok(None),
        Err(error) => Err(error).context("save vault version"),
    }
}

/// Merges `local` with what Drive holds now against `base` (a recorded
/// version of `base_file_id`, when there is one), saves the result as a
/// version made from what it merged, and retries when another save lands
/// first. `Ok(None)`: no key opens the vault; nothing was changed.
pub(crate) fn merge_and_save(
    client: &Client,
    keys: &mut VaultKeys,
    rel: &str,
    vault: &VaultFile,
    base: Option<(&str, &str)>,
    local: &[u8],
) -> Result<Option<Saved>> {
    let Some((mut ours, ours_key)) = keys.open(client, rel, vault.file_id, local, true) else {
        return Ok(None);
    };
    // The base opens with a key already known; an old version under a key
    // nobody has is merged without one (KeePassXC's rules), not prompted for.
    let mut base_db = match base {
        Some((file_id, version)) if file_id == vault.file_id => {
            fetch_version(client, vault, version)
                .ok()
                .and_then(|contents| keys.open(client, rel, vault.file_id, &contents, false))
        }
        _ => None,
    };
    let mut report = MergeReport::default();
    for _ in 0..SAVE_ATTEMPTS {
        let (theirs_contents, theirs_version) = fetch_current(client, vault)?;
        let Some((theirs, theirs_key)) =
            keys.open(client, rel, vault.file_id, &theirs_contents, true)
        else {
            return Ok(None);
        };
        let (merged, this_report) =
            kutup_pass::merge(base_db.as_ref().map(|(db, _)| db), &ours, &theirs);
        accumulate(&mut report, this_report);
        if same_content(&merged, &theirs) {
            return Ok(Some(Saved {
                contents: theirs_contents,
                version: recorded(&theirs_version),
                report,
                uploaded: false,
            }));
        }
        // A key changed on one side since the base wins, as any other change.
        let base_key = base_db.as_ref().map(|(_, index)| *index);
        let key_index = if Some(ours_key) == base_key {
            theirs_key
        } else {
            ours_key
        };
        let key = keys
            .key(rel, key_index)
            .ok_or_else(|| anyhow!("vault key went missing"))?
            .clone();
        let contents = kutup_pass::save(&merged, &key).context("save merged vault")?;
        if let Some(version) = save_version(client, vault, &contents, &recorded(&theirs_version))? {
            return Ok(Some(Saved {
                contents,
                version,
                report,
                uploaded: true,
            }));
        }
        // Another save landed first: what was merged is now ours, made from
        // what Drive held.
        ours = merged;
        base_db = Some((theirs, theirs_key));
    }
    Err(anyhow!("the vault kept changing on Drive; try again"))
}

/// One line describing a merge, for the sync log.
pub(crate) fn describe(report: &MergeReport) -> String {
    let mut parts = Vec::new();
    let mut count = |n: usize, what: &str| {
        if n > 0 {
            parts.push(format!("{n} {what}"));
        }
    };
    count(report.added.len(), "added");
    count(report.updated.len(), "updated");
    count(report.deleted.len(), "deleted");
    count(report.restored.len(), "restored");
    count(report.moved.len(), "moved");
    count(
        report.groups_added.len() + report.groups_updated.len() + report.groups_deleted.len(),
        "group changes",
    );
    let conflicts =
        report.conflicts.len() + report.group_conflicts.len() + report.metadata_conflicts.len();
    count(
        conflicts,
        "to review (both sides changed them; the other side is in their history)",
    );
    if parts.is_empty() {
        "no changes".to_owned()
    } else {
        parts.join(", ")
    }
}

fn accumulate(total: &mut MergeReport, next: MergeReport) {
    total.added.extend(next.added);
    total.updated.extend(next.updated);
    total.conflicts.extend(next.conflicts);
    total.restored.extend(next.restored);
    total.deleted.extend(next.deleted);
    total.moved.extend(next.moved);
    total.groups_added.extend(next.groups_added);
    total.groups_updated.extend(next.groups_updated);
    total.groups_deleted.extend(next.groups_deleted);
    total.groups_restored.extend(next.groups_restored);
    total.group_conflicts.extend(next.group_conflicts);
    total.metadata_conflicts.extend(next.metadata_conflicts);
}

/// Equal entries, groups and metadata; the file settings (KDF salts, seeds)
/// differ on every save.
fn same_content(a: &Database, b: &Database) -> bool {
    let mut a = a.clone();
    a.config = b.config.clone();
    a == *b
}

/// The `409 version_conflict` in `error`: the version the file holds now.
pub(crate) fn version_conflict(error: &anyhow::Error) -> Option<String> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<ApiError>())
        .and_then(|api| api.version_conflict.clone())
}

/// The file as Drive lists it now (its key may have moved on), with its key.
fn current_file(client: &Client, vault: &VaultFile) -> Result<(File, [u8; 32])> {
    let file = client
        .list_files(vault.collection_id)?
        .into_iter()
        .find(|f| f.id == vault.file_id)
        .ok_or_else(|| anyhow!("the vault is no longer in its folder"))?;
    let key = crate::file_crypto::open_key(&file, vault.keys).context("decrypt file key")?;
    Ok((file, key))
}

/// What the file holds now, with the version it is (as the server names it).
pub(crate) fn fetch_current(client: &Client, vault: &VaultFile) -> Result<(Vec<u8>, String)> {
    let (response, version) = client.download_current_stream(vault.file_id)?;
    let sealed = response.bytes().context("download vault")?.to_vec();
    let version = match version {
        Some(version) => version,
        // A server without the header: its newest whole-file version.
        None => client
            .list_versions(vault.file_id)?
            .into_iter()
            .find(|v| v.kind == "file")
            .map_or_else(|| ORIGINAL.to_owned(), |v| v.id),
    };
    Ok((open_sealed(client, vault, &sealed, &version)?, version))
}

/// A recorded version's contents (`""`: the original upload).
fn fetch_version(client: &Client, vault: &VaultFile, version: &str) -> Result<Vec<u8>> {
    let version = based_on(version);
    let sealed = if version == ORIGINAL {
        client.download_original(vault.file_id)?
    } else {
        client.download_version(vault.file_id, &version)?
    };
    open_sealed(client, vault, &sealed, &version)
}

/// Opens a sealed blob of the file: version `version`, at the key generation
/// it was saved with.
fn open_sealed(
    client: &Client,
    vault: &VaultFile,
    sealed: &[u8],
    version: &str,
) -> Result<Vec<u8>> {
    let (file, file_key) = current_file(client, vault)?;
    let generation = if version == ORIGINAL {
        file.original_key_generation
    } else {
        client
            .list_versions(&file.id)?
            .into_iter()
            .find(|v| v.id == version)
            .map(|v| v.key_generation)
            .ok_or_else(|| anyhow!("version {version} is gone"))?
    };
    let key = crate::file_crypto::key_at(&file, &file_key, generation)?;
    let plain = drive_object::decrypt_file_blob(
        sealed,
        &key,
        DriveFileBlobContextV1::new(&file.id, generation)?,
    )
    .context("decrypt vault")?;
    Ok(plain.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vaults_are_kdbx_files() {
        assert!(is_vault("Passwords.kdbx"));
        assert!(is_vault("work/Team.KDBX"));
        assert!(!is_vault(".kdbx"));
        assert!(!is_vault("notes.kdbx.txt"));
        assert!(!is_vault("kdbx"));
    }

    #[test]
    fn the_original_is_recorded_as_empty() {
        assert_eq!(based_on(""), "original");
        assert_eq!(based_on("v1"), "v1");
        assert_eq!(recorded("original"), "");
        assert_eq!(recorded("v1"), "v1");
    }

    const VAULT_ID: &str = "3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70";

    /// Never reached: without a signed-in account no secret is fetched.
    fn offline() -> Client {
        Client::new("http://127.0.0.1:9", "")
    }

    fn vault(title: &str, key: &VaultKey) -> Vec<u8> {
        let mut db = Database::new();
        db.root_mut().add_entry().set_unprotected("Title", title);
        kutup_pass::save(&db, key).unwrap()
    }

    #[test]
    fn configured_keys_open_and_are_remembered_per_vault() {
        let key = VaultKey::new().with_password("p");
        let contents = vault("a", &key);
        let mut keys = VaultKeys::new(Some("p"), None, false);
        let (_, index) = keys
            .open(&offline(), "a.kdbx", VAULT_ID, &contents, true)
            .unwrap();
        assert_eq!(index, 0);
        assert!(keys.key("a.kdbx", 0).is_some());
        // A version under another key does not open without a prompt.
        let other = vault("a", &VaultKey::new().with_password("q"));
        assert!(keys
            .open(&offline(), "a.kdbx", VAULT_ID, &other, true)
            .is_none());
    }

    #[test]
    fn without_a_key_or_a_terminal_nothing_opens() {
        let contents = vault("a", &VaultKey::new().with_password("p"));
        let mut keys = VaultKeys::new(None, None, false);
        assert!(keys
            .open(&offline(), "a.kdbx", VAULT_ID, &contents, true)
            .is_none());
    }

    #[test]
    fn same_content_ignores_the_file_settings() {
        let key = VaultKey::new().with_password("p");
        let contents = vault("a", &key);
        let first = kutup_pass::open(&contents, &key).unwrap();
        let resaved = kutup_pass::open(&kutup_pass::save(&first, &key).unwrap(), &key).unwrap();
        assert!(same_content(&first, &resaved));
        let mut changed = resaved.clone();
        changed.root_mut().add_entry().set_unprotected("Title", "b");
        assert!(!same_content(&first, &changed));
    }
}
