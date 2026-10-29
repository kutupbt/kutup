//! Session persistence — mirrors `cmd/kutup/internal/session/store.go`.
//!
//! Two-tier model: a 32-byte **device key** lives in the OS keyring (service
//! `kutup-cli/<profile>`, account `device-key`), and the session JSON is
//! encrypted with it in a profile-bound `LocalStateEnvelopeV1` at rest.
//!
//! Storage backend: `redb` (the Go CLI used BoltDB). The on-disk file is named
//! `kutup.redb` so it never collides with a Go-era `kutup.db` BoltDB file —
//! switching binaries simply requires `kutup login` again.

use anyhow::{anyhow, Context, Result};
use kutup_crypto::primitives::{Hasher, Suite};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::config;

const KEYRING_ACCOUNT: &str = "device-key";
const DB_FILE: &str = "kutup.redb";

/// `(key -> value)` blobs. `data` holds the encrypted session.
const SESSION: TableDefinition<&str, &[u8]> = TableDefinition::new("session");
/// Sync state v2, keyed `"{pair}|f|{rel_path}"` / `"{pair}|d|{rel_dir}"`
/// where `pair` = sha256(collection_id ++ "\0" ++ canonical_local_root).
const SYNC_STATE: TableDefinition<&str, &[u8]> = TableDefinition::new("sync_state");
/// The CLI's collaboration device (encrypted), key `device`.
const COLLAB_DEVICE: TableDefinition<&str, &[u8]> = TableDefinition::new("collab_device");
/// The newest manifest of its own account this profile saw (plain JSON of a
/// `kutup_chat_proto::OwnManifestPinV1`, key `pin`): not secret, and kept
/// across sign-ins, so a server can't roll the account back under it.
const MANIFEST_PIN: TableDefinition<&str, &[u8]> = TableDefinition::new("manifest_pin");
/// Interrupted-upload resume records, keyed `"{collection_id}\n{canonical_path}"`.
const RESUME: TableDefinition<&str, &[u8]> = TableDefinition::new("resume");

fn keyring_service(profile: &str) -> String {
    format!("kutup-cli/{profile}")
}

/// In-memory session state for a single profile. Field names are serialized as
/// camelCase to match the Go struct (the blob is internal either way).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub server: String,
    /// What the account signed in with: its username or Kutup address.
    pub name: String,
    /// What the account's sealed keys are bound to: its key binding, as the
    /// sign-in told it.
    pub envelope_binding: String,
    /// The account's permanent id (`users.id`) and its server's name: who
    /// this account is to everyone (docs/plans/account-ids.md).
    pub user_id: String,
    pub server_name: String,
    /// Shown only: the account's username, as `/user/me` last said.
    pub username: String,
    pub access_token: String,
    pub refresh_token: String,
    /// Derived keys (base64), decrypted from server blobs at login.
    pub master_key: String,
    pub private_key: String,
    pub public_key: String,
    /// Server-returned encrypted blobs (kept for possible re-derivation).
    pub master_key_envelope: String,
    pub storage_quota_bytes: i64,
    pub storage_used_bytes: i64,
}

impl Session {
    /// The string every seal and open uses (docs/plans/account-identity.md).
    pub fn binding(&self) -> &str {
        &self.envelope_binding
    }

    /// This account as every share and binding names it.
    pub fn person(&self) -> Result<kutup_crypto::account_ref::AccountRef> {
        kutup_crypto::account_ref::AccountRef::new(&self.server_name, &self.user_id)
            .map_err(|_| anyhow!("this session's account is not known: run 'kutup login' again"))
    }
}

impl Session {
    pub fn master_key_bytes(&self) -> Result<Vec<u8>> {
        b64(&self.master_key)
    }
    pub fn private_key_bytes(&self) -> Result<Vec<u8>> {
        b64(&self.private_key)
    }
}

fn b64(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .context("invalid base64 in session")
}

/// Manages session persistence for one profile.
pub struct Store {
    db: Database,
    device_key: Option<[u8; 32]>,
    profile: String,
}

impl Store {
    /// Opens (or creates) the redb store and loads the device key if present.
    pub fn open(profile: &str) -> Result<Store> {
        let dir = config::data_dir(profile)?;
        let db = Database::create(dir.join(DB_FILE)).context("open session db")?;
        // Ensure tables exist.
        {
            let wtx = db.begin_write()?;
            wtx.open_table(SESSION)?;
            wtx.open_table(SYNC_STATE)?;
            wtx.open_table(RESUME)?;
            wtx.open_table(MANIFEST_PIN)?;
            wtx.commit()?;
        }
        let mut store = Store {
            db,
            device_key: None,
            profile: profile.to_string(),
        };
        store.load_device_key();
        Ok(store)
    }

    fn key_file(&self) -> Result<std::path::PathBuf> {
        Ok(config::data_dir(&self.profile)?.join("device.key"))
    }

    /// Loads the device key from keyring → `KUTUP_DEVICE_KEY` env → file fallback.
    fn load_device_key(&mut self) {
        // 1. OS keyring (macOS/Windows only — see keyring_get).
        if let Some(stored) = keyring_get(&keyring_service(&self.profile), KEYRING_ACCOUNT) {
            if let Some(k) = decode_key(&stored) {
                self.device_key = Some(k);
                return;
            }
        }
        // 2. Env var (Docker / CI).
        if let Ok(env_key) = std::env::var("KUTUP_DEVICE_KEY") {
            if let Some(k) = decode_key(&env_key) {
                self.device_key = Some(k);
                return;
            }
        }
        // 3. File fallback.
        if let Ok(path) = self.key_file() {
            if let Ok(data) = std::fs::read_to_string(&path) {
                if let Some(k) = decode_key(data.trim()) {
                    self.device_key = Some(k);
                }
            }
        }
    }

    /// Generates and persists a new device key (keyring, else chmod-600 file).
    fn create_device_key(&mut self) -> Result<()> {
        let mut key = [0u8; 32];
        kutup_crypto::primitives::random(&mut key);
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(key);

        if keyring_set(&keyring_service(&self.profile), KEYRING_ACCOUNT, &encoded) {
            self.device_key = Some(key);
            return Ok(());
        }
        // Fall back to a chmod-600 file.
        let path = self.key_file()?;
        write_private_file(&path, encoded.as_bytes())?;
        self.device_key = Some(key);
        Ok(())
    }

    pub fn has_device_key(&self) -> bool {
        self.device_key.is_some()
    }

    /// Encrypts and persists the session.
    pub fn save_session(&mut self, sess: &Session) -> Result<()> {
        if !self.has_device_key() {
            self.create_device_key().context("create device key")?;
        }
        let data = serde_json::to_vec(sess)?;
        let encrypted = self.encrypt(&data)?;
        let wtx = self.db.begin_write()?;
        {
            let mut t = wtx.open_table(SESSION)?;
            t.insert("data", encrypted.as_slice())?;
        }
        wtx.commit()?;
        Ok(())
    }

    /// Decrypts and returns the stored session, or `None` if not logged in.
    pub fn load_session(&self) -> Result<Option<Session>> {
        let rtx = self.db.begin_read()?;
        let t = rtx.open_table(SESSION)?;
        let Some(v) = t.get("data")? else {
            return Ok(None);
        };
        let encrypted = v.value().to_vec();
        if !self.has_device_key() {
            return Err(crate::errors::NotLoggedIn(
                "no device key — run 'kutup login' first".into(),
            )
            .into());
        }
        let data = self.decrypt(&encrypted)?;
        let sess: Session = serde_json::from_slice(&data)?;
        Ok(Some(sess))
    }

    /// Removes all session data.
    pub fn clear_session(&self) -> Result<()> {
        let wtx = self.db.begin_write()?;
        {
            let mut t = wtx.open_table(SESSION)?;
            t.remove("data")?;
            // The device belongs to the account signed out of.
            let mut t = wtx.open_table(COLLAB_DEVICE)?;
            t.remove("device")?;
        }
        wtx.commit()?;
        Ok(())
    }

    /// The collaboration device this profile registered, if any.
    pub fn collab_device(&self) -> Result<Option<CollabDevice>> {
        let rtx = self.db.begin_read()?;
        let t = match rtx.open_table(COLLAB_DEVICE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let Some(v) = t.get("device")? else {
            return Ok(None);
        };
        if !self.has_device_key() {
            return Ok(None);
        }
        let data = self.decrypt(v.value())?;
        // One kept in an earlier form (before devices were manifest entries)
        // is no device now: a new one registers.
        Ok(serde_json::from_slice(&data).ok())
    }

    /// Keeps the collaboration device (`None`: forgets it).
    pub fn put_collab_device(&self, device: Option<&CollabDevice>) -> Result<()> {
        let wtx = self.db.begin_write()?;
        {
            let mut t = wtx.open_table(COLLAB_DEVICE)?;
            match device {
                Some(device) => {
                    let encrypted = self.encrypt(&serde_json::to_vec(device)?)?;
                    t.insert("device", encrypted.as_slice())?;
                }
                None => {
                    t.remove("device")?;
                }
            }
        }
        wtx.commit()?;
        Ok(())
    }

    /// The pin [`Self::put_manifest_pin`] kept, if any.
    pub fn manifest_pin(&self) -> Result<Option<kutup_chat_proto::OwnManifestPinV1>> {
        let rtx = self.db.begin_read()?;
        let t = rtx.open_table(MANIFEST_PIN)?;
        let Some(v) = t.get("pin")? else {
            return Ok(None);
        };
        Ok(Some(
            serde_json::from_slice(v.value()).context("the kept manifest pin is malformed")?,
        ))
    }

    /// Forgets the pin (`kutup devices forget-pin`, after a server restore).
    pub fn forget_manifest_pin(&self) -> Result<()> {
        let wtx = self.db.begin_write()?;
        {
            let mut t = wtx.open_table(MANIFEST_PIN)?;
            t.remove("pin")?;
        }
        wtx.commit()?;
        Ok(())
    }

    pub fn put_manifest_pin(&self, pin: &kutup_chat_proto::OwnManifestPinV1) -> Result<()> {
        let wtx = self.db.begin_write()?;
        {
            let mut t = wtx.open_table(MANIFEST_PIN)?;
            t.insert("pin", serde_json::to_vec(pin)?.as_slice())?;
        }
        wtx.commit()?;
        Ok(())
    }

    // --- device-key encryption (typed, profile-bound XChaCha envelope) ---

    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let key = self.device_key.expect("device key present");
        kutup_crypto::local_state::seal(
            data,
            &key,
            kutup_crypto::local_state::LocalStatePurpose::CliSession,
            &self.profile,
        )
        .map_err(|e| anyhow!("session encrypt: {e}"))
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let key = self.device_key.expect("device key present");
        kutup_crypto::local_state::open(
            data,
            &key,
            kutup_crypto::local_state::LocalStatePurpose::CliSession,
            &self.profile,
        )
        .map_err(|_| anyhow!("session decryption failed — wrong device key"))
    }

    // --- sync state v2 (used by the sync engine) ---

    pub fn put_sync_file(&self, pair: &str, rel: &str, st: &SyncFileState) -> Result<()> {
        self.sync_state_put(&format!("{pair}|f|{rel}"), &serde_json::to_vec(st)?)
    }

    pub fn delete_sync_file(&self, pair: &str, rel: &str) -> Result<()> {
        self.sync_state_delete(&format!("{pair}|y|{rel}"))?;
        self.sync_state_delete(&format!("{pair}|f|{rel}"))
    }

    /// The Yjs state a note or list was last in sync at (encrypted: it
    /// holds the document).
    pub fn yjs_base(&self, pair: &str, rel: &str) -> Result<Option<YjsBase>> {
        let rtx = self.db.begin_read()?;
        let t = rtx.open_table(SYNC_STATE)?;
        let Some(v) = t.get(format!("{pair}|y|{rel}").as_str())? else {
            return Ok(None);
        };
        if !self.has_device_key() {
            return Ok(None);
        }
        Ok(serde_json::from_slice(&self.decrypt(v.value())?).ok())
    }

    pub fn delete_yjs_base(&self, pair: &str, rel: &str) -> Result<()> {
        self.sync_state_delete(&format!("{pair}|y|{rel}"))
    }

    pub fn put_yjs_base(&self, pair: &str, rel: &str, base: &YjsBase) -> Result<()> {
        let encrypted = self.encrypt(&serde_json::to_vec(base)?)?;
        self.sync_state_put(&format!("{pair}|y|{rel}"), &encrypted)
    }

    /// All file records for a pair, as `(rel_path, state)`.
    pub fn list_sync_files(&self, pair: &str) -> Result<Vec<(String, SyncFileState)>> {
        self.sync_state_prefix(&format!("{pair}|f|"))
    }

    pub fn put_sync_dir(&self, pair: &str, rel: &str, st: &SyncDirState) -> Result<()> {
        self.sync_state_put(&format!("{pair}|d|{rel}"), &serde_json::to_vec(st)?)
    }

    pub fn delete_sync_dir(&self, pair: &str, rel: &str) -> Result<()> {
        self.sync_state_delete(&format!("{pair}|d|{rel}"))
    }

    /// All directory records for a pair, as `(rel_dir, state)`.
    pub fn list_sync_dirs(&self, pair: &str) -> Result<Vec<(String, SyncDirState)>> {
        self.sync_state_prefix(&format!("{pair}|d|"))
    }

    fn sync_state_put(&self, key: &str, value: &[u8]) -> Result<()> {
        let wtx = self.db.begin_write()?;
        {
            let mut t = wtx.open_table(SYNC_STATE)?;
            t.insert(key, value)?;
        }
        wtx.commit()?;
        Ok(())
    }

    fn sync_state_delete(&self, key: &str) -> Result<()> {
        let wtx = self.db.begin_write()?;
        {
            let mut t = wtx.open_table(SYNC_STATE)?;
            t.remove(key)?;
        }
        wtx.commit()?;
        Ok(())
    }

    fn sync_state_prefix<T: serde::de::DeserializeOwned>(
        &self,
        prefix: &str,
    ) -> Result<Vec<(String, T)>> {
        let rtx = self.db.begin_read()?;
        let t = rtx.open_table(SYNC_STATE)?;
        let mut out = Vec::new();
        for row in t.range(prefix..)? {
            let (k, v) = row?;
            let key = k.value();
            if !key.starts_with(prefix) {
                break;
            }
            if let Ok(st) = serde_json::from_slice(v.value()) {
                out.push((key[prefix.len()..].to_string(), st));
            }
        }
        Ok(out)
    }

    // --- upload resume state ---

    pub fn get_resume(&self, key: &str) -> Result<Option<ResumeState>> {
        let rtx = self.db.begin_read()?;
        let t = rtx.open_table(RESUME)?;
        Ok(t.get(key)?
            .and_then(|v| serde_json::from_slice(v.value()).ok()))
    }

    pub fn save_resume(&self, key: &str, st: &ResumeState) -> Result<()> {
        let wtx = self.db.begin_write()?;
        {
            let mut t = wtx.open_table(RESUME)?;
            t.insert(key, serde_json::to_vec(st)?.as_slice())?;
        }
        wtx.commit()?;
        Ok(())
    }

    pub fn delete_resume(&self, key: &str) -> Result<()> {
        let wtx = self.db.begin_write()?;
        {
            let mut t = wtx.open_table(RESUME)?;
            t.remove(key)?;
        }
        wtx.commit()?;
        Ok(())
    }

    /// Removes records idle longer than `max_idle_secs` (the server sweeps
    /// its side at 24 h) and returns them so the caller can best-effort
    /// `tus_delete` the orphaned sessions.
    pub fn sweep_resume(&self, max_idle_secs: i64, now: i64) -> Result<Vec<(String, ResumeState)>> {
        let mut stale = Vec::new();
        {
            let rtx = self.db.begin_read()?;
            let t = rtx.open_table(RESUME)?;
            for row in t.iter()? {
                let (k, v) = row?;
                let Some(st) = serde_json::from_slice::<ResumeState>(v.value()).ok() else {
                    stale.push((k.value().to_string(), ResumeState::default()));
                    continue;
                };
                if now - st.updated_at > max_idle_secs {
                    stale.push((k.value().to_string(), st));
                }
            }
        }
        if !stale.is_empty() {
            let wtx = self.db.begin_write()?;
            {
                let mut t = wtx.open_table(RESUME)?;
                for (k, _) in &stale {
                    t.remove(k.as_str())?;
                }
            }
            wtx.commit()?;
        }
        Ok(stale)
    }
}

/// State needed to resume an interrupted tus upload. Values in the sync/resume
/// tables are plaintext JSON, so the file key is stored only in its
/// collection-key wrap (`file_key_envelope` — the exact blob the server already
/// holds), never raw; the 24-byte header is public (it's the first bytes of
/// ciphertext the server already received).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResumeState {
    pub upload_id: String,
    /// Pre-allocated file id from the tus create body.
    pub file_id: String,
    /// Typed envelope wrapped with the collection key.
    pub file_key_envelope: String,
    pub key_epoch: u32,
    /// base64 24-byte secretstream header.
    pub header: String,
    pub plain_size: i64,
    pub cipher_total: i64,
    pub mtime_secs: i64,
    pub mtime_nanos: u32,
    pub created_at: i64,
    /// Bumped after each successful PATCH; drives idle sweeping.
    pub updated_at: i64,
    /// A new version's upload: the file it is a version of (empty for a new
    /// file), sealed at `key_generation`.
    #[serde(default)]
    pub version_of: String,
    #[serde(default)]
    pub key_generation: u32,
}

/// Sync pair id: one synced (collection, local dir) combination.
pub fn sync_pair_id(collection_id: &str, canonical_root: &str) -> String {
    let mut h = Hasher::new(Suite::V1);
    h.update(collection_id.as_bytes());
    h.update([0u8]);
    h.update(canonical_root.as_bytes());
    hex_lower(&h.finish())
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The three-way-merge base for one synced file: what local and remote looked
/// like the last time this rel_path was in sync.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncFileState {
    pub file_id: String,
    /// The (sub-)collection currently holding the file.
    pub collection_id: String,
    /// `-1` marks a conflicted base: local is forced push-dirty next run.
    pub local_size: i64,
    pub local_mtime_secs: i64,
    pub local_mtime_nanos: u32,
    /// Newest `file_versions` id at last sync ("" = none) — the remote
    /// change signal (`files.updated_at` is never bumped server-side).
    pub remote_version_id: String,
    pub synced_at: i64,
}

/// The CLI's device of its account (docs/plans/one-device-list.md): its id
/// in the account's manifest, the key its frames are signed with, and its
/// credential, for one account on one server.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollabDevice {
    pub server: String,
    pub user_id: String,
    pub device_id: u32,
    /// The Ed25519 seed, base64.
    pub seed: String,
    /// The device credential, base64.
    pub credential: String,
}

/// Where a note or place list was last in sync (docs/plans/cli-yjs-sync.md):
/// its Yjs state then, which a local edit is diffed against so edits made
/// elsewhere since merge instead of being undone.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YjsBase {
    pub file_id: String,
    /// Yjs V2, base64: what the file on disk held at the last sync (with any
    /// edit of it in `pending` already in).
    pub state: String,
    /// Every frame of the log up to here is in `state`.
    pub seq: i64,
    /// Updates (Yjs V1, base64) sent or being sent and not yet acknowledged:
    /// sent again, byte for byte, by the next run (Yjs drops a repeat by
    /// its client and clock), never made again as new operations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending: Vec<String>,
    /// A merged file being written: the next run tells from the file whether
    /// it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writing: Option<YjsWriting>,
}

/// A write of a merged document in progress.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YjsWriting {
    /// SHA-256 (hex) of the file before, and of what is being written.
    pub before: String,
    pub after: String,
    /// The merged state (Yjs V2, base64) and its log position: the base once
    /// the file holds `after`.
    pub state: String,
    pub seq: i64,
}

/// Base record for one synced sub-directory ↔ sub-collection.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncDirState {
    pub collection_id: String,
}

// --- OS keychain access (macOS/Windows only; Linux uses the file fallback to
// avoid a libdbus C dependency) ---

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn keyring_get(service: &str, account: &str) -> Option<String> {
    keyring::Entry::new(service, account)
        .ok()?
        .get_password()
        .ok()
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn keyring_get(_service: &str, _account: &str) -> Option<String> {
    None
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn keyring_set(service: &str, account: &str, value: &str) -> bool {
    keyring::Entry::new(service, account)
        .and_then(|e| e.set_password(value))
        .is_ok()
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn keyring_set(_service: &str, _account: &str, _value: &str) -> bool {
    false
}

fn decode_key(encoded: &str) -> Option<[u8; 32]> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    bytes.try_into().ok()
}

fn write_private_file(path: &std::path::Path, contents: &[u8]) -> Result<()> {
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

impl Drop for Store {
    fn drop(&mut self) {
        if let Some(mut k) = self.device_key.take() {
            k.zeroize();
        }
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;
    use base64::Engine;

    // Exercises the full encrypt → redb → decrypt session path with the device
    // key supplied via env (XDG_DATA_HOME isolates the on-disk store).
    #[test]
    fn session_save_load_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("kutup-test-{}", std::process::id()));
        std::env::set_var("XDG_DATA_HOME", &tmp);
        let key = [7u8; 32];
        std::env::set_var(
            "KUTUP_DEVICE_KEY",
            base64::engine::general_purpose::STANDARD.encode(key),
        );

        let profile = "test";
        {
            let mut store = Store::open(profile).unwrap();
            assert!(store.has_device_key());
            assert!(store.load_session().unwrap().is_none());
            let sess = Session {
                name: "a@b.c".into(),
                envelope_binding: String::new(),
                username: "alice".into(),
                master_key: "bWtleQ==".into(),
                ..Default::default()
            };
            store.save_session(&sess).unwrap();
        }
        {
            let store = Store::open(profile).unwrap();
            let loaded = store.load_session().unwrap().expect("session present");
            assert_eq!(loaded.name, "a@b.c");
            assert_eq!(loaded.username, "alice");
            assert_eq!(loaded.master_key, "bWtleQ==");
            store.clear_session().unwrap();
            assert!(store.load_session().unwrap().is_none());
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
