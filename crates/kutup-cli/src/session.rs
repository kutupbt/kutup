//! Session persistence — mirrors `cmd/kutup/internal/session/store.go`.
//!
//! Two-tier model: a 32-byte **device key** lives in the OS keyring (service
//! `kutup-cli/<profile>`, account `device-key`), and the session JSON is
//! encrypted with it (XSalsa20-Poly1305, nonce-prepended) at rest.
//!
//! Storage backend: `redb` (the Go CLI used BoltDB). The on-disk file is named
//! `kutup.redb` so it never collides with a Go-era `kutup.db` BoltDB file —
//! switching binaries simply requires `kutup login` again.

use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use redb::{Database, TableDefinition};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::config;

const KEYRING_ACCOUNT: &str = "device-key";
const DB_FILE: &str = "kutup.redb";
const NONCE_BYTES: usize = 24;

/// `(key -> value)` blobs. `data` holds the encrypted session.
const SESSION: TableDefinition<&str, &[u8]> = TableDefinition::new("session");
/// Sync state (per-collection metadata + synced-file records).
const SYNC: TableDefinition<&str, &[u8]> = TableDefinition::new("sync");

fn keyring_service(profile: &str) -> String {
    format!("kutup-cli/{profile}")
}

/// In-memory session state for a single profile. Field names are serialized as
/// camelCase to match the Go struct (the blob is internal either way).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub server: String,
    pub email: String,
    pub user_id: String,
    pub username: String,
    pub access_token: String,
    pub refresh_token: String,
    /// Derived keys (base64), decrypted from server blobs at login.
    pub master_key: String,
    pub private_key: String,
    pub public_key: String,
    /// Server-returned encrypted blobs (kept for possible re-derivation).
    pub encrypted_master_key: String,
    pub master_key_nonce: String,
    pub encrypted_private_key: String,
    pub private_key_nonce: String,
    pub storage_quota_bytes: i64,
    pub storage_used_bytes: i64,
}

impl Session {
    pub fn master_key_bytes(&self) -> Result<Vec<u8>> {
        b64(&self.master_key)
    }
    pub fn private_key_bytes(&self) -> Result<Vec<u8>> {
        b64(&self.private_key)
    }
    pub fn public_key_bytes(&self) -> Result<Vec<u8>> {
        b64(&self.public_key)
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
            wtx.open_table(SYNC)?;
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
        rand::rngs::OsRng.fill_bytes(&mut key);
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
            return Err(anyhow!("no device key — run 'kutup login' first"));
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
        }
        wtx.commit()?;
        Ok(())
    }

    // --- device-key encryption (XSalsa20-Poly1305, nonce-prepended) ---

    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let key = self.device_key.expect("device key present");
        let mut nonce = [0u8; NONCE_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct = kutup_crypto::secretbox::seal_with_nonce(data, &nonce, &key)
            .map_err(|e| anyhow!("session encrypt: {e}"))?;
        let mut out = Vec::with_capacity(NONCE_BYTES + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < NONCE_BYTES {
            return Err(anyhow!("session data too short"));
        }
        let key = self.device_key.expect("device key present");
        let (nonce, ct) = data.split_at(NONCE_BYTES);
        kutup_crypto::secretbox::open(ct, nonce, &key)
            .map_err(|_| anyhow!("session decryption failed — wrong device key"))
    }

    // --- sync state (used by the sync engine) ---

    pub(crate) fn sync_get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let rtx = self.db.begin_read()?;
        let t = rtx.open_table(SYNC)?;
        Ok(t.get(key)?.map(|v| v.value().to_vec()))
    }

    pub(crate) fn sync_put(&self, key: &str, value: &[u8]) -> Result<()> {
        let wtx = self.db.begin_write()?;
        {
            let mut t = wtx.open_table(SYNC)?;
            t.insert(key, value)?;
        }
        wtx.commit()?;
        Ok(())
    }

    pub(crate) fn sync_remove(&self, key: &str) -> Result<()> {
        let wtx = self.db.begin_write()?;
        {
            let mut t = wtx.open_table(SYNC)?;
            t.remove(key)?;
        }
        wtx.commit()?;
        Ok(())
    }

    /// Returns the synced-file record for `(collection, remote_id)`, if any.
    pub fn get_synced_file(
        &self,
        collection_id: &str,
        remote_id: &str,
    ) -> Result<Option<SyncedFile>> {
        let key = format!("{collection_id}/files/{remote_id}");
        match self.sync_get(&key)? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
            None => Ok(None),
        }
    }

    /// Records a synced file for `(collection, remote_id)`.
    pub fn save_synced_file(
        &self,
        collection_id: &str,
        remote_id: &str,
        f: &SyncedFile,
    ) -> Result<()> {
        let key = format!("{collection_id}/files/{remote_id}");
        self.sync_put(&key, &serde_json::to_vec(f)?)
    }
}

/// Tracks a file that has been synced. Mirrors `session.SyncedFile`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncedFile {
    pub local_path: String,
    pub size: i64,
    pub mod_time: i64,
    pub synced_at: i64,
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
                email: "a@b.c".into(),
                username: "alice".into(),
                master_key: "bWtleQ==".into(),
                ..Default::default()
            };
            store.save_session(&sess).unwrap();
        }
        {
            let store = Store::open(profile).unwrap();
            let loaded = store.load_session().unwrap().expect("session present");
            assert_eq!(loaded.email, "a@b.c");
            assert_eq!(loaded.username, "alice");
            assert_eq!(loaded.master_key, "bWtleQ==");
            store.clear_session().unwrap();
            assert!(store.load_session().unwrap().is_none());
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
