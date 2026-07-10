//! Bidirectional one-shot sync between a local directory and a remote
//! collection — mirrors `internal/sync/engine.go`.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::Engine;

use crate::api::{Client, FileMetadata};
use crate::session::{Session, Store, SyncedFile};
use kutup_crypto::{secretbox, stream};

/// Summary of a sync run.
#[derive(Default)]
pub struct SyncResult {
    pub uploaded: usize,
    pub downloaded: usize,
    pub conflicts: usize,
    pub errors: Vec<String>,
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// Performs a bidirectional sync between `local_dir` and `collection_id`.
pub fn sync(
    client: &Client,
    store: &Store,
    sess: &Session,
    local_dir: &str,
    collection_id: &str,
) -> Result<SyncResult> {
    let mut result = SyncResult::default();
    let master_key = sess.master_key_bytes().context("master key")?;

    let cols = client.list_collections().context("list collections")?;
    let col = cols
        .iter()
        .find(|c| c.id == collection_id)
        .ok_or_else(|| crate::errors::NotFound(format!("collection {collection_id} not found")))?;
    let collection_key =
        secretbox::open_b64(&col.encrypted_key, &col.encrypted_key_nonce, &master_key)
            .context("decrypt collection key")?;

    let remote_files = client.list_files(collection_id).context("list files")?;

    // Decrypt remote metadata → (file, name, size).
    struct Remote {
        file: crate::api::File,
        name: String,
    }
    let mut remote_index: Vec<Remote> = Vec::new();
    for f in remote_files {
        let decode = || -> Result<String> {
            let file_key =
                secretbox::open_b64(&f.encrypted_file_key, &f.file_key_nonce, &collection_key)?;
            let meta_bytes =
                secretbox::open_b64(&f.encrypted_metadata, &f.metadata_nonce, &file_key)?;
            let meta: FileMetadata = serde_json::from_slice(&meta_bytes)?;
            Ok(meta.name)
        };
        match decode() {
            Ok(name) if !name.is_empty() => remote_index.push(Remote { file: f, name }),
            Ok(_) => {}
            Err(e) => result.errors.push(format!("decrypt {}: {e}", f.id)),
        }
    }

    // Pull: download remote files not yet synced.
    for r in &remote_index {
        if store.get_synced_file(collection_id, &r.file.id)?.is_some() {
            continue;
        }
        let local_path = Path::new(local_dir).join(sanitize_name(&r.name));
        if let Err(e) = download_file(client, &r.file, &collection_key, &local_path) {
            result.errors.push(format!("download {}: {e}", r.name));
            continue;
        }
        let (size, mod_time) = file_stat(&local_path);
        let _ = store.save_synced_file(
            collection_id,
            &r.file.id,
            &SyncedFile {
                local_path: local_path.to_string_lossy().into_owned(),
                size,
                mod_time,
                synced_at: now_unix(),
            },
        );
        println!("  ↓ {}", r.name);
        result.downloaded += 1;
    }

    // Build local-path → already-synced set.
    let mut synced_paths = std::collections::HashSet::new();
    for r in &remote_index {
        if let Some(sf) = store.get_synced_file(collection_id, &r.file.id)? {
            synced_paths.insert(sf.local_path);
        }
    }

    // Push: upload local files not yet synced.
    for entry in std::fs::read_dir(local_dir).context("read dir")? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            continue;
        }
        let path_str = path.to_string_lossy().into_owned();
        if synced_paths.contains(&path_str) {
            continue;
        }
        match upload_file(client, &path, collection_id, &collection_key) {
            Ok(remote_id) => {
                let (size, mod_time) = file_stat(&path);
                let _ = store.save_synced_file(
                    collection_id,
                    &remote_id,
                    &SyncedFile {
                        local_path: path_str,
                        size,
                        mod_time,
                        synced_at: now_unix(),
                    },
                );
                println!("  ↑ {}", entry.file_name().to_string_lossy());
                result.uploaded += 1;
            }
            Err(e) => result.errors.push(format!(
                "upload {}: {e}",
                entry.file_name().to_string_lossy()
            )),
        }
    }

    Ok(result)
}

fn download_file(
    client: &Client,
    f: &crate::api::File,
    collection_key: &[u8],
    local_path: &Path,
) -> Result<()> {
    let file_key = secretbox::open_b64(&f.encrypted_file_key, &f.file_key_nonce, collection_key)
        .context("decrypt file key")?;
    // Version-aware: prefer the latest snapshot (collab-edited files).
    let (encrypted, _) = client.latest_encrypted_bytes(&f.id)?;
    let plaintext = stream::decrypt_stream(&encrypted, &file_key).context("decrypt stream")?;
    std::fs::write(local_path, plaintext)?;
    Ok(())
}

fn upload_file(
    client: &Client,
    local_path: &Path,
    collection_id: &str,
    collection_key: &[u8],
) -> Result<String> {
    use rand::RngCore;
    let data = std::fs::read(local_path)?;

    let mut file_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut file_key);

    let encrypted = stream::encrypt_stream(&data, &file_key).context("encrypt")?;
    let (enc_file_key, file_key_nonce) =
        secretbox::seal(&file_key, collection_key).context("wrap file key")?;

    let meta = FileMetadata {
        name: local_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        mime_type: guess_mime(local_path).to_string(),
        size: data.len() as i64,
    };
    let meta_bytes = serde_json::to_vec(&meta)?;
    let (enc_meta, meta_nonce) =
        secretbox::seal(&meta_bytes, &file_key).context("encrypt metadata")?;

    let e = b64();
    let resp = client
        .upload_file(
            collection_id,
            &e.encode(&enc_meta),
            &e.encode(meta_nonce),
            &e.encode(&enc_file_key),
            &e.encode(file_key_nonce),
            encrypted,
        )
        .context("upload")?;
    Ok(resp.id)
}

fn file_stat(path: &Path) -> (i64, i64) {
    match std::fs::metadata(path) {
        Ok(m) => {
            let size = m.len() as i64;
            let mod_time = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            (size, mod_time)
        }
        Err(_) => (0, 0),
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Strips path separators to prevent traversal. Mirrors `sanitizeName`.
fn sanitize_name(name: &str) -> String {
    let cleaned = name.replace(['/', '\\'], "_");
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        return "_file".to_string();
    }
    cleaned
}

/// Mirrors the sync engine's `guessMIME` (note: no .zip, matching Go).
fn guess_mime(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("pdf") => "application/pdf",
        Some("txt") => "text/plain",
        Some("mp4") => "video/mp4",
        Some("mp3") => "audio/mpeg",
        _ => "application/octet-stream",
    }
}
