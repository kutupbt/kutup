//! `kutup upload` — encrypt and stream-upload a file or directory via tus.
//! Mirrors `cmd/upload.go`.
//!
//! Note: the whiteboard (`.excalidraw`) asset-extraction step from the Go CLI
//! is deferred — it's a best-effort optimization that needs the asset/snapshot
//! API surface (tracked in docs/roadmap.md). Regular-file upload is complete.

use std::fs::File;
use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::Engine;
use rand::RngCore;

use crate::api::{Client, CreateCollectionRequest, FileMetadata};
use crate::context::require_session;
use crate::cryptohelpers::{decrypt_collection_key, decrypt_collections, find_collection};
use crate::mimetype::guess_mime;
use crate::output::progress_bar;
use crate::transfer::{cipher_size, StreamUploader};
use kutup_crypto::secretbox;

pub fn run(
    profile: &str,
    json: bool,
    local_path: &str,
    collection_id: &str,
    recursive: bool,
) -> Result<()> {
    let ctx = require_session(profile)?;
    let master_key = ctx.session.master_key_bytes()?;

    let cols = decrypt_collections(ctx.client.list_collections()?, &master_key, &ctx.session);
    let col = find_collection(&cols, collection_id)
        .ok_or_else(|| crate::errors::NotFound(format!("collection {collection_id} not found")))?;
    let collection_key =
        decrypt_collection_key(col, &master_key, &ctx.session).context("decrypt collection key")?;

    let meta = std::fs::metadata(local_path)?;
    if meta.is_dir() {
        if !recursive {
            bail!("{local_path} is a directory — use --recursive to upload directories");
        }
        let mut stats = DirUpload::default();
        upload_dir(
            &ctx.client,
            Path::new(local_path),
            collection_id,
            &master_key,
            &mut stats,
        )?;
        if json {
            crate::output::print_json(&serde_json::json!({
                "collectionId": collection_id,
                "uploaded": stats.uploaded,
                "warnings": stats.warnings,
            }))?;
        } else if stats.warnings.is_empty() {
            println!("Uploaded {} file(s)", stats.uploaded.len());
        } else {
            println!(
                "Uploaded {} file(s), {} warning(s)",
                stats.uploaded.len(),
                stats.warnings.len()
            );
        }
        return Ok(());
    }

    let id = upload_single_file(
        &ctx.client,
        Path::new(local_path),
        collection_id,
        &collection_key,
    )?;

    let name = file_name(local_path);
    if json {
        crate::output::print_json(&serde_json::json!({ "id": id, "name": name }))?;
    } else {
        println!("Uploaded {name}  id={id}");
    }
    Ok(())
}

/// Accumulates a recursive upload's results for the summary / `--json` doc.
#[derive(Default)]
struct DirUpload {
    uploaded: Vec<serde_json::Value>,
    warnings: Vec<String>,
}

/// Streams one file through the tus endpoint: secretstream-encrypt one 5 MiB
/// chunk at a time, PATCH each chunk. Memory stays bounded. Returns the file id.
fn upload_single_file(
    client: &Client,
    local_path: &Path,
    collection_id: &str,
    collection_key: &[u8],
) -> Result<String> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut file = File::open(local_path)?;
    let plain_size = file.metadata()?.len() as i64;
    let total = cipher_size(plain_size);

    let mut file_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut file_key);

    let meta = FileMetadata {
        name: file_name(&local_path.to_string_lossy()),
        mime_type: guess_mime(local_path),
        size: plain_size,
    };
    let meta_bytes = serde_json::to_vec(&meta)?;
    let (enc_meta, meta_nonce) =
        secretbox::seal(&meta_bytes, &file_key).context("encrypt metadata")?;
    let (enc_file_key, file_key_nonce) =
        secretbox::seal(&file_key, collection_key).context("wrap file key")?;

    let upload_id = client
        .tus_create(
            total,
            collection_id,
            &b64.encode(&enc_meta),
            &b64.encode(meta_nonce),
            &b64.encode(&enc_file_key),
            &b64.encode(file_key_nonce),
        )
        .context("tus create")?;

    let result = (|| -> Result<String> {
        let mut up = StreamUploader::new(&mut file, &file_key, plain_size)?;
        let bar = progress_bar(Some(plain_size as u64), &meta.name);

        let mut offset = 0i64;
        let mut file_id = String::new();
        while let Some(chunk) = up.next_chunk()? {
            let (new_offset, final_id) = client.tus_patch(&upload_id, offset, chunk)?;
            offset = new_offset;
            if !final_id.is_empty() {
                file_id = final_id;
            }
            bar.set_position(up.plain_read() as u64);
        }
        bar.finish_and_clear();

        if file_id.is_empty() {
            bail!("tus: upload completed but server returned no file id");
        }
        Ok(file_id)
    })();

    if result.is_err() {
        let _ = client.tus_delete(&upload_id);
    }
    result
}

/// Recursively uploads a directory, creating sub-collections as needed.
fn upload_dir(
    client: &Client,
    dir: &Path,
    parent_col_id: &str,
    master_key: &[u8],
    stats: &mut DirUpload,
) -> Result<()> {
    let dir_name = file_name(&dir.to_string_lossy());
    let (sub_col_id, sub_col_key) =
        create_sub_collection(client, &dir_name, parent_col_id, master_key)
            .with_context(|| format!("create sub-folder {dir_name}"))?;

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if let Err(e) = upload_dir(client, &path, &sub_col_id, master_key, stats) {
                let w = format!("{e:#}");
                eprintln!("warning: {w}");
                stats.warnings.push(w);
            }
        } else {
            match upload_single_file(client, &path, &sub_col_id, &sub_col_key) {
                Ok(id) => {
                    eprintln!("  ↑ {}", path.display());
                    stats.uploaded.push(serde_json::json!({
                        "id": id,
                        "path": path.display().to_string(),
                        "collectionId": sub_col_id,
                    }));
                }
                Err(e) => {
                    let w = format!("upload {}: {e:#}", entry.file_name().to_string_lossy());
                    eprintln!("warning: {w}");
                    stats.warnings.push(w);
                }
            }
        }
    }
    Ok(())
}

fn create_sub_collection(
    client: &Client,
    name: &str,
    parent_id: &str,
    master_key: &[u8],
) -> Result<(String, [u8; 32])> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut collection_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut collection_key);

    let (enc_key, key_nonce) = secretbox::seal(&collection_key, master_key)?;
    let (enc_name, name_nonce) = secretbox::seal(name.as_bytes(), &collection_key)?;

    let resp = client.create_collection(&CreateCollectionRequest {
        encrypted_name: b64.encode(&enc_name),
        name_nonce: b64.encode(name_nonce),
        encrypted_key: b64.encode(&enc_key),
        encrypted_key_nonce: b64.encode(key_nonce),
        parent_collection_id: Some(parent_id.to_string()),
    })?;
    Ok((resp.id, collection_key))
}

fn file_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string())
}
