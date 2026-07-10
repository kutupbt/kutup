//! `kutup download` — download and decrypt a file. Mirrors `cmd/download.go`.
//!
//! Note: the whiteboard (`.excalidraw`) asset-hydration step from the Go CLI is
//! deferred — a best-effort optimization needing the asset API (tracked in
//! docs/roadmap.md). Regular-file download (incl. the version-snapshot-preferred
//! path for collab-edited files) is complete.

use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};

use crate::api::FileMetadata;
use crate::context::require_session;
use crate::cryptohelpers::{decrypt_collection_key, decrypt_collections};
use crate::transfer::stream_download;
use kutup_crypto::secretbox;

pub fn run(profile: &str, json: bool, file_id: &str, dest: Option<&str>) -> Result<()> {
    let dest_dir = dest.unwrap_or(".");
    let ctx = require_session(profile)?;
    let master_key = ctx.session.master_key_bytes()?;

    let cols = decrypt_collections(ctx.client.list_collections()?, &master_key, &ctx.session);
    for col in &cols {
        let Ok(col_key) = decrypt_collection_key(col, &master_key, &ctx.session) else {
            continue;
        };
        let Ok(files) = ctx.client.list_files(&col.id) else {
            continue;
        };
        let Some(f) = files.iter().find(|f| f.id == file_id) else {
            continue;
        };

        let file_key = secretbox::open_b64(&f.encrypted_file_key, &f.file_key_nonce, &col_key)
            .context("decrypt file key")?;
        let meta_bytes = secretbox::open_b64(&f.encrypted_metadata, &f.metadata_nonce, &file_key)
            .context("decrypt metadata")?;
        let meta: FileMetadata = serde_json::from_slice(&meta_bytes).unwrap_or_default();

        let dest_path = resolve_dest(dest_dir, &meta.name);

        // Prefer the newest version snapshot (collab-edited files carry their
        // post-load state there), else the main blob.
        let (stream, from_version) = ctx.client.latest_encrypted_stream(file_id)?;

        let bar = ProgressBar::new(f.encrypted_size_bytes.max(0) as u64);
        bar.set_style(
            ProgressStyle::with_template("{msg} {bar:30} {bytes}/{total_bytes}")
                .unwrap_or_else(|_| ProgressStyle::default_bar()),
        );
        bar.set_message(meta.name.clone());

        let mut out = File::create(&dest_path).context("open dest")?;
        let written =
            match stream_download(stream, &file_key, &mut out, |n| bar.set_position(n as u64)) {
                Ok(w) => w,
                Err(e) => {
                    drop(out);
                    let _ = std::fs::remove_file(&dest_path);
                    return Err(e).context("decrypt-write");
                }
            };
        bar.finish_and_clear();

        // Integrity check (only meaningful for the cold-start blob; snapshot
        // bytes carry their own size and may differ from the original).
        if !from_version && meta.size > 0 && written != meta.size {
            let _ = std::fs::remove_file(&dest_path);
            bail!(
                "size mismatch: expected {} bytes, got {}",
                meta.size,
                written
            );
        }

        let dest_str = dest_path.to_string_lossy().into_owned();
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "id": file_id,
                    "name": meta.name,
                    "size": written,
                    "dest": dest_str,
                    "fromVersion": from_version,
                })
            );
        } else {
            let suffix = if from_version {
                " (latest snapshot)"
            } else {
                ""
            };
            println!("Downloaded {} → {dest_str}{suffix}", meta.name);
        }
        return Ok(());
    }

    Err(crate::errors::NotFound(format!(
        "file {file_id} not found in any accessible collection"
    ))
    .into())
}

/// If `dest_dir` is an existing directory, place the file inside it under its
/// decrypted name; otherwise treat `dest_dir` as the full destination path.
fn resolve_dest(dest_dir: &str, name: &str) -> PathBuf {
    let p = Path::new(dest_dir);
    if p.is_dir() {
        p.join(name)
    } else {
        p.to_path_buf()
    }
}
