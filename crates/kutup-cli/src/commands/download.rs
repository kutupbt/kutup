//! `kutup download` — download and decrypt a file (snapshot-preferred for
//! collab-edited files). Whiteboards (`.excalidraw`) additionally get their
//! separately-stored image assets re-inlined (see `crate::whiteboard`).

use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

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

        let bar =
            crate::output::progress_bar(Some(f.encrypted_size_bytes.max(0) as u64), &meta.name);

        let mut out = File::create(&dest_path).context("open dest")?;
        let mut written =
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

        // Whiteboards may reference images stored as separate asset blobs;
        // re-inline them so the on-disk file is self-contained. Best-effort.
        if crate::whiteboard::is_excalidraw(&meta.name) {
            match crate::whiteboard::hydrate(&ctx.client, file_id, &col_key, &dest_path) {
                Ok(Some(new_len)) => written = new_len,
                Ok(None) => {}
                Err(e) => eprintln!("warning: asset hydration failed: {e:#}"),
            }
        }

        let dest_str = dest_path.to_string_lossy().into_owned();
        if json {
            crate::output::print_json(&serde_json::json!({
                "id": file_id,
                "name": meta.name,
                "size": written,
                "dest": dest_str,
                "fromVersion": from_version,
            }))?;
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
