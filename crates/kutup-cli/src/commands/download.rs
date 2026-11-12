//! `kutup download` — download and decrypt a file (snapshot-preferred for
//! collab-edited files). Whiteboards (`.excalidraw`) additionally get their
//! separately-stored image assets re-inlined (see `crate::whiteboard`).

use std::fs::File;
use std::path::{Path, PathBuf};

use crate::api::versions::ContentRoute;
use crate::context::require_session;
use crate::cryptohelpers::{decrypt_collection_key, decrypt_collections};
use anyhow::{Context, Result};

pub fn run(profile: &str, json: bool, file_id: &str, dest: Option<&str>) -> Result<()> {
    let dest_dir = dest.unwrap_or(".");
    let ctx = require_session(profile)?;
    let master_key = ctx.session.master_key_bytes()?;
    crate::drive_signer::load_pins(&ctx, profile);

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

        let keys = crate::keyring::Keyring::load(&ctx.client, col, &col_key, &master_key)?;
        let (file_key, meta) = crate::file_crypto::open(f, &keys).context("decrypt file record")?;

        let dest_path = resolve_dest(dest_dir, &meta.name);

        // What the file holds now (its latest whole-file version, else the
        // upload), sealed at `contentKeyGeneration`: the revision and
        // manifest its metadata commits to, read block by block.
        let (content_key, content_generation) = crate::file_crypto::content_key(f, &file_key)?;
        let bar = crate::output::progress_bar(Some(meta.size), &meta.name);
        let mut out = File::create(&dest_path).context("open dest")?;
        let opened = match crate::revisions::read(
            &ctx.client,
            &ContentRoute::Current(file_id),
            &content_key,
            &f.id,
            content_generation,
            &crate::revisions::current(&meta),
            &mut out,
            |n| bar.set_position(n),
        ) {
            Ok(opened) => opened,
            Err(e) => {
                drop(out);
                let _ = std::fs::remove_file(&dest_path);
                return Err(e).context("decrypt-write");
            }
        };
        bar.finish_and_clear();
        let mut written = opened.size as i64;
        let from_version = opened
            .version
            .as_deref()
            .is_some_and(|v| v != crate::api::versions::ORIGINAL);

        // Whiteboards may reference images stored as separate asset blobs;
        // re-inline them so the on-disk file is self-contained. Best-effort.
        if crate::whiteboard::is_excalidraw(&meta.name) {
            match crate::whiteboard::hydrate(&ctx.client, f, &file_key, &dest_path) {
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
