//! `kutup upload` — encrypt and stream-upload a file or directory via tus,
//! resuming interrupted uploads automatically (see `crate::uploader`).
//! Whiteboards (`.excalidraw`) additionally get their embedded images
//! extracted as encrypted asset blobs (see `crate::whiteboard`).

use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::api::Client;
use crate::context::require_session;
use crate::cryptohelpers::{decrypt_collection_key, decrypt_collections, find_collection};
use crate::session::Store;
use crate::uploader::{
    self, create_sub_collection, file_name, now_unix, upload_streaming, Progress,
    RESUME_MAX_IDLE_SECS,
};

pub fn run(
    profile: &str,
    json: bool,
    local_path: &str,
    collection_id: &str,
    recursive: bool,
    no_resume: bool,
) -> Result<()> {
    let ctx = require_session(profile)?;
    let master_key = ctx.session.master_key_bytes()?;

    // Sweep resume records the server has certainly reaped by now, and
    // best-effort abort their sessions.
    if let Ok(stale) = ctx.store.sweep_resume(RESUME_MAX_IDLE_SECS, now_unix()) {
        for (_, rec) in &stale {
            if !rec.upload_id.is_empty() {
                let _ = ctx.client.tus_delete(&rec.upload_id);
            }
        }
    }

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
            &ctx.store,
            Path::new(local_path),
            collection_id,
            &master_key,
            no_resume,
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

    let up = upload_streaming(
        &ctx.client,
        &ctx.store,
        Path::new(local_path),
        collection_id,
        &collection_key,
        !no_resume,
        Progress::Bar,
    )?;
    extract_whiteboard_assets(
        &ctx.client,
        &up,
        &collection_key,
        Path::new(local_path),
        &mut Vec::new(),
    );

    let name = file_name(local_path);
    if json {
        crate::output::print_json(&serde_json::json!({ "id": up.file_id, "name": name }))?;
    } else {
        println!("Uploaded {name}  id={}", up.file_id);
    }
    Ok(())
}

/// Accumulates a recursive upload's results for the summary / `--json` doc.
#[derive(Default)]
struct DirUpload {
    uploaded: Vec<serde_json::Value>,
    warnings: Vec<String>,
}

/// Best-effort whiteboard asset extraction after a successful upload — a
/// failure here never fails the main transfer.
fn extract_whiteboard_assets(
    client: &Client,
    up: &crate::uploader::Uploaded,
    collection_key: &[u8],
    path: &Path,
    warnings: &mut Vec<String>,
) {
    if !crate::whiteboard::is_excalidraw(&path.to_string_lossy()) {
        return;
    }
    if let Err(e) = crate::whiteboard::extract_and_upload(
        client,
        &up.file_id,
        &up.file_key,
        collection_key,
        path,
    ) {
        let w = format!("asset extraction {}: {e:#}", path.display());
        eprintln!("warning: {w}");
        warnings.push(w);
    }
}

/// Recursively uploads a directory, creating sub-collections as needed.
#[allow(clippy::too_many_arguments)]
fn upload_dir(
    client: &Client,
    store: &Store,
    dir: &Path,
    parent_col_id: &str,
    master_key: &[u8],
    no_resume: bool,
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
            if let Err(e) = upload_dir(
                client,
                store,
                &path,
                &sub_col_id,
                master_key,
                no_resume,
                stats,
            ) {
                let w = format!("{e:#}");
                eprintln!("warning: {w}");
                stats.warnings.push(w);
            }
        } else {
            match uploader::upload_streaming(
                client,
                store,
                &path,
                &sub_col_id,
                &sub_col_key,
                !no_resume,
                Progress::Bar,
            ) {
                Ok(up) => {
                    eprintln!("  ↑ {}", path.display());
                    extract_whiteboard_assets(
                        client,
                        &up,
                        &sub_col_key,
                        &path,
                        &mut stats.warnings,
                    );
                    stats.uploaded.push(serde_json::json!({
                        "id": up.file_id,
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
