//! `kutup versions` — list/download/restore/label file snapshots.
//! Mirrors `cmd/versions.go`.

use anyhow::{Context, Result};
use clap::Subcommand;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::api::versions::{NewVersion, PatchVersionRequest};
use crate::context::require_session;
use crate::cryptohelpers::{find_file_and_key, rekey_if_behind};
use kutup_crypto::drive_object::{self, DriveFileBlobContextV1};

#[derive(Subcommand)]
pub enum VersionsCmd {
    /// List snapshot versions of a file (newest first).
    List { file_id: String },
    /// Download a specific snapshot version.
    Download {
        file_id: String,
        version_id: String,
        dest: Option<String>,
    },
    /// Restore a snapshot as the latest version (creates a new snapshot).
    Restore { file_id: String, version_id: String },
    /// Set a label on a version (optionally pin it via --keep-forever).
    Label {
        file_id: String,
        version_id: String,
        label: String,
        #[arg(long)]
        keep_forever: bool,
    },
}

pub fn run(profile: &str, json: bool, cmd: &VersionsCmd) -> Result<()> {
    match cmd {
        VersionsCmd::List { file_id } => list(profile, json, file_id),
        VersionsCmd::Download {
            file_id,
            version_id,
            dest,
        } => download(profile, json, file_id, version_id, dest.as_deref()),
        VersionsCmd::Restore {
            file_id,
            version_id,
        } => restore(profile, json, file_id, version_id),
        VersionsCmd::Label {
            file_id,
            version_id,
            label,
            keep_forever,
        } => set_label(profile, json, file_id, version_id, label, *keep_forever),
    }
}

fn list(profile: &str, json: bool, file_id: &str) -> Result<()> {
    let ctx = require_session(profile)?;
    let versions = ctx.client.list_versions(file_id)?;

    if json {
        crate::output::print_json(&versions)?;
        return Ok(());
    }
    if versions.is_empty() {
        println!("(no snapshot versions for this file)");
        return Ok(());
    }
    println!(
        "{}",
        crate::output::header(format!(
            "{:<36}  {:<16}  {:>10}  PIN  LABEL",
            "ID", "CREATED", "SIZE"
        ))
    );
    for v in &versions {
        let pin = if v.keep_forever { "★" } else { " " };
        let label = v.label.as_deref().unwrap_or("");
        println!(
            "{:<36}  {:<16}  {:>10}  {}    {}",
            v.id,
            crate::output::format_time(&v.created_at),
            crate::output::format_bytes(v.size_bytes),
            pin,
            label
        );
    }
    Ok(())
}

fn download(
    profile: &str,
    json: bool,
    file_id: &str,
    version_id: &str,
    dest: Option<&str>,
) -> Result<()> {
    let dest_dir = dest.unwrap_or(".");
    let ctx = require_session(profile)?;
    let master_key = ctx.session.master_key_bytes()?;

    let found = find_file_and_key(&ctx.client, &master_key, file_id)?;
    let (row, file_key) = (&found.file, &found.file_key);
    let meta = crate::file_crypto::open_metadata(row, file_key).context("decrypt metadata")?;
    // A version opens with the file key of the generation it was saved at.
    let generation = ctx
        .client
        .list_versions(file_id)?
        .into_iter()
        .find(|v| v.id == version_id)
        .map(|v| v.key_generation)
        .ok_or_else(|| {
            crate::errors::NotFound(format!("version {version_id} not found for file {file_id}"))
        })?;
    let version_key = crate::file_crypto::key_at(row, file_key, generation)?;

    let short = &version_id[..version_id.len().min(8)];
    let dest_path = {
        let p = std::path::Path::new(dest_dir);
        if p.is_dir() {
            p.join(format!("{}.v-{}", meta.name, short))
        } else {
            p.to_path_buf()
        }
    };

    // Stream: bounded memory + a progress bar, like the main `download`.
    let stream = ctx.client.download_version_stream(file_id, version_id)?;
    let bar = crate::output::progress_bar(stream.content_length(), &meta.name);
    let mut out = std::fs::File::create(&dest_path).context("open dest")?;
    let blob_context = DriveFileBlobContextV1::new(&row.id, generation)?;
    let written =
        match crate::transfer::stream_download(stream, &version_key, blob_context, &mut out, |n| {
            bar.set_position(n as u64)
        }) {
            Ok(w) => w,
            Err(e) => {
                drop(out);
                let _ = std::fs::remove_file(&dest_path);
                return Err(e).context("decrypt-write");
            }
        };
    bar.finish_and_clear();

    let dest_str = dest_path.to_string_lossy().into_owned();
    if json {
        crate::output::print_json(
            &serde_json::json!({ "fileId": file_id, "versionId": version_id, "size": written, "dest": dest_str }),
        )?;
    } else {
        println!("Downloaded version {short} of {} → {dest_str}", meta.name);
    }
    Ok(())
}

fn restore(profile: &str, json: bool, file_id: &str, version_id: &str) -> Result<()> {
    let ctx = require_session(profile)?;
    let master_key = ctx.session.master_key_bytes()?;
    // The restored copy is new content: under a file key the folder's
    // current members alone hold.
    let found = rekey_if_behind(
        &ctx.client,
        find_file_and_key(&ctx.client, &master_key, file_id)?,
    )?;
    let (row, file_key) = (&found.file, &found.file_key);
    let blob_context = DriveFileBlobContextV1::new(&row.id, row.key_generation)?;

    // The restored row carries the SOURCE version's collab metadata: those
    // values become the served x-kutup-seq / x-kutup-doc-key-id headers, and
    // the live-collab values the web client would use are unknowable offline.
    // The update log was already truncated to that seq when the source was
    // recorded, so this is truncation-safe.
    let versions = ctx.client.list_versions(file_id)?;
    let src = versions
        .iter()
        .find(|v| v.id == version_id)
        .ok_or_else(|| {
            crate::errors::NotFound(format!("version {version_id} not found for file {file_id}"))
        })?;

    // download chosen version → decrypt → re-encrypt → store as the newest.
    let encrypted = ctx.client.download_version(file_id, version_id)?;
    // The source opens with the file key of the generation it was saved at.
    let old = drive_object::decrypt_file_blob(
        &encrypted,
        &crate::file_crypto::key_at(row, file_key, src.key_generation)?,
        DriveFileBlobContextV1::new(&row.id, src.key_generation)?,
    )
    .context("decrypt")?;
    let re_encrypted =
        drive_object::encrypt_file_blob(&old, file_key, blob_context).context("re-encrypt")?;
    let now = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default();
    let res = ctx.client.create_version(
        file_id,
        re_encrypted,
        &NewVersion {
            // The same kind as the source: a note's state stays a note's state.
            kind: if src.kind.is_empty() {
                "yjs".into()
            } else {
                src.kind.clone()
            },
            seq_at_snapshot: src.seq_at_snapshot,
            doc_key_id: src.doc_key_id,
            label: format!("Restored from {now}"),
            keep_forever: false,
        },
    )?;

    let short = &version_id[..version_id.len().min(8)];
    if json {
        crate::output::print_json(
            &serde_json::json!({ "fileId": file_id, "newVersionId": res.id, "restoredFrom": version_id }),
        )?;
    } else {
        println!(
            "Restored: file={file_id} new-version={} (from {short})",
            res.id
        );
    }
    Ok(())
}

fn set_label(
    profile: &str,
    json: bool,
    file_id: &str,
    version_id: &str,
    label: &str,
    keep_forever: bool,
) -> Result<()> {
    let ctx = require_session(profile)?;
    let patch = PatchVersionRequest {
        label: Some(label.to_string()),
        keep_forever: if keep_forever { Some(true) } else { None },
    };
    let row = ctx.client.patch_version(file_id, version_id, &patch)?;

    if json {
        crate::output::print_json(&row)?;
    } else {
        let short = &version_id[..version_id.len().min(8)];
        println!("Labeled version {short} of file {file_id}");
    }
    Ok(())
}
