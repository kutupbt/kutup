//! `kutup versions` — list/download/restore/label file snapshots.
//! Mirrors `cmd/versions.go`.

use anyhow::{Context, Result};
use base64::Engine as _;
use clap::Subcommand;
use kutup_crypto::primitives::{hash, Suite};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::api::versions::{NewVersion, PatchVersionRequest};
use crate::context::require_session;
use crate::cryptohelpers::{find_file_and_key, rekey_if_behind};

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
    crate::drive_signer::load_pins(&ctx, profile);

    let found = find_file_and_key(&ctx.client, &master_key, file_id)?;
    let (row, file_key) = (&found.file, &found.file_key);
    let meta = crate::file_crypto::open_metadata(row, file_key).context("decrypt metadata")?;
    // A version opens with the file key of the generation it was saved at,
    // against its sealed content record.
    let version = ctx
        .client
        .list_versions(file_id)?
        .into_iter()
        .find(|v| v.id == version_id)
        .ok_or_else(|| {
            crate::errors::NotFound(format!("version {version_id} not found for file {file_id}"))
        })?;
    let version_key = crate::file_crypto::key_at(row, file_key, version.key_generation)?;

    let short = &version_id[..version_id.len().min(8)];
    let dest_path = {
        let p = std::path::Path::new(dest_dir);
        if p.is_dir() {
            p.join(format!("{}.v-{}", meta.name, short))
        } else {
            p.to_path_buf()
        }
    };

    // Block by block: bounded memory + a progress bar, like the main `download`.
    let bar = crate::output::progress_bar(Some(version.size_bytes.max(0) as u64), &meta.name);
    let mut out = std::fs::File::create(&dest_path).context("open dest")?;
    let written = match crate::revisions::read(
        &ctx.client,
        &crate::api::versions::ContentRoute::Version(file_id, version_id),
        &version_key,
        &row.id,
        version.key_generation,
        &crate::transfer::Expect::Revision {
            revision_id: version.id.clone(),
            envelope: version.revision_content_envelope.clone(),
        },
        &mut out,
        |n| bar.set_position(n),
    ) {
        Ok(opened) => opened.size,
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

    // download chosen version → open → seal again as a new revision → store
    // it as the newest, with the file's next metadata committing to it.
    let old = crate::revisions::read_version(&ctx.client, row, file_key, src).context("decrypt")?;
    let now = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default();
    // The same kind as the source: a note's state stays a note's state.
    let kind = if src.kind.is_empty() {
        "yjs".to_string()
    } else {
        src.kind.clone()
    };
    let whole_file = kind == "file";
    let sha256: [u8; 32] = hash(Suite::V1, &old).into();
    let res = crate::revisions::save_version(
        &ctx.client,
        &crate::revisions::Target {
            file: row,
            file_key,
        },
        &old,
        NewVersion {
            kind,
            seq_at_snapshot: src.seq_at_snapshot,
            doc_key_id: src.doc_key_id,
            label: format!("Restored from {now}"),
            keep_forever: false,
            ..Default::default()
        },
        |current, sealed, revision_id| {
            let mut next = current.clone();
            if whole_file {
                // The file's content now: its size and SHA-256 follow.
                next.content = sealed.content.clone();
                next.size = old.len() as u64;
                next.sha256 = Some(base64::engine::general_purpose::STANDARD.encode(sha256));
            } else {
                next.state_revision_id = Some(revision_id.to_string());
            }
            next
        },
    )?;
    if whole_file {
        // The version cleared the content hash: recorded again.
        match crate::names::folder_hash_key(&found.keys, &found.collection.id) {
            Ok(hash_key) => {
                crate::uploader::record_content_hash(&ctx.client, file_id, &hash_key, &sha256)
            }
            Err(e) => eprintln!("warning: the content hash was not recorded: {e:#}"),
        }
    }

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
