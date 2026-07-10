//! `kutup trash` — list, restore, and permanently delete trashed items.
//!
//! Trash is owner-scoped: every wrapped key in the listing is the owner's
//! master-key secretbox wrap (never a sealed box), so decryption here doesn't
//! need the shared-collection branch of `cryptohelpers`.

use anyhow::Result;
use clap::Subcommand;
use serde::Serialize;

use crate::api::trash::{TrashFile, TrashFolder};
use crate::api::{ApiError, FileMetadata};
use crate::commands::confirm;
use crate::context::require_session;
use crate::output::{format_bytes, format_time, header, print_json};
use kutup_crypto::secretbox;

#[derive(Subcommand)]
pub enum TrashCmd {
    /// List trashed items (newest first).
    Ls,
    /// Restore a trashed item to where it was.
    Restore {
        /// Trashed file or folder id.
        id: String,
    },
    /// Permanently delete one trashed item. Irreversible.
    Rm {
        /// Trashed file or folder id.
        id: String,
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// Permanently delete everything in the trash. Irreversible.
    Empty {
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
}

pub fn run(profile: &str, json: bool, cmd: &TrashCmd) -> Result<()> {
    match cmd {
        TrashCmd::Ls => ls(profile, json),
        TrashCmd::Restore { id } => restore(profile, json, id),
        TrashCmd::Rm { id, yes } => rm(profile, json, id, *yes),
        TrashCmd::Empty { yes } => empty(profile, json, *yes),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TrashEntry {
    id: String,
    #[serde(rename = "type")]
    entry_type: &'static str,
    name: String,
    deleted_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    items: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    color: Option<String>,
}

/// master key → folder's own collection key → name. `[encrypted]` on failure
/// so one bad row never aborts the listing.
fn folder_name(f: &TrashFolder, master_key: &[u8]) -> String {
    let inner = || -> Result<String> {
        let col_key = secretbox::open_b64(&f.encrypted_key, &f.encrypted_key_nonce, master_key)?;
        let name = secretbox::open_b64(&f.encrypted_name, &f.name_nonce, &col_key)?;
        Ok(String::from_utf8_lossy(&name).into_owned())
    };
    inner().unwrap_or_else(|_| "[encrypted]".to_string())
}

/// master key → row-level collection key wrap → file key → metadata.
fn file_meta(f: &TrashFile, master_key: &[u8]) -> (String, Option<i64>) {
    let inner = || -> Result<FileMetadata> {
        let col_key = secretbox::open_b64(
            &f.collection_encrypted_key,
            &f.collection_encrypted_key_nonce,
            master_key,
        )?;
        let file_key = secretbox::open_b64(&f.encrypted_file_key, &f.file_key_nonce, &col_key)?;
        let meta_bytes = secretbox::open_b64(&f.encrypted_metadata, &f.metadata_nonce, &file_key)?;
        Ok(serde_json::from_slice(&meta_bytes)?)
    };
    match inner() {
        Ok(meta) => (meta.name, Some(meta.size)),
        Err(_) => ("[encrypted]".to_string(), None),
    }
}

fn ls(profile: &str, json: bool) -> Result<()> {
    let ctx = require_session(profile)?;
    let master_key = ctx.session.master_key_bytes()?;
    let trash = ctx.client.list_trash()?;

    let mut entries: Vec<TrashEntry> = Vec::new();
    for f in &trash.folders {
        entries.push(TrashEntry {
            id: f.id.clone(),
            entry_type: "folder",
            name: folder_name(f, &master_key),
            deleted_at: f.deleted_at.clone(),
            size: None,
            items: Some(f.items),
            color: f.color.clone(),
        });
    }
    for f in &trash.files {
        let (name, size) = file_meta(f, &master_key);
        entries.push(TrashEntry {
            id: f.id.clone(),
            entry_type: "file",
            name,
            deleted_at: f.deleted_at.clone(),
            size,
            items: None,
            color: None,
        });
    }
    // Newest first across both kinds (RFC3339 sorts lexicographically).
    entries.sort_by(|a, b| b.deleted_at.cmp(&a.deleted_at));

    if json {
        return print_json(&entries);
    }
    if entries.is_empty() {
        println!("(trash is empty)");
        return Ok(());
    }
    println!(
        "{}",
        header(format!(
            "{:<36}  {:<6}  {:<16}  {:>10}  NAME",
            "ID", "TYPE", "DELETED", "SIZE"
        ))
    );
    for e in &entries {
        let size = match (e.size, e.items) {
            (Some(s), _) => format_bytes(s),
            (None, Some(n)) => format!("{n} items"),
            (None, None) => "-".to_string(),
        };
        println!(
            "{:<36}  {:<6}  {:<16}  {:>10}  {}",
            e.id,
            e.entry_type,
            format_time(&e.deleted_at),
            size,
            e.name
        );
    }
    Ok(())
}

fn restore(profile: &str, json: bool, id: &str) -> Result<()> {
    let ctx = require_session(profile)?;
    ctx.client.restore_trash(id).map_err(|err| {
        // The server 409s a file whose parent folder is itself still trashed.
        match err.downcast_ref::<ApiError>() {
            Some(e) if e.status == 409 => {
                err.context("restore the parent folder first (it is still in the trash)")
            }
            _ => err.context("restore"),
        }
    })?;
    if json {
        print_json(&serde_json::json!({ "id": id, "restored": true }))?;
    } else {
        println!("Restored {id}");
    }
    Ok(())
}

fn rm(profile: &str, json: bool, id: &str, yes: bool) -> Result<()> {
    confirm(
        &format!("Permanently delete trashed item {id}? This cannot be undone."),
        yes,
    )?;
    let ctx = require_session(profile)?;
    ctx.client.purge_trash(id)?;
    if json {
        print_json(&serde_json::json!({ "id": id, "purged": true }))?;
    } else {
        println!("Permanently deleted {id}");
    }
    Ok(())
}

fn empty(profile: &str, json: bool, yes: bool) -> Result<()> {
    confirm(
        "Permanently delete EVERYTHING in the trash? This cannot be undone.",
        yes,
    )?;
    let ctx = require_session(profile)?;
    ctx.client.empty_trash()?;
    if json {
        print_json(&serde_json::json!({ "emptied": true }))?;
    } else {
        println!("Trash emptied.");
    }
    Ok(())
}
