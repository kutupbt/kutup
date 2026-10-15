//! `kutup trash` — list, restore, and permanently delete trashed items.
//!
//! Trash is owner-scoped: every wrapped key in the listing is an authenticated
//! owner envelope, so decryption here does not need named-share handling.

use anyhow::{Context, Result};
use clap::Subcommand;
use serde::Serialize;

use crate::api::trash::{RestoreRequest, TrashFile, TrashFolder};
use crate::api::{ApiError, FileMetadata};
use crate::commands::confirm;
use crate::context::require_session;
use crate::cryptohelpers::decrypt_collection_key;
use crate::errors::NotFound;
use crate::keyring::Keyring;
use crate::output::{format_bytes, format_time, header, print_json};
use crate::session::Session;

#[derive(Subcommand)]
pub enum TrashCmd {
    /// List trashed items (newest first).
    Ls,
    /// Restore a trashed item to where it was. When its name is taken there
    /// now (or a folder comes back at the top level, its parent gone), it
    /// comes back under the first free numbered name, or `--name`.
    Restore {
        /// Trashed file or folder id.
        id: String,
        /// The name to restore it under.
        #[arg(long)]
        name: Option<String>,
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
        TrashCmd::Restore { id, name } => restore(profile, json, id, name.as_deref()),
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
fn folder_name(f: &TrashFolder, master_key: &[u8], session: &Session) -> String {
    let inner = || -> Result<String> {
        let collection = folder_collection(f);
        let col_key = crate::collection_crypto::open_key(&collection, master_key, session)?;
        crate::collection_crypto::open_name(&collection, &col_key)
    };
    inner().unwrap_or_else(|_| "[encrypted]".to_string())
}

/// A trashed folder as the collection record it is.
fn folder_collection(f: &TrashFolder) -> crate::api::Collection {
    crate::api::Collection {
        name_hash: None,
        id: f.id.clone(),
        owner_user_id: f.owner_user_id.clone(),
        name_envelope: f.name_envelope.clone(),
        owner_key_envelope: Some(f.owner_key_envelope.clone()),
        named_share_envelope: None,
        key_epoch: f.key_epoch,
        name_revision: f.name_revision,
        epoch_statement: f.epoch_statement.clone(),
        epoch_statement_hash: f.epoch_statement_hash.clone(),
        owner_server: None,
        owner_account: None,
        owner_incarnation_id: None,
        owner_drive_signing_public_key: None,
        owner_authority_public_key: None,
        parent_collection_id: f.parent_collection_id.clone(),
        color: f.color.clone(),
        is_shared: false,
        is_remote: false,
        can_upload: false,
        can_delete: false,
        upload_quota_bytes: None,
        name: String::new(),
    }
}

/// master key → row-level collection key wrap → file key → metadata.
fn file_meta(
    client: &crate::api::Client,
    f: &TrashFile,
    master_key: &[u8],
    session: &Session,
) -> (String, Option<i64>) {
    let inner = || -> Result<FileMetadata> {
        let collection = crate::api::Collection {
            name_hash: None,
            id: f.collection_id.clone(),
            owner_user_id: f.collection_owner_user_id.clone(),
            name_envelope: String::new(),
            owner_key_envelope: Some(f.collection_owner_key_envelope.clone()),
            named_share_envelope: None,
            key_epoch: f.collection_key_epoch,
            name_revision: 1,
            epoch_statement: f.collection_epoch_statement.clone(),
            epoch_statement_hash: f.collection_epoch_statement_hash.clone(),
            owner_server: None,
            owner_account: None,
            owner_incarnation_id: None,
            owner_drive_signing_public_key: None,
            owner_authority_public_key: None,
            parent_collection_id: None,
            color: None,
            is_shared: false,
            is_remote: false,
            can_upload: false,
            can_delete: false,
            upload_quota_bytes: None,
            name: String::new(),
        };
        let col_key = crate::collection_crypto::open_key(&collection, master_key, session)?;
        let file = trashed_file(f);
        // Older keys only if the file predates the folder's last rotation.
        let keys = if f.key_epoch == f.collection_key_epoch {
            crate::keyring::Keyring::current_only(&col_key, f.collection_key_epoch)
        } else {
            crate::keyring::Keyring::load(client, &collection, &col_key, master_key)?
        };
        let (_, metadata) = crate::file_crypto::open(&file, &keys)?;
        Ok(metadata)
    };
    match inner() {
        Ok(meta) => (meta.name, Some(meta.size as i64)),
        Err(_) => ("[encrypted]".to_string(), None),
    }
}

/// A trashed file as the file record it is.
fn trashed_file(f: &TrashFile) -> crate::api::File {
    crate::api::File {
        content_hash: None,
        name_hash: None,
        id: f.id.clone(),
        collection_id: f.collection_id.clone(),
        metadata_envelope: f.metadata_envelope.clone(),
        file_key_envelope: f.file_key_envelope.clone(),
        key_epoch: f.key_epoch,
        key_generation: f.key_generation,
        metadata_revision: f.metadata_revision,
        encrypted_size_bytes: 0,
        created_at: String::new(),
        // Only the name is read here: no content, no older keys.
        content_key_generation: f.key_generation,
        original_key_generation: f.key_generation,
        key_history: Vec::new(),
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
            name: folder_name(f, &master_key, &ctx.session),
            deleted_at: f.deleted_at.clone(),
            size: None,
            items: Some(f.items),
            color: f.color.clone(),
        });
    }
    for f in &trash.files {
        let (name, size) = file_meta(&ctx.client, f, &master_key, &ctx.session);
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

fn restore(profile: &str, json: bool, id: &str, name: Option<&str>) -> Result<()> {
    let ctx = require_session(profile)?;
    let renamed = match name {
        Some(name) => Some(restore_renamed(&ctx, id, Some(name))?),
        None => match ctx.client.restore_trash(id, None) {
            Ok(()) => None,
            Err(err) => {
                let needs_name = err
                    .downcast_ref::<ApiError>()
                    .filter(|e| e.status == 409)
                    .and_then(|e| e.code.as_deref())
                    .filter(|code| matches!(*code, "name_taken" | "nameNeeded"))
                    .is_some();
                if !needs_name {
                    // The server 409s a file whose parent folder is itself still trashed.
                    return Err(match err.downcast_ref::<ApiError>() {
                        Some(e) if e.status == 409 => err
                            .context("restore the parent folder first (it is still in the trash)"),
                        _ => err.context("restore"),
                    });
                }
                Some(restore_renamed(&ctx, id, None)?)
            }
        },
    };
    if json {
        print_json(&serde_json::json!({ "id": id, "restored": true, "name": renamed }))?;
    } else if let Some(name) = renamed {
        println!("Restored {id} as {name:?} (its name is taken there)");
    } else {
        println!("Restored {id}");
    }
    Ok(())
}

/// Restores `id` under `wanted`, or the first numbered name free where it
/// lands. Returns the name it came back under
/// (docs/plans/drive-unique-names.md).
fn restore_renamed(ctx: &crate::context::Ctx, id: &str, wanted: Option<&str>) -> Result<String> {
    let master_key = ctx.session.master_key_bytes()?;
    let trash = ctx.client.list_trash()?;
    let cols = ctx.client.list_collections()?;
    if let Some(f) = trash.files.iter().find(|f| f.id == id) {
        let col = cols
            .iter()
            .find(|c| c.id == f.collection_id)
            .context("restore the parent folder first (it is still in the trash)")?;
        let col_key = decrypt_collection_key(col, &master_key, &ctx.session)?;
        let keys = Keyring::load(&ctx.client, col, &col_key, &master_key)?;
        let hash_key = crate::names::folder_hash_key(&keys, &col.id)?;
        let file = trashed_file(f);
        let (file_key, mut meta) = crate::file_crypto::open(&file, &keys)?;
        let (name, hash) = pick_name(ctx, Some(&col.id), &hash_key, &meta.name, wanted)?;
        meta.name = name.clone();
        let sealed = crate::file_crypto::rename_request(&file, &file_key, &meta)?;
        ctx.client.restore_trash(
            id,
            Some(&RestoreRequest {
                name_hash: hash,
                metadata_envelope: Some(sealed.metadata_envelope),
                metadata_revision: Some(sealed.metadata_revision),
                ..Default::default()
            }),
        )?;
        return Ok(name);
    }
    let f = trash
        .folders
        .iter()
        .find(|f| f.id == id)
        .ok_or_else(|| NotFound(format!("{id} is not in the trash")))?;
    let collection = folder_collection(f);
    let col_key = crate::collection_crypto::open_key(&collection, &master_key, &ctx.session)?;
    let own = crate::collection_crypto::open_name(&collection, &col_key)?;
    // Where it lands, as the trash listing says.
    let place = f.parent_collection_id.clone();
    let hash_key = match &place {
        Some(parent) => {
            let parent = cols
                .iter()
                .find(|c| &c.id == parent)
                .context("the folder it goes back to is not listed")?;
            let key = decrypt_collection_key(parent, &master_key, &ctx.session)?;
            let keys = Keyring::load(&ctx.client, parent, &key, &master_key)?;
            crate::names::folder_hash_key(&keys, &parent.id)?
        }
        None => crate::names::top_level_hash_key(&master_key)?,
    };
    let (name, hash) = pick_name(ctx, place.as_deref(), &hash_key, &own, wanted)?;
    let sealed = crate::collection_crypto::rename_request(&collection, &col_key, &name)?;
    ctx.client.restore_trash(
        id,
        Some(&RestoreRequest {
            name_hash: hash,
            name_envelope: Some(sealed.name_envelope),
            name_revision: Some(sealed.name_revision),
            ..Default::default()
        }),
    )?;
    Ok(name)
}

/// `wanted` with its hash, or the first numbered name after `own` that is
/// free in the place.
fn pick_name(
    ctx: &crate::context::Ctx,
    place: Option<&str>,
    hash_key: &[u8; 32],
    own: &str,
    wanted: Option<&str>,
) -> Result<(String, String)> {
    match wanted {
        Some(name) => Ok((name.to_string(), crate::names::name_hash(hash_key, name)?)),
        None => crate::names::first_available(
            &ctx.client,
            place,
            hash_key,
            crate::names::numbered_names(own),
            |_| false,
        ),
    }
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
