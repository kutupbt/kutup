//! `kutup mv` — rename a file or folder (re-encrypts the name; content
//! untouched). File rename mirrors `cmd/mv.go`; folder rename re-seals the
//! collection name under the collection key (same crypto as `mkdir`).

use crate::api::FileMetadata;
use crate::context::require_session;
use crate::cryptohelpers::{decrypt_collection_key, find_file_and_key};
use crate::errors::NotFound;
use anyhow::{bail, Context, Result};

pub fn run(profile: &str, json: bool, id: &str, new_name: &str, folder: bool) -> Result<()> {
    if folder {
        return rename_folder(profile, json, id, new_name);
    }

    let ctx = require_session(profile)?;
    let master_key = ctx.session.master_key_bytes()?;

    // Locate the file and unwrap its key, then merge the new name into the
    // existing {name, mimeType, size} metadata and re-encrypt.
    let (row, file_key) = find_file_and_key(&ctx.client, &master_key, id)?;

    let mut meta: FileMetadata =
        crate::file_crypto::open_metadata(&row, &file_key).context("decrypt existing metadata")?;
    meta.name = new_name.to_string();
    let request = crate::file_crypto::rename_request(&row, &file_key, &meta)?;
    ctx.client.update_file_metadata(id, &request)?;

    if json {
        crate::output::print_json(
            &serde_json::json!({ "id": id, "name": new_name, "type": "file" }),
        )?;
    } else {
        println!("Renamed file {id} → {new_name}");
    }
    Ok(())
}

fn rename_folder(profile: &str, json: bool, id: &str, new_name: &str) -> Result<()> {
    let ctx = require_session(profile)?;
    let master_key = ctx.session.master_key_bytes()?;

    let cols = ctx.client.list_collections()?;
    let col = cols
        .iter()
        .find(|c| c.id == id)
        .ok_or_else(|| NotFound(format!("folder {id} not found")))?;
    // The server updates only owner-scoped rows; fail with a real reason
    // instead of its opaque 404.
    if col.is_shared {
        bail!("only the owner can rename a shared folder");
    }

    let collection_key =
        decrypt_collection_key(col, &master_key, &ctx.session).context("decrypt collection key")?;
    let rename = crate::collection_crypto::rename_request(col, &collection_key, new_name)
        .context("encrypt name")?;

    ctx.client
        .rename_collection(id, &rename)
        .context("rename folder")?;

    if json {
        crate::output::print_json(
            &serde_json::json!({ "id": id, "name": new_name, "type": "folder" }),
        )?;
    } else {
        println!("Renamed folder {id} → {new_name}");
    }
    Ok(())
}
