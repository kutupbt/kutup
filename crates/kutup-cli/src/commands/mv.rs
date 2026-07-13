//! `kutup mv` — rename a file or folder (re-encrypts the name; content
//! untouched). File rename mirrors `cmd/mv.go`; folder rename re-seals the
//! collection name under the collection key (same crypto as `mkdir`).

use anyhow::{bail, Context, Result};
use base64::Engine;

use crate::api::{FileMetadata, RenameCollectionRequest, UpdateFileMetadataRequest};
use crate::context::require_session;
use crate::cryptohelpers::{decrypt_collection_key, find_file_and_key};
use crate::errors::NotFound;
use kutup_crypto::secretbox;

pub fn run(profile: &str, json: bool, id: &str, new_name: &str, folder: bool) -> Result<()> {
    if folder {
        return rename_folder(profile, json, id, new_name);
    }

    let b64 = base64::engine::general_purpose::STANDARD;
    let ctx = require_session(profile)?;
    let master_key = ctx.session.master_key_bytes()?;

    // Locate the file and unwrap its key, then merge the new name into the
    // existing {name, mimeType, size} metadata and re-encrypt.
    let (row, file_key) = find_file_and_key(&ctx.client, &master_key, id)?;

    let meta_bytes = secretbox::open_b64(&row.encrypted_metadata, &row.metadata_nonce, &file_key)
        .context("decrypt existing metadata")?;
    let mut meta: FileMetadata = serde_json::from_slice(&meta_bytes).unwrap_or_default();
    meta.name = new_name.to_string();

    let updated = serde_json::to_vec(&meta)?;
    let (enc_meta, meta_nonce) =
        secretbox::seal(&updated, &file_key).context("encrypt new metadata")?;

    ctx.client.update_file_metadata(
        id,
        &UpdateFileMetadataRequest {
            encrypted_metadata: b64.encode(&enc_meta),
            metadata_nonce: b64.encode(meta_nonce),
        },
    )?;

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
    let b64 = base64::engine::general_purpose::STANDARD;
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
    let (enc_name, name_nonce) =
        secretbox::seal(new_name.as_bytes(), &collection_key).context("encrypt name")?;

    ctx.client
        .rename_collection(
            id,
            &RenameCollectionRequest {
                encrypted_name: b64.encode(&enc_name),
                name_nonce: b64.encode(name_nonce),
            },
        )
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
