//! `kutup mv` — rename a file (re-encrypts metadata; content untouched).
//! Mirrors `cmd/mv.go`.

use anyhow::{Context, Result};
use base64::Engine;

use crate::api::{FileMetadata, UpdateFileMetadataRequest};
use crate::context::require_session;
use crate::cryptohelpers::find_file_and_key;
use kutup_crypto::secretbox;

pub fn run(profile: &str, json: bool, file_id: &str, new_name: &str) -> Result<()> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let ctx = require_session(profile)?;
    let master_key = ctx.session.master_key_bytes()?;

    // Locate the file and unwrap its key, then merge the new name into the
    // existing {name, mimeType, size} metadata and re-encrypt.
    let (row, file_key) = find_file_and_key(&ctx.client, &master_key, file_id)?;

    let meta_bytes = secretbox::open_b64(&row.encrypted_metadata, &row.metadata_nonce, &file_key)
        .context("decrypt existing metadata")?;
    let mut meta: FileMetadata = serde_json::from_slice(&meta_bytes).unwrap_or_default();
    meta.name = new_name.to_string();

    let updated = serde_json::to_vec(&meta)?;
    let (enc_meta, meta_nonce) =
        secretbox::seal(&updated, &file_key).context("encrypt new metadata")?;

    ctx.client.update_file_metadata(
        file_id,
        &UpdateFileMetadataRequest {
            encrypted_metadata: b64.encode(&enc_meta),
            metadata_nonce: b64.encode(meta_nonce),
        },
    )?;

    if json {
        crate::output::print_json(&serde_json::json!({ "id": file_id, "name": new_name }))?;
    } else {
        println!("Renamed file {file_id} → {new_name}");
    }
    Ok(())
}
