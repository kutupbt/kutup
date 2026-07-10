//! `kutup mkdir` — mirrors `cmd/mkdir.go`.

use anyhow::{Context, Result};
use base64::Engine;
use rand::RngCore;

use crate::api::CreateCollectionRequest;
use crate::context::require_session;
use kutup_crypto::secretbox;

pub fn run(profile: &str, json: bool, name: &str, parent: Option<&str>) -> Result<()> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let ctx = require_session(profile)?;
    let master_key = ctx.session.master_key_bytes()?;

    // New random 32-byte collection key (mirrors crypto.NewStreamKey).
    let mut collection_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut collection_key);

    // Wrap the collection key under the master key, and the name under it.
    let (enc_key, key_nonce) =
        secretbox::seal(&collection_key, &master_key).context("encrypt collection key")?;
    let (enc_name, name_nonce) =
        secretbox::seal(name.as_bytes(), &collection_key).context("encrypt name")?;

    let req = CreateCollectionRequest {
        encrypted_name: b64.encode(&enc_name),
        name_nonce: b64.encode(name_nonce),
        encrypted_key: b64.encode(&enc_key),
        encrypted_key_nonce: b64.encode(key_nonce),
        parent_collection_id: parent.filter(|p| !p.is_empty()).map(String::from),
    };

    let resp = ctx
        .client
        .create_collection(&req)
        .context("create folder")?;

    if json {
        crate::output::print_json(&serde_json::json!({ "id": resp.id, "name": name }))?;
    } else {
        println!("Created folder {name:?}  id={}", resp.id);
    }
    Ok(())
}
