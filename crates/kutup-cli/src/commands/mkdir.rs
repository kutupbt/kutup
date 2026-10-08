//! `kutup mkdir` — mirrors `cmd/mkdir.go`.

use crate::context::require_session;
use anyhow::{Context, Result};

pub fn run(profile: &str, json: bool, name: &str, parent: Option<&str>) -> Result<()> {
    let ctx = require_session(profile)?;
    let master_key = ctx.session.master_key_bytes()?;
    let parent = parent.filter(|p| !p.is_empty());
    let (mut req, _) = crate::collection_crypto::create_owned(
        name,
        parent.map(String::from),
        &ctx.session.user_id,
        &master_key,
    )
    .context("encrypt collection")?;
    // Its name's hash in its place: the parent's hash key, or the account's
    // for a top-level folder (docs/plans/drive-unique-names.md).
    let hash_key = match parent {
        Some(parent) => {
            let cols = ctx.client.list_collections()?;
            let col = cols
                .iter()
                .find(|c| c.id == parent)
                .ok_or_else(|| crate::errors::NotFound(format!("folder {parent} not found")))?;
            let keys =
                crate::cryptohelpers::folder_keyring(&ctx.client, col, &master_key, &ctx.session)?;
            crate::names::folder_hash_key(&keys, &col.id)?
        }
        None => crate::names::top_level_hash_key(&master_key)?,
    };
    req.name_hash = Some(crate::names::name_hash(&hash_key, name)?);

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
