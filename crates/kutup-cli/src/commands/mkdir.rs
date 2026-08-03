//! `kutup mkdir` — mirrors `cmd/mkdir.go`.

use crate::context::require_session;
use anyhow::{Context, Result};

pub fn run(profile: &str, json: bool, name: &str, parent: Option<&str>) -> Result<()> {
    let ctx = require_session(profile)?;
    let master_key = ctx.session.master_key_bytes()?;
    let (req, _) = crate::collection_crypto::create_owned(
        name,
        parent.filter(|p| !p.is_empty()).map(String::from),
        &ctx.session.user_id,
        &master_key,
    )
    .context("encrypt collection")?;

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
