//! `kutup rm` — move a file or folder to the trash. Mirrors `cmd/rm.go`.

use anyhow::{Context, Result};

use crate::commands::confirm;
use crate::context::require_session;

pub fn run(profile: &str, json: bool, id: &str, folder: bool, yes: bool) -> Result<()> {
    if folder {
        confirm(
            &format!("Move folder {id} and everything in it to the trash?"),
            yes,
        )?;
    } else {
        confirm(&format!("Move file {id} to the trash?"), yes)?;
    }

    let ctx = require_session(profile)?;

    if folder {
        ctx.client.delete_collection(id).context("delete folder")?;
        if json {
            crate::output::print_json(&serde_json::json!({ "deleted": id, "type": "folder" }))?;
        } else {
            println!("Moved folder {id} to trash");
        }
        return Ok(());
    }

    ctx.client.delete_file(id).context("delete file")?;
    if json {
        crate::output::print_json(&serde_json::json!({ "deleted": id, "type": "file" }))?;
    } else {
        println!("Moved file {id} to trash");
    }
    Ok(())
}
