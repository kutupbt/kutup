//! `kutup rm` — delete a file or folder. Mirrors `cmd/rm.go`.

use anyhow::{Context, Result};

use crate::context::require_session;

pub fn run(profile: &str, json: bool, id: &str, folder: bool) -> Result<()> {
    let ctx = require_session(profile)?;

    if folder {
        ctx.client.delete_collection(id).context("delete folder")?;
        if json {
            println!("{}", serde_json::json!({ "deleted": id, "type": "folder" }));
        } else {
            println!("Deleted folder {id}");
        }
        return Ok(());
    }

    ctx.client.delete_file(id).context("delete file")?;
    if json {
        println!("{}", serde_json::json!({ "deleted": id, "type": "file" }));
    } else {
        println!("Deleted file {id}");
    }
    Ok(())
}
