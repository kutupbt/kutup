//! `kutup ls` — mirrors `cmd/ls.go`.

use anyhow::Result;
use serde::Serialize;

use crate::api::Collection;
use crate::context::require_session;
use crate::cryptohelpers::{
    decrypt_collection_key, decrypt_collections, decrypt_file_meta, find_collection,
};
use crate::output::{format_bytes, format_time};

#[derive(Serialize)]
struct LsEntry {
    id: String,
    #[serde(rename = "type")]
    entry_type: String,
    name: String,
    #[serde(skip_serializing_if = "is_zero")]
    size: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    created: String,
    #[serde(rename = "parentId", skip_serializing_if = "Option::is_none")]
    parent: Option<String>,
    #[serde(skip_serializing_if = "is_false")]
    shared: bool,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}
fn is_false(v: &bool) -> bool {
    !*v
}

pub fn run(profile: &str, json: bool, tree: bool, folder_id: Option<&str>) -> Result<()> {
    let ctx = require_session(profile)?;
    let master_key = ctx.session.master_key_bytes()?;

    let cols = ctx.client.list_collections()?;
    let cols = decrypt_collections(cols, &master_key, &ctx.session);

    let filter_parent = folder_id.map(|s| s.to_string());

    if tree && filter_parent.is_none() {
        print_col_tree(&cols, "", 0);
        return Ok(());
    }

    let mut entries: Vec<LsEntry> = Vec::new();
    for col in &cols {
        let keep = match &filter_parent {
            None => col.parent_collection_id.is_none(),
            Some(parent) => col.parent_collection_id.as_deref() == Some(parent.as_str()),
        };
        if !keep {
            continue;
        }
        entries.push(LsEntry {
            id: col.id.clone(),
            entry_type: "folder".into(),
            name: col.name.clone(),
            size: 0,
            created: String::new(),
            parent: col.parent_collection_id.clone(),
            shared: col.is_shared,
        });
    }

    if let Some(parent) = &filter_parent {
        if let Some(col) = find_collection(&cols, parent) {
            if let Ok(col_key) = decrypt_collection_key(col, &master_key, &ctx.session) {
                let files = ctx.client.list_files(&col.id).unwrap_or_default();
                for f in &files {
                    let (name, size) = decrypt_file_meta(f, &col_key);
                    entries.push(LsEntry {
                        id: f.id.clone(),
                        entry_type: "file".into(),
                        name,
                        size,
                        created: format_time(&f.created_at),
                        parent: None,
                        shared: false,
                    });
                }
            }
        }
    }

    if json {
        crate::output::print_json(&entries)?;
        return Ok(());
    }

    for e in &entries {
        if e.entry_type == "folder" {
            let shared = if e.shared { " [shared]" } else { "" };
            println!("📁  {:<38}  {}{}", e.name, e.id, shared);
        } else {
            println!(
                "    {:<38}  {}  {}  {}",
                e.name,
                e.id,
                format_bytes(e.size),
                e.created
            );
        }
    }
    Ok(())
}

fn print_col_tree(cols: &[Collection], parent_id: &str, depth: usize) {
    let prefix = "  ".repeat(depth);
    for col in cols {
        let p_id = col.parent_collection_id.as_deref().unwrap_or("");
        if p_id != parent_id {
            continue;
        }
        println!("{prefix}📁  {}  ({})", col.name, col.id);
        print_col_tree(cols, &col.id, depth + 1);
    }
}
