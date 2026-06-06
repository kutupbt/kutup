//! `kutup color` — set/clear a collection's display color. Mirrors `cmd/color.go`.

use anyhow::{bail, Result};

use crate::context::require_session;

pub fn run(profile: &str, json: bool, collection_id: &str, color: &str) -> Result<()> {
    if !color.is_empty() && !is_hex_color(color) {
        bail!("color must be #rrggbb hex or empty string to clear");
    }

    let ctx = require_session(profile)?;
    ctx.client.update_collection_color(collection_id, color)?;

    if json {
        println!(
            "{}",
            serde_json::json!({ "collectionId": collection_id, "color": color })
        );
    } else if color.is_empty() {
        println!("Cleared color on {collection_id}");
    } else {
        println!("Set color of {collection_id} to {color}");
    }
    Ok(())
}

/// Matches `^#[0-9a-fA-F]{6}$`.
fn is_hex_color(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 7 && b[0] == b'#' && b[1..].iter().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::is_hex_color;

    #[test]
    fn hex() {
        assert!(is_hex_color("#ef4444"));
        assert!(is_hex_color("#ABCDEF"));
        assert!(!is_hex_color("ef4444"));
        assert!(!is_hex_color("#ef444"));
        assert!(!is_hex_color("#gggggg"));
    }
}
