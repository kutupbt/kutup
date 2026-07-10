//! `kutup whoami` — mirrors `cmd/whoami.go`.

use anyhow::Result;

use crate::context::require_session;
use crate::output::format_bytes;

pub fn run(profile: &str, json: bool) -> Result<()> {
    let ctx = require_session(profile)?;
    let me = ctx.client.me()?;

    if json {
        crate::output::print_json(&me)?;
        return Ok(());
    }

    let pct = if me.storage_quota_bytes > 0 {
        format!(
            " ({:.1}%)",
            me.storage_used_bytes as f64 * 100.0 / me.storage_quota_bytes as f64
        )
    } else {
        String::new()
    };
    println!("Username:  {}", me.username);
    println!("Email:     {}", me.email);
    println!(
        "Storage:   {} / {}{pct}",
        format_bytes(me.storage_used_bytes),
        format_bytes(me.storage_quota_bytes)
    );
    println!("Admin:     {}", me.is_admin);
    println!("2FA:       {}", me.totp_enabled);
    Ok(())
}
