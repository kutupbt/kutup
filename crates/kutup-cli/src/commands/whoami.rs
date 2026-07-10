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

    println!("Username:  {}", me.username);
    println!("Email:     {}", me.email);
    println!(
        "Storage:   {} / {}",
        format_bytes(me.storage_used_bytes),
        format_bytes(me.storage_quota_bytes)
    );
    println!("Admin:     {}", me.is_admin);
    println!("2FA:       {}", me.totp_enabled);
    Ok(())
}
