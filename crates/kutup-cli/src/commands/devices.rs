//! `kutup devices` — list and revoke account devices. Mirrors `cmd/devices.go`.

use anyhow::{bail, Result};
use clap::Subcommand;

use crate::commands::prompt_line;
use crate::context::require_session;

#[derive(Subcommand)]
pub enum DevicesCmd {
    /// List devices registered for your account.
    List,
    /// Revoke a device (closes its in-flight WebSocket sessions).
    Revoke {
        /// Numeric device id.
        device_id: i64,
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
}

pub fn run(profile: &str, json: bool, cmd: &DevicesCmd) -> Result<()> {
    match cmd {
        DevicesCmd::List => list(profile, json),
        DevicesCmd::Revoke { device_id, yes } => revoke(profile, json, *device_id, *yes),
    }
}

fn list(profile: &str, json: bool) -> Result<()> {
    let ctx = require_session(profile)?;
    let devices = ctx.client.list_user_devices()?;

    if json {
        println!("{}", serde_json::to_string(&devices)?);
        return Ok(());
    }
    if devices.is_empty() {
        println!("(no devices registered)");
        return Ok(());
    }
    println!(
        "{:<12}  {:<30}  {:<25}  {:<25}  STATUS",
        "ID", "LABEL", "CREATED", "LAST SEEN"
    );
    for d in &devices {
        let last = d.last_seen_at.as_deref().unwrap_or("(never)");
        let status = if d.is_active { "active" } else { "revoked" };
        println!(
            "{:<12}  {:<30}  {:<25}  {:<25}  {}",
            d.device_id, d.label, d.created_at, last, status
        );
    }
    Ok(())
}

fn revoke(profile: &str, json: bool, device_id: i64, yes: bool) -> Result<()> {
    let ctx = require_session(profile)?;

    if !yes {
        let ans = prompt_line(&format!(
            "Revoke device {device_id}? This closes its active sessions. [y/N]: "
        ))?
        .to_lowercase();
        if ans != "y" && ans != "yes" {
            bail!("aborted");
        }
    }

    ctx.client.revoke_user_device(device_id)?;
    if json {
        println!(
            "{}",
            serde_json::json!({ "deviceId": device_id, "revoked": true })
        );
    } else {
        println!("Revoked device {device_id}");
    }
    Ok(())
}
