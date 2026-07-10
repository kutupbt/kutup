//! `kutup devices` — list and revoke account devices. Mirrors `cmd/devices.go`.

use anyhow::Result;
use clap::Subcommand;

use crate::commands::confirm;
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
        crate::output::print_json(&devices)?;
        return Ok(());
    }
    if devices.is_empty() {
        println!("(no devices registered)");
        return Ok(());
    }
    println!(
        "{}",
        crate::output::header(format!(
            "{:<12}  {:<30}  {:<16}  {:<16}  STATUS",
            "ID", "LABEL", "CREATED", "LAST SEEN"
        ))
    );
    for d in &devices {
        let last = d
            .last_seen_at
            .as_deref()
            .map(crate::output::format_time)
            .unwrap_or_else(|| "(never)".to_string());
        let status = if d.is_active { "active" } else { "revoked" };
        println!(
            "{:<12}  {:<30}  {:<16}  {:<16}  {}",
            d.device_id,
            d.label,
            crate::output::format_time(&d.created_at),
            last,
            status
        );
    }
    Ok(())
}

fn revoke(profile: &str, json: bool, device_id: i64, yes: bool) -> Result<()> {
    let ctx = require_session(profile)?;

    confirm(
        &format!("Revoke device {device_id}? This closes its active sessions."),
        yes,
    )?;

    ctx.client.revoke_user_device(device_id)?;
    if json {
        crate::output::print_json(&serde_json::json!({ "deviceId": device_id, "revoked": true }))?;
    } else {
        println!("Revoked device {device_id}");
    }
    Ok(())
}
