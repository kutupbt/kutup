//! `kutup devices` — list and revoke account devices. Mirrors `cmd/devices.go`.

use anyhow::Result;
use base64::Engine;
use clap::Subcommand;
use kutup_crypto::device_registration;

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
        let status = if !d.is_active {
            "revoked"
        } else if d.trusted {
            "active"
        } else {
            "untrusted"
        };
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

    // Revoking is the account's act: its authority signs the revocation, so
    // a session alone cannot revoke devices (docs/plans/device-registration.md).
    if ctx.session.master_key.is_empty() {
        return Err(anyhow::anyhow!(
            "this session holds no account keys; sign in again to revoke a device"
        ));
    }
    let device = ctx
        .client
        .list_user_devices()?
        .into_iter()
        .find(|d| d.device_id == device_id && d.is_active)
        .ok_or_else(|| anyhow::anyhow!("no active device {device_id}"))?;
    let key: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(&device.public_signing)
        .ok()
        .and_then(|k| k.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("the server sent a malformed device key"))?;
    let me = crate::identity::Me::of(&ctx, profile)?;
    let server = ctx.client.settings()?.chat.server_name;
    let revoked_at_ms = (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64;
    let signature =
        device_registration::sign_revocation(&me.identity, &server, &key, revoked_at_ms)?;
    ctx.client
        .revoke_user_device(device_id, revoked_at_ms, &signature)?;
    if json {
        crate::output::print_json(&serde_json::json!({ "deviceId": device_id, "revoked": true }))?;
    } else {
        println!("Revoked device {device_id}");
    }
    Ok(())
}
