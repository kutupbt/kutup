//! `kutup devices` — the account's devices (docs/plans/one-device-list.md):
//! list them, and remove one. Removing is the account's act: its authority
//! signs the next manifest without the device, so a session alone cannot.

use anyhow::{anyhow, Result};
use clap::Subcommand;

use crate::collab_device::Signer;
use crate::commands::confirm;
use crate::context::require_session;

#[derive(Subcommand)]
pub enum DevicesCmd {
    /// List the account's devices (Chat, editing apps, the CLI).
    List,
    /// Remove a device from the account (closes its open sessions).
    #[command(alias = "revoke")]
    Remove {
        /// The device's id in the account's list.
        device_id: u32,
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// Forget the newest account manifest this profile has seen. Only after
    /// the server was restored from a backup: its device list is then older
    /// than the one kept here, which is refused as a rollback until this
    /// profile trusts the server's list again on first use.
    ForgetPin {
        /// Another account's pin instead (`aci:<uuid>@<server>`, as `sync`
        /// names it): only when you know its account was reset; its next
        /// device list is then trusted on first use.
        #[arg(long)]
        sender: Option<String>,
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
}

pub fn run(profile: &str, json: bool, cmd: &DevicesCmd) -> Result<()> {
    match cmd {
        DevicesCmd::List => list(profile, json),
        DevicesCmd::Remove { device_id, yes } => remove(profile, json, *device_id, *yes),
        DevicesCmd::ForgetPin { sender: None, yes } => forget_pin(profile, json, *yes),
        DevicesCmd::ForgetPin {
            sender: Some(sender),
            yes,
        } => forget_sender_pin(profile, json, sender, *yes),
    }
}

fn forget_sender_pin(profile: &str, json: bool, sender: &str, yes: bool) -> Result<()> {
    let account: kutup_crypto::account_ref::AccountRef = sender
        .parse()
        .map_err(|_| anyhow!("{sender} is not an account (aci:<uuid>@<server>)"))?;
    let ctx = require_session(profile)?;
    confirm(
        &format!(
            "Trust {sender}'s new keys? Do this only if you know its account was reset: \
             its next device list is trusted on first use."
        ),
        yes,
    )?;
    let forgotten = ctx.store.forget_sender_pin(&account)?;
    if json {
        crate::output::print_json(
            &serde_json::json!({ "forgotten": forgotten, "sender": sender }),
        )?;
    } else if forgotten {
        println!("Forgot the device list kept for {sender}.");
    } else {
        println!("This profile keeps no device list for {sender}.");
    }
    Ok(())
}

fn forget_pin(profile: &str, json: bool, yes: bool) -> Result<()> {
    let ctx = require_session(profile)?;
    let Some(pin) = ctx.store.manifest_pin()? else {
        if json {
            crate::output::print_json(&serde_json::json!({ "forgotten": false }))?;
        } else {
            println!("This profile keeps no account manifest.");
        }
        return Ok(());
    };
    confirm(
        &format!(
            "Forget the account manifest kept here (sequence {})? Do this only after the server \
             was restored from a backup: the next one it serves is trusted on first use.",
            pin.sequence
        ),
        yes,
    )?;
    ctx.store.forget_manifest_pin()?;
    if json {
        crate::output::print_json(
            &serde_json::json!({ "forgotten": true, "sequence": pin.sequence }),
        )?;
    } else {
        println!(
            "Forgot the account manifest kept at sequence {}.",
            pin.sequence
        );
    }
    Ok(())
}

fn list(profile: &str, json: bool) -> Result<()> {
    let ctx = require_session(profile)?;
    let devices = ctx.client.list_devices()?;

    if json {
        crate::output::print_json(&devices)?;
        return Ok(());
    }
    if devices.is_empty() {
        println!("(no devices)");
        return Ok(());
    }
    println!(
        "{}",
        crate::output::header(format!(
            "{:<4}  {:<7}  {:<30}  {:<16}  {:<16}  STATUS",
            "ID", "KIND", "NAME", "CREATED", "LAST SEEN"
        ))
    );
    for d in &devices {
        let last = d
            .last_seen_at
            .as_deref()
            .map(crate::output::format_time)
            .unwrap_or_else(|| "(never)".to_string());
        let status = if d.expired {
            "expired"
        } else if !d.listed {
            "not listed"
        } else if d.this_sign_in {
            "active (this sign-in)"
        } else {
            "active"
        };
        println!(
            "{:<4}  {:<7}  {:<30}  {:<16}  {:<16}  {}",
            d.device_id,
            d.kind.as_str(),
            d.name,
            crate::output::format_time(&d.created_at),
            last,
            status
        );
    }
    Ok(())
}

fn remove(profile: &str, json: bool, device_id: u32, yes: bool) -> Result<()> {
    let ctx = require_session(profile)?;
    if !ctx
        .client
        .list_devices()?
        .iter()
        .any(|d| d.device_id == device_id)
    {
        return Err(anyhow!("the account has no device {device_id}"));
    }
    confirm(
        &format!("Remove device {device_id}? This closes its open sessions."),
        yes,
    )?;
    // Published as this CLI's own device of the account.
    let signer = Signer::new(&ctx.client, &ctx.store, &ctx.session)?;
    let me = signer.device()?;
    signer.publish(&me.header(), |devices| {
        devices.retain(|d| d.device_id != device_id);
        if devices.is_empty() {
            return Err(anyhow!("the account's last device stays"));
        }
        Ok(())
    })?;
    if device_id == me.id {
        ctx.store.put_collab_device(None)?;
    }
    if json {
        crate::output::print_json(&serde_json::json!({ "deviceId": device_id, "removed": true }))?;
    } else {
        println!("Removed device {device_id}");
    }
    Ok(())
}
