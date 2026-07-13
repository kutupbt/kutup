//! `kutup 2fa` — mirrors `cmd/kutup/cmd/twofa.go`.
//!
//! Manage TOTP two-factor auth: show status, enable (scan a QR / enter the secret, then
//! confirm a code), or disable (requires a current code). The backend won't flip
//! `totp_enabled` until a verify succeeds, so an unverified setup is a no-op for login.

use anyhow::{bail, Result};
use clap::Subcommand;
use qrcode::render::unicode;
use qrcode::QrCode;

use crate::commands::prompt_line;
use crate::context::require_session;

#[derive(Subcommand)]
pub enum TwofaCmd {
    /// Show whether 2FA is enabled on your account.
    Status,
    /// Enable 2FA: prints a QR + provisioning URI, then verifies a code.
    Enable,
    /// Disable 2FA (requires a current TOTP code).
    Disable,
}

pub fn run(profile: &str, json: bool, cmd: &TwofaCmd) -> Result<()> {
    match cmd {
        TwofaCmd::Status => status(profile, json),
        TwofaCmd::Enable => enable(profile, json),
        TwofaCmd::Disable => disable(profile, json),
    }
}

fn status(profile: &str, json: bool) -> Result<()> {
    let ctx = require_session(profile)?;
    let me = ctx.client.me()?;
    if json {
        crate::output::print_json(&serde_json::json!({ "totpEnabled": me.totp_enabled }))?;
    } else if me.totp_enabled {
        println!("2FA: enabled");
    } else {
        println!("2FA: not enabled");
    }
    Ok(())
}

fn enable(profile: &str, json: bool) -> Result<()> {
    let ctx = require_session(profile)?;
    let res = ctx.client.setup_totp()?;

    // Render the otpauth:// URI as a terminal QR (most authenticator apps scan it directly).
    // Also print the URI + base32 secret for terminals that mangle the QR or manual entry.
    // All of it goes to stderr — it's part of the interactive enrollment dialog,
    // and stdout stays reserved for the final result document.
    let qr = QrCode::new(res.qr_uri.as_bytes()).map_err(|e| anyhow::anyhow!("render QR: {e}"))?;
    let img = qr.render::<unicode::Dense1x2>().quiet_zone(true).build();
    eprintln!("{img}\n");
    eprintln!("Provisioning URI: {}", res.qr_uri);
    eprintln!("Or enter this secret manually: {}\n", res.secret);

    let code = prompt_line("Enter the 6-digit code from your authenticator: ")?;
    if code.is_empty() {
        bail!("aborted (no code entered)");
    }
    ctx.client.verify_totp(&code)?;

    if json {
        crate::output::print_json(&serde_json::json!({ "totpEnabled": true }))?;
    } else {
        println!(
            "2FA enabled. Save your recovery phrase — losing your authenticator without it \
             locks you out."
        );
    }
    Ok(())
}

fn disable(profile: &str, json: bool) -> Result<()> {
    let ctx = require_session(profile)?;
    let code = prompt_line("Enter your current 6-digit code to confirm: ")?;
    if code.is_empty() {
        bail!("aborted (no code entered)");
    }
    ctx.client.disable_totp(&code)?;

    if json {
        crate::output::print_json(&serde_json::json!({ "totpEnabled": false }))?;
    } else {
        println!("2FA disabled.");
    }
    Ok(())
}
