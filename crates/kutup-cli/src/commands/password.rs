//! `kutup password` — change the account password (docs/plans/opaque.md):
//! the current one proved again for a `passwordChange` grant, the new one
//! registered with it and the master key sealed under it. Every other
//! sign-in of the account ends; this one goes on.

use anyhow::{bail, Context, Result};

use crate::context::require_session;

pub fn run(profile: &str, json: bool) -> Result<()> {
    let mut ctx = require_session(profile)?;
    let (current, new) = match (
        std::env::var("KUTUP_PASSWORD")
            .ok()
            .filter(|p| !p.is_empty()),
        std::env::var("KUTUP_NEW_PASSWORD")
            .ok()
            .filter(|p| !p.is_empty()),
    ) {
        (Some(current), Some(new)) => (current, new),
        _ => {
            let current = rpassword::prompt_password("Current password: ")?;
            let new = rpassword::prompt_password("New password: ")?;
            if rpassword::prompt_password("Confirm new password: ")? != new {
                bail!("passwords do not match");
            }
            (current, new)
        }
    };
    if new.is_empty() {
        bail!("the new password is empty");
    }
    let master_key: [u8; 32] = ctx
        .session
        .master_key_bytes()?
        .as_slice()
        .try_into()
        .context("this session holds no account keys; sign in again")?;

    // The current password, proved again: a reauth, whose answer is a grant.
    eprintln!("Checking the current password…");
    let grant = super::login::reauth_grant(&ctx.client, &current, "passwordChange")
        .map_err(|e| anyhow::anyhow!("the current password: {e:#}"))?;

    eprintln!("Setting the new password…");
    let envelope = super::login::set_password(
        &ctx.client,
        &grant,
        ctx.session.binding(),
        &new,
        &master_key,
    )?;
    ctx.session.master_key_envelope = envelope;
    ctx.store
        .save_session(&ctx.session)
        .context("save session")?;

    if json {
        crate::output::print_json(&serde_json::json!({ "changed": true }))?;
    } else {
        println!("Password changed. Your other sign-ins have ended.");
    }
    Ok(())
}
