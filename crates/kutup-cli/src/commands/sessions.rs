//! `kutup sessions` — list and end the account's sign-ins (web apps, other CLIs).

use anyhow::Result;
use clap::Subcommand;

use crate::commands::confirm;
use crate::context::require_session;

#[derive(Subcommand)]
pub enum SessionsCmd {
    /// List the account's live sign-ins, most recently used first.
    List,
    /// End one sign-in (and the app sessions forked from it).
    Revoke {
        /// Session id (see `kutup sessions list`).
        session_id: String,
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// End every sign-in except this one.
    RevokeOthers {
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
}

pub fn run(profile: &str, json: bool, cmd: &SessionsCmd) -> Result<()> {
    match cmd {
        SessionsCmd::List => list(profile, json),
        SessionsCmd::Revoke { session_id, yes } => revoke(profile, json, session_id, *yes),
        SessionsCmd::RevokeOthers { yes } => revoke_others(profile, json, *yes),
    }
}

fn list(profile: &str, json: bool) -> Result<()> {
    let ctx = require_session(profile)?;
    let sessions = ctx.client.list_sessions()?;
    if json {
        crate::output::print_json(&sessions)?;
        return Ok(());
    }
    println!(
        "{}",
        crate::output::header(format!(
            "{:<36}  {:<12}  {:<16}  {:<16}  THIS",
            "ID", "CLIENT", "CREATED", "LAST USED"
        ))
    );
    for s in &sessions {
        println!(
            "{:<36}  {:<12}  {:<16}  {:<16}  {}",
            s.id,
            s.client_type,
            crate::output::format_time(&s.created_at),
            crate::output::format_time(&s.last_used_at),
            if s.current { "yes" } else { "" },
        );
    }
    Ok(())
}

fn revoke(profile: &str, json: bool, session_id: &str, yes: bool) -> Result<()> {
    let ctx = require_session(profile)?;
    confirm(&format!("End session {session_id}?"), yes)?;
    ctx.client.revoke_session(session_id)?;
    if json {
        crate::output::print_json(&serde_json::json!({ "revoked": session_id }))?;
    } else {
        println!("Session ended.");
    }
    Ok(())
}

fn revoke_others(profile: &str, json: bool, yes: bool) -> Result<()> {
    let ctx = require_session(profile)?;
    confirm("End every other sign-in of this account?", yes)?;
    ctx.client.revoke_other_sessions()?;
    if json {
        crate::output::print_json(&serde_json::json!({ "revokedOthers": true }))?;
    } else {
        println!("Every other sign-in has ended.");
    }
    Ok(())
}
