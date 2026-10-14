//! `kutup account` — this device's view of the account's history
//! (docs/plans/rollback-protection.md): the state it trusts, and going on
//! with the server's data after a rollback or a fork.

use anyhow::Result;
use clap::Subcommand;

use crate::commands::confirm;
use crate::context::require_session;
use crate::identity::Me;
use crate::output::print_json;

#[derive(Subcommand)]
pub enum AccountCmd {
    /// Where this device stands with the account's history (`trusted`,
    /// `rollback` or `fork`), and the sequence it remembers and the server shows.
    State,
    /// After a rollback or a fork (exit code 6): go on with the server's data.
    /// Another device may have been shown a different history, or the server
    /// was restored from a backup and recent changes may be lost: review them
    /// first.
    Reanchor {
        /// Skip the confirmation.
        #[arg(long)]
        yes: bool,
    },
}

pub fn run(profile: &str, json: bool, cmd: &AccountCmd) -> Result<()> {
    let ctx = require_session(profile)?;
    let me = Me::of(&ctx, profile)?;
    let mut head = me.head(&ctx)?;
    let report = head.report()?;
    match cmd {
        AccountCmd::State => {
            if json {
                print_json(&report)?;
            } else {
                println!("Account history: {}", report.status);
                match report.anchor {
                    Some(sequence) => println!("This device remembers: #{sequence}"),
                    None => println!("This device remembers: nothing yet"),
                }
                match report.current {
                    Some(sequence) => println!("The server shows:      #{sequence}"),
                    None => println!("The server shows:      no history yet"),
                }
            }
        }
        AccountCmd::Reanchor { yes } => {
            if report.status == "trusted" {
                if json {
                    print_json(
                        &serde_json::json!({ "status": report.status, "reanchored": false }),
                    )?;
                } else {
                    println!(
                        "Nothing to do: the server's history descends from what this device knows."
                    );
                }
                return Ok(());
            }
            if !json {
                eprintln!(
                    "The server shows {} history than this device knows ({}). Another device may have \
                     been shown a different one, or the server was restored from a backup and recent \
                     changes may be lost. Review your contacts, labels, saved keys and vault keys afterwards.",
                    if report.status == "fork" { "another" } else { "an older" },
                    report.status
                );
            }
            confirm("Continue with the server's data?", *yes)?;
            let moved = head.continue_with_server()?;
            if json {
                print_json(&serde_json::json!({ "status": report.status, "reanchored": moved }))?;
            } else {
                println!("This device now follows the server's data.");
            }
        }
    }
    Ok(())
}
