//! `kutup identity` — who the people you share with are
//! (docs/plans/drive-identity-pins.md): the identities this account trusts,
//! comparing a safety number in person, and trusting a new identity. The same
//! list and the same safety numbers as Drive and Chat.

use anyhow::{bail, Result};
use clap::Subcommand;
use kutup_crypto::identity_pins::PinState;

use crate::commands::confirm;
use crate::context::require_session;
use crate::identity::{self, Claimed, Me};

#[derive(Subcommand)]
pub enum IdentityCmd {
    /// List the identities this account trusts (shared with Drive and Chat).
    List,
    /// Show someone's identity: whether it can be trusted, and the safety number.
    Show {
        /// Their address (user@server).
        account: String,
    },
    /// Compare the safety number with someone in person and mark them verified.
    Verify {
        /// Their address (user@server).
        account: String,
        /// The text of their safety QR code, instead of comparing the digits.
        #[arg(long)]
        payload: Option<String>,
        /// Skip the "do the numbers match?" prompt (you compared them).
        #[arg(long)]
        yes: bool,
    },
    /// Trust someone's new identity without comparing it (after an
    /// administrator reset their account).
    Trust {
        /// Their address (user@server).
        account: String,
        #[arg(long)]
        yes: bool,
    },
}

pub fn run(profile: &str, json: bool, cmd: &IdentityCmd) -> Result<()> {
    let ctx = require_session(profile)?;
    let me = Me::of(&ctx, profile)?;
    match cmd {
        IdentityCmd::List => {
            let (_, list) = identity::load_pins(&ctx, &me)?;
            if json {
                let rows: Vec<_> = list
                    .pins
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "account": p.address(),
                            "accountRef": p.account,
                            "state": if p.state == PinState::Verified { "verified" } else { "trusted" },
                            "since": p.since,
                            "replaced": p.replaced.len(),
                        })
                    })
                    .collect();
                return crate::output::print_json(&rows);
            }
            if list.pins.is_empty() {
                println!(
                    "No identities yet: people are remembered the first time you share with them."
                );
            }
            for p in &list.pins {
                let state = if p.state == PinState::Verified {
                    "verified"
                } else {
                    "trusted"
                };
                // A person by the newest address met; one met with none yet
                // shows as "(no address)", never by its account id.
                let address = p.address().unwrap_or("(no address)");
                println!("{address:<40} {state:<9} since {}", p.since);
            }
            Ok(())
        }
        IdentityCmd::Show { account } => {
            let status = identity::check(&ctx, &me, account, &Claimed::default())?;
            let number = identity::safety(&ctx, &me, account).ok();
            if json {
                return crate::output::print_json(&serde_json::json!({
                    "account": account,
                    "status": status.label(),
                    "safetyNumber": number.as_ref().map(|(n, _)| &n.fingerprint),
                }));
            }
            println!("{account}: {}", status.label());
            if status.in_doubt() {
                eprintln!("warning: {}", status.warning(account));
            }
            if let Some((number, _)) = number {
                println!("Safety number:\n{}", group(&number.fingerprint));
            }
            Ok(())
        }
        IdentityCmd::Verify {
            account,
            payload,
            yes,
        } => {
            let (number, person) = identity::safety(&ctx, &me, account)?;
            match payload {
                Some(payload) => {
                    if !kutup_crypto::safety_number::matches_qr_payload(&number, payload.trim()) {
                        bail!("that safety QR is not the one for you and {account}: do not trust this identity");
                    }
                }
                None => {
                    println!(
                        "Safety number with {account}:\n{}",
                        group(&number.fingerprint)
                    );
                    println!("Compare it with the one {account} sees (in Chat, Drive or 'kutup identity show'), in person or on a call you trust.");
                    confirm("Do the numbers match exactly?", *yes)?;
                }
            }
            identity::verify(&ctx, &me, account, &person)?;
            if json {
                crate::output::print_json(&serde_json::json!({ "verified": account }))
            } else {
                println!("{account} is verified, in every Kutup app of this account.");
                Ok(())
            }
        }
        IdentityCmd::Trust { account, yes } => {
            confirm(
                &format!(
                    "Trust the identity the server now gives for {account}, without comparing it?"
                ),
                *yes,
            )?;
            identity::trust(&ctx, &me, account)?;
            if json {
                crate::output::print_json(&serde_json::json!({ "trusted": account }))
            } else {
                println!("{account}'s current identity is trusted.");
                Ok(())
            }
        }
    }
}

/// Sixteen groups, four to a line, as people read them out.
fn group(fingerprint: &str) -> String {
    fingerprint
        .split(' ')
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|line| line.join(" "))
        .collect::<Vec<_>>()
        .join("\n")
}
