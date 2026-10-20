//! `kutup account` — this device's view of the account's history
//! (docs/plans/rollback-protection.md): the state it trusts, and going on
//! with the server's data after a rollback or a fork; and the account's
//! username (docs/plans/username-renames.md): rename it, list the names it
//! holds, and stop receiving at an old one.

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use clap::Subcommand;
use reqwest::Method;
use serde_json::{json, Value};

use crate::api::{check_ok, decode_json};
use crate::commands::{confirm, prompt_line};
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
    /// Take a new username. The old one receives mail for a while, cannot
    /// send, and is freed later (the server says when).
    Rename {
        /// The new username (3-32 of a-z, 0-9, _ and -).
        name: String,
        /// Do not ask before renaming.
        #[arg(long)]
        yes: bool,
    },
    /// The names this account has: the current one and those it holds.
    Names {
        #[command(subcommand)]
        command: Option<NamesCmd>,
    },
}

#[derive(Subcommand)]
pub enum NamesCmd {
    /// Stop receiving mail at a held name now (it stays held until its date).
    Drop {
        /// A name this account holds.
        name: String,
    },
}

pub fn run(profile: &str, json: bool, cmd: &AccountCmd) -> Result<()> {
    match cmd {
        AccountCmd::State | AccountCmd::Reanchor { .. } => history(profile, json, cmd),
        AccountCmd::Rename { name, yes } => rename(profile, json, name, *yes),
        AccountCmd::Names { command: None } => names(profile, json),
        AccountCmd::Names {
            command: Some(NamesCmd::Drop { name }),
        } => drop_name(profile, json, name),
    }
}

/// `state` and `reanchor`: the account head this device keeps.
fn history(profile: &str, json: bool, cmd: &AccountCmd) -> Result<()> {
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
                if report.started_over.as_deref() == Some("unreadable") {
                    println!("This device started over: its stored record could not be read (kept aside).");
                }
            }
        }
        AccountCmd::Reanchor { yes } => {
            // Nobody confirms what they did not see: with --json the warning
            // is not shown, so --yes must be given on purpose.
            if json && !*yes {
                return Err(crate::errors::UsageError(
                    "--json needs --yes for kutup account reanchor".into(),
                )
                .into());
            }
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
        AccountCmd::Rename { .. } | AccountCmd::Names { .. } => unreachable!("not history"),
    }
    Ok(())
}

fn rename(profile: &str, json: bool, name: &str, yes: bool) -> Result<()> {
    let mut ctx = require_session(profile)?;
    let me: Value = decode_json(ctx.client.request(Method::GET, "/user/me").send()?)?;
    let address = me["address"]
        .as_str()
        .filter(|a| !a.is_empty())
        .context("this account has no address yet")?
        .to_owned();
    let server = address
        .rsplit_once('@')
        .map(|(_, server)| server.to_owned())
        .context("the account's address has no server")?;
    let check: Value = decode_json(
        ctx.client
            .request(Method::GET, "/user/rename/check")
            .query(&[("name", name)])
            .send()?,
    )?;
    if check["available"] != true {
        bail!(
            "the name {name} cannot be had: {}",
            check["reason"].as_str().unwrap_or("unavailable")
        );
    }
    // One of this account's old names is taken back as it was spelled.
    if let Some(spelling) = check["spelling"].as_str().filter(|s| *s != name) {
        bail!(
            "{name} is your old name {spelling}: take it back as `kutup account rename {spelling}`"
        );
    }
    let settings: Value = decode_json(ctx.client.request(Method::GET, "/auth/settings").send()?)?;
    let receive = settings["oldAddressReceiveDays"].as_i64().unwrap_or(90);
    let hold = settings["nameHoldDays"].as_i64().unwrap_or(180);
    eprintln!(
        "Your old address, {address}, will receive mail for {receive} days and cannot send. \
         After that it stops receiving, and after {hold} days someone else can take the name. \
         Update every service that uses the old address now."
    );
    if !yes && !json {
        let answer = prompt_line(&format!("Rename to {name}@{server}? [y/N] "))?;
        if !matches!(answer.trim(), "y" | "Y" | "yes") {
            bail!("not renamed");
        }
    }
    let password = super::login::current_password()?;
    let grant = super::login::reauth_grant(&ctx.client, &password, "rename")?;
    let master_key: [u8; 32] = ctx
        .session
        .master_key_bytes()?
        .as_slice()
        .try_into()
        .context("this session holds no account keys; sign in again")?;
    let identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(&master_key)
        .context("account keys")?;
    let current = format!("{name}@{server}");
    let sequence = me["renames"]["sequence"].as_u64().unwrap_or(0) + 1;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as i64;
    let statement =
        kutup_crypto::account_rename::sign(&identity, sequence, &address, &current, now_ms)
            .context("sign the rename")?;
    // The new address's key comes with the rename, unless the name is one
    // taken back whose address kept its keys: the check says so, and so do
    // the account's own addresses (a key or key list there means none is
    // made over it, whatever the check said).
    let own = if check["needsKey"] == false {
        OwnAddress::Keyed
    } else {
        own_address(&ctx, &current)?
    };
    // One's own freed name must continue its old key list, which isn't built
    // yet: refused, never restarted at 1 (every device that saw the old list
    // would take a restart for a rollback).
    if own == OwnAddress::Freed {
        bail!(
            "{name} was your name before, and its old encryption keys must be carried over to \
             take it back; that isn't possible yet"
        );
    }
    let mail_address = if own == OwnAddress::Keyed {
        Value::Null
    } else {
        let issued_at = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .context("the time")?;
        let first = kutup_crypto::mail_key::first_address_key(
            &identity,
            &master_key,
            ctx.session.binding(),
            &current,
            (now_ms / 1000) as u32,
            &issued_at,
        )
        .context("the new address's mail key")?;
        json!({
            "publicKey": STANDARD.encode(&first.key.public_key),
            "privateKeyEnvelope": STANDARD.encode(&first.private_key_envelope),
            "keyList": {
                "data": STANDARD.encode(&first.key_list.data),
                "signature": STANDARD.encode(first.key_list.signature),
            },
        })
    };
    let renamed: Value = decode_json(
        ctx.client
            .request(Method::POST, "/user/rename")
            .json(&json!({
                "grant": grant,
                "rename": statement,
                "mailAddress": mail_address,
            }))
            .send()?,
    )?;
    let username = renamed["username"].as_str().unwrap_or(name).to_owned();
    ctx.session.username = username.clone();
    ctx.session.name = username.clone();
    ctx.store
        .save_session(&ctx.session)
        .context("save session")?;
    if json {
        crate::output::print_json(&renamed)?;
    } else {
        println!(
            "Renamed to {current}. {address} receives until {}; the name is freed at {}.",
            renamed["oldAddressReceivesUntil"].as_str().unwrap_or("?"),
            renamed["oldNameFreeAt"].as_str().unwrap_or("?"),
        );
    }
    Ok(())
}

fn names(profile: &str, json: bool) -> Result<()> {
    let ctx = require_session(profile)?;
    let rows: Value = decode_json(ctx.client.request(Method::GET, "/user/names").send()?)?;
    if json {
        return crate::output::print_json(&rows);
    }
    for row in rows.as_array().into_iter().flatten() {
        let name = row["name"].as_str().unwrap_or("?");
        match row["state"].as_str() {
            Some("current") => println!("{name}  (current)"),
            _ => println!(
                "{name}  held: receives until {}, freed at {}",
                row["receiveUntil"].as_str().unwrap_or("-"),
                row["freeAt"].as_str().unwrap_or("-"),
            ),
        }
    }
    Ok(())
}

fn drop_name(profile: &str, json: bool, name: &str) -> Result<()> {
    let ctx = require_session(profile)?;
    let password = super::login::current_password()?;
    let grant = super::login::reauth_grant(&ctx.client, &password, "rename")?;
    check_ok(
        ctx.client
            .request(Method::DELETE, &format!("/user/names/{name}"))
            .json(&json!({ "grant": grant }))
            .send()?,
    )?;
    if json {
        crate::output::print_json(&json!({ "dropped": name }))?;
    } else {
        println!("{name} receives no more mail; it stays held until its date.");
    }
    Ok(())
}

/// What the account's own addresses say about an address a rename goes to.
#[derive(PartialEq, Eq)]
enum OwnAddress {
    /// A held (not freed) address of the account is it, with a key or a key
    /// list: no first key is made over it, whatever the check said.
    Keyed,
    /// The account's own freed row is it, with a key list.
    Freed,
    /// A first key at sequence 1.
    New,
}

fn own_address(ctx: &crate::context::Ctx, address: &str) -> Result<OwnAddress> {
    let rows: Value = decode_json(ctx.client.request(Method::GET, "/mail/addresses").send()?)?;
    Ok(own_address_of(&rows, address))
}

/// [`own_address`] over `GET /api/mail/addresses`'s rows.
fn own_address_of(rows: &Value, address: &str) -> OwnAddress {
    let folded = kutup_crypto::names::fold_address(address);
    let mut own = OwnAddress::New;
    for row in rows.as_array().into_iter().flatten() {
        let same = row["address"]
            .as_str()
            .and_then(kutup_crypto::names::fold_address)
            .is_some_and(|row_address| Some(row_address) == folded);
        if !same {
            continue;
        }
        let freed = row["state"] == "freed";
        let keyed = row["keys"].as_array().is_some_and(|keys| !keys.is_empty());
        let listed = !row["keyList"].is_null();
        if !freed && (keyed || listed) {
            return OwnAddress::Keyed;
        }
        if freed && listed {
            own = OwnAddress::Freed;
        }
    }
    own
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(address: &str, state: &str, keyed: bool) -> Value {
        json!({
            "address": address,
            "state": state,
            "keys": if keyed { json!([{ "fingerprint": "aa" }]) } else { json!([]) },
            "keyList": if keyed { json!({ "data": "d", "signature": "s" }) } else { Value::Null },
        })
    }

    #[test]
    fn a_rename_makes_a_first_key_only_over_nothing() {
        let rows = json!([
            row("ada.lovelace@kutup.test", "active", true),
            row("ada.l@kutup.test", "receiving", true),
            row("ada@kutup.test", "freed", true),
        ]);
        // A held name taken back keeps its keys, in any spelling.
        assert!(own_address_of(&rows, "Ada-L@kutup.test") == OwnAddress::Keyed);
        // One's own freed name: refused until its list can be continued.
        assert!(own_address_of(&rows, "a.da@kutup.test") == OwnAddress::Freed);
        // A new name, or one never held: a first key.
        assert!(own_address_of(&rows, "grace@kutup.test") == OwnAddress::New);
        // A freed row without a list says nothing.
        let bare = json!([row("ada@kutup.test", "freed", false)]);
        assert!(own_address_of(&bare, "ada@kutup.test") == OwnAddress::New);
    }
}
