//! `kutup recover` — reset the account password with the 24-word recovery
//! phrase, then log in with the new password.
//!
//! Mirrors the web `Recovery` page exactly: the phrase decodes to the 32-byte
//! recovery entropy, which unwraps the master key from the preflight response;
//! its proof buys a recovery grant, with which the new password is registered
//! (OPAQUE) and the master key sealed under it. The master key, private key
//! and recovery wrap are unchanged — so all existing data stays decryptable
//! and the same phrase keeps working.

use anyhow::{bail, Context, Result};
use base64::Engine;

use crate::api::Client;
use crate::commands::prompt_line;
use kutup_crypto::{
    account_envelope::{self, AccountEnvelopePurpose},
    kdf, mnemonic,
};

pub fn run(
    profile: &str,
    json: bool,
    server_flag: Option<&str>,
    name_flag: Option<&str>,
) -> Result<()> {
    let b64 = base64::engine::general_purpose::STANDARD;

    let mut server = server_flag.unwrap_or("").to_string();
    if server.is_empty() {
        server = prompt_line("Server URL: ")?;
    }
    let server = server.trim_end_matches('/').to_string();
    let name = match name_flag {
        Some(e) => e.to_string(),
        None => prompt_line("Username: ")?,
    };

    // Phrase: KUTUP_RECOVERY_PHRASE env for non-interactive use — never a
    // flag (shell history / process lists leak) — else a visible prompt
    // (24 words are hopeless to type blind, matching the web textarea).
    let phrase = match std::env::var("KUTUP_RECOVERY_PHRASE") {
        Ok(p) if !p.is_empty() => p,
        _ => prompt_line("Recovery phrase (24 words): ")?,
    };
    let phrase = phrase
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();

    let password = match std::env::var("KUTUP_PASSWORD") {
        Ok(p) if !p.is_empty() => p,
        _ => {
            let p1 = rpassword::prompt_password("New password: ")?;
            let p2 = rpassword::prompt_password("Confirm new password: ")?;
            if p1 != p2 {
                bail!("passwords do not match");
            }
            p1
        }
    };

    // BIP39 checksum validation happens here — bad words fail before any
    // network traffic.
    let entropy =
        mnemonic::decode(&phrase).context("invalid recovery phrase (check the 24 words)")?;

    let client = Client::new(&server, "");
    let pre = client
        .recover_preflight(&name)
        .context("recovery preflight (rate-limited — a few attempts per hour)")?;
    let binding = pre.envelope_binding.clone();

    // A wrong phrase — or an unknown name, which the server answers with
    // deterministic fake data — fails to unwrap here, before anything changes.
    let master_key = account_envelope::open_b64(
        &pre.recovery_key_envelope,
        &entropy,
        AccountEnvelopePurpose::RecoveryMasterKey,
        &binding,
    )
    .map_err(|_| {
        anyhow::anyhow!("recovery phrase does not match this account (wrong phrase or username)")
    })?;

    // The phrase's proof, for a recovery grant; then the new password,
    // registered with it (every sign-in of the account ends).
    eprintln!("Setting the new password…");
    let recovery_proof = kdf::derive_recovery_auth_proof(&entropy, &binding)
        .context("derive recovery authorization proof")?;
    let grant = client
        .recover_grant(&name, &b64.encode(recovery_proof.as_slice()))
        .context("recover")?;
    let master_key: [u8; 32] = master_key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("the master key has the wrong length"))?;
    super::login::set_password(&client, &grant, &binding, &password, &master_key)?;

    // Log straight in with the new password so the user ends up ready to work.
    let sess = super::login::login_with_password(profile, &server, &name, &password)?;

    if json {
        crate::output::print_json(&serde_json::json!({
            "name": name,
            "username": sess.username,
            "recovered": true,
            "loggedIn": true,
        }))?;
    } else {
        println!("Password reset. Logged in as {}", sess.username);
    }
    Ok(())
}
