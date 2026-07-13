//! `kutup recover` — reset the account password with the 24-word recovery
//! phrase, then log in with the new password.
//!
//! Mirrors the web `Recovery` page exactly: the phrase decodes to the 32-byte
//! recovery entropy, which unwraps the master key from the preflight response.
//! Only the KEK wrap, the two KDF salts, and the login key rotate server-side;
//! the master key value, private key, and recovery wrap are unchanged — so all
//! existing data stays decryptable and the same phrase keeps working.

use anyhow::{bail, Context, Result};
use base64::Engine;
use rand::RngCore;

use crate::api::{Client, RecoverRequest};
use crate::commands::prompt_line;
use kutup_crypto::{kdf, mnemonic, secretbox};

pub fn run(
    profile: &str,
    json: bool,
    server_flag: Option<&str>,
    email_flag: Option<&str>,
) -> Result<()> {
    let b64 = base64::engine::general_purpose::STANDARD;

    let mut server = server_flag.unwrap_or("").to_string();
    if server.is_empty() {
        server = prompt_line("Server URL: ")?;
    }
    let server = server.trim_end_matches('/').to_string();
    let email = match email_flag {
        Some(e) => e.to_string(),
        None => prompt_line("Email: ")?,
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
        .recover_preflight(&email)
        .context("recovery preflight (rate-limited — a few attempts per hour)")?;

    // A wrong phrase — or an unknown email, which the server answers with
    // deterministic fake data — fails to unwrap here, before anything changes.
    let master_key = secretbox::open_b64(
        &pre.encrypted_recovery_key,
        &pre.recovery_key_nonce,
        &entropy,
    )
    .map_err(|_| {
        anyhow::anyhow!("recovery phrase does not match this account (wrong phrase or email)")
    })?;

    eprintln!("Deriving new keys…");
    let mut kdf_salt = [0u8; 16];
    let mut login_key_salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut kdf_salt);
    rand::rngs::OsRng.fill_bytes(&mut login_key_salt);

    let kek = kdf::derive_kek(&password, &kdf_salt).context("derive KEK")?;
    let login_key =
        kdf::derive_login_key(&password, &login_key_salt).context("derive login key")?;
    let (enc_mk, mk_nonce) =
        secretbox::seal(&master_key, kek.as_slice()).context("seal master key")?;

    client
        .recover(&RecoverRequest {
            email: email.clone(),
            new_login_key: b64.encode(login_key.as_slice()),
            new_encrypted_master_key: b64.encode(&enc_mk),
            new_master_key_nonce: b64.encode(mk_nonce),
            new_kdf_salt: b64.encode(kdf_salt),
            new_login_key_salt: b64.encode(login_key_salt),
            recovery_proof: b64.encode(&entropy),
        })
        .context("recover")?;

    // Log straight in with the new password so the user ends up ready to work.
    let sess = super::login::login_with_password(profile, &server, &email, &password)?;

    if json {
        crate::output::print_json(&serde_json::json!({
            "email": email,
            "username": sess.username,
            "recovered": true,
            "loggedIn": true,
        }))?;
    } else {
        println!(
            "Password reset. Logged in as {} ({})",
            sess.username, sess.email
        );
    }
    Ok(())
}
