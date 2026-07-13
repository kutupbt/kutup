//! `kutup login` — mirrors `cmd/login.go`.

use anyhow::{bail, Context, Result};
use base64::Engine;

use crate::api::{Client, LoginRequest, TotpRequest};
use crate::commands::prompt_line;
use crate::session::{Session, Store};
use kutup_crypto::{kdf, secretbox};

pub fn run(
    profile: &str,
    json: bool,
    server_flag: Option<&str>,
    email_flag: Option<&str>,
) -> Result<()> {
    let mut server = server_flag.unwrap_or("").to_string();
    if server.is_empty() {
        server = prompt_line("Server URL: ")?;
    }
    let server = server.trim_end_matches('/').to_string();

    // Email: --email flag, else prompt. Password: KUTUP_PASSWORD env (for
    // non-interactive automation/CI), else a hidden prompt.
    let email = match email_flag {
        Some(e) => e.to_string(),
        None => prompt_line("Email: ")?,
    };
    let password = match std::env::var("KUTUP_PASSWORD") {
        Ok(p) if !p.is_empty() => p,
        _ => rpassword::prompt_password("Password: ")?,
    };

    let sess = login_with_password(profile, &server, &email, &password)?;

    if json {
        crate::output::print_json(&serde_json::json!({
            "username": sess.username,
            "email": sess.email,
            "server": sess.server,
            "userId": sess.user_id,
        }))?;
    } else {
        println!("Logged in as {} ({})", sess.username, sess.email);
    }
    Ok(())
}

/// The full login flow: preflight → login (with a TOTP prompt when the
/// account has 2FA) → decrypt the vault → persist the session. Shared by
/// `login` and `recover`.
pub(crate) fn login_with_password(
    profile: &str,
    server: &str,
    email: &str,
    password: &str,
) -> Result<Session> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let client = Client::new(server, "");

    // Step 1: preflight — fetch the KDF salts.
    eprintln!("Deriving keys…");
    let preflight = client.login_preflight(email).context("preflight")?;

    // Step 2: derive the login key (independent Argon2id over loginKeySalt).
    let login_key = kdf::derive_login_key_b64(password, &preflight.login_key_salt)
        .context("derive login key")?;

    // Step 3: login.
    let mut resp = client
        .login(&LoginRequest {
            email: email.to_string(),
            login_key: b64.encode(login_key.as_slice()),
        })
        .context("login")?;

    // Step 4: TOTP if required.
    if resp.requires_totp {
        let code = prompt_line("TOTP code: ")?;
        resp = client
            .login_totp(&TotpRequest {
                pre_auth_token: resp.pre_auth_token.clone(),
                code,
            })
            .context("TOTP")?;
    }

    if resp.requires_setup {
        bail!("account requires first-login setup — use the web UI to complete setup first");
    }

    // Step 5: derive the KEK and decrypt the master + private keys.
    eprintln!("Decrypting vault…");
    let kek = kdf::derive_kek_b64(password, &preflight.kdf_salt).context("derive KEK")?;
    let master_key = secretbox::open_b64(
        &resp.encrypted_master_key,
        &resp.master_key_nonce,
        kek.as_slice(),
    )
    .context("decrypt master key")?;
    let private_key = secretbox::open_b64(
        &resp.encrypted_private_key,
        &resp.private_key_nonce,
        &master_key,
    )
    .context("decrypt private key")?;

    // Step 6: persist the session.
    let mut store = Store::open(profile)?;
    let sess = Session {
        server: server.to_string(),
        email: email.to_string(),
        user_id: resp.user_id,
        username: resp.username,
        access_token: resp.access_token,
        refresh_token: resp.refresh_token,
        master_key: b64.encode(&master_key),
        private_key: b64.encode(&private_key),
        public_key: resp.public_key,
        encrypted_master_key: resp.encrypted_master_key,
        master_key_nonce: resp.master_key_nonce,
        encrypted_private_key: resp.encrypted_private_key,
        private_key_nonce: resp.private_key_nonce,
        storage_quota_bytes: resp.storage_quota_bytes,
        storage_used_bytes: resp.storage_used_bytes,
    };
    store.save_session(&sess).context("save session")?;
    Ok(sess)
}
