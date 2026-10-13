//! `kutup login` — mirrors `cmd/login.go`.

use anyhow::{bail, Context, Result};
use base64::Engine;

use crate::api::{Client, LoginRequest, TotpRequest};
use crate::commands::prompt_line;
use crate::session::{Session, Store};
use kutup_crypto::{
    account_envelope::{self, AccountEnvelopePurpose},
    kdf,
};

pub fn run(
    profile: &str,
    json: bool,
    server_flag: Option<&str>,
    name_flag: Option<&str>,
) -> Result<()> {
    let mut server = server_flag.unwrap_or("").to_string();
    if server.is_empty() {
        server = prompt_line("Server URL: ")?;
    }
    let server = server.trim_end_matches('/').to_string();

    // Username or Kutup address: --username flag, else prompt. Password: KUTUP_PASSWORD env (for
    // non-interactive automation/CI), else a hidden prompt.
    let name = match name_flag {
        Some(e) => e.to_string(),
        None => prompt_line("Username: ")?,
    };
    let password = match std::env::var("KUTUP_PASSWORD") {
        Ok(p) if !p.is_empty() => p,
        _ => rpassword::prompt_password("Password: ")?,
    };

    let sess = login_with_password(profile, &server, &name, &password)?;
    // An account made before Drive key bindings signs its own now, as the web
    // app does at sign-in (docs/plans/drive-identity-pins.md). Best effort:
    // the next sign-in tries again.
    if let Ok(ctx) = crate::context::require_session(profile) {
        if let Ok(me) = crate::identity::Me::of(&ctx, profile) {
            let _ = crate::identity::ensure_binding(&ctx, &me);
        }
    }

    if json {
        crate::output::print_json(&serde_json::json!({
            "username": sess.username,
            "name": sess.name,
            "server": sess.server,
            "userId": sess.user_id,
        }))?;
    } else {
        println!("Logged in as {}", sess.username);
    }
    Ok(())
}

/// The full login flow: preflight → login (with a TOTP prompt when the
/// account has 2FA) → decrypt the vault → persist the session. Shared by
/// `login` and `recover`.
pub(crate) fn login_with_password(
    profile: &str,
    server: &str,
    name: &str,
    password: &str,
) -> Result<Session> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let client = Client::new(server, "");

    // Step 1: preflight — fetch the complete account-protection revision.
    eprintln!("Deriving keys…");
    let preflight = client.login_preflight(name).context("preflight")?;

    // Step 2: run Argon2id once, then expand the KEK and login key.
    kdf::AccountProtectionSuiteId::try_from(preflight.account_protection_suite)
        .context("unsupported account-protection suite")?;
    let account_keys = kdf::derive_account_protection_keys_b64(
        password,
        &preflight.account_protection_salt,
        kdf::AccountProtectionParameters {
            memory_kib: preflight.argon_memory_kib,
            iterations: preflight.argon_iterations,
            parallelism: preflight.argon_parallelism,
        },
    )
    .context("derive account-protection keys")?;

    // Step 3: login.
    let mut resp = client
        .login(&LoginRequest {
            name: name.to_string(),
            login_key: b64.encode(account_keys.login_key.as_slice()),
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
    // What the account's keys are bound to (its key binding), told only with
    // the session.
    if resp.envelope_binding.is_empty() {
        bail!("the server did not say what the account's keys are bound to");
    }
    let binding = resp.envelope_binding.clone();

    // Step 5: derive the KEK and decrypt the master + private keys.
    eprintln!("Decrypting vault…");
    let master_key = account_envelope::open_b64(
        &resp.master_key_envelope,
        account_keys.key_encryption_key.as_slice(),
        AccountEnvelopePurpose::PasswordMasterKey,
        &binding,
    )
    .context("decrypt master key")?;
    let private_key = account_envelope::open_b64(
        &resp.drive_private_key_envelope,
        &master_key,
        AccountEnvelopePurpose::DriveHpkePrivateKey,
        &binding,
    )
    .context("decrypt private key")?;

    // Step 6: persist the session.
    let mut store = Store::open(profile)?;
    let sess = Session {
        server: server.to_string(),
        name: name.to_string(),
        envelope_binding: binding,
        user_id: resp.user_id,
        username: resp.username,
        access_token: resp.access_token,
        refresh_token: resp.refresh_token,
        master_key: b64.encode(&master_key),
        private_key: b64.encode(&private_key),
        public_key: resp.public_key,
        master_key_envelope: resp.master_key_envelope,
        drive_private_key_envelope: resp.drive_private_key_envelope,
        storage_quota_bytes: resp.storage_quota_bytes,
        storage_used_bytes: resp.storage_used_bytes,
    };
    store.save_session(&sess).context("save session")?;
    Ok(sess)
}
