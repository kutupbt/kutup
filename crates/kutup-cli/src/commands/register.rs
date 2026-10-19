//! `kutup register` — create a new account from the terminal.
//!
//! kutup is end-to-end encrypted: all key material is generated + encrypted client-side and
//! the server only ever stores ciphertext. This mirrors the web client's
//! `generateRegistrationKeys` (`frontend/src/crypto/index.ts`) exactly, so an account created
//! here behaves identically to one made in the browser — same login flow, same recovery
//! phrase. The 24-word recovery phrase is shown once and never stored; the user must save it.

use std::io::IsTerminal;

use anyhow::{Context, Result};
use base64::Engine;
use rand::RngCore;

use crate::api::{Client, RegisterRequest};
use crate::commands::prompt_line;
use kutup_crypto::{
    account_envelope::{self, AccountEnvelopePurpose},
    identity::AccountIdentityKeysV1,
    kdf, mnemonic,
};

pub fn run(json: bool, server_flag: Option<&str>, username_flag: Option<&str>) -> Result<()> {
    let b64 = base64::engine::general_purpose::STANDARD;

    let mut server = server_flag.unwrap_or("").to_string();
    if server.is_empty() {
        server = prompt_line("Server URL: ")?;
    }
    let server = server.trim_end_matches('/').to_string();

    let username = match username_flag {
        Some(u) => u.to_string(),
        None => prompt_line("Username: ")?,
    };

    // Who may register here, before any key work: a closed server or a bad
    // referral code is said at once, not after Argon2.
    let client = Client::new(&server, "");
    let settings = client.settings().context("server settings")?;
    let registration_code = registration_code(&client, &settings.registration_mode)?;

    // Password: KUTUP_PASSWORD env (non-interactive), else a hidden prompt confirmed twice
    // (a typo here would set an unknown password on a brand-new account).
    let password = match std::env::var("KUTUP_PASSWORD") {
        Ok(p) if !p.is_empty() => p,
        _ => {
            let p1 = rpassword::prompt_password("Password: ")?;
            let p2 = rpassword::prompt_password("Confirm password: ")?;
            if p1 != p2 {
                anyhow::bail!("passwords do not match");
            }
            p1
        }
    };

    eprintln!("Generating keys…");
    // Mirror generateRegistrationKeys: random master/recovery keys, the
    // password registered with OPAQUE (its export key seals the master key),
    // purpose-separated account identity keys and three encrypted envelopes.
    let mut rng = rand::thread_rng();
    let mut master_key = [0u8; 32];
    let mut recovery_entropy = [0u8; 32];
    rng.fill_bytes(&mut master_key);
    rng.fill_bytes(&mut recovery_entropy);

    // The account's key binding: drawn here, what its keys are bound to for
    // good (docs/plans/account-identity.md), never a name.
    let key_binding = uuid::Uuid::new_v4().to_string();
    let (registering, request) =
        kutup_crypto::opaque::client_registration_start(&password).context("OPAQUE")?;
    let started = client
        .register_start(&key_binding, &request, None)
        .context("register")?;
    let registered = registering
        .finish(&started.response()?)
        .context("the server's registration answer")?;
    let recovery_proof = kdf::derive_recovery_auth_proof(&recovery_entropy, &key_binding)
        .context("derive recovery authorization proof")?;
    let account_identity =
        AccountIdentityKeysV1::derive(&master_key).context("derive account identity")?;

    let master_key_envelope = registered
        .export_key
        .seal_master_key(&master_key, &key_binding)
        .context("seal master-key envelope")?;
    let recovery_key_envelope = account_envelope::seal_b64(
        &master_key,
        &recovery_entropy,
        AccountEnvelopePurpose::RecoveryMasterKey,
        &key_binding,
    )
    .context("seal recovery envelope")?;
    let drive_private_key_envelope = account_envelope::seal_b64(
        account_identity.drive_hpke_private_key(),
        &master_key,
        AccountEnvelopePurpose::DriveHpkePrivateKey,
        &key_binding,
    )
    .context("seal Drive private-key envelope")?;
    let phrase = mnemonic::encode(&recovery_entropy).context("encode mnemonic")?;

    // The account the server minted for this sign-up (its permanent id),
    // which its authority vouches for together with its Drive keys
    // (docs/plans/account-ids.md).
    let (Some(account_id), Some(account_id_proof)) =
        (started.account_id.clone(), started.account_id_proof.clone())
    else {
        anyhow::bail!("the server gave no account id for the sign-up");
    };
    let person =
        kutup_crypto::account_ref::AccountRef::new(&settings.chat.server_name, &account_id)
            .context("the server's account id")?;
    let drive_key_binding = kutup_crypto::drive_key_binding::sign(&account_identity, &person, 1)
        .context("sign the Drive key binding")?;

    let req = RegisterRequest {
        username: username.clone(),
        account_id,
        account_id_proof,
        registration_code,
        key_binding: key_binding.clone(),
        opaque_record: b64.encode(&registered.record),
        opaque_server_key_id: started.server_key_id,
        master_key_envelope,
        recovery_key_envelope,
        drive_private_key_envelope,
        public_key: b64.encode(account_identity.drive_hpke_public_key()),
        account_authority_public_key: b64.encode(account_identity.authority_public_key()),
        account_authority_key_id: account_identity.authority_key_id(),
        account_incarnation_id: account_identity.incarnation_id(),
        drive_signing_public_key: b64.encode(account_identity.drive_signing_public_key()),
        recovery_proof: b64.encode(recovery_proof.as_slice()),
        drive_key_binding: b64.encode(drive_key_binding),
    };

    // Sign-up answers a session; this command does not keep one (`kutup
    // login` does), so it ends it now.
    let session = client.register(&req).context("register")?;
    let _ = Client::new(&server, &session.access_token).logout();

    if json {
        // Machine-readable: include the phrase so automation can capture it once.
        crate::output::print_json(&serde_json::json!({
            "username": username,
            "recoveryPhrase": phrase,
        }))?;
    } else {
        println!("\nAccount created: {username}.\n");
        println!("RECOVERY PHRASE — write this down and store it safely. It is shown ONCE and");
        println!("is the ONLY way to recover your account if you forget your password:\n");
        println!("    {phrase}\n");
        println!("Then log in with:  kutup login --server {server} --username {username}");
    }
    Ok(())
}

/// The referral code to sign up with, for the server's registration `mode`:
/// `KUTUP_REGISTRATION_CODE`, else (when the server needs one) a hidden
/// prompt, never an argument, which shell history and `ps` would keep. A code
/// is checked here, before any key work; checking uses nothing up.
fn registration_code(client: &Client, mode: &str) -> Result<Option<String>> {
    let from_env = std::env::var("KUTUP_REGISTRATION_CODE")
        .ok()
        .map(|code| code.trim().to_owned())
        .filter(|code| !code.is_empty());
    let code = match mode {
        "off" => anyhow::bail!("registration is closed on this server"),
        "code" => match from_env {
            Some(code) => code,
            None if std::io::stdin().is_terminal() => {
                let code = rpassword::prompt_password("Referral code: ")?;
                let code = code.trim().to_owned();
                if code.is_empty() {
                    anyhow::bail!("this server needs a referral code to register");
                }
                code
            }
            None => anyhow::bail!(
                "this server needs a referral code to register: set KUTUP_REGISTRATION_CODE"
            ),
        },
        // `on`: anyone; a code given anyway is recorded with the account.
        _ => match from_env {
            Some(code) => code,
            None => return Ok(None),
        },
    };
    // The server's answer as it is (it names the problem, and its status
    // sets the exit code).
    client.check_registration_code(&code)?;
    Ok(Some(code))
}
