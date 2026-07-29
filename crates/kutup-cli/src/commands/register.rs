//! `kutup register` — create a new account from the terminal.
//!
//! kutup is end-to-end encrypted: all key material is generated + encrypted client-side and
//! the server only ever stores ciphertext. This mirrors the web client's
//! `generateRegistrationKeys` (`frontend/src/crypto/index.ts`) exactly, so an account created
//! here behaves identically to one made in the browser — same login flow, same recovery
//! phrase. The 24-word recovery phrase is shown once and never stored; the user must save it.

use anyhow::{Context, Result};
use base64::Engine;
use rand::RngCore;

use crate::api::{Client, RegisterRequest};
use crate::commands::prompt_line;
use kutup_crypto::{kdf, mnemonic, sealedbox, secretbox};

pub fn run(
    json: bool,
    server_flag: Option<&str>,
    email_flag: Option<&str>,
    username_flag: Option<&str>,
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
    let username = match username_flag {
        Some(u) => u.to_string(),
        None => prompt_line("Username: ")?,
    };

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
    // Mirror generateRegistrationKeys: random master/recovery keys, one
    // Argon2id root with HKDF-separated KEK/login keys, an X25519 keypair and
    // three encrypted key envelopes.
    let mut rng = rand::thread_rng();
    let mut master_key = [0u8; 32];
    let mut recovery_entropy = [0u8; 32];
    let mut account_protection_salt = [0u8; 16];
    rng.fill_bytes(&mut master_key);
    rng.fill_bytes(&mut recovery_entropy);
    rng.fill_bytes(&mut account_protection_salt);

    let account_keys = kdf::derive_account_protection_keys(
        &password,
        &account_protection_salt,
        kdf::AccountProtectionParameters::V1,
    )
    .context("derive account-protection keys")?;
    let recovery_proof = kdf::derive_recovery_auth_proof(&recovery_entropy, &email)
        .context("derive recovery authorization proof")?;
    let (public_key, secret_key) = sealedbox::generate_keypair();

    let (enc_mk, mk_nonce) =
        secretbox::seal(&master_key, account_keys.key_encryption_key.as_slice())
            .context("seal master key")?;
    let (enc_rk, rk_nonce) =
        secretbox::seal(&master_key, &recovery_entropy).context("seal recovery key")?;
    let (enc_pk, pk_nonce) =
        secretbox::seal(&secret_key, &master_key).context("seal private key")?;
    let phrase = mnemonic::encode(&recovery_entropy).context("encode mnemonic")?;

    let req = RegisterRequest {
        email: email.clone(),
        username: username.clone(),
        login_key: b64.encode(account_keys.login_key.as_slice()),
        encrypted_master_key: b64.encode(&enc_mk),
        master_key_nonce: b64.encode(mk_nonce),
        encrypted_recovery_key: b64.encode(&enc_rk),
        recovery_key_nonce: b64.encode(rk_nonce),
        encrypted_private_key: b64.encode(&enc_pk),
        private_key_nonce: b64.encode(pk_nonce),
        public_key: b64.encode(public_key),
        account_protection_suite: kdf::AccountProtectionSuiteId::Argon2idHkdfSha256V1.as_u16(),
        account_protection_salt: b64.encode(account_protection_salt),
        argon_memory_kib: kdf::AccountProtectionParameters::V1.memory_kib,
        argon_iterations: kdf::AccountProtectionParameters::V1.iterations,
        argon_parallelism: kdf::AccountProtectionParameters::V1.parallelism,
        recovery_proof: b64.encode(recovery_proof.as_slice()),
    };

    let client = Client::new(&server, "");
    client.register(&req).context("register")?;

    if json {
        // Machine-readable: include the phrase so automation can capture it once.
        crate::output::print_json(&serde_json::json!({
            "email": email,
            "username": username,
            "recoveryPhrase": phrase,
        }))?;
    } else {
        println!("\nAccount created for {email} (@{username}).\n");
        println!("RECOVERY PHRASE — write this down and store it safely. It is shown ONCE and");
        println!("is the ONLY way to recover your account if you forget your password:\n");
        println!("    {phrase}\n");
        println!("Then log in with:  kutup login --server {server} --email {email}");
    }
    Ok(())
}
