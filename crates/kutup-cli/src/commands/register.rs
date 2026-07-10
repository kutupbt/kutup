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
    // Mirror generateRegistrationKeys: random master key + recovery entropy, two independent
    // 16-byte KDF salts, Argon2id KEK + login key, an X25519 keypair, and the three seals.
    let mut rng = rand::thread_rng();
    let mut master_key = [0u8; 32];
    let mut recovery_entropy = [0u8; 32];
    let mut kdf_salt = [0u8; 16];
    let mut login_key_salt = [0u8; 16];
    rng.fill_bytes(&mut master_key);
    rng.fill_bytes(&mut recovery_entropy);
    rng.fill_bytes(&mut kdf_salt);
    rng.fill_bytes(&mut login_key_salt);

    let kek = kdf::derive_kek(&password, &kdf_salt).context("derive KEK")?;
    let login_key =
        kdf::derive_login_key(&password, &login_key_salt).context("derive login key")?;
    let (public_key, secret_key) = sealedbox::generate_keypair();

    let (enc_mk, mk_nonce) =
        secretbox::seal(&master_key, kek.as_slice()).context("seal master key")?;
    let (enc_rk, rk_nonce) =
        secretbox::seal(&master_key, &recovery_entropy).context("seal recovery key")?;
    let (enc_pk, pk_nonce) =
        secretbox::seal(&secret_key, &master_key).context("seal private key")?;
    let phrase = mnemonic::encode(&recovery_entropy).context("encode mnemonic")?;

    let req = RegisterRequest {
        email: email.clone(),
        username: username.clone(),
        login_key: b64.encode(login_key.as_slice()),
        encrypted_master_key: b64.encode(&enc_mk),
        master_key_nonce: b64.encode(mk_nonce),
        encrypted_recovery_key: b64.encode(&enc_rk),
        recovery_key_nonce: b64.encode(rk_nonce),
        encrypted_private_key: b64.encode(&enc_pk),
        private_key_nonce: b64.encode(pk_nonce),
        public_key: b64.encode(public_key),
        kdf_salt: b64.encode(kdf_salt),
        login_key_salt: b64.encode(login_key_salt),
        recovery_proof: b64.encode(recovery_entropy),
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
