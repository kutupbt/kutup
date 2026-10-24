//! `kutup login` — mirrors `cmd/login.go`.

use anyhow::{bail, Context, Result};
use base64::Engine;

use crate::api::{Client, TotpRequest};
use crate::commands::prompt_line;
use crate::session::{Session, Store};
use kutup_crypto::{
    account_envelope::{self, AccountEnvelopePurpose},
    opaque,
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

/// Registers `password` as the account's new one (docs/plans/opaque.md):
/// `register/start` with `grant` for the account's own key binding, the
/// client's half, then `register/finish` with the master key sealed under
/// the new password's export key. `client` carries the session the grant was
/// issued to (none for a recovery). The new password envelope.
pub(crate) fn set_password(
    client: &Client,
    grant: &str,
    key_binding: &str,
    password: &str,
    master_key: &[u8; 32],
) -> Result<String> {
    let (registering, request) = opaque::client_registration_start(password).context("OPAQUE")?;
    let started = client
        .register_start(key_binding, &request, Some(grant))
        .context("register the password")?;
    let registered = registering
        .finish(&started.response()?)
        .context("the server's registration answer")?;
    let envelope = registered
        .export_key
        .seal_master_key(master_key, key_binding)
        .context("seal master-key envelope")?;
    client
        .register_finish(
            grant,
            key_binding,
            &registered.record,
            started.server_key_id,
            &envelope,
        )
        .context("set the password")?;
    Ok(envelope)
}

/// The account's password proved again for a one-time grant `for` one
/// action (`passwordChange`, `totp`, …): a reauth of `client`'s session, for
/// the session's own account (no name: it cannot go stale across a rename).
pub(crate) fn reauth_grant(client: &Client, password: &str, grant_for: &str) -> Result<String> {
    let (signing_in, request) = opaque::client_login_start(password).context("OPAQUE")?;
    let started = client
        .login_start(None, &request, "reauth", Some(grant_for))
        .context("reauth")?;
    let signed_in = signing_in
        .finish(&started.response()?)
        .map_err(|_| anyhow::anyhow!("the password is wrong"))?;
    client
        .reauth_finish(&started.login_id, &signed_in.finalization)
        .context("reauth")
}

/// The account password for a reauth: `KUTUP_PASSWORD`, else a prompt.
pub(crate) fn current_password() -> Result<String> {
    match std::env::var("KUTUP_PASSWORD") {
        Ok(p) if !p.is_empty() => Ok(p),
        _ => Ok(rpassword::prompt_password("Password: ")?),
    }
}

/// The full login flow: the OPAQUE exchange → the second factor when the
/// account has one → open the vault with the export key → persist the
/// session. Shared by `login` and `recover`.
pub(crate) fn login_with_password(
    profile: &str,
    server: &str,
    name: &str,
    password: &str,
) -> Result<Session> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let client = Client::new(server, "");

    // Step 1: the exchange. The password is checked here, by this side: a
    // wrong one never reaches a finish.
    eprintln!("Deriving keys…");
    let (signing_in, request) = opaque::client_login_start(password).context("OPAQUE")?;
    let started = client
        .login_start(Some(name), &request, "session", None)
        .context("login")?;
    let signed_in = signing_in
        .finish(&started.response()?)
        .map_err(|_| anyhow::anyhow!("wrong username or password"))?;
    let mut resp = client
        .login_finish(&started.login_id, &signed_in.finalization)
        .context("login")?;

    // Step 2: TOTP if required.
    if resp.requires_totp {
        // An authenticator code, or one of the recovery codes in its place.
        let code = prompt_line("Authenticator or recovery code: ")?;
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

    // Step 3: the export key opens the master key, and that the private key.
    eprintln!("Decrypting vault…");
    let master_key = signed_in
        .export_key
        .open_master_key(&resp.master_key_envelope, &binding)
        .context("decrypt master key")?;
    let private_key = account_envelope::open_b64(
        &resp.drive_private_key_envelope,
        master_key.as_slice(),
        AccountEnvelopePurpose::DriveHpkePrivateKey,
        &binding,
    )
    .context("decrypt private key")?;

    // Step 4: the server moved to a new setup: the same password registered
    // under it, now, while this side holds it (a failure only waits for the
    // next sign-in).
    let mut master_key_envelope = resp.master_key_envelope;
    if let (true, Some(grant)) = (resp.rotate, resp.grant.as_deref()) {
        let signed = Client::new(server, &resp.access_token);
        match set_password(&signed, grant, &binding, password, &master_key) {
            Ok(envelope) => master_key_envelope = envelope,
            Err(e) => eprintln!("note: moving the password to the server's new key failed: {e:#}"),
        }
    }

    // Step 5: who the account is: its permanent id and its server, which
    // every share names it by (docs/plans/account-ids.md).
    let account = Client::new(server, &resp.access_token)
        .me()
        .context("read the account")?;
    if account.account_id != resp.user_id {
        bail!("the server described another account than the one signed in");
    }

    // Step 5b: an account from before X-Wing moves to it now, once: the Drive
    // key derived again from the master key, bound by the account's own
    // authority, its seed sealed as before (docs/plans/pq-shares.md).
    let (mut public_key, mut private_key, mut drive_private_key_envelope) = (
        resp.public_key,
        private_key,
        resp.drive_private_key_envelope,
    );
    if resp.identity_suite == Some(1) {
        let master: [u8; 32] = master_key
            .as_slice()
            .try_into()
            .context("the master key is 32 bytes")?;
        let identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(&master)
            .context("derive the account's keys")?;
        let person =
            kutup_crypto::account_ref::AccountRef::new(&account.server, &account.account_id)
                .context("the account's id")?;
        let binding_signature = kutup_crypto::drive_key_binding::sign(&identity, &person, 1)
            .context("sign the Drive key binding")?;
        let envelope = account_envelope::seal_b64(
            identity.drive_hpke_private_key(),
            master_key.as_slice(),
            AccountEnvelopePurpose::DriveHpkePrivateKey,
            &binding,
        )
        .context("seal the Drive private key")?;
        let new_public = b64.encode(identity.drive_hpke_public_key());
        Client::new(server, &resp.access_token)
            .upgrade_identity_suite(&serde_json::json!({
                "publicKey": new_public,
                "driveKeyBinding": b64.encode(binding_signature),
                "driveKeyBindingEpoch": 1,
                "drivePrivateKeyEnvelope": envelope,
            }))
            .context("move the account's Drive key to X-Wing")?;
        eprintln!("Moved this account's sharing key to post-quantum encryption.");
        public_key = new_public;
        private_key = identity.drive_hpke_private_key().to_vec();
        drive_private_key_envelope = envelope;
    }

    // Step 6: persist the session.
    let mut store = Store::open(profile)?;
    let sess = Session {
        server: server.to_string(),
        name: name.to_string(),
        envelope_binding: binding,
        user_id: resp.user_id,
        server_name: account.server,
        username: account.username,
        access_token: resp.access_token,
        refresh_token: resp.refresh_token,
        master_key: b64.encode(master_key.as_slice()),
        private_key: b64.encode(&private_key),
        public_key,
        master_key_envelope,
        drive_private_key_envelope,
        storage_quota_bytes: resp.storage_quota_bytes,
        storage_used_bytes: resp.storage_used_bytes,
    };
    store.save_session(&sess).context("save session")?;
    Ok(sess)
}
