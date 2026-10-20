//! Accounts as the apps make and use them: an OPAQUE sign-up with the
//! account's identity keys, an OPAQUE sign-in that opens the master key, and
//! session refreshes. Ported from the server's live-test helpers
//! (`crates/kutup-server/tests/common`), whose request shapes the gates keep
//! current.

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
use kutup_crypto::account_ref::AccountRef;
use kutup_crypto::identity::AccountIdentityKeysV1;
use rand_08::RngCore as _;
use serde_json::{json, Value};

use crate::api::{self, Api};

/// The password every load-test account has.
pub const PASSWORD: &str = "loadtest-password-123456";

pub struct User {
    pub id: String,
    pub username: String,
    /// What the account's keys are bound to.
    pub binding: String,
    pub master_key: [u8; 32],
    pub identity: AccountIdentityKeysV1,
    pub person: AccountRef,
    pub token: String,
    pub refresh_token: String,
}

impl User {
    /// The account's Chat string form, `aci:<uuid>@<server>`.
    pub fn chat_account(&self) -> String {
        self.person.to_string()
    }
}

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn text(value: &Value, field: &str) -> Result<String> {
    value[field]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("the answer has no {field}"))
}

/// A sign-up as the apps make it: OPAQUE registration, the master key sealed
/// under the export key, the identity keys and the Drive key binding.
pub async fn sign_up(api: &Api, server_name: &str, username: &str) -> Result<User> {
    let mut rng = rand_08::thread_rng();
    let key_binding = uuid::Uuid::new_v4().to_string();
    let mut master_key = [0u8; 32];
    let mut recovery_entropy = [0u8; 32];
    rng.fill_bytes(&mut master_key);
    rng.fill_bytes(&mut recovery_entropy);

    let (registering, request) = kutup_crypto::opaque::client_registration_start(PASSWORD)?;
    let started = api::json(
        api.http
            .post(api.url("/auth/opaque/register/start"))
            .json(&json!({ "keyBinding": key_binding, "registrationRequest": b64(&request) }))
            .send()
            .await?,
    )
    .await
    .context("register/start")?;
    let response = STANDARD.decode(text(&started, "registrationResponse")?)?;
    let registered = registering.finish(&response)?;
    let account_id = text(&started, "accountId")?;
    let person = AccountRef::new(server_name, &account_id)?;
    let identity = AccountIdentityKeysV1::derive(&master_key)?;
    let recovery_proof =
        kutup_crypto::kdf::derive_recovery_auth_proof(&recovery_entropy, &key_binding)?;
    let seal = |plain: &[u8], key: &[u8], purpose| {
        account_envelope::seal_b64(plain, key, purpose, &key_binding)
    };
    let body = json!({
        "keyBinding": key_binding, "username": username,
        "accountId": account_id, "accountIdProof": started["accountIdProof"],
        "opaqueRecord": b64(&registered.record), "opaqueServerKeyId": started["serverKeyId"],
        "masterKeyEnvelope": registered.export_key.seal_master_key(&master_key, &key_binding)?,
        "recoveryKeyEnvelope": seal(&master_key, &recovery_entropy, AccountEnvelopePurpose::RecoveryMasterKey)?,
        "drivePrivateKeyEnvelope": seal(identity.drive_hpke_private_key(), &master_key, AccountEnvelopePurpose::DriveHpkePrivateKey)?,
        "publicKey": b64(&identity.drive_hpke_public_key()),
        "accountAuthorityPublicKey": b64(&identity.authority_public_key()),
        "accountAuthorityKeyId": identity.authority_key_id(),
        "accountIncarnationId": identity.incarnation_id(),
        "driveSigningPublicKey": b64(&identity.drive_signing_public_key()),
        "recoveryProof": b64(recovery_proof.as_slice()),
        "driveKeyBinding": b64(&kutup_crypto::drive_key_binding::sign(&identity, &person, 1)?),
    });
    let session = api::json(
        api.http
            .post(api.url("/auth/register"))
            .header("x-kutup-client", "cli")
            .json(&body)
            .send()
            .await?,
    )
    .await
    .context("register")?;
    Ok(User {
        id: account_id,
        username: username.to_owned(),
        binding: key_binding,
        master_key,
        identity,
        person,
        token: text(&session, "accessToken")?,
        refresh_token: session["refreshToken"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    })
}

/// A full sign-in: OPAQUE, then the export key opens the master key and that
/// the Drive private key, as every app does before it shows anything.
pub async fn sign_in(api: &Api, user: &mut User) -> Result<()> {
    let (signing_in, request) = kutup_crypto::opaque::client_login_start(PASSWORD)?;
    let started = api::json(
        api.http
            .post(api.url("/auth/login/start"))
            .header("x-kutup-client", "cli")
            .json(&json!({
                "name": user.username, "credentialRequest": b64(&request), "purpose": "session",
            }))
            .send()
            .await?,
    )
    .await
    .context("login/start")?;
    let response = STANDARD.decode(text(&started, "credentialResponse")?)?;
    let signed_in = signing_in.finish(&response)?;
    let session = api::json(
        api.http
            .post(api.url("/auth/login/finish"))
            .header("x-kutup-client", "cli")
            .json(&json!({
                "loginId": started["loginId"],
                "credentialFinalization": b64(&signed_in.finalization),
            }))
            .send()
            .await?,
    )
    .await
    .context("login/finish")?;
    let binding = text(&session, "envelopeBinding")?;
    let master_key = signed_in
        .export_key
        .open_master_key(&text(&session, "masterKeyEnvelope")?, &binding)?;
    account_envelope::open_b64(
        &text(&session, "drivePrivateKeyEnvelope")?,
        master_key.as_slice(),
        AccountEnvelopePurpose::DriveHpkePrivateKey,
        &binding,
    )?;
    user.token = text(&session, "accessToken")?;
    user.refresh_token = text(&session, "refreshToken")?;
    Ok(())
}

/// A refresh: the access token and the (rotated) refresh token.
pub async fn refresh(api: &Api, user: &mut User) -> Result<()> {
    let session = api::json(
        api.http
            .post(api.url("/auth/refresh"))
            .header("x-kutup-client", "cli")
            .json(&json!({ "refreshToken": user.refresh_token }))
            .send()
            .await?,
    )
    .await
    .context("refresh")?;
    user.token = text(&session, "accessToken")?;
    if let Some(next) = session["refreshToken"].as_str().filter(|t| !t.is_empty()) {
        user.refresh_token = next.to_owned();
    }
    Ok(())
}
