//! Live e2e for Kutup Pass vault secrets (docs/plans/pass.md, "Vault
//! secrets").
//!
//! Each person keeps, per vault they can open, the vault's key sealed under
//! their master key. The server checks the envelope is that account's vault
//! secret and that the vault is theirs to open; a trashed vault's secret is
//! kept but unlisted, and a purged vault takes its secrets with it.
//!
//! Gated on `KUTUP_LIVE_SERVER`:
//!   KUTUP_LIVE_SERVER=http://localhost:3000 \
//!     cargo test -p kutup-server --test pass_live -- --nocapture

use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
use kutup_crypto::pass_vault::{open_vault_secret, seal_vault_secret, VaultSecretV1};
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};
use zeroize::Zeroizing;

mod common;
use common::*;

fn secret(password: &str) -> VaultSecretV1 {
    VaultSecretV1 {
        password: Some(Zeroizing::new(password.to_owned())),
        key_file: None,
    }
}

fn sealed_for(user: &User, file_id: &str, password: &str) -> String {
    let id = uuid::Uuid::parse_str(file_id).unwrap();
    b64(&seal_vault_secret(
        &user.master_key,
        &user.email,
        id.as_bytes(),
        &secret(password),
    )
    .unwrap())
}

fn put(c: &Client, base: &str, user: &User, file_id: &str, envelope: &str) -> StatusCode {
    bearer(
        c.put(format!("{base}/api/pass/vault-secrets/{file_id}")),
        &user.token,
    )
    .json(&json!({ "envelope": envelope }))
    .send()
    .unwrap()
    .status()
}

fn list(c: &Client, base: &str, user: &User) -> Vec<Value> {
    let r = bearer(c.get(format!("{base}/api/pass/vault-secrets")), &user.token)
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    r.json().unwrap()
}

#[test]
fn vault_secrets() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let owner = register(&c, &base);
    let member = register(&c, &base);
    let stranger = register(&c, &base);
    let folder = create_folder(&c, &base, &owner);
    share(&c, &base, &owner, &folder, &member, true);
    let vault = seal_file(&folder, &uuid(), b"a KeePass file");
    assert!(upload(&c, &base, &owner.token, &folder, &vault)
        .status()
        .is_success());

    // Each person keeps their own; nobody sees another's.
    assert_eq!(list(&c, &base, &owner), Vec::<Value>::new());
    assert_eq!(
        put(
            &c,
            &base,
            &owner,
            &vault.id,
            &sealed_for(&owner, &vault.id, "o")
        ),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        put(
            &c,
            &base,
            &member,
            &vault.id,
            &sealed_for(&member, &vault.id, "m")
        ),
        StatusCode::NO_CONTENT
    );
    let mine = list(&c, &base, &owner);
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0]["fileId"], vault.id.as_str());
    let envelope =
        account_envelope::decode_canonical_b64(mine[0]["envelope"].as_str().unwrap()).unwrap();
    let id = uuid::Uuid::parse_str(&vault.id).unwrap();
    let opened =
        open_vault_secret(&envelope, &owner.master_key, &owner.email, id.as_bytes()).unwrap();
    assert_eq!(opened.password.unwrap().as_str(), "o");
    assert_eq!(list(&c, &base, &member).len(), 1);

    // Replacing one keeps one.
    assert_eq!(
        put(
            &c,
            &base,
            &owner,
            &vault.id,
            &sealed_for(&owner, &vault.id, "o2")
        ),
        StatusCode::NO_CONTENT
    );
    assert_eq!(list(&c, &base, &owner).len(), 1);

    // Refused: someone who cannot open the vault; another account's
    // envelope; an envelope of another purpose; not base64.
    assert_eq!(
        put(
            &c,
            &base,
            &stranger,
            &vault.id,
            &sealed_for(&stranger, &vault.id, "s")
        ),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        put(
            &c,
            &base,
            &owner,
            &vault.id,
            &sealed_for(&member, &vault.id, "x")
        ),
        StatusCode::BAD_REQUEST
    );
    let other_purpose = account_envelope::seal_b64(
        b"x",
        &owner.master_key,
        AccountEnvelopePurpose::ChatBackupRoot,
        &owner.email,
    )
    .unwrap();
    assert_eq!(
        put(&c, &base, &owner, &vault.id, &other_purpose),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        put(&c, &base, &owner, &vault.id, "not base64!"),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        put(
            &c,
            &base,
            &owner,
            &uuid(),
            &sealed_for(&owner, &vault.id, "o")
        ),
        StatusCode::NOT_FOUND
    );

    // Forgetting one leaves the other person's.
    let forgot = bearer(
        c.delete(format!("{base}/api/pass/vault-secrets/{}", vault.id)),
        &member.token,
    )
    .send()
    .unwrap();
    assert_eq!(forgot.status(), StatusCode::NO_CONTENT);
    assert_eq!(list(&c, &base, &member).len(), 0);
    assert_eq!(list(&c, &base, &owner).len(), 1);

    // In the trash: kept, unlisted; restored: listed again.
    let trashed = bearer(
        c.delete(format!("{base}/api/files/{}", vault.id)),
        &owner.token,
    )
    .send()
    .unwrap();
    assert!(trashed.status().is_success(), "trash: {}", trashed.status());
    assert_eq!(list(&c, &base, &owner).len(), 0);
    let restored = bearer(
        c.post(format!("{base}/api/trash/{}/restore", vault.id)),
        &owner.token,
    )
    .send()
    .unwrap();
    assert!(
        restored.status().is_success(),
        "restore: {}",
        restored.status()
    );
    assert_eq!(list(&c, &base, &owner).len(), 1);

    // Purged: its secrets go with it.
    bearer(
        c.delete(format!("{base}/api/files/{}", vault.id)),
        &owner.token,
    )
    .send()
    .unwrap();
    let purged = bearer(
        c.delete(format!("{base}/api/trash/{}", vault.id)),
        &owner.token,
    )
    .send()
    .unwrap();
    assert_eq!(purged.status(), StatusCode::NO_CONTENT);
    bearer(
        c.post(format!("{base}/api/trash/{}/restore", vault.id)),
        &owner.token,
    )
    .send()
    .unwrap();
    assert_eq!(list(&c, &base, &owner).len(), 0);
}

#[test]
fn reauth_checks_the_password_like_sign_in_with_its_lockout() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let user = register(&c, &base);
    // The login key from the public preflight, as the app derives it.
    let preflight: Value = c
        .get(format!("{base}/api/auth/login/preflight"))
        .query(&[("email", &user.email)])
        .send()
        .unwrap()
        .json()
        .unwrap();
    let salt = account_envelope::decode_canonical_b64(
        preflight["accountProtectionSalt"].as_str().unwrap(),
    )
    .unwrap();
    let derive = |password: &str| {
        let keys = kutup_crypto::kdf::derive_account_protection_keys(
            password,
            &salt,
            kutup_crypto::kdf::AccountProtectionParameters::V1,
        )
        .unwrap();
        b64(keys.login_key.as_slice())
    };
    let reauth = |login_key: &str| {
        bearer(c.post(format!("{base}/api/user/reauth")), &user.token)
            .json(&json!({ "loginKey": login_key }))
            .send()
            .unwrap()
            .status()
    };
    let right = derive("integrity-pw-123456");
    let wrong = derive("not-the-password");
    assert_eq!(reauth(&right), StatusCode::NO_CONTENT);
    assert_eq!(reauth(&wrong), StatusCode::UNAUTHORIZED);
    // Signed out: refused.
    assert_eq!(
        c.post(format!("{base}/api/user/reauth"))
            .json(&json!({ "loginKey": right }))
            .send()
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // The sign-in lockout (LOGIN_LOCKOUT_THRESHOLD, 5 by default): misses
    // here count, and then even the right password waits.
    let mut locked = false;
    for _ in 0..10 {
        if reauth(&wrong) == StatusCode::TOO_MANY_REQUESTS {
            locked = true;
            break;
        }
    }
    assert!(locked, "the lockout never came");
    assert_eq!(reauth(&right), StatusCode::TOO_MANY_REQUESTS);
}

/// The login key for `password`, from the public preflight, as the app
/// derives it.
fn login_key(c: &Client, base: &str, user: &User, password: &str) -> String {
    let preflight: Value = c
        .get(format!("{base}/api/auth/login/preflight"))
        .query(&[("email", &user.email)])
        .send()
        .unwrap()
        .json()
        .unwrap();
    let salt = account_envelope::decode_canonical_b64(
        preflight["accountProtectionSalt"].as_str().unwrap(),
    )
    .unwrap();
    let keys = kutup_crypto::kdf::derive_account_protection_keys(
        password,
        &salt,
        kutup_crypto::kdf::AccountProtectionParameters::V1,
    )
    .unwrap();
    b64(keys.login_key.as_slice())
}

#[test]
fn pin_is_set_with_the_password_checked_here_and_three_misses_end_the_sign_in() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let user = register(&c, &base);
    let right = login_key(&c, &base, &user, "integrity-pw-123456");
    let wrong = login_key(&c, &base, &user, "not-the-password");
    let status = || -> Value {
        bearer(c.get(format!("{base}/api/pass/pin")), &user.token)
            .send()
            .unwrap()
            .json()
            .unwrap()
    };
    let set = |login_key: &str, pin: &str| {
        bearer(c.put(format!("{base}/api/pass/pin")), &user.token)
            .json(&json!({ "loginKey": login_key, "pin": pin }))
            .send()
            .unwrap()
            .status()
    };
    let verify = |pin: &str| {
        let response = bearer(c.post(format!("{base}/api/pass/pin/verify")), &user.token)
            .json(&json!({ "pin": pin }))
            .send()
            .unwrap();
        let code = response.status();
        let body: Value = response.json().unwrap_or(Value::Null);
        (code, body)
    };

    assert_eq!(status()["set"], false);
    assert_eq!(verify("123456").1["error"], "noPin");
    // Six digits, and the account password.
    assert_eq!(set(&right, "12345"), StatusCode::BAD_REQUEST);
    assert_eq!(set(&right, "12345a"), StatusCode::BAD_REQUEST);
    assert_eq!(set(&wrong, "246802"), StatusCode::UNAUTHORIZED);
    assert_eq!(set(&right, "246802"), StatusCode::NO_CONTENT);
    assert_eq!(status()["set"], true);

    assert_eq!(verify("246802").0, StatusCode::NO_CONTENT);
    let (code, body) = verify("111111");
    assert_eq!(code, StatusCode::FORBIDDEN);
    assert_eq!(body, json!({ "error": "wrongPin", "attemptsLeft": 2 }));
    // A right PIN starts the count again.
    assert_eq!(verify("246802").0, StatusCode::NO_CONTENT);
    assert_eq!(verify("111111").1["attemptsLeft"], 2);
    assert_eq!(verify("222222").1["attemptsLeft"], 1);
    let (code, body) = verify("333333");
    assert_eq!(code, StatusCode::FORBIDDEN);
    assert_eq!(body, json!({ "error": "signedOut", "attemptsLeft": 0 }));
    // The sign-in has ended: the session is refused.
    assert_eq!(
        bearer(c.get(format!("{base}/api/pass/pin")), &user.token)
            .send()
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[test]
fn pin_is_removed_only_with_the_password() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let user = register(&c, &base);
    let right = login_key(&c, &base, &user, "integrity-pw-123456");
    let wrong = login_key(&c, &base, &user, "not-the-password");
    let pin = |method: reqwest::Method, body: Value| {
        bearer(
            c.request(method, format!("{base}/api/pass/pin")),
            &user.token,
        )
        .json(&body)
        .send()
        .unwrap()
        .status()
    };
    assert_eq!(
        pin(
            reqwest::Method::PUT,
            json!({ "loginKey": right, "pin": "135790" })
        ),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        pin(reqwest::Method::DELETE, json!({ "loginKey": wrong })),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        pin(reqwest::Method::DELETE, json!({ "loginKey": right })),
        StatusCode::NO_CONTENT
    );
    let status: Value = bearer(c.get(format!("{base}/api/pass/pin")), &user.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(status["set"], false);
}

/// A second sign-in of `user` (another device): its access token.
fn sign_in(c: &Client, base: &str, user: &User) -> String {
    let login_key = login_key(c, base, user, "integrity-pw-123456");
    let r = c
        .post(format!("{base}/api/auth/login"))
        .header("x-kutup-client", "cli")
        .json(&json!({ "email": user.email, "loginKey": login_key }))
        .send()
        .unwrap();
    assert!(r.status().is_success(), "login: {}", r.status());
    r.json::<Value>().unwrap()["accessToken"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn pin_tries_are_counted_per_sign_in() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let user = register(&c, &base);
    let right = login_key(&c, &base, &user, "integrity-pw-123456");
    assert_eq!(
        bearer(c.put(format!("{base}/api/pass/pin")), &user.token)
            .json(&json!({ "loginKey": right, "pin": "975310" }))
            .send()
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    let other = sign_in(&c, &base, &user);
    let verify = |token: &str, pin: &str| -> Value {
        let response = bearer(c.post(format!("{base}/api/pass/pin/verify")), token)
            .json(&json!({ "pin": pin }))
            .send()
            .unwrap();
        if response.status() == StatusCode::NO_CONTENT {
            return json!("ok");
        }
        response.json().unwrap()
    };
    // Another sign-in's misses leave this one its three tries…
    assert_eq!(verify(&other, "000001")["attemptsLeft"], 2);
    assert_eq!(verify(&other, "000002")["attemptsLeft"], 1);
    assert_eq!(verify(&user.token, "000003")["attemptsLeft"], 2);
    // …and this one's right PIN gives the other none back.
    assert_eq!(verify(&user.token, "975310"), json!("ok"));
    assert_eq!(verify(&other, "000004")["error"], "signedOut");
    // The other sign-in has ended; this one goes on.
    assert_eq!(
        bearer(c.get(format!("{base}/api/pass/pin")), &other)
            .send()
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(verify(&user.token, "975310"), json!("ok"));
}
