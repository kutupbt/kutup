//! One identity per account (docs/plans/account-identity.md), against a live
//! server and its database: an account made before keeps signing in until
//! its browser re-seals its keys to its key binding, which the server takes
//! only whole, with the password proved again.
//!
//! Needs `KUTUP_LIVE_SERVER` and `KUTUP_LIVE_DATABASE_URL` (no API makes an
//! account bound to an email any more, so the test turns a new one into such
//! an account in the database).

mod common;

use common::{b64, bearer, rebind_request, register, User};
use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
use reqwest::blocking::Client;
use serde_json::{json, Value};

fn client() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

/// Turns `user` into an account as it was before: signing in with `email`,
/// every envelope and the recovery check bound to it, no key binding.
fn make_old(c: &Client, base: &str, database_url: &str, user: &User, email: &str) {
    let kek = common::password_key_encryption_key(c, base, user);
    // As such an account's were: suite 1 (the wrapping key itself as the key).
    let seal = |plain: &[u8], key: &[u8], purpose| {
        let mut nonce = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        b64(&account_envelope::seal_v1_with_nonce(plain, key, purpose, email, &nonce).unwrap())
    };
    let master = seal(
        &user.master_key,
        &kek,
        AccountEnvelopePurpose::PasswordMasterKey,
    );
    let recovery = seal(
        &user.master_key,
        &user.recovery_entropy,
        AccountEnvelopePurpose::RecoveryMasterKey,
    );
    let drive = seal(
        user.identity.drive_hpke_private_key(),
        &user.master_key,
        AccountEnvelopePurpose::DriveHpkePrivateKey,
    );
    let proof =
        kutup_crypto::kdf::derive_recovery_auth_proof(&user.recovery_entropy, email).unwrap();
    let verifier = bcrypt::hash(proof.as_slice(), 4).unwrap();
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let pool = sqlx::PgPool::connect(database_url).await.unwrap();
        sqlx::query(
            "UPDATE users SET email = $2, key_binding = NULL, envelope_binding = $2,
                    master_key_envelope = $3, recovery_key_envelope = $4,
                    recovery_key_verifier = $5, drive_private_key_envelope = $6
              WHERE id = $1::uuid",
        )
        .bind(&user.id)
        .bind(email)
        .bind(master)
        .bind(recovery)
        .bind(verifier)
        .bind(drive)
        .execute(&pool)
        .await
        .unwrap();
    });
}

/// What the account's envelopes carry, as a sign-in hands it over (only
/// once the password is proved: preflight never tells it).
fn binding_of(c: &Client, base: &str, user: &User, name: &str) -> String {
    let login: Value = c
        .post(format!("{base}/api/auth/login"))
        .header("x-kutup-client", "cli")
        .json(&json!({ "name": name, "loginKey": user.login_key }))
        .send()
        .unwrap()
        .json()
        .unwrap();
    login["envelopeBinding"]
        .as_str()
        .unwrap_or_else(|| panic!("no binding: {login}"))
        .to_string()
}

fn sign_in(c: &Client, base: &str, user: &User, name: &str) -> u16 {
    c.post(format!("{base}/api/auth/login"))
        .header("x-kutup-client", "cli")
        .json(&json!({ "name": name, "loginKey": user.login_key }))
        .send()
        .unwrap()
        .status()
        .as_u16()
}

#[test]
fn an_old_account_is_re_sealed_to_its_key_binding() {
    let (Ok(base), Ok(database_url)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_DATABASE_URL"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_DATABASE_URL not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = client();
    let user = register(&c, &base);
    let old_email = format!("{}@old.example", user.username);
    make_old(&c, &base, &database_url, &user, &old_email);

    // Before: the keys carry the old email; the username and the old email sign in.
    assert_eq!(binding_of(&c, &base, &user, &user.username), old_email);
    assert_eq!(binding_of(&c, &base, &user, &old_email), old_email);
    assert_eq!(sign_in(&c, &base, &user, &user.username), 200);
    assert_eq!(sign_in(&c, &base, &user, &old_email), 200);
    let me = common::me(&c, &base, &user.token);
    assert_eq!(me["envelopeBinding"], old_email.as_str());

    let rebind = |body: &Value| {
        bearer(c.post(format!("{base}/api/user/rebind")), &user.token)
            .json(body)
            .send()
            .unwrap()
    };
    let key_binding = uuid::Uuid::new_v4().to_string();
    let body = rebind_request(&c, &base, &user, &key_binding);

    // Refused whole: a wrong password, an envelope bound elsewhere, a key
    // binding that is not a UUID v4, a mail key the account does not have.
    let mut wrong = body.clone();
    wrong["loginKey"] = json!(b64(&[7u8; 32]));
    assert_eq!(rebind(&wrong).status(), 401);
    let mut elsewhere = rebind_request(&c, &base, &user, &uuid::Uuid::new_v4().to_string());
    elsewhere["keyBinding"] = json!(key_binding);
    assert_eq!(rebind(&elsewhere).status(), 400);
    let mut named = body.clone();
    named["keyBinding"] = json!("not-a-uuid");
    assert_eq!(rebind(&named).status(), 400);
    // Re-sealed, but with the old suite (the wrapping key used as the key).
    let mut old_suite = body.clone();
    let mut nonce = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    old_suite["drivePrivateKeyEnvelope"] = json!(b64(&account_envelope::seal_v1_with_nonce(
        user.identity.drive_hpke_private_key(),
        &user.master_key,
        AccountEnvelopePurpose::DriveHpkePrivateKey,
        &key_binding,
        &nonce,
    )
    .unwrap()));
    assert_eq!(rebind(&old_suite).status(), 400, "suite 1 is not taken");
    let mut extra = body.clone();
    extra["mailKeys"] = json!([{ "id": uuid::Uuid::new_v4().to_string(), "privateKeyEnvelope": body["drivePrivateKeyEnvelope"] }]);
    assert_eq!(
        rebind(&extra).status(),
        400,
        "a mail key envelope of the wrong purpose"
    );
    // Nothing changed.
    assert_eq!(binding_of(&c, &base, &user, &user.username), old_email);

    // Whole: from now on the keys carry the key binding.
    let r = rebind(&body);
    assert_eq!(r.status(), 200, "{}", r.text().unwrap_or_default());
    assert_eq!(binding_of(&c, &base, &user, &user.username), key_binding);
    assert_eq!(
        common::me(&c, &base, &user.token)["envelopeBinding"],
        key_binding.as_str()
    );
    // The old email no longer signs in; the username and the address do.
    assert_eq!(sign_in(&c, &base, &user, &old_email), 401);
    assert_eq!(sign_in(&c, &base, &user, &user.username), 200);
    assert_eq!(sign_in(&c, &base, &user, &user.account), 200);
    // Done once.
    assert_eq!(rebind(&body).status(), 409);

    // The keys open with the key binding: the password wrapping and the
    // recovery phrase (a recovery derives its check with the new binding).
    let recover_preflight: Value = c
        .get(format!("{base}/api/auth/recover/preflight"))
        .query(&[("name", &user.username)])
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(recover_preflight["envelopeBinding"], key_binding.as_str());
    let opened = account_envelope::open_b64(
        recover_preflight["recoveryKeyEnvelope"].as_str().unwrap(),
        &user.recovery_entropy,
        AccountEnvelopePurpose::RecoveryMasterKey,
        &key_binding,
    )
    .unwrap();
    assert_eq!(opened, user.master_key);
}

#[test]
fn unknown_names_look_like_accounts() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = client();
    let name = format!("nobody{}", uuid::Uuid::new_v4().simple());
    let preflight = |name: &str, path: &str| -> Value {
        c.get(format!("{base}/api/auth/{path}/preflight"))
            .query(&[("name", name)])
            .send()
            .unwrap()
            .json()
            .unwrap()
    };
    // Sign-in's: a salt and parameters as any account's, the same each time,
    // and no binding (that comes only with a session).
    let first = preflight(&name, "login");
    assert_eq!(first, preflight(&name, "login"));
    assert_eq!(first["accountProtectionSuite"], 1);
    assert_eq!(
        common::b64_decode(first["accountProtectionSalt"].as_str().unwrap()).len(),
        16
    );
    assert!(first.get("envelopeBinding").is_none(), "{first}");
    let real = preflight(&register(&c, &base).username, "login");
    let keys = |v: &Value| {
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    };
    assert_eq!(keys(&first), keys(&real));
    // A recovery's: a key binding's shape and an envelope, the same each time.
    let recovery = preflight(&name, "recover");
    assert_eq!(recovery, preflight(&name, "recover"));
    let binding = recovery["envelopeBinding"].as_str().unwrap();
    assert!(uuid::Uuid::parse_str(binding).is_ok_and(|id| id.get_version_num() == 4));
    // A recovery for it is refused as a wrong phrase is.
    let r = c
        .post(format!("{base}/api/auth/recover"))
        .json(&json!({
            "name": name, "newLoginKey": b64(&[1u8; 32]), "newMasterKeyEnvelope": "x",
            "newAccountProtectionSuite": 1, "newAccountProtectionSalt": b64(&[2u8; 16]),
            "newArgonMemoryKib": 65536, "newArgonIterations": 3, "newArgonParallelism": 1,
            "recoveryProof": b64(&[3u8; 32]),
        }))
        .send()
        .unwrap();
    assert_eq!(r.status(), 401);
}

/// An administrator's temporary password never reaches the server (review
/// H1): the browser derives it as any password, the server keeps only the
/// login key's hash with its salt, and sign-in derives the same way. The
/// break-glass administrator is known by its username.
#[test]
fn temporary_passwords_are_derived_in_the_administrators_browser() {
    let (Ok(base), Ok(admin)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_ADMIN"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_ADMIN not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = client();
    let (admin_name, admin_password) = admin
        .split_once(':')
        .expect("KUTUP_LIVE_ADMIN is username:password");
    let token = common::admin_token(&c, &base, "", admin_password, admin_name);
    let username = format!("tmp{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let create = |body: Value| {
        bearer(c.post(format!("{base}/api/admin/users")), &token)
            .json(&body)
            .send()
            .unwrap()
            .status()
            .as_u16()
    };
    // A password itself is not taken.
    assert_eq!(
        create(json!({ "username": username, "tempPassword": "Temporary*Password123" })),
        400
    );
    let setup = common::setup_key("Temporary*Password123");
    assert_eq!(create(json!({ "username": username, "setup": setup })), 201);
    let users: Vec<Value> = bearer(c.get(format!("{base}/api/admin/users")), &token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let id_of = |name: &str| {
        users
            .iter()
            .find(|u| u["username"] == name)
            .unwrap_or_else(|| panic!("{name} listed"))["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let id = id_of(&username);

    let salt = |name: &str| -> Value {
        c.get(format!("{base}/api/auth/login/preflight"))
            .query(&[("name", name)])
            .send()
            .unwrap()
            .json::<Value>()
            .unwrap()["accountProtectionSalt"]
            .clone()
    };
    let login = |key: &Value| {
        c.post(format!("{base}/api/auth/login"))
            .header("x-kutup-client", "cli")
            .json(&json!({ "name": username, "loginKey": key }))
            .send()
            .unwrap()
    };
    // Preflight answers its salt, as for any account; the password sent as
    // it is fails; derived, the account asks for its setup.
    assert_eq!(salt(&username), setup["accountProtectionSalt"]);
    assert_eq!(login(&json!(b64(b"Temporary*Password123"))).status(), 401);
    let first = login(&setup["loginKey"]);
    assert_eq!(first.status(), 200);
    assert!(first.json::<Value>().unwrap()["setupToken"].is_string());

    // Rotated: the new one only.
    let again = common::setup_key("Another*Temporary456");
    let r = bearer(
        c.post(format!("{base}/api/admin/users/{id}/rotate-temp-password")),
        &token,
    )
    .json(&json!({ "setup": again }))
    .send()
    .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(salt(&username), again["accountProtectionSalt"]);
    assert_eq!(login(&setup["loginKey"]).status(), 401);
    assert_eq!(login(&again["loginKey"]).status(), 200);

    // The break-glass administrator, known by its username, is kept.
    let r = bearer(
        c.delete(format!("{base}/api/admin/users/{}", id_of(admin_name))),
        &token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), 403);
    let r = bearer(c.delete(format!("{base}/api/admin/users/{id}")), &token)
        .send()
        .unwrap();
    assert!(r.status().is_success(), "delete: {}", r.status());
}

/// Kutup Pass's kept vault keys (docs/plans/pass.md, "Vault secrets and the
/// account's binding") move with the rest: every record, vaults in the trash
/// included, re-sealed to the key binding; one that no longer opened is
/// dropped; the set must be exactly the account's.
#[test]
fn kept_vault_keys_are_re_sealed_with_the_account() {
    use kutup_crypto::pass_vault::{open_vault_secret, seal_vault_secret, VaultSecretV1};
    use zeroize::Zeroizing;

    let (Ok(base), Ok(database_url)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_DATABASE_URL"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_DATABASE_URL not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = client();
    let user = register(&c, &base);
    let folder = common::create_folder(&c, &base, &user);
    let vaults: Vec<common::Sealed> = (0..3)
        .map(|_| {
            let vault = common::seal_file(&folder, &common::uuid(), b"a KeePass file");
            assert!(common::upload(&c, &base, &user.token, &folder, &vault)
                .status()
                .is_success());
            vault
        })
        .collect();
    let (live, trashed, dead) = (&vaults[0].id, &vaults[1].id, &vaults[2].id);
    let old_email = format!("{}@old.example", user.username);
    make_old(&c, &base, &database_url, &user, &old_email);

    let seal = |master: &[u8], binding: &str, file_id: &str, password: &str| {
        let id = uuid::Uuid::parse_str(file_id).unwrap();
        let secret = VaultSecretV1 {
            password: Some(Zeroizing::new(password.to_owned())),
            key_file: None,
        };
        b64(&seal_vault_secret(master, binding, id.as_bytes(), &secret).unwrap())
    };
    let put = |file_id: &str, envelope: &str| {
        bearer(
            c.put(format!("{base}/api/pass/vault-secrets/{file_id}")),
            &user.token,
        )
        .json(&json!({ "envelope": envelope }))
        .send()
        .unwrap()
    };
    let listed = |all: bool| -> Vec<Value> {
        let url = format!(
            "{base}/api/pass/vault-secrets{}",
            if all { "?all=true" } else { "" }
        );
        bearer(c.get(url), &user.token)
            .send()
            .unwrap()
            .json()
            .unwrap()
    };
    // Kept as an account made before keeps them: bound to the old email. The
    // third under another master key, so it no longer opens (as after a
    // recovery that replaced the master key).
    assert_eq!(
        put(live, &seal(&user.master_key, &old_email, live, "live")).status(),
        204
    );
    assert_eq!(
        put(
            trashed,
            &seal(&user.master_key, &old_email, trashed, "trashed")
        )
        .status(),
        204
    );
    assert_eq!(
        put(dead, &seal(&[9u8; 32], &old_email, dead, "dead")).status(),
        204
    );
    let trash = bearer(c.delete(format!("{base}/api/files/{trashed}")), &user.token)
        .send()
        .unwrap();
    assert!(trash.status().is_success(), "trash: {}", trash.status());
    assert_eq!(listed(false).len(), 2);
    let all = listed(true);
    assert_eq!(all.len(), 3);
    assert_eq!(
        all.iter().filter(|row| row["inTrash"] == true).count(),
        1,
        "{all:?}"
    );

    // What the browser sends: each record opened with the old binding and
    // sealed with the key binding; the one that does not open, null.
    let key_binding = uuid::Uuid::new_v4().to_string();
    let reseal = |file_id: &str| -> Value {
        let row = all.iter().find(|row| row["fileId"] == file_id).unwrap();
        let envelope =
            account_envelope::decode_canonical_b64(row["envelope"].as_str().unwrap()).unwrap();
        let id = uuid::Uuid::parse_str(file_id).unwrap();
        match open_vault_secret(&envelope, &user.master_key, &old_email, id.as_bytes()) {
            Ok(secret) => json!({
                "fileId": file_id,
                "envelope": seal(&user.master_key, &key_binding, file_id, secret.password.unwrap().as_str()),
            }),
            Err(_) => json!({ "fileId": file_id, "envelope": null }),
        }
    };
    let pass_rows = json!([reseal(live), reseal(trashed), reseal(dead)]);
    assert!(pass_rows[2]["envelope"].is_null());
    let mut body = rebind_request(&c, &base, &user, &key_binding);
    body["passVaultSecrets"] = pass_rows.clone();
    let rebind = |body: &Value| {
        bearer(c.post(format!("{base}/api/user/rebind")), &user.token)
            .json(body)
            .send()
            .unwrap()
    };
    let with_pass = |rows: Value| {
        let mut b = body.clone();
        b["passVaultSecrets"] = rows;
        b
    };

    // Refused whole, nothing changed: a record left out (the trashed one),
    // one the account does not have, one named twice, one still sealed for
    // the old email, one of another purpose.
    let r = rebind(&with_pass(json!([pass_rows[0], pass_rows[2]])));
    assert_eq!(r.status(), 409, "missing: {}", r.text().unwrap_or_default());
    let mut stranger = pass_rows.as_array().unwrap().clone();
    stranger.push(json!({ "fileId": common::uuid(), "envelope": null }));
    assert_eq!(rebind(&with_pass(Value::Array(stranger))).status(), 409);
    let mut twice = pass_rows.as_array().unwrap().clone();
    twice.push(pass_rows[0].clone());
    assert_eq!(rebind(&with_pass(Value::Array(twice))).status(), 400);
    let mut stale = pass_rows.clone();
    stale[0]["envelope"] = json!(seal(&user.master_key, &old_email, live, "live"));
    let r = rebind(&with_pass(stale));
    assert_eq!(r.status(), 409, "old binding");
    assert_eq!(r.json::<Value>().unwrap()["code"], "bindingChanged");
    let mut purpose = pass_rows.clone();
    purpose[0]["envelope"] = body["drivePrivateKeyEnvelope"].clone();
    assert_eq!(rebind(&with_pass(purpose)).status(), 400);
    assert_eq!(binding_of(&c, &base, &user, &user.username), old_email);
    assert_eq!(listed(true).len(), 3);

    // Whole.
    let r = rebind(&body);
    assert_eq!(r.status(), 200, "{}", r.text().unwrap_or_default());
    let after = listed(true);
    assert_eq!(after.len(), 2, "the record that did not open is gone");
    for (file_id, password) in [(live, "live"), (trashed, "trashed")] {
        let row = after
            .iter()
            .find(|row| row["fileId"] == file_id.as_str())
            .unwrap();
        let envelope =
            account_envelope::decode_canonical_b64(row["envelope"].as_str().unwrap()).unwrap();
        let id = uuid::Uuid::parse_str(file_id).unwrap();
        let secret =
            open_vault_secret(&envelope, &user.master_key, &key_binding, id.as_bytes()).unwrap();
        assert_eq!(secret.password.unwrap().as_str(), password);
    }
    assert_eq!(listed(false).len(), 1, "the trashed one is still unlisted");

    // A page still sealing for the old email is told the binding changed;
    // sealed for the key binding, it is kept.
    let r = put(live, &seal(&user.master_key, &old_email, live, "again"));
    assert_eq!(r.status(), 409);
    assert_eq!(r.json::<Value>().unwrap()["code"], "bindingChanged");
    assert_eq!(
        put(live, &seal(&user.master_key, &key_binding, live, "again")).status(),
        204
    );

    // Leave no stored bytes behind (the integration script checks).
    for vault in &vaults {
        let _ = bearer(
            c.delete(format!("{base}/api/files/{}", vault.id)),
            &user.token,
        )
        .send();
    }
    let emptied = bearer(c.delete(format!("{base}/api/trash")), &user.token)
        .send()
        .unwrap();
    assert!(
        emptied.status().is_success(),
        "empty trash: {}",
        emptied.status()
    );
    assert_eq!(
        listed(true).len(),
        0,
        "purging the vaults deletes their records"
    );
}
