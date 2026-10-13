//! One identity per account (docs/plans/account-identity.md), against a live
//! server: accounts sign in by username or Kutup address, their keys are
//! bound to a key binding told only with a session, and names that are no
//! account get answers no one can tell from real ones.
//!
//! Needs `KUTUP_LIVE_SERVER` (and `KUTUP_LIVE_ADMIN` for temporary passwords).

mod common;

use common::{b64, bearer, register};
use reqwest::blocking::Client;
use serde_json::{json, Value};

fn client() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

#[test]
fn an_account_signs_in_by_its_name_and_its_keys_carry_its_key_binding() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = client();
    let user = register(&c, &base);
    let sign_in = |name: &str| {
        c.post(format!("{base}/api/auth/login"))
            .header("x-kutup-client", "cli")
            .json(&json!({ "name": name, "loginKey": user.login_key }))
            .send()
            .unwrap()
    };
    // By username or by address; the binding comes with the session.
    for name in [user.username.clone(), user.account.clone()] {
        let r = sign_in(&name);
        assert_eq!(r.status(), 200, "{name}");
        assert_eq!(
            r.json::<Value>().unwrap()["envelopeBinding"],
            user.binding.as_str()
        );
    }
    assert_eq!(
        common::me(&c, &base, &user.token)["envelopeBinding"],
        user.binding.as_str()
    );
    // The same name at another domain is no one here.
    let elsewhere = format!("{}@elsewhere.example", user.username);
    assert_eq!(sign_in(&elsewhere).status(), 401);
    // Preflight tells no binding.
    let preflight: Value = c
        .get(format!("{base}/api/auth/login/preflight"))
        .query(&[("name", &user.username)])
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert!(preflight.get("envelopeBinding").is_none(), "{preflight}");
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
    // The same name at this server's address gets the same answers, as a
    // real account's username and address do.
    let account = register(&c, &base);
    let domain = account.account.split_once('@').unwrap().1.to_string();
    let at_domain = format!("{name}@{domain}");
    assert_eq!(preflight(&at_domain, "login"), first);
    assert_eq!(
        preflight(&at_domain, "recover"),
        preflight(&name, "recover")
    );
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
