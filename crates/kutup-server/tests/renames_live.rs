//! Username renames against a live server (docs/plans/username-renames.md):
//! one account per folded name, a rename that keeps everything but the name,
//! the old name held (the fake answer at sign-in, `409 renamed` at lookups,
//! deliveries still routed), the limits, and names freed for someone else.
//!
//! Needs `KUTUP_LIVE_SERVER` (and `KUTUP_LIVE_ADMIN` for the admin cases and
//! to purge).

mod common;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use common::*;
use rand::RngCore;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

fn client() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

/// A fresh name, `prefix` and digits.
fn name(prefix: &str) -> String {
    format!("{prefix}{}", rand::thread_rng().next_u32() % 1_000_000_000)
}

fn get(c: &Client, base: &str, token: &str, path: &str) -> reqwest::blocking::Response {
    bearer(c.get(format!("{base}{path}")), token)
        .send()
        .unwrap()
}

/// Renames `user` to `to`: the server's answer (status, body).
fn rename(c: &Client, base: &str, user: &User, to: &str) -> (StatusCode, Value) {
    let me: Value = get(c, base, &user.token, "/api/user/me").json().unwrap();
    let address = me["address"].as_str().unwrap().to_owned();
    let server = address.rsplit_once('@').unwrap().1.to_owned();
    let sequence = me["renames"]["sequence"].as_u64().unwrap() + 1;
    let current = format!("{to}@{server}");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let statement =
        kutup_crypto::account_rename::sign(&user.identity, sequence, &address, &current, now)
            .unwrap();
    let binding = kutup_crypto::drive_key_binding::sign(&user.identity, &current).unwrap();
    let grant = reauth_grant(c, base, user, "rename");
    let r = bearer(c.post(format!("{base}/api/user/rename")), &user.token)
        .json(&json!({ "grant": grant, "rename": statement,
                       "driveKeyBinding": STANDARD.encode(binding) }))
        .send()
        .unwrap();
    let status = r.status();
    (status, r.json().unwrap_or(Value::Null))
}

/// A sign-in start for `name`: its answer, from `ip`.
fn start(c: &Client, base: &str, name: &str, password: &str, ip: &str) -> (StatusCode, Value) {
    let (_, ke1) = kutup_crypto::opaque::client_login_start(password).unwrap();
    let r = c
        .post(format!("{base}/api/auth/login/start"))
        .header("x-kutup-client", "cli")
        .header("x-real-ip", ip)
        .json(&json!({ "name": name, "credentialRequest": b64(&ke1) }))
        .send()
        .unwrap();
    let status = r.status();
    (status, r.json().unwrap_or(Value::Null))
}

#[test]
fn a_rename_keeps_the_account_and_holds_the_old_name() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let mut user = register(&c, &base);
    let old = user.username.clone();
    let new = name("renamed_");
    let (status, body) = rename(&c, &base, &user, &new);
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["username"], json!(new));
    assert_eq!(body["sequence"], 1);
    let me: Value = get(&c, &base, &user.token, "/api/user/me").json().unwrap();
    assert_eq!(me["username"], json!(new));
    assert_eq!(me["renames"]["sequence"], 1);
    assert!(me["renames"]["digest"]
        .as_str()
        .is_some_and(|d| d.len() == 64));

    // The new name and its variants sign in, the same account; the old one
    // is no account.
    for spelling in [new.clone(), new.to_uppercase(), new.replace('_', "")] {
        let session = sign_in(&c, &base, &spelling, &user.password);
        assert_eq!(session["userId"], json!(user.id), "{spelling}");
    }
    let (status, _, _) = opaque_login(&c, &base, &old, &user.password, "session", None, None);
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the old name signs nobody in"
    );

    // Lookups of the old name say where it went, with the chain.
    let domain = server_domain(&c, &base);
    let r = get(
        &c,
        &base,
        &user.token,
        &format!("/api/users/by-address/{old}@{domain}"),
    );
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let renamed: Value = r.json().unwrap();
    assert_eq!(renamed["code"], "renamed");
    let chains = &renamed["renames"];
    assert_eq!(chains["version"], 1);
    assert_eq!(
        chains["chains"][0]["current"],
        json!(format!("{new}@{domain}"))
    );
    assert_eq!(chains["chains"][0]["state"], "current");
    let chain: Vec<kutup_crypto::account_rename::AccountRenameV1> =
        serde_json::from_value(chains["chains"][0]["chain"].clone()).unwrap();
    let view =
        kutup_crypto::account_rename::verify_chain(&user.identity.authority_public_key(), &chain)
            .unwrap();
    assert_eq!(view.current, format!("{new}@{domain}"));
    let listed: Value = get(
        &c,
        &base,
        &user.token,
        &format!("/api/users/renames/{old}@{domain}"),
    )
    .json()
    .unwrap();
    assert_eq!(&listed, chains);

    // The names the account has, and the event.
    let names: Value = get(&c, &base, &user.token, "/api/user/names")
        .json()
        .unwrap();
    assert_eq!(names[0]["name"], json!(new));
    assert_eq!(names[0]["state"], "current");
    assert_eq!(names[1]["name"], json!(old));
    assert_eq!(names[1]["state"], "held");
    let events: Value = get(&c, &base, &user.token, "/api/user/security-events")
        .json()
        .unwrap();
    assert_eq!(events["events"][0]["kind"], "rename");
    assert_eq!(events["events"][0]["oldName"], json!(old));
    assert_eq!(events["events"][0]["newName"], json!(new));

    // One rename a month; the free undo back, once, restarts the clock.
    let (status, body) = rename(&c, &base, &user, &name("again_"));
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["code"], "renameTooSoon");
    let (status, body) = rename(&c, &base, &user, &old);
    assert_eq!(status, StatusCode::OK, "the free undo: {body}");
    let (status, _) = rename(&c, &base, &user, &new);
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "only one free undo");
    user.username = old;
    purge_accounts(&c, &base, &[&user]);
}

#[test]
fn a_held_name_gets_the_fake_answer_and_shares_one_lockout() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let mut user = register_as(&c, &base, &name("ada_l")).unwrap();
    let old = user.username.clone();
    let new = name("moved");
    assert_eq!(rename(&c, &base, &user, &new).0, StatusCode::OK);
    user.username = new.clone();

    // The held name's answer has the shape of any unknown name's.
    let (held_status, held) = start(&c, &base, &old, "wrong-password-1", "192.0.2.150");
    let (unknown_status, unknown) = start(
        &c,
        &base,
        &name("nobody"),
        "wrong-password-1",
        "192.0.2.151",
    );
    assert_eq!(
        (held_status, unknown_status),
        (StatusCode::OK, StatusCode::OK)
    );
    let keys = |v: &Value| v.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
    assert_eq!(keys(&held), keys(&unknown));
    assert_eq!(
        held["credentialResponse"].as_str().unwrap().len(),
        unknown["credentialResponse"].as_str().unwrap().len()
    );
    // Every spelling of it is one bucket: five misses lock them all.
    let spellings = [
        old.clone(),
        old.replace('_', ""),
        old.replace('_', "."),
        old.to_uppercase(),
    ];
    for spelling in spellings.iter().cycle().take(5) {
        assert_eq!(
            start(&c, &base, spelling, "wrong", "192.0.2.152").0,
            StatusCode::OK
        );
    }
    for spelling in &spellings {
        assert_eq!(
            start(&c, &base, spelling, "wrong", "192.0.2.152").0,
            StatusCode::TOO_MANY_REQUESTS,
            "{spelling}"
        );
    }
    // The new name still signs in from that address.
    let (status, _, _) = opaque_login(&c, &base, &new, &user.password, "session", None, None);
    assert_eq!(status, StatusCode::OK);
    purge_accounts(&c, &base, &[&user]);
}

#[test]
fn one_account_per_folded_name() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let taken = name("fold_");
    let user = register_as(&c, &base, &taken).unwrap();
    // Another spelling of it is the same name.
    assert_eq!(
        register_named(&c, &base, &taken.replace('_', "-")),
        StatusCode::CONFLICT
    );
    assert_eq!(
        register_named(&c, &base, &taken.replace('_', "")),
        StatusCode::CONFLICT
    );
    // So is a rename to one, by someone else.
    let other = register(&c, &base);
    let (status, body) = rename(&c, &base, &other, &taken.replace('_', ""));
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "nameTaken");
    let check: Value = get(
        &c,
        &base,
        &other.token,
        &format!("/api/user/rename/check?name={}", taken.replace('_', "-")),
    )
    .json()
    .unwrap();
    assert_eq!(check, json!({ "available": false, "reason": "taken" }));
    purge_accounts(&c, &base, &[&user, &other]);
}

#[test]
fn a_deleted_accounts_name_is_held_until_freed() {
    // (The break-glass account's refusal, 403 breakGlassAccount, needs the
    // admin's own keys to sign a statement; it is checked in review.)
    let (Ok(base), Ok(admin)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_ADMIN"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_ADMIN not set; skipping");
        return;
    };
    let c = client();
    let (admin_name, admin_password) = admin.split_once(':').unwrap();
    let token = admin_token(&c, &base, admin_password, admin_name);
    let gone = register(&c, &base);
    let r = bearer(
        c.delete(format!("{base}/api/admin/users/{}", gone.id)),
        &token,
    )
    .send()
    .unwrap();
    assert!(r.status().is_success());
    // Nobody takes it while it is held...
    assert_eq!(
        register_named(&c, &base, &gone.username),
        StatusCode::CONFLICT
    );
    // ...until an administrator frees it: a new account, a new incarnation.
    let r = bearer(
        c.post(format!("{base}/api/admin/names/{}/free", gone.username)),
        &token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let taker = register_as(&c, &base, &gone.username).unwrap();
    assert_ne!(
        taker.identity.incarnation_id(),
        gone.identity.incarnation_id()
    );
    purge_accounts(&c, &base, &[&taker]);
}
