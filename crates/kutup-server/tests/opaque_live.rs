//! OPAQUE sign-in and new passwords against a live server
//! (docs/plans/opaque.md): a login id finishes once, the per-name cap drops
//! the oldest, a password change ends the account's other sign-ins and a
//! recovery all of them, and every grant is bound to its account, purpose
//! and session.
//!
//! Needs `KUTUP_LIVE_SERVER` (and `KUTUP_LIVE_ADMIN` to purge its accounts).

mod common;

use common::*;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

fn client() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

/// A start from `ip` with `password`: (login id, the client's finalization).
fn start(c: &Client, base: &str, name: &str, password: &str, ip: &str) -> (Value, Vec<u8>) {
    let (signing_in, ke1) = kutup_crypto::opaque::client_login_start(password).unwrap();
    let r = c
        .post(format!("{base}/api/auth/login/start"))
        .header("x-kutup-client", "cli")
        .header("x-real-ip", ip)
        .json(&json!({ "name": name, "credentialRequest": b64(&ke1) }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body: Value = r.json().unwrap();
    let ke2 = b64_decode(body["credentialResponse"].as_str().unwrap());
    let ke3 = signing_in.finish(&ke2).unwrap().finalization;
    (body["loginId"].clone(), ke3)
}

fn finish(c: &Client, base: &str, login_id: &Value, ke3: &[u8]) -> StatusCode {
    c.post(format!("{base}/api/auth/login/finish"))
        .header("x-kutup-client", "cli")
        .json(&json!({ "loginId": login_id, "credentialFinalization": b64(ke3) }))
        .send()
        .unwrap()
        .status()
}

fn live(c: &Client, base: &str, token: &str) -> StatusCode {
    bearer(c.get(format!("{base}/api/user/me")), token)
        .send()
        .unwrap()
        .status()
}

#[test]
fn a_login_id_finishes_once_and_the_oldest_of_too_many_goes() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let user = register(&c, &base);
    let (id, ke3) = start(&c, &base, &user.username, &user.password, "192.0.2.50");
    assert_eq!(finish(&c, &base, &id, &ke3), StatusCode::OK);
    assert_eq!(
        finish(&c, &base, &id, &ke3),
        StatusCode::UNAUTHORIZED,
        "used"
    );
    // Six under way for one name (from six addresses, under the lockout):
    // the first is gone, the last finishes.
    let pending: Vec<(Value, Vec<u8>)> = (0..6)
        .map(|i| {
            start(
                &c,
                &base,
                &user.username,
                &user.password,
                &format!("192.0.2.{}", 60 + i),
            )
        })
        .collect();
    assert_eq!(
        finish(&c, &base, &pending[0].0, &pending[0].1),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        finish(&c, &base, &pending[5].0, &pending[5].1),
        StatusCode::OK
    );
    purge_accounts(&c, &base, &[&user]);
}

#[test]
fn a_new_password_ends_the_other_sign_ins_and_keeps_the_master_key() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let mut user = register(&c, &base);
    let other = sign_in(&c, &base, &user.username, &user.password)["accessToken"]
        .as_str()
        .unwrap()
        .to_owned();
    let new_password = "a-new-password-654321";
    // A grant that does not fit is refused at register/start already.
    let change = |grant: &str, token: Option<&str>| {
        let (record, key_id, export_key) =
            match try_opaque_register(&c, &base, new_password, &user.binding, Some(grant), None) {
                Ok(registered) => registered,
                Err((status, _)) => return status,
            };
        let mut request = c
            .post(format!("{base}/api/auth/opaque/register/finish"))
            .json(&json!({
                "grant": grant, "keyBinding": user.binding,
                "opaqueRecord": record, "opaqueServerKeyId": key_id,
                "masterKeyEnvelope": export_key.seal_master_key(&user.master_key, &user.binding).unwrap(),
            }));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        request.send().unwrap().status()
    };
    // A grant for something else, or used by another sign-in: refused.
    let wrong_purpose = reauth_grant(&c, &base, &user, "pass");
    let refused = c
        .post(format!("{base}/api/auth/opaque/register/start"))
        .json(
            &json!({ "keyBinding": user.binding, "registrationRequest": b64(&[0u8; 32]),
                       "grant": wrong_purpose }),
        )
        .send()
        .unwrap();
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let grant = reauth_grant(&c, &base, &user, "passwordChange");
    assert_eq!(
        change(&grant, Some(&other)),
        StatusCode::FORBIDDEN,
        "another sign-in's"
    );
    assert_eq!(change(&grant, Some(&user.token)), StatusCode::NO_CONTENT);
    assert_eq!(
        change(&grant, Some(&user.token)),
        StatusCode::FORBIDDEN,
        "used once"
    );
    // This sign-in goes on; the other is over.
    assert_eq!(live(&c, &base, &user.token), StatusCode::OK);
    assert_eq!(live(&c, &base, &other), StatusCode::UNAUTHORIZED);
    // The old password no longer opens anything; the new one opens the same
    // master key.
    let (status, _, _) = opaque_login(
        &c,
        &base,
        &user.username,
        &user.password,
        "session",
        None,
        None,
    );
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, session, export_key) = opaque_login(
        &c,
        &base,
        &user.username,
        new_password,
        "session",
        None,
        None,
    );
    assert_eq!(status, StatusCode::OK);
    let master = export_key
        .unwrap()
        .open_master_key(
            session["masterKeyEnvelope"].as_str().unwrap(),
            &user.binding,
        )
        .unwrap();
    assert_eq!(master.as_slice(), user.master_key.as_slice());
    user.password = new_password.to_owned();
    purge_accounts(&c, &base, &[&user]);
}

#[test]
fn a_recovery_sets_a_new_password_and_ends_every_sign_in() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let mut user = register(&c, &base);
    let proof =
        kutup_crypto::kdf::derive_recovery_auth_proof(&user.recovery_entropy, &user.binding)
            .unwrap();
    let grant_for = |proof: &[u8]| {
        c.post(format!("{base}/api/auth/recover/grant"))
            .json(&json!({ "name": user.username, "recoveryProof": b64(proof) }))
            .send()
            .unwrap()
    };
    assert_eq!(grant_for(&[7u8; 32]).status(), StatusCode::UNAUTHORIZED);
    let granted: Value = grant_for(proof.as_slice()).json().unwrap();
    let grant = granted["grant"]
        .as_str()
        .unwrap_or_else(|| panic!("recovery grant: {granted}"))
        .to_owned();
    let new_password = "recovered-password-112233";
    let (record, key_id, export_key) =
        opaque_register(&c, &base, new_password, &user.binding, Some(&grant), None);
    let r = c
        .post(format!("{base}/api/auth/opaque/register/finish"))
        .json(&json!({
            "grant": grant, "keyBinding": user.binding,
            "opaqueRecord": record, "opaqueServerKeyId": key_id,
            "masterKeyEnvelope": export_key.seal_master_key(&user.master_key, &user.binding).unwrap(),
        }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        live(&c, &base, &user.token),
        StatusCode::UNAUTHORIZED,
        "every sign-in ends"
    );
    user.password = new_password.to_owned();
    let session = sign_in(&c, &base, &user.username, &user.password);
    user.token = session["accessToken"].as_str().unwrap().to_owned();
    purge_accounts(&c, &base, &[&user]);
}

/// A new password for `user` with `grant` from `token`'s session: its status.
fn set_password(
    c: &Client,
    base: &str,
    user: &User,
    grant: &str,
    token: Option<&str>,
    password: &str,
) -> StatusCode {
    let (record, key_id, export_key) =
        match try_opaque_register(c, base, password, &user.binding, Some(grant), None) {
            Ok(registered) => registered,
            Err((status, _)) => return status,
        };
    let mut request = c
        .post(format!("{base}/api/auth/opaque/register/finish"))
        .json(&json!({
            "grant": grant, "keyBinding": user.binding,
            "opaqueRecord": record, "opaqueServerKeyId": key_id,
            "masterKeyEnvelope": export_key.seal_master_key(&user.master_key, &user.binding).unwrap(),
        }));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    request.send().unwrap().status()
}

fn security_events(c: &Client, base: &str, token: &str, query: &str) -> Value {
    let r = bearer(
        c.get(format!("{base}/api/user/security-events{query}")),
        token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    r.json().unwrap()
}

#[test]
fn a_sign_in_that_straddles_a_new_password_gets_nothing() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let mut user = register(&c, &base);
    // Started with the old password, finished after a password change.
    let (id, ke3) = start(&c, &base, &user.username, &user.password, "192.0.2.90");
    let grant = reauth_grant(&c, &base, &user, "passwordChange");
    let changed = "straddled-password-445566";
    assert_eq!(
        set_password(&c, &base, &user, &grant, Some(&user.token), changed),
        StatusCode::NO_CONTENT
    );
    user.password = changed.to_owned();
    assert_eq!(finish(&c, &base, &id, &ke3), StatusCode::UNAUTHORIZED);
    // And across a recovery.
    let (id, ke3) = start(&c, &base, &user.username, &user.password, "192.0.2.91");
    let proof =
        kutup_crypto::kdf::derive_recovery_auth_proof(&user.recovery_entropy, &user.binding)
            .unwrap();
    let granted: Value = c
        .post(format!("{base}/api/auth/recover/grant"))
        .json(&json!({ "name": user.username, "recoveryProof": b64(proof.as_slice()) }))
        .send()
        .unwrap()
        .json()
        .unwrap();
    let recovered = "recovered-after-start-778899";
    assert_eq!(
        set_password(
            &c,
            &base,
            &user,
            granted["grant"].as_str().unwrap(),
            None,
            recovered
        ),
        StatusCode::NO_CONTENT
    );
    user.password = recovered.to_owned();
    assert_eq!(finish(&c, &base, &id, &ke3), StatusCode::UNAUTHORIZED);
    user.token = sign_in(&c, &base, &user.username, &user.password)["accessToken"]
        .as_str()
        .unwrap()
        .to_owned();
    purge_accounts(&c, &base, &[&user]);
}

#[test]
fn a_grant_is_used_once_even_at_once() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let mut user = register(&c, &base);
    let grant = reauth_grant(&c, &base, &user, "passwordChange");
    let statuses: Vec<StatusCode> = std::thread::scope(|scope| {
        let runs: Vec<_> = ["racing-password-one-1", "racing-password-two-2"]
            .into_iter()
            .map(|password| {
                let (c, base, user, grant) = (&c, &base, &user, &grant);
                scope.spawn(move || set_password(c, base, user, grant, Some(&user.token), password))
            })
            .collect();
        runs.into_iter().map(|run| run.join().unwrap()).collect()
    });
    let won = statuses
        .iter()
        .filter(|s| **s == StatusCode::NO_CONTENT)
        .count();
    assert_eq!(won, 1, "{statuses:?}");
    assert!(statuses.contains(&StatusCode::FORBIDDEN), "{statuses:?}");
    // Whichever won is the password now.
    user.password = ["racing-password-one-1", "racing-password-two-2"]
        .into_iter()
        .find(|p| {
            opaque_login(&c, &base, &user.username, p, "session", None, None).0 == StatusCode::OK
        })
        .expect("one of the two")
        .to_owned();
    purge_accounts(&c, &base, &[&user]);
}

#[test]
fn a_reauth_is_for_the_signed_in_account_only() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let (a, b) = (register(&c, &base), register(&c, &base));
    // A's session, B's name and password.
    let (status, _, _) = opaque_login(
        &c,
        &base,
        &b.username,
        &b.password,
        "reauth",
        Some("passwordChange"),
        Some(&a.token),
    );
    assert_eq!(status, StatusCode::FORBIDDEN);
    purge_accounts(&c, &base, &[&a, &b]);
}

#[test]
fn every_spelling_of_a_name_shares_its_lockout() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let user = register(&c, &base);
    let upper = user.username.to_uppercase();
    // A start alone, never finished: a miss.
    let bare_start = |name: &str| {
        let (_, ke1) = kutup_crypto::opaque::client_login_start("a-wrong-password-1").unwrap();
        c.post(format!("{base}/api/auth/login/start"))
            .header("x-kutup-client", "cli")
            .header("x-real-ip", "192.0.2.120")
            .json(&json!({ "name": name, "credentialRequest": b64(&ke1) }))
            .send()
            .unwrap()
            .status()
    };
    // Five misses under other spellings of the name...
    for name in [
        &upper,
        &format!(" {upper} "),
        &upper,
        &format!("{} ", user.username),
        &upper,
    ] {
        assert_eq!(bare_start(name), StatusCode::OK);
    }
    // ...lock it, as spelled any way, for that address.
    assert_eq!(bare_start(&user.username), StatusCode::TOO_MANY_REQUESTS);
    // Another address is not held.
    let (id, ke3) = start(&c, &base, &user.username, &user.password, "192.0.2.121");
    assert_eq!(finish(&c, &base, &id, &ke3), StatusCode::OK);
    purge_accounts(&c, &base, &[&user]);
}

#[test]
fn security_events_record_changes_for_their_owner_only() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let mut user = register(&c, &base);
    let other = register(&c, &base);
    assert_eq!(
        security_events(&c, &base, &user.token, "")["events"],
        json!([])
    );
    // A password change from this session, then a recovery from none.
    let grant = reauth_grant(&c, &base, &user, "passwordChange");
    let changed = "evented-password-112233";
    assert_eq!(
        set_password(&c, &base, &user, &grant, Some(&user.token), changed),
        StatusCode::NO_CONTENT
    );
    user.password = changed.to_owned();
    let proof =
        kutup_crypto::kdf::derive_recovery_auth_proof(&user.recovery_entropy, &user.binding)
            .unwrap();
    let granted: Value = c
        .post(format!("{base}/api/auth/recover/grant"))
        .json(&json!({ "name": user.username, "recoveryProof": b64(proof.as_slice()) }))
        .send()
        .unwrap()
        .json()
        .unwrap();
    let recovered = "evented-recovered-445566";
    assert_eq!(
        set_password(
            &c,
            &base,
            &user,
            granted["grant"].as_str().unwrap(),
            None,
            recovered
        ),
        StatusCode::NO_CONTENT
    );
    user.password = recovered.to_owned();
    user.token = sign_in(&c, &base, &user.username, &user.password)["accessToken"]
        .as_str()
        .unwrap()
        .to_owned();
    // Newest first, a page at a time.
    let first = security_events(&c, &base, &user.token, "?limit=1");
    assert_eq!(first["events"][0]["kind"], "recovery");
    assert_eq!(first["events"][0]["thisSession"], false);
    assert_eq!(first["events"][0]["client"], Value::Null);
    let next = first["next"].as_str().expect("a second page");
    let second = security_events(&c, &base, &user.token, &format!("?limit=1&cursor={next}"));
    assert_eq!(second["events"][0]["kind"], "passwordChange");
    assert_eq!(second["events"][0]["client"], "cli");
    assert_eq!(second["events"][0]["byAdmin"], false);
    assert_eq!(second["next"], Value::Null);
    // Nobody else's, and nobody else sees them.
    assert_eq!(
        security_events(&c, &base, &other.token, "")["events"],
        json!([])
    );
    // A cursor is one of the caller's own events: another's, or none, is 400.
    for cursor in [next.to_owned(), uuid::Uuid::new_v4().to_string()] {
        let r = bearer(
            c.get(format!("{base}/api/user/security-events?cursor={cursor}")),
            &other.token,
        )
        .send()
        .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }
    purge_accounts(&c, &base, &[&user, &other]);
}

#[test]
fn two_step_sign_in_changes_take_the_password() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let user = register(&c, &base);
    let setup: Value = bearer(c.post(format!("{base}/api/user/2fa/setup")), &user.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let code = || {
        totp_rs::TOTP::new(
            totp_rs::Algorithm::SHA1,
            6,
            1,
            30,
            totp_rs::Secret::Encoded(setup["secret"].as_str().unwrap().to_owned())
                .to_bytes()
                .unwrap(),
            None,
            String::new(),
        )
        .unwrap()
        .generate_current()
        .unwrap()
    };
    let verify = |grant: &str| {
        bearer(c.post(format!("{base}/api/user/2fa/verify")), &user.token)
            .json(&json!({ "code": code(), "grant": grant }))
            .send()
            .unwrap()
            .status()
    };
    // A code alone, or a grant for something else, turns nothing on.
    assert_eq!(verify(""), StatusCode::FORBIDDEN);
    assert_eq!(
        verify(&reauth_grant(&c, &base, &user, "pass")),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        verify(&reauth_grant(&c, &base, &user, "totp")),
        StatusCode::OK
    );
    // While it is on, its secret stays.
    let again = bearer(c.post(format!("{base}/api/user/2fa/setup")), &user.token)
        .send()
        .unwrap();
    assert_eq!(again.status(), StatusCode::CONFLICT);
    // The second step: a wrong code is tried again, a token that is no
    // longer good goes back to the password.
    let second_step = |token: &str, code: &str| {
        let r = c
            .post(format!("{base}/api/auth/login/2fa"))
            .header("x-kutup-client", "cli")
            .json(&json!({ "preAuthToken": token, "code": code }))
            .send()
            .unwrap();
        let status = r.status();
        (
            status,
            r.json::<Value>().unwrap_or(Value::Null)["code"].clone(),
        )
    };
    let first = sign_in(&c, &base, &user.username, &user.password);
    let pre_auth = first["preAuthToken"]
        .as_str()
        .expect("the second step")
        .to_owned();
    let wrong = if code() == "000000" {
        "111111"
    } else {
        "000000"
    };
    assert_eq!(
        second_step(&pre_auth, wrong),
        (StatusCode::UNAUTHORIZED, json!("invalidCredentials"))
    );
    assert_eq!(
        second_step("not-a-token", &code()),
        (StatusCode::UNAUTHORIZED, json!("preAuthInvalid"))
    );
    // A new password between the two steps: the token is over.
    let mut user = user;
    let grant = reauth_grant(&c, &base, &user, "passwordChange");
    let changed = "two-step-new-password-1";
    assert_eq!(
        set_password(&c, &base, &user, &grant, Some(&user.token), changed),
        StatusCode::NO_CONTENT
    );
    user.password = changed.to_owned();
    assert_eq!(
        second_step(&pre_auth, &code()),
        (StatusCode::UNAUTHORIZED, json!("preAuthInvalid"))
    );
    let disable = |grant: &str| {
        bearer(c.delete(format!("{base}/api/user/2fa")), &user.token)
            .json(&json!({ "code": code(), "grant": grant }))
            .send()
            .unwrap()
            .status()
    };
    assert_eq!(disable(""), StatusCode::FORBIDDEN);
    assert_eq!(
        disable(&reauth_grant(&c, &base, &user, "totp")),
        StatusCode::OK
    );
    purge_accounts(&c, &base, &[&user]);
}

#[test]
fn a_verify_reauth_checks_the_password_and_keeps_nothing() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let user = register(&c, &base);
    let (status, body, _) = opaque_login(
        &c,
        &base,
        &user.username,
        &user.password,
        "reauth",
        Some("verify"),
        Some(&user.token),
    );
    assert_eq!((status, body), (StatusCode::OK, json!({ "ok": true })));
    // A wrong password (a finalization that does not fit its start) is a
    // 401, and counts: four more starts from that address lock the name.
    let reauth_start = |password: &str| {
        let (signing_in, ke1) = kutup_crypto::opaque::client_login_start(password).unwrap();
        let r = bearer(c.post(format!("{base}/api/auth/login/start")), &user.token)
            .header("x-kutup-client", "cli")
            .header("x-real-ip", "192.0.2.140")
            .json(
                &json!({ "name": user.username, "credentialRequest": b64(&ke1),
                           "purpose": "reauth", "for": "verify" }),
            )
            .send()
            .unwrap();
        let status = r.status();
        (status, r.json::<Value>().unwrap_or(Value::Null), signing_in)
    };
    let (_, right, signing_in) = reauth_start(&user.password);
    let ke2 = b64_decode(right["credentialResponse"].as_str().unwrap());
    let other_ke3 = signing_in.finish(&ke2).unwrap().finalization;
    let (_, wrong, _) = reauth_start("not-the-password-1");
    let r = bearer(c.post(format!("{base}/api/auth/login/finish")), &user.token)
        .header("x-kutup-client", "cli")
        .json(&json!({ "loginId": wrong["loginId"], "credentialFinalization": b64(&other_ke3) }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(r.json::<Value>().unwrap()["code"], "invalidCredentials");
    for _ in 0..3 {
        assert_eq!(reauth_start("not-the-password-1").0, StatusCode::OK);
    }
    assert_eq!(
        reauth_start(&user.password).0,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Nor is a setup token anything but one.
    let r = c
        .post(format!("{base}/api/auth/complete-setup"))
        .header("x-kutup-client", "cli")
        .bearer_auth("not-a-token")
        .json(&json!({}))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(r.json::<Value>().unwrap()["code"], "setupTokenInvalid");
    purge_accounts(&c, &base, &[&user]);
}
