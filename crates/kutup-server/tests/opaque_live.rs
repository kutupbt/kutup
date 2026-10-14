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
    let change = |grant: &str, token: Option<&str>| {
        let (record, key_id, export_key) =
            opaque_register(&c, &base, new_password, &user.binding, Some(grant), None);
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
    let grant: Value = grant_for(proof.as_slice()).json().unwrap();
    let grant = grant["grant"].as_str().unwrap().to_owned();
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
