//! Live e2e for collaboration devices signed by their account
//! (docs/plans/device-registration.md): only a statement by the account's own
//! authority, over a fresh challenge from this server, registers a device; a
//! device of an earlier incarnation or a revoked one is not trusted.
//!
//! Gated on `KUTUP_LIVE_SERVER` (and `KUTUP_LIVE_ADMIN` to purge its accounts).

use rand::RngCore;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

mod common;
use common::*;

fn device_key() -> [u8; 32] {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes()
}

fn post_device(c: &Client, base: &str, user: &User, body: &Value) -> (StatusCode, Value) {
    let r = bearer(c.post(format!("{base}/api/devices")), &user.token)
        .json(body)
        .send()
        .unwrap();
    let status = r.status();
    (status, r.json().unwrap_or(Value::Null))
}

#[test]
fn only_the_accounts_own_statement_registers_a_device() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER unset; skipping");
        return;
    };
    let c = Client::new();
    let alice = register(&c, &base);
    let mallory = register(&c, &base);
    let key = device_key();

    // No statement (what the web sent before): refused.
    let challenge = device_challenge(&c, &base, &alice);
    let (status, body) = post_device(
        &c,
        &base,
        &alice,
        &json!({
            "publicSigning": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key),
            "label": "x", "challenge": challenge, "signature": "",
        }),
    );
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "deviceNotAuthorized");
    // The challenge was used up by that answer.
    let (status, _) = post_device(
        &c,
        &base,
        &alice,
        &device_registration_body(&c, &base, &alice, &alice, &key, &challenge),
    );
    assert_eq!(status, StatusCode::FORBIDDEN, "a used challenge");

    // Signed by another account's authority: refused.
    let challenge = device_challenge(&c, &base, &alice);
    let (status, body) = post_device(
        &c,
        &base,
        &alice,
        &device_registration_body(&c, &base, &alice, &mallory, &key, &challenge),
    );
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("deviceNotAuthorized"))
    );
    // Another account's challenge: refused.
    let theirs = device_challenge(&c, &base, &mallory);
    let (status, _) = post_device(
        &c,
        &base,
        &alice,
        &device_registration_body(&c, &base, &alice, &alice, &key, &theirs),
    );
    assert_eq!(status, StatusCode::FORBIDDEN);
    // A made-up challenge: refused.
    let made_up = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [7u8; 32]);
    let (status, _) = post_device(
        &c,
        &base,
        &alice,
        &device_registration_body(&c, &base, &alice, &alice, &key, &made_up),
    );
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The account's own statement over a fresh challenge: registered.
    let challenge = device_challenge(&c, &base, &alice);
    let body = device_registration_body(&c, &base, &alice, &alice, &key, &challenge);
    let (status, created) = post_device(&c, &base, &alice, &body);
    assert_eq!(status, StatusCode::CREATED, "{created}");
    // Played again: the challenge is gone.
    let (status, _) = post_device(&c, &base, &alice, &body);
    assert_eq!(status, StatusCode::FORBIDDEN);
    // The same key for another account: refused.
    let challenge = device_challenge(&c, &base, &mallory);
    let (status, _) = post_device(
        &c,
        &base,
        &mallory,
        &device_registration_body(&c, &base, &mallory, &mallory, &key, &challenge),
    );
    assert_eq!(status, StatusCode::CONFLICT);

    // At most five challenges stay open: the oldest of six is gone.
    let first = device_challenge(&c, &base, &alice);
    for _ in 0..5 {
        device_challenge(&c, &base, &alice);
    }
    let (status, _) = post_device(
        &c,
        &base,
        &alice,
        &device_registration_body(&c, &base, &alice, &alice, &device_key(), &first),
    );
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the oldest challenge was evicted"
    );

    // A revoked device is not trusted on the collaboration routes.
    let device = created["deviceId"].as_i64().unwrap();
    // Revoking takes the account's signed revocation: a session alone, or
    // another account's statement, cannot revoke.
    let revoke = |body: Value| {
        bearer(
            c.delete(format!("{base}/api/devices/{device}")),
            &alice.token,
        )
        .json(&body)
        .send()
        .unwrap()
        .status()
    };
    assert_eq!(
        revoke(json!({ "revokedAtMs": 1, "signature": "" })),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        revoke(device_revocation_body(&c, &base, &mallory, &key)),
        StatusCode::FORBIDDEN
    );
    assert!(revoke(device_revocation_body(&c, &base, &alice, &key)).is_success());
    // Its key never registers again.
    let challenge = device_challenge(&c, &base, &alice);
    let (status, _) = post_device(
        &c,
        &base,
        &alice,
        &device_registration_body(&c, &base, &alice, &alice, &key, &challenge),
    );
    assert_eq!(status, StatusCode::CONFLICT);
    let folder = create_folder(&c, &base, &alice);
    let file = seal_file(&folder, &uuid(), b"x");
    assert!(upload(&c, &base, &alice.token, &folder, &file)
        .status()
        .is_success());
    let r = bearer(
        c.get(format!(
            "{base}/api/files/{}/collab/frames?deviceId={device}&after=0",
            file.id
        )),
        &alice.token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let body: Value = r.json().unwrap();
    assert_eq!(body["code"], "deviceNotAuthorized");
    purge_accounts(&c, &base, &[&alice, &mallory]);
}

fn devices(c: &Client, base: &str, user: &User) -> Vec<Value> {
    bearer(c.get(format!("{base}/api/devices")), &user.token)
        .send()
        .unwrap()
        .json::<Vec<Value>>()
        .unwrap()
}

fn row(rows: &[Value], id: i64) -> Value {
    rows.iter()
        .find(|r| r["deviceId"] == id)
        .cloned()
        .unwrap_or_else(|| panic!("device {id} listed"))
}

/// A device lives with the sign-in that registered it: a sign-out retires
/// it (no signature needed, not revoked for good); a renewal under another
/// live sign-in takes it up again; the cap counts only devices in use.
#[test]
fn a_device_lives_with_its_sign_in() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER unset; skipping");
        return;
    };
    let c = Client::new();
    let mut alice = register(&c, &base);
    let device = register_device(&c, &base, &alice);
    let key = ed25519_dalek::SigningKey::from_bytes(&device.seed)
        .verifying_key()
        .to_bytes();
    let folder = create_folder(&c, &base, &alice);
    let file = seal_file(&folder, &uuid(), b"x");
    assert!(upload(&c, &base, &alice.token, &folder, &file)
        .status()
        .is_success());
    let frames = |user: &User, device: i64| {
        bearer(
            c.get(format!(
                "{base}/api/files/{}/collab/frames?deviceId={device}&after=0",
                file.id
            )),
            &user.token,
        )
        .send()
        .unwrap()
        .status()
    };
    assert_eq!(frames(&alice, device.id), StatusCode::OK);
    let listed = row(&devices(&c, &base, &alice), device.id);
    assert_eq!(
        (&listed["trusted"], &listed["inUse"], &listed["thisSession"]),
        (&json!(true), &json!(true), &json!(true))
    );

    // Signed out: the device is retired, though not revoked.
    let first = alice.token.clone();
    alice.token = sign_in_again(&c, &base, &alice);
    assert!(bearer(c.post(format!("{base}/api/auth/logout")), &first)
        .send()
        .unwrap()
        .status()
        .is_success());
    let listed = row(&devices(&c, &base, &alice), device.id);
    assert_eq!(
        (
            &listed["isActive"],
            &listed["trusted"],
            &listed["inUse"],
            &listed["thisSession"]
        ),
        (&json!(true), &json!(false), &json!(false), &json!(false))
    );
    let r = bearer(
        c.get(format!(
            "{base}/api/files/{}/collab/frames?deviceId={}&after=0",
            file.id, device.id
        )),
        &alice.token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_eq!(r.json::<Value>().unwrap()["code"], "deviceNotAuthorized");

    // Renewed under the live sign-in (the account's statement again): back.
    let challenge = device_challenge(&c, &base, &alice);
    let body = device_registration_body(&c, &base, &alice, &alice, &key, &challenge);
    let renew = json!({
        "challenge": body["challenge"],
        "issuedAtMs": body["issuedAtMs"],
        "signature": body["signature"],
    });
    let r = bearer(
        c.post(format!("{base}/api/devices/{}/renew", device.id)),
        &alice.token,
    )
    .json(&renew)
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert_eq!(frames(&alice, device.id), StatusCode::OK);
    assert_eq!(
        row(&devices(&c, &base, &alice), device.id)["thisSession"],
        true
    );

    // The cap: 20 in use, the 21st refused...
    for _ in 0..19 {
        register_device(&c, &base, &alice);
    }
    let challenge = device_challenge(&c, &base, &alice);
    let r = bearer(c.post(format!("{base}/api/devices")), &alice.token)
        .json(&device_registration_body(
            &c,
            &base,
            &alice,
            &alice,
            &device_key(),
            &challenge,
        ))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(r.json::<Value>().unwrap()["code"], "tooManyDevices");
    // ...until the sign-in they were made under ends: devices of ended
    // sign-ins are not in use, so a new sign-in registers.
    let second = alice.token.clone();
    alice.token = sign_in_again(&c, &base, &alice);
    assert!(bearer(c.post(format!("{base}/api/auth/logout")), &second)
        .send()
        .unwrap()
        .status()
        .is_success());
    register_device(&c, &base, &alice);
    let in_use = devices(&c, &base, &alice)
        .iter()
        .filter(|r| r["inUse"] == true)
        .count();
    assert_eq!(in_use, 1);
    purge_accounts(&c, &base, &[&alice]);
}
