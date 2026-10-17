//! A rotation of the server's OPAQUE setup (docs/plans/opaque.md §5), in two
//! runs around a restart that adds a setup key:
//! - `KUTUP_ROTATION_PHASE=before`: an account registered under the only
//!   setup, written to `KUTUP_ROTATION_FILE`;
//! - `KUTUP_ROTATION_PHASE=after` (the server now has a newer key): its
//!   sign-in carries a `rotate` grant; moving the record keeps every session
//!   and the master key, is a security event, and happens once. A second
//!   `rotate` grant, or one used as a password change, is refused.
//!
//! Needs `KUTUP_LIVE_SERVER`, the two variables above,
//! `KUTUP_LIVE_DATABASE_URL` (after) and `KUTUP_LIVE_ADMIN` to purge the
//! account.

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

fn live(c: &Client, base: &str, token: &str) -> StatusCode {
    bearer(c.get(format!("{base}/api/user/me")), token)
        .send()
        .unwrap()
        .status()
}

/// Moves `user`'s record with `grant` (from `token`'s session), the same
/// password: its status.
fn rotate(
    c: &Client,
    base: &str,
    user: &User,
    password: &str,
    grant: &str,
    token: &str,
) -> StatusCode {
    let (record, key_id, export_key) =
        match try_opaque_register(c, base, password, &user.binding, Some(grant), None) {
            Ok(registered) => registered,
            Err((status, _)) => return status,
        };
    c.post(format!("{base}/api/auth/opaque/register/finish"))
        .bearer_auth(token)
        .json(&json!({
            "grant": grant, "keyBinding": user.binding,
            "opaqueRecord": record, "opaqueServerKeyId": key_id,
            "masterKeyEnvelope": export_key.seal_master_key(&user.master_key, &user.binding).unwrap(),
        }))
        .send()
        .unwrap()
        .status()
}

#[test]
fn a_rotation_moves_the_record_once_and_shows() {
    let (Ok(base), Ok(phase), Ok(file)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_ROTATION_PHASE"),
        std::env::var("KUTUP_ROTATION_FILE"),
    ) else {
        eprintln!(
            "KUTUP_LIVE_SERVER, KUTUP_ROTATION_PHASE or KUTUP_ROTATION_FILE not set; skipping"
        );
        return;
    };
    let c = client();
    if phase == "before" {
        let user = register(&c, &base);
        let session = sign_in(&c, &base, &user.username, &user.password);
        assert_eq!(session["rotate"], Value::Null, "nothing to move yet");
        std::fs::write(
            &file,
            json!({
                "id": user.id, "binding": user.binding, "username": user.username,
                "password": user.password, "masterKey": b64(&user.master_key),
                "recoveryEntropy": b64(&user.recovery_entropy), "account": user.account,
            })
            .to_string(),
        )
        .unwrap();
        return;
    }
    assert_eq!(phase, "after");
    let saved: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    let text = |key: &str| saved[key].as_str().unwrap().to_owned();
    let bytes = |key: &str| -> [u8; 32] { b64_decode(&text(key)).try_into().unwrap() };
    let master_key = bytes("masterKey");
    let first = sign_in(&c, &base, &text("username"), &text("password"));
    let mut user = User {
        id: text("id"),
        binding: text("binding"),
        username: text("username"),
        password: text("password"),
        recovery_entropy: bytes("recoveryEntropy"),
        token: first["accessToken"].as_str().unwrap().to_owned(),
        identity: kutup_crypto::identity::AccountIdentityKeysV1::derive(&master_key).unwrap(),
        master_key,
        person: kutup_crypto::account_ref::AccountRef::new(&server_domain(&c, &base), &text("id"))
            .unwrap(),
        account: text("account"),
    };
    // Each sign-in under the retired setup is offered the move.
    assert_eq!(first["rotate"], true, "{first}");
    let grant = first["grant"].as_str().unwrap().to_owned();
    let second = sign_in(&c, &base, &user.username, &user.password);
    assert_eq!(second["rotate"], true);
    let second_grant = second["grant"].as_str().unwrap().to_owned();
    let second_token = second["accessToken"].as_str().unwrap().to_owned();
    // The guard itself: an account already on the current setup is moved by
    // no rotate grant (here the account is put there behind the server's
    // back, and back again: the refused move leaves the grant unused).
    let database_url = std::env::var("KUTUP_LIVE_DATABASE_URL").expect("KUTUP_LIVE_DATABASE_URL");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let pool = runtime
        .block_on(sqlx::PgPool::connect(&database_url))
        .unwrap();
    let set_key = |sql: &str| {
        runtime
            .block_on(sqlx::query(sql).bind(&user.id).execute(&pool))
            .unwrap();
    };
    set_key(
        "UPDATE users SET opaque_server_key_id = (SELECT max(key_id) FROM opaque_server_setups)
         WHERE id = $1::uuid",
    );
    assert_eq!(
        rotate(
            &c,
            &base,
            &user,
            &user.password.clone(),
            &grant,
            &user.token
        ),
        StatusCode::FORBIDDEN,
        "already on the current setup"
    );
    set_key(
        "UPDATE users SET opaque_server_key_id = (SELECT min(key_id) FROM opaque_server_setups)
         WHERE id = $1::uuid",
    );
    // A rotate grant is no password change.
    assert_eq!(
        rotate(
            &c,
            &base,
            &user,
            "a-different-password-9",
            &second_grant,
            &user.token
        ),
        StatusCode::FORBIDDEN,
        "another session's grant"
    );
    assert_eq!(
        rotate(
            &c,
            &base,
            &user,
            &user.password.clone(),
            &grant,
            &user.token
        ),
        StatusCode::NO_CONTENT
    );
    // Moved once: the other grant is over, and nobody's sign-in ended.
    assert_eq!(
        rotate(
            &c,
            &base,
            &user,
            "a-different-password-9",
            &second_grant,
            &second_token
        ),
        StatusCode::FORBIDDEN
    );
    assert_eq!(live(&c, &base, &user.token), StatusCode::OK);
    assert_eq!(live(&c, &base, &second_token), StatusCode::OK);
    // The same password opens the same master key, with nothing left to move.
    let (status, session, export_key) = opaque_login(
        &c,
        &base,
        &user.username,
        &user.password,
        "session",
        None,
        None,
    );
    assert_eq!(status, StatusCode::OK);
    assert_eq!(session["rotate"], Value::Null, "nothing left to move");
    let opened = export_key
        .unwrap()
        .open_master_key(
            session["masterKeyEnvelope"].as_str().unwrap(),
            &user.binding,
        )
        .unwrap();
    assert_eq!(opened.as_slice(), user.master_key.as_slice());
    // The owner sees it.
    let events: Value = bearer(
        c.get(format!("{base}/api/user/security-events")),
        &user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    let kinds: Vec<&str> = events["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["rotate"], "{events}");
    assert_eq!(events["events"][0]["thisSession"], true);
    user.token = session["accessToken"].as_str().unwrap().to_owned();
    purge_accounts(&c, &base, &[&user]);
}
