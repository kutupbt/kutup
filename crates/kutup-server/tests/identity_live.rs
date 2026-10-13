//! Drive identity (docs/plans/drive-identity-pins.md) against a live server
//! named `kutup.localhost`: Drive key bindings, required at registration,
//! in person lookups, and the synced identity pin list.

use kutup_crypto::drive_key_binding;
use kutup_crypto::identity::AccountIdentityKeysV1;
use kutup_crypto::identity_pins::{self, IdentityPinV1, IdentityPinsV1, PinState};
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

mod common;
use common::*;

fn lookup(c: &Client, base: &str, token: &str, account: &str) -> Value {
    bearer(
        c.get(format!("{base}/api/users/by-address/{account}")),
        token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap()
}

#[test]
fn drive_key_bindings() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = Client::new();
    // A registration must carry its Drive key binding.
    assert_eq!(register_without_binding(&c, &base), StatusCode::BAD_REQUEST);
    let (alice, bob) = (register(&c, &base), register(&c, &base));
    let alice_account = alice.account.clone();
    let bob_account = bob.account.clone();

    // A lookup carries the authority and the binding, which verifies.
    let found = lookup(&c, &base, &bob.token, &alice_account);
    assert_eq!(found["account"], alice_account.as_str());
    let key = |field: &str| key32(found[field].as_str().unwrap());
    drive_key_binding::verify(
        &alice_account,
        &key("accountAuthorityPublicKey"),
        &key("driveHpkePublicKey"),
        &key("driveSigningPublicKey"),
        &base64_decode(found["driveKeyBinding"].as_str().unwrap()),
    )
    .unwrap();
    assert!(lookup(&c, &base, &alice.token, &bob_account)["driveKeyBinding"].is_string());

    // Many people at once: the ones here, by exact address.
    let found: Value = bearer(c.post(format!("{base}/api/users/drive-identities")), &alice.token)
        .json(&json!({ "accounts": [alice_account, bob_account, format!("nobody@{}", server_domain(&c, &base)), "x@elsewhere.example"] }))
        .send()
        .unwrap()
        .json()
        .unwrap();
    let mut accounts: Vec<_> = found
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["account"].as_str().unwrap().to_owned())
        .collect();
    accounts.sort();
    let mut expected = vec![alice_account.clone(), bob_account.clone()];
    expected.sort();
    assert_eq!(accounts, expected);
    assert!(found
        .as_array()
        .unwrap()
        .iter()
        .all(|i| i["driveKeyBinding"].is_string()));
    let too_many: Vec<String> = (0..101).map(|i| format!("u{i}@kutup.localhost")).collect();
    assert_eq!(
        bearer(
            c.post(format!("{base}/api/users/drive-identities")),
            &alice.token
        )
        .json(&json!({ "accounts": too_many }))
        .send()
        .unwrap()
        .status(),
        StatusCode::BAD_REQUEST
    );

    // Registration refuses a binding that does not match the keys sent.
    let mallory = AccountIdentityKeysV1::derive(&[9u8; 32]).unwrap();
    let forged = drive_key_binding::sign(&mallory, &alice_account).unwrap();
    let r = c
        .post(format!("{base}/api/auth/register"))
        .json(&json!({ "username": "forged", "driveKeyBinding": b64(&forged) }))
        .send()
        .unwrap();
    assert!(r.status().is_client_error());
}

#[test]
fn identity_pins_sync_by_revision() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = Client::new();
    let owner = register(&c, &base);
    let binding = owner.binding.clone();
    let key = identity_pins::derive_key(&owner.master_key).unwrap();
    let friend = AccountIdentityKeysV1::derive(&[3u8; 32]).unwrap();
    let list = IdentityPinsV1 {
        pins: vec![IdentityPinV1 {
            account: "friend@kutup.localhost".into(),
            authority_public_key: b64(&friend.authority_public_key()),
            state: PinState::Seen,
            since: "2026-10-10T12:00:00Z".into(),
            replaced: vec![],
        }],
    };
    let get = || {
        bearer(
            c.get(format!("{base}/api/user/identity-pins")),
            &owner.token,
        )
        .send()
        .unwrap()
    };
    let put = |base_revision: i64, envelope: String| {
        bearer(
            c.put(format!("{base}/api/user/identity-pins")),
            &owner.token,
        )
        .json(&json!({ "baseRevision": base_revision, "envelope": envelope }))
        .send()
        .unwrap()
    };
    assert_eq!(get().status(), StatusCode::NOT_FOUND);
    let seal = |revision: u64| b64(&identity_pins::seal(&key, &binding, revision, &list).unwrap());

    // A list is stored on top of the revision it started from (0: none yet),
    // with a newer one in its header; a write that started from another is
    // refused with the current revision.
    const T: u64 = 1_791_633_600_000;
    assert_eq!(put(5, seal(T)).status(), StatusCode::CONFLICT);
    assert_eq!(put(0, seal(T)).status(), StatusCode::NO_CONTENT);
    let again = put(0, seal(T + 1));
    assert_eq!(again.status(), StatusCode::CONFLICT);
    let body: Value = again.json().unwrap();
    assert_eq!(body["code"], "revision_conflict");
    assert_eq!(body["revision"], T);
    // Not newer than its base: refused.
    assert_eq!(put(T as i64, seal(T)).status(), StatusCode::BAD_REQUEST);
    assert_eq!(put(T as i64, seal(T + 7)).status(), StatusCode::NO_CONTENT);
    assert_eq!(put(T as i64, seal(T + 8)).status(), StatusCode::CONFLICT);

    // What comes back carries its revision in its header, for its owner's key binding.
    let stored: Value = get().json().unwrap();
    assert_eq!(stored["revision"], T + 7);
    let sealed = base64_decode(stored["envelope"].as_str().unwrap());
    assert_eq!(
        identity_pins::open(&key, &binding, &sealed).unwrap(),
        (list.clone(), T + 7)
    );
    let mut relabelled = sealed.clone();
    relabelled[17] ^= 1;
    assert!(identity_pins::open(&key, &binding, &relabelled).is_err());

    // Not a sealed list: refused.
    assert_eq!(
        put((T + 7) as i64, b64(b"plain text")).status(),
        StatusCode::BAD_REQUEST
    );
    // Another account sees only its own.
    let other = register(&c, &base);
    assert_eq!(
        bearer(
            c.get(format!("{base}/api/user/identity-pins")),
            &other.token
        )
        .send()
        .unwrap()
        .status(),
        StatusCode::NOT_FOUND
    );
}

fn base64_decode(value: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .unwrap()
}

fn key32(value: &str) -> [u8; 32] {
    base64_decode(value).try_into().unwrap()
}
