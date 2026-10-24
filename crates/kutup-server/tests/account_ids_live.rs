//! Permanent account ids (docs/plans/account-ids.md) against a running
//! server: a sign-up gets the id the server minted for it and nothing else,
//! a deleted account's id is never given again, accounts are found by id,
//! and a rename keeps the account and its Drive key binding.
//!
//! Needs `KUTUP_LIVE_SERVER` (and `KUTUP_LIVE_ADMIN` to delete accounts).

mod common;
use common::*;

use kutup_crypto::account_ref::AccountRef;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

fn live() -> Option<(Client, String)> {
    let base = std::env::var("KUTUP_LIVE_SERVER").ok()?;
    Some((
        crate::common::client(),
        base.trim_end_matches('/').to_string(),
    ))
}

fn name() -> String {
    format!(
        "aid{}",
        kutup_crypto::primitives::random_below(1_000_000_000)
    )
}

fn by_id(
    c: &Client,
    base: &str,
    token: &str,
    account_id: &str,
    server: Option<&str>,
) -> reqwest::blocking::Response {
    let mut request = bearer(c.get(format!("{base}/api/users/by-id/{account_id}")), token);
    if let Some(server) = server {
        request = request.query(&[("server", server)]);
    }
    request.send().unwrap()
}

fn refused(result: Result<User, (StatusCode, Value)>) -> (StatusCode, Value) {
    match result {
        Ok(user) => panic!("{} was registered", user.username),
        Err(refusal) => refusal,
    }
}

#[test]
fn sign_up_takes_only_the_id_minted_for_it() {
    let Some((c, base)) = live() else {
        return;
    };
    // The account is the id register/start minted (checked in the helper),
    // and `/user/me` names it with this server.
    let alice = register(&c, &base);
    let me = me(&c, &base, &alice.token);
    assert_eq!(me["accountId"], alice.id.as_str());
    assert_eq!(me["server"], alice.person.server.as_str());

    // None given back, or one not minted for this key binding: refused.
    let (status, body) = refused(
        sign_up(&c, &base, true, name(), None, None, |body| {
            body.as_object_mut().unwrap().remove("accountId");
        })
        .0,
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "accountIdInvalid", "{body}");
    let (status, body) = refused(
        sign_up(&c, &base, true, name(), None, None, |body| {
            body["accountIdProof"] = json!("00".repeat(32));
        })
        .0,
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "accountIdInvalid", "{body}");
    // Someone else's id (minted for another key binding) with its proof.
    let (status, body) = refused(
        sign_up(&c, &base, true, name(), None, None, |body| {
            body["accountId"] = json!(alice.id);
        })
        .0,
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "accountIdInvalid", "{body}");

    // The Drive key binding names the minted id: one signed for another
    // account is refused.
    let other = AccountRef::new(&alice.person.server, &uuid::Uuid::new_v4().to_string()).unwrap();
    let (status, _) = refused(
        sign_up(&c, &base, true, name(), None, None, |body| {
            // The sign-up's own keys (the body's), bound to another account.
            let identity =
                kutup_crypto::identity::AccountIdentityKeysV1::derive(&[7u8; 32]).unwrap();
            body["accountAuthorityPublicKey"] = json!(b64(&identity.authority_public_key()));
            body["accountAuthorityKeyId"] = json!(identity.authority_key_id());
            body["accountIncarnationId"] = json!(identity.incarnation_id());
            body["publicKey"] = json!(b64(&identity.drive_hpke_public_key()));
            body["driveSigningPublicKey"] = json!(b64(&identity.drive_signing_public_key()));
            body["driveKeyBinding"] = json!(b64(&kutup_crypto::drive_key_binding::sign(
                &identity, &other, 1
            )
            .unwrap()));
        })
        .0,
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    purge_accounts(&c, &base, &[&alice]);
}

#[test]
fn a_deleted_accounts_id_is_never_given_again() {
    let Some((c, base)) = live() else {
        return;
    };
    let Ok(admin) = std::env::var("KUTUP_LIVE_ADMIN") else {
        eprintln!("KUTUP_LIVE_ADMIN unset; skipping");
        return;
    };
    let (admin_name, admin_password) = admin.split_once(':').unwrap();
    let (user, sent) = sign_up(&c, &base, true, name(), None, None, |_| {});
    let user = user.unwrap();
    let sent = sent.unwrap();
    let token = admin_token(&c, &base, admin_password, admin_name);
    let r = bearer(
        c.delete(format!("{base}/api/admin/users/{}", user.id)),
        &token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);

    // The same key binding is free again and the proof is still the
    // server's own for it, but the id is retired.
    let (result, _) = sign_up(
        &c,
        &base,
        true,
        name(),
        None,
        Some(sent.key_binding.clone()),
        |body| {
            body["accountId"] = json!(sent.account_id);
            body["accountIdProof"] = json!(sent.account_id_proof);
        },
    );
    let (status, body) = refused(result);
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "accountIdTaken", "{body}");
}

#[test]
fn accounts_are_found_by_id_and_keep_it_through_a_rename() {
    let Some((c, base)) = live() else {
        return;
    };
    let (alice, bob) = (register(&c, &base), register(&c, &base));

    let found: Value = by_id(&c, &base, &bob.token, &alice.id, None)
        .json()
        .unwrap();
    assert_eq!(found["server"], alice.person.server.as_str());
    assert_eq!(found["accountId"], alice.id.as_str());
    assert_eq!(found["account"], alice.account.as_str());
    let binding = found["driveKeyBinding"].as_str().unwrap().to_owned();
    // Naming this server explicitly is the same lookup.
    let again: Value = by_id(&c, &base, &bob.token, &alice.id, Some(&alice.person.server))
        .json()
        .unwrap();
    assert_eq!(again, found);

    // No such account; not an account id at all; not a server name.
    let nobody = uuid::Uuid::new_v4().to_string();
    assert_eq!(
        by_id(&c, &base, &bob.token, &nobody, None).status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        by_id(&c, &base, &bob.token, "alice", None).status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        by_id(&c, &base, &bob.token, &alice.id.to_uppercase(), None).status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        by_id(&c, &base, &bob.token, &alice.id, Some("127.0.0.1")).status(),
        StatusCode::BAD_REQUEST
    );
    // Signed in only.
    assert_eq!(
        c.get(format!("{base}/api/users/by-id/{}", alice.id))
            .send()
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );

    // A rename: the same account, its new address, the same binding (it
    // names the id, so nothing is signed again), and it still verifies.
    let to = name();
    let renamed = rename_account(&c, &base, &alice, &to, false);
    assert!(renamed.status.is_success(), "rename: {}", renamed.body);
    let after: Value = by_id(&c, &base, &bob.token, &alice.id, None)
        .json()
        .unwrap();
    assert_eq!(after["accountId"], alice.id.as_str());
    assert_eq!(after["account"], format!("{to}@{}", alice.person.server));
    assert_eq!(after["driveKeyBinding"], binding.as_str());
    let key = |field: &str| -> [u8; 32] {
        b64_decode(after[field].as_str().unwrap())
            .try_into()
            .unwrap()
    };
    assert_eq!(after["identitySuite"], 2);
    kutup_crypto::drive_key_binding::verify(
        &alice.person,
        &key("accountAuthorityPublicKey"),
        after["driveKeyBindingEpoch"].as_u64().unwrap() as u32,
        &b64_decode(after["driveHpkePublicKey"].as_str().unwrap())
            .try_into()
            .unwrap(),
        &key("driveSigningPublicKey"),
        &b64_decode(&binding),
    )
    .unwrap();
    // The new address leads to the same account.
    let lookup: Value = bearer(
        c.get(format!(
            "{base}/api/users/by-address/{to}@{}",
            alice.person.server
        )),
        &bob.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert_eq!(lookup["accountId"], alice.id.as_str());
    assert_eq!(lookup["server"], alice.person.server.as_str());

    purge_accounts(&c, &base, &[&alice, &bob]);
}
