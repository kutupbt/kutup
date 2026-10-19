//! The one-way identity suite upgrade (docs/plans/pq-shares.md) against a
//! live server: an account still on suite 1 (an X25519 Drive key) is shown
//! as such and refused shares (`keysPendingUpgrade`) until it moves to suite
//! 2 with a binding its own authority signed; the move happens once.
//!
//! Needs `KUTUP_LIVE_SERVER` and `KUTUP_LIVE_DATABASE_URL` (an account is set
//! back to suite 1 in the database, as one from before X-Wing).

mod common;

use common::*;
use reqwest::StatusCode;
use serde_json::{json, Value};

fn identity_of(c: &reqwest::blocking::Client, base: &str, asker: &User, who: &User) -> Value {
    let found: Value = bearer(
        c.post(format!("{base}/api/users/drive-identities")),
        &asker.token,
    )
    .json(&json!({ "accounts": [who.account] }))
    .send()
    .unwrap()
    .json()
    .unwrap();
    found[0].clone()
}

#[test]
fn a_suite_1_account_upgrades_once_and_is_shared_with_only_after() {
    let (Ok(base), Ok(database_url)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_DATABASE_URL"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_DATABASE_URL not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = crate::common::client();
    let alice = register(&c, &base);
    let bob = register(&c, &base);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let pool = runtime
        .block_on(sqlx::PgPool::connect(&database_url))
        .unwrap();
    let bob_id: uuid::Uuid = bob.id.parse().unwrap();

    // Bob as an account from before X-Wing: suite 1, a 32-byte key.
    let envelope: String = runtime
        .block_on(
            sqlx::query_scalar("SELECT drive_private_key_envelope FROM users WHERE id = $1")
                .bind(bob_id)
                .fetch_one(&pool),
        )
        .unwrap();
    runtime
        .block_on(
            sqlx::query("UPDATE users SET identity_suite = 1, public_key = $2 WHERE id = $1")
                .bind(bob_id)
                .bind(b64(&[7u8; 32]))
                .execute(&pool),
        )
        .unwrap();
    assert_eq!(identity_of(&c, &base, &alice, &bob)["identitySuite"], 1);

    // Nothing is shared to him meanwhile.
    let folder = create_folder(&c, &base, &alice);
    let r = bearer(
        c.post(format!("{base}/api/collections/{}/share", folder.id)),
        &alice.token,
    )
    .json(&json!({
        "recipientUserId": bob.id,
        "namedShareEnvelope": "AAAA",
        "canUpload": false,
        "canDelete": false,
        "uploadQuotaBytes": null,
    }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(r.json::<Value>().unwrap()["code"], "keysPendingUpgrade");

    let upgrade = |user: &User, binding: [u8; 64]| {
        bearer(
            c.post(format!("{base}/api/account/identity-suite")),
            &user.token,
        )
        .json(&json!({
            "publicKey": b64(&bob.identity.drive_hpke_public_key()),
            "driveKeyBinding": b64(&binding),
            "driveKeyBindingEpoch": 1,
            "drivePrivateKeyEnvelope": envelope,
        }))
        .send()
        .unwrap()
    };
    // Someone else's authority can't vouch for Bob's keys.
    let mallory = kutup_crypto::identity::AccountIdentityKeysV1::derive(&[9u8; 32]).unwrap();
    let forged = kutup_crypto::drive_key_binding::sign(&mallory, &bob.person, 1).unwrap();
    assert_eq!(upgrade(&bob, forged).status(), StatusCode::BAD_REQUEST);

    // His own binding: upgraded, once.
    let binding = kutup_crypto::drive_key_binding::sign(&bob.identity, &bob.person, 1).unwrap();
    assert_eq!(upgrade(&bob, binding).status(), StatusCode::NO_CONTENT);
    let again = upgrade(&bob, binding);
    assert_eq!(again.status(), StatusCode::CONFLICT);
    assert_eq!(
        again.json::<Value>().unwrap()["code"],
        "identitySuiteCurrent"
    );
    let found = identity_of(&c, &base, &alice, &bob);
    assert_eq!(found["identitySuite"], 2);
    assert_eq!(found["driveKeyBindingEpoch"], 1);
    assert_eq!(
        found["driveHpkePublicKey"],
        b64(&bob.identity.drive_hpke_public_key())
    );

    // Now shared with as anyone.
    share(&c, &base, &alice, &folder, &bob, false);
    purge_accounts(&c, &base, &[&alice, &bob]);
}
