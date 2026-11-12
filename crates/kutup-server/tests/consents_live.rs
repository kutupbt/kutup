//! Consents and the federation switch (docs/plans/server-personal-data.md,
//! A4) against a live server: turning federation on asks the
//! `federation_abroad` consent once its text is published; withdrawing the
//! consent turns it off; while off, the account's requests to other servers
//! are refused.
//!
//! It publishes no document required at sign-up: the tests after it register
//! accounts without confirming any.
//!
//!   KUTUP_LIVE_SERVER=http://… KUTUP_LIVE_ADMIN=name:password \
//!   cargo test -p kutup-server --test consents_live

mod common;

use common::*;
use reqwest::StatusCode;
use serde_json::{json, Value};

#[test]
fn federation_follows_its_consent() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let Ok(admin) = std::env::var("KUTUP_LIVE_ADMIN") else {
        eprintln!("KUTUP_LIVE_ADMIN unset; skipping");
        return;
    };
    let (name, password) = admin.split_once(':').expect("name:password");
    let c = client();
    let admin = admin_token(&c, &base, password, name);
    let user = register(&c, &base);
    assert_eq!(me(&c, &base, &user.token)["federation"], "on");

    // The consent's text, published (not required at sign-up).
    let published = bearer(c.post(format!("{base}/api/admin/legal/documents")), &admin)
        .json(&json!({
            "kind": "federation_abroad",
            "version": uuid(),
            "language": "en",
            "url": "https://example.org/federation",
            "sha256": "a".repeat(64),
            "requiredAtSignup": false,
        }))
        .send()
        .unwrap();
    assert_eq!(published.status(), StatusCode::CREATED);
    let text = published.json::<Value>().unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let set = |on: bool, document: Option<&str>| {
        bearer(c.put(format!("{base}/api/user/federation")), &user.token)
            .json(&json!({ "on": on, "documentId": document }))
            .send()
            .unwrap()
    };
    // Off: requests to other servers are refused.
    assert_eq!(set(false, None).status(), StatusCode::NO_CONTENT);
    assert_eq!(me(&c, &base, &user.token)["federation"], "off");
    let remote = bearer(
        c.get(format!(
            "{base}/api/users/by-id/{}?server=elsewhere.example",
            uuid()
        )),
        &user.token,
    )
    .send()
    .unwrap();
    assert_eq!(remote.status(), StatusCode::FORBIDDEN);
    assert_eq!(remote.json::<Value>().unwrap()["code"], "federationOff");

    // On again: the consent first, under the current text.
    let refused = set(true, None);
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert_eq!(refused.json::<Value>().unwrap()["code"], "consentRequired");
    assert_eq!(set(true, Some(&text)).status(), StatusCode::NO_CONTENT);
    assert_eq!(me(&c, &base, &user.token)["federation"], "on");
    let consents: Value = bearer(c.get(format!("{base}/api/user/consents")), &user.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let given = consents["consents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["purpose"] == "federation_abroad")
        .expect("the consent is recorded");
    assert_eq!(
        (given["given"].as_bool(), given["documentId"].as_str()),
        (Some(true), Some(text.as_str()))
    );

    // Withdrawn: federation goes off with it.
    let withdrawn = bearer(c.put(format!("{base}/api/user/consents")), &user.token)
        .json(&json!({ "purpose": "federation_abroad", "given": false }))
        .send()
        .unwrap();
    assert_eq!(withdrawn.status(), StatusCode::NO_CONTENT);
    assert_eq!(me(&c, &base, &user.token)["federation"], "off");

    purge_accounts(&c, &base, &[&user]);
}
