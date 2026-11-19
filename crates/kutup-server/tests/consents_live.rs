//! Consents and the federation switch (docs/plans/server-personal-data.md,
//! A4) against a live server: where the site asks for it
//! (`federationConsentRequired`, off in the core), turning federation on
//! asks the `federation` consent under its published text; withdrawing the
//! consent turns it off; while off, the account's requests to other servers
//! are refused. It sets the site setting back off when done.
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
    let published = bearer(
        c.post(format!("{base}/api/v1/admin/legal/documents")),
        &admin,
    )
    .json(&json!({
        "kind": "federation",
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
        bearer(
            c.put(format!("{base}/api/v1/account/federation")),
            &user.token,
        )
        .json(&json!({ "on": on, "documentId": document }))
        .send()
        .unwrap()
    };
    // Off: requests to other servers are refused.
    assert_eq!(set(false, None).status(), StatusCode::NO_CONTENT);
    assert_eq!(me(&c, &base, &user.token)["federation"], "off");
    let remote = bearer(
        c.get(format!(
            "{base}/api/v1/accounts/{}?server=elsewhere.example",
            uuid()
        )),
        &user.token,
    )
    .send()
    .unwrap();
    assert_eq!(remote.status(), StatusCode::FORBIDDEN);
    assert_eq!(remote.json::<Value>().unwrap()["code"], "federationOff");

    // The core asks for no consent, a text published or not.
    assert_eq!(set(true, None).status(), StatusCode::NO_CONTENT);
    assert_eq!(set(false, None).status(), StatusCode::NO_CONTENT);

    // Where the site asks for it: on again needs the consent first, under
    // the current text.
    let consent_required = |required: bool| {
        let r = bearer(c.put(format!("{base}/api/v1/admin/settings")), &admin)
            .json(&json!({ "federationConsentRequired": required }))
            .send()
            .unwrap();
        assert!(r.status().is_success(), "{}", r.text().unwrap());
    };
    consent_required(true);
    let refused = set(true, None);
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert_eq!(refused.json::<Value>().unwrap()["code"], "consentRequired");
    assert_eq!(set(true, Some(&text)).status(), StatusCode::NO_CONTENT);
    assert_eq!(me(&c, &base, &user.token)["federation"], "on");
    let consents: Value = bearer(
        c.get(format!("{base}/api/v1/account/consents")),
        &user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    let given = consents["consents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["purpose"] == "federation")
        .expect("the consent is recorded");
    assert_eq!(
        (given["given"].as_bool(), given["documentId"].as_str()),
        (Some(true), Some(text.as_str()))
    );

    // Withdrawn: federation goes off with it.
    let withdrawn = bearer(
        c.put(format!("{base}/api/v1/account/consents")),
        &user.token,
    )
    .json(&json!({ "purpose": "federation", "given": false }))
    .send()
    .unwrap();
    assert_eq!(withdrawn.status(), StatusCode::NO_CONTENT);
    assert_eq!(me(&c, &base, &user.token)["federation"], "off");

    // An administrator can't turn it on over a withdrawn consent: the
    // transfer rests on the user's own (409 consentRequired). Off, it can.
    let by_admin = |federation: &str| {
        bearer(
            c.put(format!("{base}/api/v1/admin/accounts/{}", user.id)),
            &admin,
        )
        .json(&json!({ "federation": federation }))
        .send()
        .unwrap()
    };
    let refused = by_admin("on");
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert_eq!(refused.json::<Value>().unwrap()["code"], "consentRequired");
    assert_eq!(me(&c, &base, &user.token)["federation"], "off");
    // Given again by the user, the administrator's switch works both ways.
    assert_eq!(set(true, Some(&text)).status(), StatusCode::NO_CONTENT);
    assert!(by_admin("off").status().is_success());
    assert_eq!(me(&c, &base, &user.token)["federation"], "off");
    assert!(by_admin("on").status().is_success());
    assert_eq!(me(&c, &base, &user.token)["federation"], "on");

    // A new account starts off where the consent is asked: it hasn't given it.
    let newcomer = register(&c, &base);
    assert_eq!(me(&c, &base, &newcomer.token)["federation"], "off");
    consent_required(false);

    purge_accounts(&c, &base, &[&user, &newcomer]);
}
