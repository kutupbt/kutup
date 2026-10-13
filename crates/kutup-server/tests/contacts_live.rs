//! Contacts (docs/plans/contacts.md) against a live server: a contact's
//! revision is its card's, which the summary's signature binds, and an edit
//! is stored only on top of the revision it started from
//! (docs/plans/sealed-revisions.md).

use kutup_crypto::contact_card::{self, ContactEmailV1, ContactSummaryV1};
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

mod common;
use common::*;

const T: u64 = 1_791_633_600_000;

fn summary(name: &str) -> ContactSummaryV1 {
    ContactSummaryV1 {
        uid: "urn:uuid:3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70".into(),
        name: name.into(),
        emails: vec![ContactEmailV1 {
            address: "ayse@example.com".into(),
            label: None,
        }],
        groups: vec![],
        pinned_keys: vec![],
    }
}

/// A contact body at `card_revision`, its summary signed for `signed_revision`.
fn body(user: &User, name: &str, card_revision: u64, signed_revision: u64) -> Value {
    let summary = summary(name);
    let (bytes, signature) = contact_card::sign_summary(
        &summary,
        &user.binding,
        signed_revision,
        user.identity.authority_signing_key(),
    )
    .unwrap();
    let key = contact_card::derive_contacts_key(&user.master_key).unwrap();
    let vcard = format!(
        "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:{}\r\nFN:{name}\r\nEND:VCARD\r\n",
        summary.uid
    );
    let card = contact_card::seal_card(
        &key,
        &user.binding,
        &summary.uid,
        card_revision,
        vcard.as_bytes(),
    )
    .unwrap();
    json!({
        "summary": String::from_utf8(bytes).unwrap(),
        "signature": b64(&signature),
        "card": b64(&card),
    })
}

#[test]
fn contact_revisions() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = Client::new();
    let user = register(&c, &base);
    let post = |body: Value| {
        bearer(c.post(format!("{base}/api/contacts")), &user.token)
            .json(&body)
            .send()
            .unwrap()
    };

    // A summary signed for another revision than its card's is refused.
    assert_eq!(
        post(body(&user, "Ayşe", T, T + 1)).status(),
        StatusCode::BAD_REQUEST
    );
    let created = post(body(&user, "Ayşe", T, T));
    assert_eq!(created.status(), StatusCode::CREATED);
    let created: Value = created.json().unwrap();
    assert_eq!(created["revision"], T);
    let id = created["id"].as_str().unwrap().to_string();

    let put = |mut body: Value, base_revision: u64| {
        body["baseRevision"] = json!(base_revision);
        bearer(c.put(format!("{base}/api/contacts/{id}")), &user.token)
            .json(&body)
            .send()
            .unwrap()
    };
    // Not newer than the revision it started from: refused.
    assert_eq!(
        put(body(&user, "Ayşe Y.", T, T), T).status(),
        StatusCode::BAD_REQUEST
    );
    let saved = put(body(&user, "Ayşe Y.", T + 5, T + 5), T);
    assert_eq!(saved.status(), StatusCode::OK);
    assert_eq!(saved.json::<Value>().unwrap()["revision"], T + 5);
    // A second device that started from the old revision does not overwrite it.
    let late = put(body(&user, "Ayşe Yılmaz", T + 6, T + 6), T);
    assert_eq!(late.status(), StatusCode::CONFLICT);
    let late: Value = late.json().unwrap();
    assert_eq!(late["code"], "revision_conflict");
    assert_eq!(late["revision"], T + 5);
    // Started from the current one, it is stored.
    assert_eq!(
        put(body(&user, "Ayşe Yılmaz", T + 6, T + 6), T + 5).status(),
        StatusCode::OK
    );

    // What comes back opens at the revision the list names.
    let page: Value = bearer(c.get(format!("{base}/api/contacts")), &user.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let row = &page["contacts"][0];
    assert_eq!(row["revision"], T + 6);
    let key = contact_card::derive_contacts_key(&user.master_key).unwrap();
    let (_, revision) = contact_card::open_card(
        &key,
        &user.binding,
        &summary("x").uid,
        &b64_decode(row["card"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(revision, T + 6);
}
