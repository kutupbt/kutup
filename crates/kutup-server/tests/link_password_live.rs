//! Live e2e for a public link's password and expiry
//! (docs/plans/drive-link-password.md): the owner sets a password, the link
//! shows nothing without the proof, a wrong proof is refused, the right one
//! hands over the link key under the password; a folder re-key sealed under
//! the old link key is refused; the password comes off again; the expiry is
//! bounded.
//!
//! Gated on `KUTUP_LIVE_SERVER`:
//!   KUTUP_LIVE_SERVER=http://localhost:3000 \
//!     cargo test -p kutup-server --test link_password_live -- --nocapture

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::collection_epoch::CollectionEpochStatementV1;
use kutup_crypto::collection_keyring;
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};
use kutup_crypto::link_password;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

mod common;
use common::*;

fn ctx_at(
    purpose: DriveEnvelopePurpose,
    epoch: u32,
    revision: u64,
    object: &str,
    parent: &str,
) -> DriveEnvelopeContextV1 {
    DriveEnvelopeContextV1::new(purpose, epoch, revision, object, parent).unwrap()
}

/// The fastest cost the server takes, so the test doesn't wait on Argon2id.
fn fast() -> kutup_crypto::primitives::PwhashParams {
    link_password::check_params(
        link_password::MIN_OPERATIONS,
        link_password::MIN_MEMORY as u64,
    )
    .unwrap()
}

fn get(c: &Client, url: String, proof: Option<&[u8]>) -> (StatusCode, Value) {
    let mut request = c.get(url);
    if let Some(proof) = proof {
        request = request.header("X-Kutup-Link-Proof", STANDARD.encode(proof));
    }
    let r = request.send().unwrap();
    let status = r.status();
    (status, r.json().unwrap_or(Value::Null))
}

#[test]
fn a_link_password_gates_the_link_and_survives_a_rekey() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let c = client();
    let owner = register(&c, &base);
    let folder = create_folder(&c, &base, &owner);

    // A link whose key is its URL secret.
    let mut secret = [0u8; 32];
    kutup_crypto::primitives::random(&mut secret);
    let link_id = uuid();
    let created = bearer(c.post(format!("{base}/api/v1/drive/public-links")), &owner.token)
        .json(&json!({
            "id": link_id,
            "shareType": "collection",
            "targetId": folder.id,
            "collectionKeyEnvelope": drive_envelope::seal_b64(&folder.key, &secret,
                ctx_at(DriveEnvelopePurpose::PublicLinkCollectionKey, 1, 1, &folder.id, &owner.id)).unwrap(),
            "ownerLinkKeyEnvelope": owner_link_key(&secret, &owner, &link_id),
        }))
        .send()
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let token = created.json::<Value>().unwrap()["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let share_url = format!("{base}/api/v1/drive/public-links/{token}");
    assert_eq!(get(&c, share_url.clone(), None).0, StatusCode::OK);
    assert_eq!(
        get(&c, format!("{share_url}/password"), None).0,
        StatusCode::NOT_FOUND,
        "no password yet"
    );

    // The password: a new link key, the folder key under it.
    let mut link_key = [0u8; 32];
    kutup_crypto::primitives::random(&mut link_key);
    let salt = [7u8; 16];
    let protection = link_password::protect_with(
        &secret,
        "hunter2",
        &link_key,
        &link_id,
        &owner.id,
        2,
        &fast(),
        &salt,
        &[9u8; 24],
    )
    .unwrap();
    let password_body = |from: i32, epoch: u32, key: &[u8; 32]| {
        json!({
            "fromKeyRevision": from,
            "keyEpoch": epoch,
            "targetKeyEnvelope": drive_envelope::seal_b64(key, &link_key,
                ctx_at(DriveEnvelopePurpose::PublicLinkCollectionKey, epoch, 1, &folder.id, &owner.id)).unwrap(),
            "ownerLinkKeyEnvelope": owner_link_key(&link_key, &owner, &link_id),
            "password": {
                "salt": STANDARD.encode(protection.salt),
                "operations": protection.params.operations,
                "memory": protection.params.memory,
                "verifier": STANDARD.encode(protection.verifier),
                "linkKeyEnvelope": protection.link_key_envelope,
                "ownerSecretEnvelope": link_password::seal_owner_secret(&secret, "hunter2",
                    &owner.roots.drive, &link_id, &owner.id, owner.roots.drive_generation).unwrap(),
            },
        })
    };
    let put_password = |body: Value, token_of: &str| {
        bearer(c.put(format!("{share_url}/password")), token_of)
            .json(&body)
            .send()
            .unwrap()
            .status()
    };
    // Someone else's link: not found.
    let stranger = register(&c, &base);
    assert_eq!(
        put_password(password_body(1, 1, &folder.key), &stranger.token),
        StatusCode::NOT_FOUND
    );
    // A stale revision: refused.
    assert_eq!(
        put_password(password_body(5, 1, &folder.key), &owner.token),
        StatusCode::CONFLICT
    );
    assert_eq!(
        put_password(password_body(1, 1, &folder.key), &owner.token),
        StatusCode::OK
    );

    // Nothing shows without the proof; a wrong one is refused.
    for route in ["", "/files", "/epochs"] {
        let (status, body) = get(&c, format!("{share_url}{route}"), None);
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{route}");
        assert_eq!(body["code"], "linkPassword", "{route}");
    }
    let (status, params) = get(&c, format!("{share_url}/password"), None);
    assert_eq!(status, StatusCode::OK);
    assert_eq!(params["linkId"], link_id);
    assert_eq!(params["salt"], STANDARD.encode(salt));
    let derive = |password: &str| {
        link_password::derive(&secret, password, &salt, &fast(), &link_id).unwrap()
    };
    let wrong = derive("hunter3");
    let (status, body) = get(&c, share_url.clone(), Some(wrong.proof.as_slice()));
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "linkPasswordWrong");

    // The right one: the link key under the password, the folder key under it.
    let right = derive("hunter2");
    let (status, share) = get(&c, share_url.clone(), Some(right.proof.as_slice()));
    assert_eq!(status, StatusCode::OK);
    assert_eq!(share["keyRevision"], 2);
    let opened = link_password::open_link_key(
        share["passwordLinkKeyEnvelope"].as_str().unwrap(),
        right.wrap_key.as_slice(),
        &link_id,
        &owner.id,
        2,
    )
    .unwrap();
    assert_eq!(opened.as_slice(), &link_key);
    let folder_key = drive_envelope::open_b64(
        share["collectionKeyEnvelope"].as_str().unwrap(),
        &link_key,
        ctx_at(
            DriveEnvelopePurpose::PublicLinkCollectionKey,
            1,
            1,
            &folder.id,
            &owner.id,
        ),
    )
    .unwrap();
    assert_eq!(folder_key.as_slice(), &folder.key);
    assert_eq!(
        get(
            &c,
            format!("{share_url}/files"),
            Some(right.proof.as_slice())
        )
        .0,
        StatusCode::OK
    );

    // The owner's listing carries the revision and the owner's secret.
    let access: Value = bearer(
        c.get(format!(
            "{base}/api/v1/drive/collections/{}/access",
            folder.id
        )),
        &owner.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    let listed = &access["publicLinks"][0];
    assert_eq!(listed["keyRevision"], 2);
    let kept = link_password::open_owner_secret(
        listed["ownerSecretEnvelope"].as_str().unwrap(),
        &owner.roots.drive,
        &link_id,
        &owner.id,
        owner.roots.drive_generation,
    )
    .unwrap();
    assert_eq!(kept.secret.as_slice(), &secret);
    assert_eq!(kept.password.as_str(), "hunter2");

    // A re-key sealed under the old link key (revision 1) is refused.
    let mut key2 = [0u8; 32];
    kutup_crypto::primitives::random(&mut key2);
    let statement = CollectionEpochStatementV1::create(
        &folder.id,
        &owner.id,
        2,
        Some(access["epochStatementHash"].as_str().unwrap()),
        &key2,
        owner.identity.authority_signing_key(),
    )
    .unwrap();
    let rotate = |under: &[u8; 32], revision: i32| {
        bearer(
            c.post(format!(
                "{base}/api/v1/drive/collections/{}/rotate",
                folder.id
            )),
            &owner.token,
        )
        .json(&json!({
            "fromEpoch": 1,
            "epochStatement": statement.encode_b64(),
            "ownerKeyEnvelope": owner_collection_key(&key2, &owner, &folder.id, 2),
            "previousKeyEnvelope": collection_keyring::seal_previous_key(&folder.key, &key2, &folder.id, &owner.id, 2).unwrap(),
            "nameEnvelope": drive_envelope::seal_b64(b"Protected", &key2,
                ctx_at(DriveEnvelopePurpose::CollectionName, 2, 2, &folder.id, &owner.id)).unwrap(),
            "members": [],
            "publicLinks": [{
                "id": link_id,
                "collectionKeyEnvelope": drive_envelope::seal_b64(&key2, under,
                    ctx_at(DriveEnvelopePurpose::PublicLinkCollectionKey, 2, 1, &folder.id, &owner.id)).unwrap(),
                "keyRevision": revision,
            }],
            "removed": { "members": [] },
        }))
        .send()
        .unwrap()
        .status()
    };
    assert_eq!(rotate(&secret, 1), StatusCode::CONFLICT);
    assert_eq!(rotate(&link_key, 2), StatusCode::OK);

    // The password comes off: the folder key back under the URL secret.
    let remove = |from: i32, epoch: u32| {
        json!({
            "fromKeyRevision": from,
            "keyEpoch": epoch,
            "targetKeyEnvelope": drive_envelope::seal_b64(&key2, &secret,
                ctx_at(DriveEnvelopePurpose::PublicLinkCollectionKey, epoch, 1, &folder.id, &owner.id)).unwrap(),
            "ownerLinkKeyEnvelope": owner_link_key(&secret, &owner, &link_id),
            "password": null,
        })
    };
    assert_eq!(
        put_password(remove(2, 1), &owner.token),
        StatusCode::CONFLICT,
        "the folder's epoch moved on"
    );
    assert_eq!(put_password(remove(2, 2), &owner.token), StatusCode::OK);
    let (status, share) = get(&c, share_url.clone(), None);
    assert_eq!(status, StatusCode::OK);
    assert_eq!(share["keyRevision"], 3);
    assert!(share.get("passwordLinkKeyEnvelope").is_none());

    // The expiry: in the future, at most the site's maximum ahead.
    let put_expiry = |value: Value| {
        bearer(c.put(format!("{share_url}/expiry")), &owner.token)
            .json(&json!({ "expiresAt": value }))
            .send()
            .unwrap()
    };
    let past = put_expiry(json!("2001-01-01T00:00:00Z"));
    assert_eq!(past.status(), StatusCode::BAD_REQUEST);
    assert_eq!(past.json::<Value>().unwrap()["code"], "expiryInPast");
    let far = put_expiry(json!("2999-01-01T00:00:00Z"));
    assert_eq!(far.status(), StatusCode::BAD_REQUEST);
    assert_eq!(far.json::<Value>().unwrap()["code"], "expiryTooFar");
    let soon = (time::OffsetDateTime::now_utc() + time::Duration::days(7))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    assert_eq!(put_expiry(json!(soon)).status(), StatusCode::NO_CONTENT);
    let (_, share) = get(&c, share_url.clone(), None);
    assert!(share["expiresAt"].is_string());
    assert_eq!(put_expiry(Value::Null).status(), StatusCode::NO_CONTENT);
    let (_, share) = get(&c, share_url, None);
    assert!(share["expiresAt"].is_null());

    purge_accounts(&c, &base, &[&owner, &stranger]);
}
