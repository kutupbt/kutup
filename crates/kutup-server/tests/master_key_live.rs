//! A master-key rotation against a running server
//! (docs/plans/mk-rotation-exercise.md): the transaction, what it ends, and
//! that records sealed before it still open while new ones are sealed under
//! the new key. Needs `KUTUP_LIVE_SERVER`.

mod common;

use common::{b64, b64_decode, bearer, register, User};
use kutup_crypto::account_head::{self, HeadKeys, VerifiedHead};
use kutup_crypto::account_record::{self, AccountRecordPurpose, MasterKeyGeneration};
use kutup_crypto::contact_card::{self, ContactEmailV1, ContactSummaryV1};
use kutup_crypto::master_keys::MasterKeys;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

fn client() -> Client {
    common::client_builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

const UID: &str = "urn:uuid:7a1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f01";

/// A contact `UID` at `revision`, its card sealed under `keys`' current key.
fn contact(user: &User, keys: &MasterKeys, revision: u64) -> Value {
    let summary = ContactSummaryV1::new(
        UID,
        "Ayşe",
        vec![ContactEmailV1::new("ayse@example.com", None)],
        vec![],
        vec![],
    );
    let (bytes, signature) = contact_card::sign_summary(
        &summary,
        &user.binding,
        revision,
        user.identity.authority_signing_key(),
    )
    .unwrap();
    let vcard =
        format!("BEGIN:VCARD\r\nVERSION:4.0\r\nUID:{UID}\r\nFN:Ayşe {revision}\r\nEND:VCARD\r\n");
    let card = contact_card::seal_card(
        keys.current(),
        keys.generation(),
        &user.binding,
        UID,
        revision,
        vcard.as_bytes(),
    )
    .unwrap();
    json!({
        "summary": String::from_utf8(bytes).unwrap(),
        "signature": b64(&signature),
        "card": b64(&card),
    })
}

fn get(c: &Client, base: &str, token: &str, path: &str) -> (StatusCode, Value) {
    let r = bearer(c.get(format!("{base}{path}")), token)
        .send()
        .unwrap();
    let status = r.status();
    (status, r.json().unwrap_or(Value::Null))
}

/// The account's newest head, verified under `keys` (no anchor).
fn verified_head(
    c: &Client,
    base: &str,
    user: &User,
    token: &str,
    keys: &HeadKeys,
) -> VerifiedHead {
    let (_, head) = get(c, base, token, "/api/account/head");
    let sealed = b64_decode(head["head"].as_str().expect("a head"));
    let incarnation = user.identity.incarnation_id();
    account_head::check(
        keys,
        &user.binding,
        &incarnation,
        user.roots.head_generations(),
        None,
        &sealed,
        None,
    )
    .unwrap()
    .verified
    .unwrap()
}

#[test]
fn a_rotation_keeps_every_record_readable_and_ends_the_old_key() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = client();
    let user = register(&c, &base);
    let old = MasterKeys::first(&user.master_key);
    let old_head_keys = HeadKeys::derive(&old, &user.roots.object_id).unwrap();
    let writer = old_head_keys.writer("rotation-live").unwrap();
    let incarnation = user.identity.incarnation_id();
    // Another sign-in, which the rotation ends.
    let other = common::sign_in(&c, &base, &user.username, &user.password)["accessToken"]
        .as_str()
        .unwrap()
        .to_owned();

    // The chain, and a contact sealed under the first key.
    let (_, index) = get(&c, &base, &user.token, "/api/account/index/contacts");
    let (first, first_verified) = account_head::first(
        &old_head_keys,
        &user.binding,
        &incarnation,
        user.roots.head_generations(),
        &writer,
        vec![],
    )
    .unwrap();
    let r = bearer(c.post(format!("{base}/api/account/head")), &user.token)
        .json(&json!({ "head": b64(&first), "basis": index["basis"] }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let entry = old_head_keys
        .scope_digest("contacts", &[(UID.to_owned(), 1)])
        .unwrap();
    let next = first_verified.next(&writer, vec![entry]).unwrap();
    let sealed = account_head::seal(&old_head_keys, &user.binding, &next).unwrap();
    let mut body = contact(&user, &old, 1);
    body["head"] = json!(b64(&sealed));
    let r = bearer(c.post(format!("{base}/api/contacts")), &user.token)
        .json(&body)
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let contact_id = r.json::<Value>().unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // The rotation: the password again, a new phrase, the roots re-wrapped,
    // the keyring and the next head, all at generation 2.
    let verified = verified_head(&c, &base, &user, &user.token, &old_head_keys);
    let entropy = kutup_crypto::primitives::random_key();
    let rotation = kutup_crypto::mk_rotation::prepare_with(
        &old,
        &user.binding,
        &user.roots,
        &verified,
        &writer,
        &kutup_crypto::primitives::random_key(),
        &entropy,
    )
    .unwrap();
    let rotate = |grant: &str, envelope_generation: MasterKeyGeneration| {
        let (record, key_id, export) = common::opaque_register(
            &c,
            &base,
            &user.password,
            &user.binding,
            Some(grant),
            Some(&user.token),
        );
        let envelope = export
            .seal_master_key(rotation.master_key(), envelope_generation, &user.binding)
            .unwrap();
        bearer(
            c.post(format!("{base}/api/account/master-key/rotate")),
            &user.token,
        )
        .json(&json!({
            "grant": grant,
            "opaqueRecord": record,
            "opaqueServerKeyId": key_id,
            "masterKeyEnvelope": envelope,
            "recoveryKeyEnvelope": b64(&rotation.recovery_envelope),
            "recoveryProof": b64(rotation.recovery_proof.as_slice()),
            "accountRoots": rotation.roots.iter().map(|r| b64(r)).collect::<Vec<_>>(),
            "masterKeyring": b64(&rotation.keyring),
            "head": b64(&rotation.head),
        }))
        .send()
        .unwrap()
    };
    // A password wrap of another generation than the rotation's: refused,
    // and nothing changes.
    let grant = common::reauth_grant(&c, &base, &user, "masterKeyRotation");
    let r = rotate(&grant, MasterKeyGeneration::FIRST);
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert_eq!(r.json::<Value>().unwrap()["code"], "rotationInvalid");
    let grant = common::reauth_grant(&c, &base, &user, "masterKeyRotation");
    let r = rotate(&grant, rotation.generation());
    assert_eq!(r.status(), StatusCode::NO_CONTENT, "{:?}", r.text());

    // The other sign-in ended; this one goes on.
    assert_eq!(
        get(&c, &base, &other, "/api/user/me").0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        get(&c, &base, &user.token, "/api/user/me").0,
        StatusCode::OK
    );

    // A sign-in now gets generation 2 and the keyring; the set opens the
    // roots and the contact sealed under the first key.
    let signed = common::sign_in(&c, &base, &user.username, &user.password);
    assert_eq!(signed["masterKeyGeneration"], 2);
    let keyring: Vec<Vec<u8>> = signed["masterKeyring"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| b64_decode(r.as_str().unwrap()))
        .collect();
    let keys = MasterKeys::open(
        rotation.master_key(),
        rotation.generation(),
        &user.binding,
        &keyring,
    )
    .unwrap();
    let roots: Vec<Vec<u8>> = signed["accountRoots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| b64_decode(r.as_str().unwrap()))
        .collect();
    let opened = kutup_crypto::account_roots::AccountRoots::open(
        &roots,
        &keys,
        &user.binding,
        &user.identity.authority_public_key(),
    )
    .unwrap();
    assert!(opened.same_for_tests_as(&user.roots));
    let (_, listed) = get(&c, &base, &user.token, "/api/contacts");
    let card = b64_decode(listed["contacts"][0]["card"].as_str().unwrap());
    assert_eq!(account_record::inspect(&card).unwrap().generation.get(), 1);
    contact_card::open_card(keys.key_for(&card).unwrap(), &user.binding, UID, &card).unwrap();

    // A head under the old key is stale; under the new one the contact is
    // sealed again at generation 2.
    let new_head_keys = HeadKeys::derive(&keys, &user.roots.object_id).unwrap();
    let current = verified_head(&c, &base, &user, &user.token, &new_head_keys);
    let entry = new_head_keys
        .scope_digest("contacts", &[(UID.to_owned(), 2)])
        .unwrap();
    let next = current.next(&writer, vec![entry]).unwrap();
    let mut update = contact(&user, &keys, 2);
    update["baseRevision"] = json!(1);
    update["head"] = json!(b64(&account_head::seal(
        &old_head_keys,
        &user.binding,
        &next
    )
    .unwrap()));
    let r = bearer(
        c.put(format!("{base}/api/contacts/{contact_id}")),
        &user.token,
    )
    .json(&update)
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(r.json::<Value>().unwrap()["code"], "masterKeyStale");
    update["head"] = json!(b64(&account_head::seal(
        &new_head_keys,
        &user.binding,
        &next
    )
    .unwrap()));
    let r = bearer(
        c.put(format!("{base}/api/contacts/{contact_id}")),
        &user.token,
    )
    .json(&update)
    .send()
    .unwrap();
    assert!(r.status().is_success(), "{}", r.status());
    let (_, listed) = get(&c, &base, &user.token, "/api/contacts");
    let card = b64_decode(listed["contacts"][0]["card"].as_str().unwrap());
    assert_eq!(account_record::inspect(&card).unwrap().generation.get(), 2);

    // The old phrase no longer recovers; the new one does, and its envelope
    // holds the new key.
    let grant_for = |entropy: &[u8; 32]| {
        let proof = kutup_crypto::kdf::derive_recovery_auth_proof(entropy, &user.binding).unwrap();
        c.post(format!("{base}/api/auth/recover/grant"))
            .json(&json!({ "name": user.username, "recoveryProof": b64(proof.as_slice()) }))
            .send()
            .unwrap()
    };
    assert_eq!(
        grant_for(&user.recovery_entropy).status(),
        StatusCode::UNAUTHORIZED
    );
    let granted: Value = grant_for(&entropy).json().unwrap();
    let recovered = account_record::open_b64(
        granted["recoveryKeyEnvelope"].as_str().unwrap(),
        entropy.as_slice(),
        AccountRecordPurpose::RecoveryMasterKey,
        &user.binding,
    )
    .unwrap();
    assert_eq!(recovered.as_slice(), rotation.master_key());

    // The owner sees it in the security log.
    let events = common::security_events(&c, &base, &user.token, "");
    assert!(events.to_string().contains("masterKeyRotated"), "{events}");
    common::purge_accounts(&c, &base, &[&user]);
}
