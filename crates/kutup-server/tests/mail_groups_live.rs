//! Shared mailboxes' keys against a running server (docs/plans/mail-groups.md,
//! docs/plans/account-ids.md):
//! - the key lists are signed by the group's signing key its owners and
//!   managers hold; the server stores links, never signs one, and refuses a
//!   link no signer in force signed, a removed manager's old signer after
//!   its handover, and a new chain from anyone but an administrator;
//! - a rotation and a removal cannot interleave: the key is checked against
//!   the members it is published for, under the group's lock;
//! - a member whose account was reset gets the keys sealed again, and no
//!   share sealed to their old keys is taken or served.
//!
//! Needs `KUTUP_LIVE_SERVER`, `KUTUP_LIVE_ADMIN` and `KUTUP_LIVE_DATABASE_URL`.

mod common;
use common::*;

use kutup_crypto::identity::{authority_key_id_from_public, incarnation_id_from_authority_public};
use kutup_crypto::mail_group::{
    open_group_signing_share, seal_group_signing_share, verify_group_key_chain,
    GroupSignerHandoverV1, GroupSigningKey,
};
use kutup_crypto::mail_key::{
    self, GeneratedAddressKey, GroupShareMember, MailKeyEntryV1, MailKeyListV1,
    SignedMailKeyListV1, DEFAULT_FLAGS, FLAG_NOT_OBSOLETE,
};
use reqwest::blocking::{Client, Response};
use reqwest::StatusCode;
use serde_json::{json, Value};

struct Live {
    c: Client,
    base: String,
    admin: String,
    admin_token: String,
    database: String,
}

fn live() -> Option<Live> {
    let (Ok(base), Ok(admin), Ok(database)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_ADMIN"),
        std::env::var("KUTUP_LIVE_DATABASE_URL"),
    ) else {
        eprintln!(
            "KUTUP_LIVE_SERVER / KUTUP_LIVE_ADMIN / KUTUP_LIVE_DATABASE_URL not set; skipping"
        );
        return None;
    };
    let c = Client::new();
    let base = base.trim_end_matches('/').to_string();
    let (name, password) = admin.split_once(':').unwrap();
    let admin_token = admin_token(&c, &base, password, name);
    Some(Live {
        c,
        base,
        admin,
        admin_token,
        database,
    })
}

fn code(r: Response) -> (u16, String) {
    let status = r.status().as_u16();
    let body: Value = r.json().unwrap_or(Value::Null);
    (status, body["code"].as_str().unwrap_or_default().to_owned())
}

/// The group key's share for `member`, as a browser seals it.
fn key_share(key: &GeneratedAddressKey, group: &str, member: &User) -> Value {
    let incarnation = member.identity.incarnation_id();
    json!({
        "userId": member.id,
        "share": b64(&mail_key::seal_group_key_share(
            &key.secret_key,
            group,
            &GroupShareMember { account: &member.person, incarnation_id: &incarnation },
            &member.identity.drive_hpke_public_key(),
        ).unwrap()),
    })
}

/// The signing key's share for an owner or manager.
fn signer_share(signer: &GroupSigningKey, group: &str, member: &User) -> Value {
    let incarnation = member.identity.incarnation_id();
    json!({
        "userId": member.id,
        "share": b64(&seal_group_signing_share(
            signer,
            group,
            &GroupShareMember { account: &member.person, incarnation_id: &incarnation },
            &member.identity.drive_hpke_public_key(),
        ).unwrap()),
    })
}

fn entry(key: &GeneratedAddressKey) -> MailKeyEntryV1 {
    MailKeyEntryV1 {
        fingerprint: key.fingerprint,
        sha256_fingerprint: key.sha256_fingerprint,
        primary: true,
        flags: DEFAULT_FLAGS,
    }
}

/// The group's chain as a browser keeps it: its lists, to sign the next.
struct Chain {
    address: String,
    lists: Vec<SignedMailKeyListV1>,
}

impl Chain {
    /// The next list naming `added` primary (the keys before kept, not to
    /// encrypt to), signed by `signer`; `restart` starts a chain over.
    fn next(
        &self,
        signer: &GroupSigningKey,
        added: &GeneratedAddressKey,
        restart: bool,
    ) -> SignedMailKeyListV1 {
        let hex32 = |value: String| -> [u8; 32] { hex::decode(value).unwrap().try_into().unwrap() };
        let newest = self.lists.last();
        let mut keys: Vec<MailKeyEntryV1> = newest
            .map(|list| {
                list.list
                    .keys
                    .iter()
                    .map(|key| MailKeyEntryV1 {
                        primary: false,
                        flags: key.flags & !FLAG_NOT_OBSOLETE,
                        ..key.clone()
                    })
                    .collect()
            })
            .unwrap_or_default();
        keys.push(entry(added));
        keys.sort_by_key(|key| key.fingerprint);
        let (sequence, previous_hash) = match newest {
            Some(list) if !restart => (list.list.sequence + 1, Some(list.hash())),
            _ => (1, None),
        };
        MailKeyListV1 {
            incarnation_id: hex32(incarnation_id_from_authority_public(&signer.public_key)),
            authority_key_id: hex32(authority_key_id_from_public(&signer.public_key)),
            address: self.address.clone(),
            sequence,
            previous_hash,
            issued_at: "2026-10-16T12:00:00Z".into(),
            keys,
        }
        .sign(&signer.signing_key())
        .unwrap()
    }
}

fn list_json(list: &SignedMailKeyListV1) -> Value {
    json!({ "data": b64(&list.data), "signature": b64(&list.signature) })
}

fn new_key(address: &str) -> GeneratedAddressKey {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    mail_key::generate_address_key(address, now).unwrap()
}

/// A shared mailbox of `owner`, made by the administrator with its first
/// key and signer: (group id, address, first key, signer, chain).
fn shared_mailbox(
    live: &Live,
    owner: &User,
) -> (String, String, GeneratedAddressKey, GroupSigningKey, Chain) {
    let domain = server_domain(&live.c, &live.base);
    let name = format!("team-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let address = format!("{name}@{domain}");
    let id = uuid::Uuid::new_v4().to_string();
    let key = new_key(&address);
    let signer = GroupSigningKey::generate();
    let mut chain = Chain {
        address: address.clone(),
        lists: Vec::new(),
    };
    let first = chain.next(&signer, &key, false);
    let r = bearer(live.c.post(format!("{}/api/admin/mail/groups", live.base)), &live.admin_token)
        .json(&json!({
            "id": id, "name": name, "displayName": "Team", "kind": "shared", "postPolicy": "anyone",
            "storageQuotaBytes": 10_000_000, "owners": [owner.id],
            "groupKey": {
                "publicKey": b64(&key.public_key),
                "shares": [key_share(&key, &id, owner)],
                "keyList": list_json(&first),
                "signer": { "publicKey": b64(&signer.public_key), "shares": [signer_share(&signer, &id, owner)] },
            },
        }))
        .send()
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "create the shared mailbox: {}",
        r.text().unwrap_or_default()
    );
    chain.lists.push(first);
    (id, address, key, signer, chain)
}

fn members(live: &Live, by: &User, id: &str, body: Value) -> Response {
    bearer(
        live.c
            .put(format!("{}/api/mail/groups/{id}/members", live.base)),
        &by.token,
    )
    .json(&body)
    .send()
    .unwrap()
}

fn rotate(live: &Live, by: &str, id: &str, key: Value) -> Response {
    bearer(
        live.c
            .post(format!("{}/api/mail/groups/{id}/keys", live.base)),
        by,
    )
    .json(&json!({ "key": key }))
    .send()
    .unwrap()
}

/// What senders see: the chain verified, its signers and length.
fn served_chain(live: &Live, address: &str, id: &str) -> (Vec<[u8; 32]>, u64) {
    let lookup: Value = bearer(
        live.c
            .get(format!("{}/api/mail/keys?email={address}", live.base)),
        &live.admin_token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert_eq!(lookup["groupId"], id);
    assert!(
        lookup.get("accountAuthorityPublicKey").is_none(),
        "{lookup}"
    );
    let first: [u8; 32] = b64_decode(lookup["firstSigner"].as_str().unwrap())
        .try_into()
        .unwrap();
    let lists: Vec<(Vec<u8>, Vec<u8>)> = lookup["keyLists"]
        .as_array()
        .unwrap()
        .iter()
        .map(|list| {
            (
                b64_decode(list["data"].as_str().unwrap()),
                b64_decode(list["signature"].as_str().unwrap()),
            )
        })
        .collect();
    let pairs: Vec<(&[u8], &[u8])> = lists
        .iter()
        .map(|(d, s)| (d.as_slice(), s.as_slice()))
        .collect();
    let handovers: Vec<GroupSignerHandoverV1> = lookup["signerHandovers"]
        .as_array()
        .map(|all| {
            all.iter()
                .map(|h| GroupSignerHandoverV1::decode(&b64_decode(h.as_str().unwrap())).unwrap())
                .collect()
        })
        .unwrap_or_default();
    let view = verify_group_key_chain(id, &first, &pairs, &handovers).unwrap();
    (view.signers, view.sequence)
}

#[test]
fn group_key_lists_are_signed_by_the_groups_signers_only() {
    let Some(live) = live() else { return };
    let (alice, bob) = (register(&live.c, &live.base), register(&live.c, &live.base));
    let (id, address, k1, a, mut chain) = shared_mailbox(&live, &alice);
    assert_eq!(served_chain(&live, &address, &id), (vec![a.public_key], 1));

    // Bob becomes a manager: the group key and the signing key both, or nothing.
    let with_bob = json!([
        { "userId": alice.id, "role": "owner", "canSendAs": true },
        { "userId": bob.id, "role": "manager" },
    ]);
    let k1_for_bob = || {
        let mut share = key_share(&k1, &id, &bob);
        share["groupFingerprint"] = json!(hex::encode(k1.fingerprint));
        share
    };
    assert_eq!(
        code(members(
            &live,
            &alice,
            &id,
            json!({ "members": with_bob, "keyShares": [k1_for_bob()] })
        ))
        .1,
        "sharesNeeded"
    );
    let r = members(
        &live,
        &alice,
        &id,
        json!({
            "members": with_bob, "keyShares": [k1_for_bob()], "signerShares": [signer_share(&a, &id, &bob)],
        }),
    );
    assert_eq!(r.status(), StatusCode::OK, "Bob joins as a manager");
    let keys: Value = bearer(
        live.c
            .get(format!("{}/api/mail/groups/{id}/keys", live.base)),
        &bob.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert_eq!(keys["signer"], b64(&a.public_key));
    let held = open_group_signing_share(
        &b64_decode(keys["signingShare"].as_str().unwrap()),
        &id,
        &a.public_key,
        &bob.person,
        bob.identity.drive_hpke_private_key(),
    )
    .unwrap();
    assert_eq!(held.public_key, a.public_key);

    // A link no signer of the group signed (what a server would forge): refused.
    let k2 = new_key(&address);
    let forger = GroupSigningKey::generate();
    let forged = chain.next(&forger, &k2, false);
    let key_signed_by =
        |list: &SignedMailKeyListV1, key: &GeneratedAddressKey, sharers: &[&User]| {
            json!({
                "publicKey": b64(&key.public_key),
                "shares": sharers.iter().map(|user| key_share(key, &id, user)).collect::<Vec<_>>(),
                "keyList": list_json(list),
            })
        };
    assert_eq!(
        code(rotate(
            &live,
            &alice.token,
            &id,
            key_signed_by(&forged, &k2, &[&alice, &bob])
        )),
        (400, "keyListInvalid".into())
    );

    // Bob may no longer sign (demoted): only with a new signer and its handover.
    let bob_member = json!([
        { "userId": alice.id, "role": "owner", "canSendAs": true },
        { "userId": bob.id, "role": "member" },
    ]);
    assert_eq!(
        code(members(
            &live,
            &alice,
            &id,
            json!({ "members": bob_member })
        ))
        .1,
        "newSignerNeeded"
    );
    let b = GroupSigningKey::generate();
    let two = chain.next(&b, &k2, false);
    let handover =
        GroupSignerHandoverV1::sign(&a, &id, 2, &chain.lists[0].hash(), &b.public_key).unwrap();
    let mut new_key_body = key_signed_by(&two, &k2, &[&alice, &bob]);
    new_key_body["signer"] = json!({
        "publicKey": b64(&b.public_key),
        "shares": [signer_share(&b, &id, &alice)],
        "handover": b64(&handover.encode()),
    });
    let r = members(
        &live,
        &alice,
        &id,
        json!({ "members": bob_member, "newKey": new_key_body }),
    );
    assert_eq!(r.status(), StatusCode::OK, "a new signer, handed over");
    chain.lists.push(two);
    assert_eq!(
        served_chain(&live, &address, &id),
        (vec![a.public_key, b.public_key], 2)
    );

    // The old signer, which Bob still knows, can no longer extend the chain.
    let k3 = new_key(&address);
    let fork = chain.next(&a, &k3, false);
    assert_eq!(
        code(rotate(
            &live,
            &alice.token,
            &id,
            key_signed_by(&fork, &k3, &[&alice, &bob])
        )),
        (400, "keyListInvalid".into())
    );
    let three = chain.next(&b, &k3, false);
    assert_eq!(
        rotate(
            &live,
            &alice.token,
            &id,
            key_signed_by(&three, &k3, &[&alice, &bob])
        )
        .status(),
        StatusCode::OK
    );
    chain.lists.push(three);

    // A rotation that still shares with someone removed: refused.
    let alice_only = json!([{ "userId": alice.id, "role": "owner", "canSendAs": true }]);
    let k4 = new_key(&address);
    let four = chain.next(&b, &k4, false);
    assert_eq!(
        members(
            &live,
            &alice,
            &id,
            json!({ "members": alice_only, "newKey": key_signed_by(&four, &k4, &[&alice]) })
        )
        .status(),
        StatusCode::OK,
        "Bob removed with a new key"
    );
    chain.lists.push(four);
    let k5 = new_key(&address);
    let five = chain.next(&b, &k5, false);
    assert_eq!(
        code(rotate(
            &live,
            &alice.token,
            &id,
            key_signed_by(&five, &k5, &[&alice, &bob])
        )),
        (400, "sharesNeeded".into())
    );

    // Starting the chain over: an administrator only; senders see another first signer.
    let c = GroupSigningKey::generate();
    let restart = chain.next(&c, &k5, true);
    let mut restart_body = key_signed_by(&restart, &k5, &[&alice]);
    restart_body["signer"] =
        json!({ "publicKey": b64(&c.public_key), "shares": [signer_share(&c, &id, &alice)] });
    assert_eq!(
        code(rotate(&live, &alice.token, &id, restart_body.clone())),
        (403, "handoverNeeded".into())
    );
    assert_eq!(
        rotate(&live, &live.admin_token, &id, restart_body).status(),
        StatusCode::OK
    );
    assert_eq!(served_chain(&live, &address, &id), (vec![c.public_key], 1));
    purge_accounts(&live.c, &live.base, &[&alice, &bob]);
}

#[test]
fn a_rotation_waiting_on_a_removal_is_checked_against_who_stays() {
    let Some(live) = live() else { return };
    let (alice, bob) = (register(&live.c, &live.base), register(&live.c, &live.base));
    let (id, address, k1, a, mut chain) = shared_mailbox(&live, &alice);
    let mut k1_share = key_share(&k1, &id, &bob);
    k1_share["groupFingerprint"] = json!(hex::encode(k1.fingerprint));
    let r = members(
        &live,
        &alice,
        &id,
        json!({
            "members": [{ "userId": alice.id, "role": "owner", "canSendAs": true }, { "userId": bob.id, "role": "member" }],
            "keyShares": [k1_share],
        }),
    );
    assert_eq!(r.status(), StatusCode::OK);

    // The group's row held, as a removal holds it; a rotation that still
    // shares with Bob comes in and waits; Bob leaves; the rotation then
    // goes on and is checked against who stays.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let pool = runtime
        .block_on(sqlx::PgPool::connect(&live.database))
        .unwrap();
    let mut tx = runtime.block_on(pool.begin()).unwrap();
    let group = uuid::Uuid::parse_str(&id).unwrap();
    runtime
        .block_on(
            sqlx::query("SELECT id FROM mail_groups WHERE id = $1 FOR UPDATE")
                .bind(group)
                .execute(&mut *tx),
        )
        .unwrap();
    let k2 = new_key(&address);
    let two = chain.next(&a, &k2, false);
    let body = json!({
        "publicKey": b64(&k2.public_key),
        "shares": [key_share(&k2, &id, &alice), key_share(&k2, &id, &bob)],
        "keyList": list_json(&two),
    });
    let (base, token, id2) = (live.base.clone(), alice.token.clone(), id.clone());
    let rotation = std::thread::spawn(move || {
        let c = Client::new();
        let r = bearer(c.post(format!("{base}/api/mail/groups/{id2}/keys")), &token)
            .json(&json!({ "key": body }))
            .send()
            .unwrap();
        code(r)
    });
    std::thread::sleep(std::time::Duration::from_secs(2));
    runtime
        .block_on(
            sqlx::query("DELETE FROM mail_group_members WHERE group_id = $1 AND user_id = $2")
                .bind(group)
                .bind(uuid::Uuid::parse_str(&bob.id).unwrap())
                .execute(&mut *tx),
        )
        .unwrap();
    runtime.block_on(tx.commit()).unwrap();
    assert_eq!(
        rotation.join().unwrap(),
        (400, "sharesNeeded".into()),
        "no key shared with someone who left"
    );
    chain.lists.truncate(1);
    purge_accounts(&live.c, &live.base, &[&alice, &bob]);
}

#[test]
fn a_reset_member_gets_the_keys_sealed_again() {
    let Some(live) = live() else { return };
    let (alice, mut bob) = (register(&live.c, &live.base), register(&live.c, &live.base));
    let (id, _address, k1, _a, _chain) = shared_mailbox(&live, &alice);
    let both = json!([
        { "userId": alice.id, "role": "owner", "canSendAs": true },
        { "userId": bob.id, "role": "member" },
    ]);
    let share_for_bob = |bob: &User| {
        let mut share = key_share(&k1, &id, bob);
        share["groupFingerprint"] = json!(hex::encode(k1.fingerprint));
        share
    };
    let old_share = share_for_bob(&bob);
    assert_eq!(
        members(
            &live,
            &alice,
            &id,
            json!({ "members": both, "keyShares": [old_share.clone()] })
        )
        .status(),
        StatusCode::OK
    );

    // An administrator resets Bob: his share, sealed to his old keys, is
    // not served; the group says he needs the keys again.
    wipe_and_set_up(&live.c, &live.base, &live.admin, &mut bob);
    let keys: Value = bearer(
        live.c
            .get(format!("{}/api/mail/groups/{id}/keys", live.base)),
        &bob.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert!(keys["keys"][0]["share"].is_null(), "{keys}");
    let detail: Value = bearer(
        live.c.get(format!("{}/api/mail/groups/{id}", live.base)),
        &alice.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    let bob_row = detail["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["userId"] == bob.id.as_str())
        .unwrap();
    assert_eq!(bob_row["needsKeys"], true);

    // A share sealed to his old keys is refused; one to his new keys is taken
    // without anyone joining, and opens.
    assert_eq!(
        code(members(
            &live,
            &alice,
            &id,
            json!({ "members": both, "keyShares": [old_share] })
        )),
        (409, "keyChanged".into())
    );
    assert_eq!(
        members(
            &live,
            &alice,
            &id,
            json!({ "members": both, "keyShares": [share_for_bob(&bob)] })
        )
        .status(),
        StatusCode::OK
    );
    let keys: Value = bearer(
        live.c
            .get(format!("{}/api/mail/groups/{id}/keys", live.base)),
        &bob.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    let opened = mail_key::open_group_key_share(
        &b64_decode(keys["keys"][0]["share"].as_str().unwrap()),
        &id,
        &k1.fingerprint,
        &bob.person,
        bob.identity.drive_hpke_private_key(),
    )
    .unwrap();
    assert_eq!(&*opened, &*k1.secret_key);
    // Someone whose keys did not change gets no share this way.
    let mut again = key_share(&k1, &id, &alice);
    again["groupFingerprint"] = json!(hex::encode(k1.fingerprint));
    assert_eq!(
        code(members(
            &live,
            &alice,
            &id,
            json!({ "members": both, "keyShares": [again] })
        ))
        .1,
        "sharesNeeded"
    );
    purge_accounts(&live.c, &live.base, &[&alice, &bob]);
}
