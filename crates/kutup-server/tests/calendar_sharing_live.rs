//! Calendar sharing (docs/plans/calendar-e3.md, E3b) against a live server:
//! invitations, members and their presets, the rotation that removes a
//! member, links and their feeds, tombstones and busy times. Needs
//! `KUTUP_LIVE_SERVER`. The client side is the Rust core, as the browser
//! runs it through WASM.

use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

use kutup_crypto::calendar::{
    self as cal, CalendarMember, CalendarOwner, CalendarShareEnvelopeV1, Passphrase, SealedEventV1,
    SealedMetadataV1, UnlockedCalendarKey, FIRST_KEY_GENERATION,
};
use kutup_crypto::calendar_event::{EventFieldsV1, TimeV1};
use kutup_crypto::calendar_link::{self, LinkSecret};
use kutup_crypto::mail_key::{self, MailKeyEntryV1, MailKeyListV1, DEFAULT_FLAGS};

mod common;
use common::*;

const EDIT: i64 = 16 | 32 | 64;
const VIEW: i64 = 32 | 64;

/// An account with an address key, as the Account app sets one up.
struct Person {
    user: User,
    address: String,
    address_id: String,
    secret_key: Vec<u8>,
}

fn person(c: &Client, base: &str) -> Person {
    let user = register(c, base);
    let addresses: Value = bearer(c.get(format!("{base}/api/v1/mail/addresses")), &user.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let id = addresses[0]["id"].as_str().unwrap().to_string();
    let address = addresses[0]["address"].as_str().unwrap().to_string();
    let key = mail_key::generate_address_key(&address, 1_790_000_000).unwrap();
    let envelope = mail_key::seal_address_key(
        &user.master_key,
        kutup_crypto::account_record::MasterKeyGeneration::FIRST,
        &user.binding,
        &address,
        &key.secret_key,
    )
    .unwrap();
    let hex32 = |value: String| -> [u8; 32] { hex::decode(value).unwrap().try_into().unwrap() };
    let list = MailKeyListV1 {
        incarnation_id: hex32(user.identity.incarnation_id()),
        authority_key_id: hex32(user.identity.authority_key_id()),
        address: address.clone(),
        sequence: 1,
        previous_hash: None,
        issued_at: "2026-10-21T12:00:00Z".into(),
        keys: vec![MailKeyEntryV1::v4(
            key.fingerprint,
            key.sha256_fingerprint,
            true,
            DEFAULT_FLAGS,
        )],
    }
    .sign(user.identity.authority_signing_key())
    .unwrap();
    let r = bearer(
        c.post(format!("{base}/api/v1/mail/addresses/{id}/keys")),
        &user.token,
    )
    .json(&json!({
        "publicKey": b64(&key.public_key),
        "privateKeyEnvelope": b64(&envelope),
        "keyList": { "data": b64(&list.data), "signature": b64(&list.signature) },
    }))
    .send()
    .unwrap();
    assert!(r.status().is_success(), "add key: {}", r.status());
    Person {
        user,
        address,
        address_id: id,
        secret_key: key.secret_key.to_vec(),
    }
}

/// A calendar the owner made: its id, its first passphrase and key.
struct Made {
    id: String,
    passphrase: Passphrase,
    key: UnlockedCalendarKey,
}

fn make_calendar(c: &Client, base: &str, owner: &Person, name: &str) -> Made {
    let id = uuid::Uuid::new_v4();
    let passphrase = Passphrase::generate();
    let key = cal::generate_calendar_key(&passphrase, 1_790_000_000).unwrap();
    let share = cal::seal_own_passphrase(
        &passphrase,
        &id.to_string(),
        FIRST_KEY_GENERATION,
        &owner.user.person,
        &owner.user.identity,
    )
    .unwrap();
    let metadata = key
        .unlocked
        .seal_metadata(&id.to_string(), name, "", &owner.secret_key)
        .unwrap();
    let r = bearer(
        c.post(format!("{base}/api/v1/calendar/calendars")),
        &owner.user.token,
    )
    .json(&json!({
        "id": id,
        "publicKey": b64(&key.public_key),
        "lockedSecretKey": b64(&key.locked_secret_key),
        "passphraseShare": share.encode_b64().unwrap(),
        "metadata": SealedMetadataV1::of(&metadata),
    }))
    .send()
    .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::CREATED,
        "{}",
        r.text().unwrap_or_default()
    );
    Made {
        id: id.to_string(),
        passphrase,
        key: key.unlocked,
    }
}

/// `owner`'s share of `passphrase` (generation `generation`) for `member`.
fn share_for(
    calendar: &str,
    generation: u32,
    passphrase: &Passphrase,
    owner: &Person,
    member: &Person,
) -> String {
    let incarnation = member.user.identity.incarnation_id();
    cal::seal_passphrase(
        passphrase,
        calendar,
        generation,
        &owner.user.person,
        &owner.user.identity,
        &CalendarMember {
            account: &member.user.person,
            incarnation_id: &incarnation,
            xwing_public_key: &member.user.identity.drive_xwing_public_key(),
        },
    )
    .unwrap()
    .encode_b64()
    .unwrap()
}

fn invite(
    c: &Client,
    base: &str,
    owner: &Person,
    calendar: &Made,
    member: &Person,
    permissions: i64,
) -> reqwest::blocking::Response {
    bearer(
        c.post(format!(
            "{base}/api/v1/calendar/calendars/{}/invitations",
            calendar.id
        )),
        &owner.user.token,
    )
    .json(&json!({
        "accountId": member.user.id,
        "incarnationId": member.user.identity.incarnation_id(),
        "permissions": permissions,
        "shares": [{
            "keyGeneration": 1,
            "share": share_for(&calendar.id, 1, &calendar.passphrase, owner, member),
        }],
    }))
    .send()
    .unwrap()
}

fn get(c: &Client, base: &str, user: &User, path: &str) -> Value {
    let r = bearer(c.get(format!("{base}{path}")), &user.token)
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "GET {path}");
    r.json().unwrap()
}

fn post(
    c: &Client,
    base: &str,
    user: &User,
    path: &str,
    body: Value,
) -> reqwest::blocking::Response {
    bearer(c.post(format!("{base}{path}")), &user.token)
        .json(&body)
        .send()
        .unwrap()
}

fn delete(c: &Client, base: &str, user: &User, path: &str) -> StatusCode {
    bearer(c.delete(format!("{base}{path}")), &user.token)
        .send()
        .unwrap()
        .status()
}

fn code(r: reqwest::blocking::Response) -> (StatusCode, String) {
    let status = r.status();
    let body: Value = r.json().unwrap_or(Value::Null);
    (status, body["code"].as_str().unwrap_or_default().to_owned())
}

fn event(uid: &str, start: &str, end: &str, summary: &str) -> EventFieldsV1 {
    EventFieldsV1 {
        uid: uid.into(),
        dtstamp: "2026-11-20T08:00:00Z".into(),
        created: None,
        start: TimeV1::Utc(start.into()),
        end: Some(TimeV1::Utc(end.into())),
        recurrence_id: None,
        rrule: None,
        exdates: Vec::new(),
        organizer: None,
        sequence: 0,
        summary: Some(summary.into()),
        description: None,
        location: None,
        status: Some("confirmed".into()),
        transp: Some("opaque".into()),
        comment: None,
        other: Vec::new(),
        signed_other: Vec::new(),
        calendar_other: Vec::new(),
        comment_other: Vec::new(),
    }
}

/// One event made in `calendar` by `author` under `key`: the sync's result.
fn create_event(
    c: &Client,
    base: &str,
    author: &Person,
    calendar: &str,
    key: &UnlockedCalendarKey,
    fields: &EventFieldsV1,
) -> Value {
    let sealed = key
        .seal_event(&fields.to_parts().unwrap(), &author.secret_key, None, None)
        .unwrap();
    let r = post(
        c,
        base,
        &author.user,
        &format!("/api/v1/calendar/calendars/{calendar}/events/sync"),
        json!({
            "addressId": author.address_id,
            "changes": [{ "create": {
                "id": uuid::Uuid::new_v4(),
                "event": SealedEventV1::of(&sealed),
            } }],
        }),
    );
    assert_eq!(r.status(), StatusCode::OK);
    r.json::<Value>().unwrap()["results"][0].clone()
}

fn storage(c: &Client, base: &str, user: &User) -> i64 {
    get(c, base, user, "/api/v1/account/storage")["calendar"]["bytes"]
        .as_i64()
        .unwrap()
}

fn live() -> Option<String> {
    match std::env::var("KUTUP_LIVE_SERVER") {
        Ok(base) => Some(base.trim_end_matches('/').to_string()),
        Err(_) => {
            eprintln!("KUTUP_LIVE_SERVER not set; skipping");
            None
        }
    }
}

#[test]
fn invitations_members_and_rotation() {
    let Some(base) = live() else { return };
    let c = client();
    let ada = person(&c, &base);
    let bob = person(&c, &base);
    let cem = person(&c, &base);
    let made = make_calendar(&c, &base, &ada, "Aile");
    let calendar = format!("/api/v1/calendar/calendars/{}", made.id);

    // Refused invitations: a share bound to someone else, a preset that
    // isn't one, the owner herself.
    let mut wrong = invite(&c, &base, &ada, &made, &bob, EDIT);
    assert_eq!(wrong.status(), StatusCode::CREATED);
    assert_eq!(
        delete(
            &c,
            &base,
            &ada.user,
            &format!(
                "{calendar}/invitations/{}",
                wrong.json::<Value>().unwrap()["id"].as_str().unwrap()
            )
        ),
        StatusCode::NO_CONTENT
    );
    wrong = post(
        &c,
        &base,
        &ada.user,
        &format!("{calendar}/invitations"),
        json!({
            "accountId": bob.user.id,
            "incarnationId": bob.user.identity.incarnation_id(),
            "permissions": EDIT,
            "shares": [{ "keyGeneration": 1, "share": share_for(&made.id, 1, &made.passphrase, &ada, &cem) }],
        }),
    );
    assert_eq!(
        code(wrong),
        (StatusCode::BAD_REQUEST, "shareNotBound".into())
    );
    let r = post(
        &c,
        &base,
        &ada.user,
        &format!("{calendar}/invitations"),
        json!({
            "accountId": bob.user.id,
            "incarnationId": bob.user.identity.incarnation_id(),
            "permissions": 127,
            "shares": [{ "keyGeneration": 1, "share": share_for(&made.id, 1, &made.passphrase, &ada, &bob) }],
        }),
    );
    assert_eq!(
        code(r),
        (StatusCode::BAD_REQUEST, "invalidPermissions".into())
    );
    // Only the owner shares: Bob can't invite to a calendar he isn't in.
    let r = invite(&c, &base, &bob, &made, &cem, VIEW);
    assert_eq!(r.status(), StatusCode::NOT_FOUND);

    // Bob is invited with the edit preset and sees it, his share opening
    // with the owner's verified key.
    assert_eq!(
        invite(&c, &base, &ada, &made, &bob, EDIT).status(),
        StatusCode::CREATED
    );
    assert_eq!(
        code(invite(&c, &base, &ada, &made, &bob, EDIT)),
        (StatusCode::CONFLICT, "alreadyShared".into())
    );
    let invitations = get(&c, &base, &bob.user, "/api/v1/calendar/invitations");
    let invitation = &invitations["invitations"][0];
    assert_eq!(invitation["calendarId"], made.id.as_str());
    assert_eq!(invitation["owner"]["accountId"], ada.user.id.as_str());
    assert_eq!(invitation["permissions"], EDIT);
    let owner_incarnation = ada.user.identity.incarnation_id();
    let owner_signing = ada.user.identity.drive_signing_public_key();
    let owner = CalendarOwner {
        account: &ada.user.person,
        incarnation_id: &owner_incarnation,
        signing_public_key: &owner_signing,
    };
    assert_eq!(
        invitation["owner"]["signingPublicKey"],
        b64(&owner_signing).as_str()
    );
    let opened = cal::open_passphrase(
        &CalendarShareEnvelopeV1::decode_b64(
            invitation["keys"][0]["passphraseShare"].as_str().unwrap(),
        )
        .unwrap(),
        &made.id,
        1,
        &owner,
        &bob.user.person,
        &bob.user.identity,
    )
    .unwrap();
    assert_eq!(opened.as_str(), made.passphrase.as_str());
    let sent = get(&c, &base, &ada.user, &format!("{calendar}/members"));
    assert_eq!(sent["members"].as_array().unwrap().len(), 0);
    assert_eq!(sent["invitations"][0]["state"], "pending");
    assert_eq!(sent["invitations"][0]["address"], bob.address.as_str());
    // Members aren't Bob's to list, nor keys before he joins.
    assert_eq!(
        bearer(c.get(format!("{base}{calendar}/keys")), &bob.user.token)
            .send()
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );

    // He accepts: the calendar is his to list, with its owner and keys.
    let accept = format!(
        "/api/v1/calendar/invitations/{}/accept",
        invitation["id"].as_str().unwrap()
    );
    assert_eq!(
        post(&c, &base, &bob.user, &accept, json!({})).status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post(&c, &base, &bob.user, &accept, json!({})).status(),
        StatusCode::NOT_FOUND
    );
    let listed = get(&c, &base, &bob.user, "/api/v1/calendar/calendars");
    let row = listed["calendars"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == made.id.as_str())
        .unwrap()
        .clone();
    assert_eq!(row["permissions"], EDIT);
    assert_eq!(row["owner"]["address"], ada.address.as_str());
    assert_eq!(row["keys"].as_array().unwrap().len(), 1);
    assert_eq!(row["shareBusy"], false);
    let owned = get(&c, &base, &ada.user, "/api/v1/calendar/calendars");
    assert!(owned["calendars"][0]["owner"].is_null());
    // Bob writes with the edit preset; Ada pays for it.
    let before = storage(&c, &base, &ada.user);
    let result = create_event(
        &c,
        &base,
        &bob,
        &made.id,
        &made.key,
        &event(
            "bob@kutup.test",
            "2026-12-01T09:00:00Z",
            "2026-12-01T10:00:00Z",
            "Bob's",
        ),
    );
    assert_eq!(result["status"], 200, "{result}");
    assert!(storage(&c, &base, &ada.user) > before);
    assert_eq!(storage(&c, &base, &bob.user), 0);
    // The view preset: he reads, never writes.
    let r = bearer(
        c.patch(format!("{base}{calendar}/members/{}", bob.user.id)),
        &ada.user.token,
    )
    .json(&json!({ "permissions": VIEW }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let r = post(
        &c,
        &base,
        &bob.user,
        &format!("{calendar}/events/sync"),
        json!({ "addressId": bob.address_id, "changes": [{ "delete": { "id": result["event"]["id"], "baseRevision": 1 } }] }),
    );
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = bearer(
        c.patch(format!("{base}{calendar}/members/{}", bob.user.id)),
        &ada.user.token,
    )
    .json(&json!({ "permissions": EDIT }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);

    // Cem is invited and waits while Bob is removed: the rotation gives
    // him the new generation too.
    assert_eq!(
        invite(&c, &base, &ada, &made, &cem, VIEW).status(),
        StatusCode::CREATED
    );
    let passphrase = Passphrase::generate();
    let key = cal::generate_calendar_key(&passphrase, 1_790_000_100).unwrap();
    let metadata = key
        .unlocked
        .seal_metadata(&made.id, "Aile", "", &ada.secret_key)
        .unwrap();
    let own = cal::seal_own_passphrase(
        &passphrase,
        &made.id,
        2,
        &ada.user.person,
        &ada.user.identity,
    )
    .unwrap()
    .encode_b64()
    .unwrap();
    let rotation = |from: i64, shares: Value| {
        json!({
            "removeAccountId": bob.user.id,
            "fromKeyGeneration": from,
            "keyGeneration": from + 1,
            "publicKey": b64(&key.public_key),
            "lockedSecretKey": b64(&key.locked_secret_key),
            "ownShare": own,
            "memberShares": shares,
            "metadata": SealedMetadataV1::of(&metadata),
            "links": [],
        })
    };
    let cem_share = json!([{ "accountId": cem.user.id, "share": share_for(&made.id, 2, &passphrase, &ada, &cem) }]);
    // Leaving Cem out, or a share for generation 1, is refused.
    let r = post(
        &c,
        &base,
        &ada.user,
        &format!("{calendar}/keys/rotate"),
        rotation(1, json!([])),
    );
    assert_eq!(
        code(r),
        (StatusCode::BAD_REQUEST, "sharesIncomplete".into())
    );
    let r = post(
        &c,
        &base,
        &ada.user,
        &format!("{calendar}/keys/rotate"),
        rotation(
            1,
            json!([{ "accountId": cem.user.id, "share": share_for(&made.id, 1, &made.passphrase, &ada, &cem) }]),
        ),
    );
    assert_eq!(code(r), (StatusCode::BAD_REQUEST, "shareNotBound".into()));
    // Bob can't rotate.
    let r = post(
        &c,
        &base,
        &bob.user,
        &format!("{calendar}/keys/rotate"),
        rotation(1, cem_share.clone()),
    );
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = post(
        &c,
        &base,
        &ada.user,
        &format!("{calendar}/keys/rotate"),
        rotation(1, cem_share.clone()),
    );
    assert_eq!(
        r.status(),
        StatusCode::NO_CONTENT,
        "{}",
        r.text().unwrap_or_default()
    );
    // A second rotation from generation 1 came too late.
    let r = post(
        &c,
        &base,
        &ada.user,
        &format!("{calendar}/keys/rotate"),
        rotation(1, cem_share),
    );
    assert_eq!(
        code(r),
        (StatusCode::CONFLICT, "keyGenerationBehind".into())
    );

    // Bob is out, told once; the calendar's newest key is generation 2.
    let listed = get(&c, &base, &bob.user, "/api/v1/calendar/calendars");
    assert!(listed["calendars"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["id"] != made.id.as_str()));
    let tombstones = get(&c, &base, &bob.user, "/api/v1/calendar/tombstones");
    assert_eq!(tombstones["tombstones"][0]["calendarId"], made.id.as_str());
    assert_eq!(tombstones["tombstones"][0]["reason"], "removed");
    assert_eq!(
        delete(
            &c,
            &base,
            &bob.user,
            &format!("/api/v1/calendar/tombstones/{}", made.id)
        ),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        get(&c, &base, &bob.user, "/api/v1/calendar/tombstones")["tombstones"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let keys = get(&c, &base, &ada.user, &format!("{calendar}/keys"));
    assert_eq!(keys["keys"].as_array().unwrap().len(), 2);
    // An event under the old key is refused; under the new one it lands.
    let stale = create_event(
        &c,
        &base,
        &ada,
        &made.id,
        &made.key,
        &event(
            "old@kutup.test",
            "2026-12-02T09:00:00Z",
            "2026-12-02T10:00:00Z",
            "Old key",
        ),
    );
    assert_eq!(
        (stale["status"].clone(), stale["code"].clone()),
        (json!(409), json!("keyRotated"))
    );
    let fresh = create_event(
        &c,
        &base,
        &ada,
        &made.id,
        &key.unlocked,
        &event(
            "new@kutup.test",
            "2026-12-02T09:00:00Z",
            "2026-12-02T10:00:00Z",
            "New key",
        ),
    );
    assert_eq!(fresh["status"], 200, "{fresh}");

    // Cem accepts and holds both generations: the history reads.
    let invitations = get(&c, &base, &cem.user, "/api/v1/calendar/invitations");
    let invitation = &invitations["invitations"][0];
    assert_eq!(invitation["keys"].as_array().unwrap().len(), 2);
    assert_eq!(
        post(
            &c,
            &base,
            &cem.user,
            &format!(
                "/api/v1/calendar/invitations/{}/accept",
                invitation["id"].as_str().unwrap()
            ),
            json!({}),
        )
        .status(),
        StatusCode::NO_CONTENT
    );
    let row = get(&c, &base, &cem.user, "/api/v1/calendar/calendars")["calendars"][0].clone();
    assert_eq!(row["keyGeneration"], 2);
    assert_eq!(row["keys"].as_array().unwrap().len(), 2);
    // He leaves; an owner never does.
    assert_eq!(
        delete(&c, &base, &cem.user, &format!("{calendar}/members/me")),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        get(&c, &base, &cem.user, "/api/v1/calendar/tombstones")["tombstones"][0]["reason"],
        "left"
    );
    assert_eq!(
        delete(&c, &base, &ada.user, &format!("{calendar}/members/me")),
        StatusCode::BAD_REQUEST
    );

    // Declined: the owner sees it, the shares are gone.
    assert_eq!(
        invite(&c, &base, &ada, &made, &bob, VIEW).status(),
        StatusCode::BAD_REQUEST
    );
    let r = post(
        &c,
        &base,
        &ada.user,
        &format!("{calendar}/invitations"),
        json!({
            "accountId": bob.user.id,
            "incarnationId": bob.user.identity.incarnation_id(),
            "permissions": VIEW,
            "shares": [
                { "keyGeneration": 1, "share": share_for(&made.id, 1, &made.passphrase, &ada, &bob) },
                { "keyGeneration": 2, "share": share_for(&made.id, 2, &passphrase, &ada, &bob) },
            ],
        }),
    );
    assert_eq!(r.status(), StatusCode::CREATED);
    let id = r.json::<Value>().unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        post(
            &c,
            &base,
            &bob.user,
            &format!("/api/v1/calendar/invitations/{id}/decline"),
            json!({})
        )
        .status(),
        StatusCode::NO_CONTENT
    );
    let sent = get(&c, &base, &ada.user, &format!("{calendar}/members"));
    assert_eq!(sent["invitations"][0]["state"], "declined");
    assert_eq!(
        get(&c, &base, &bob.user, "/api/v1/calendar/invitations")["invitations"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    // Deleting the calendar gives back everything, shares and keys too.
    assert_eq!(
        delete(&c, &base, &ada.user, &calendar),
        StatusCode::NO_CONTENT
    );
    assert_eq!(storage(&c, &base, &ada.user), 0);
}

#[test]
fn links_and_their_feeds() {
    let Some(base) = live() else { return };
    let c = client();
    let ada = person(&c, &base);
    let made = make_calendar(&c, &base, &ada, "Kulüp");
    let calendar = format!("/api/v1/calendar/calendars/{}", made.id);
    let result = create_event(
        &c,
        &base,
        &ada,
        &made.id,
        &made.key,
        &event(
            "match@kutup.test",
            "2026-12-05T15:00:00Z",
            "2026-12-05T17:00:00Z",
            "Derby, at home",
        ),
    );
    assert_eq!(result["status"], 200, "{result}");

    // A keyed link: the members' copy of its secret, every generation's
    // passphrase under it.
    let keyed = |kind: &str| {
        let id = uuid::Uuid::new_v4().to_string();
        let secret = LinkSecret::generate();
        let passphrase =
            calendar_link::seal_link_passphrase(&secret, &made.id, &id, 1, &made.passphrase)
                .unwrap();
        let sealed =
            calendar_link::seal_link_secret(&made.passphrase, &made.id, &id, 1, &secret).unwrap();
        let r = post(
            &c,
            &base,
            &ada.user,
            &format!("{calendar}/links"),
            json!({
                "id": id, "kind": kind,
                "secret": { "keyGeneration": 1, "sealed": calendar_link::encode(&sealed) },
                "passphrases": [{ "keyGeneration": 1, "sealed": calendar_link::encode(&passphrase) }],
            }),
        );
        assert_eq!(
            r.status(),
            StatusCode::CREATED,
            "{}",
            r.text().unwrap_or_default()
        );
        (id, secret)
    };
    let (full, full_secret) = keyed("full");
    let (query, query_secret) = keyed("query");
    let busy_id = uuid::Uuid::new_v4().to_string();
    let r = post(
        &c,
        &base,
        &ada.user,
        &format!("{calendar}/links"),
        json!({ "id": busy_id, "kind": "busy" }),
    );
    assert_eq!(r.status(), StatusCode::CREATED);
    let links = get(&c, &base, &ada.user, &format!("{calendar}/links"));
    assert_eq!(links["links"].as_array().unwrap().len(), 3);

    // The full link's page, without an account: the key opens from the
    // URL's secret, and the events with it.
    let anonymous = client();
    let info: Value = anonymous
        .get(format!("{base}/api/v1/calendar/links/{full}"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(info["kind"], "full");
    assert!(info.get("owner").is_none() && info.get("members").is_none());
    let key = &info["keys"][0];
    let passphrase = calendar_link::open_link_passphrase(
        &full_secret,
        &made.id,
        &full,
        1,
        &b64_decode(key["passphrase"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(passphrase.as_str(), made.passphrase.as_str());
    let events: Value = anonymous
        .get(format!(
            "{base}/api/v1/calendar/links/{full}/events?start=2026-12-01T00:00:00Z&end=2026-12-08T00:00:00Z"
        ))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(events["events"].as_array().unwrap().len(), 1);
    assert!(events["events"][0].get("authorAddress").is_none());
    // A full link has no feed: its key never reaches the server.
    assert_eq!(
        anonymous
            .get(format!("{base}/api/v1/calendar/links/{full}/calendar.ics"))
            .send()
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );

    // The query link's feed opens with its key, and with no other.
    let feed = anonymous
        .get(format!(
            "{base}/api/v1/calendar/links/{query}/calendar.ics?key={}",
            query_secret.to_url()
        ))
        .send()
        .unwrap();
    assert_eq!(feed.status(), StatusCode::OK);
    assert!(feed.headers()["content-type"]
        .to_str()
        .unwrap()
        .starts_with("text/calendar"));
    let text = feed.text().unwrap();
    assert!(text.contains("SUMMARY:Derby\\, at home"), "{text}");
    assert!(text.contains("X-WR-CALNAME:Kulüp"), "{text}");
    assert_eq!(text.matches("UID:").count(), 1);
    let wrong = anonymous
        .get(format!(
            "{base}/api/v1/calendar/links/{query}/calendar.ics?key={}",
            LinkSecret::generate().to_url()
        ))
        .send()
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::NOT_FOUND);

    // The busy link: times only, no key, no name.
    let info: Value = anonymous
        .get(format!("{base}/api/v1/calendar/links/{busy_id}"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert!(info["metadata"].is_null() && info["keys"].is_null());
    let busy: Value = anonymous
        .get(format!(
            "{base}/api/v1/calendar/links/{busy_id}/busy?start=2026-12-01T00:00:00Z&end=2026-12-08T00:00:00Z"
        ))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(
        busy["busy"],
        json!([{ "startUtc": "2026-12-05T15:00:00Z", "endUtc": "2026-12-05T17:00:00Z", "fullDay": false }])
    );
    assert_eq!(
        anonymous
            .get(format!(
                "{base}/api/v1/calendar/links/{busy_id}/events?start=2026-12-01T00:00:00Z&end=2026-12-08T00:00:00Z"
            ))
            .send()
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let feed = anonymous
        .get(format!(
            "{base}/api/v1/calendar/links/{busy_id}/calendar.ics"
        ))
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert!(feed.starts_with("BEGIN:VCALENDAR") && !feed.contains("Derby"));

    // A rotation carries the keyed links over; leaving one out is refused.
    let bob = person(&c, &base);
    assert_eq!(
        invite(&c, &base, &ada, &made, &bob, VIEW).status(),
        StatusCode::CREATED
    );
    let invitation = get(&c, &base, &bob.user, "/api/v1/calendar/invitations")["invitations"][0]
        ["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        post(
            &c,
            &base,
            &bob.user,
            &format!("/api/v1/calendar/invitations/{invitation}/accept"),
            json!({})
        )
        .status(),
        StatusCode::NO_CONTENT
    );
    let new_passphrase = Passphrase::generate();
    let new_key = cal::generate_calendar_key(&new_passphrase, 1_790_000_200).unwrap();
    let metadata = new_key
        .unlocked
        .seal_metadata(&made.id, "Kulüp", "", &ada.secret_key)
        .unwrap();
    let carried = |link: &str, secret: &LinkSecret| {
        json!({
            "id": link,
            "passphrase": calendar_link::encode(&calendar_link::seal_link_passphrase(secret, &made.id, link, 2, &new_passphrase).unwrap()),
            "secret": calendar_link::encode(&calendar_link::seal_link_secret(&new_passphrase, &made.id, link, 2, secret).unwrap()),
        })
    };
    let rotation = |links: Value| {
        json!({
            "removeAccountId": bob.user.id,
            "fromKeyGeneration": 1,
            "keyGeneration": 2,
            "publicKey": b64(&new_key.public_key),
            "lockedSecretKey": b64(&new_key.locked_secret_key),
            "ownShare": cal::seal_own_passphrase(&new_passphrase, &made.id, 2, &ada.user.person, &ada.user.identity).unwrap().encode_b64().unwrap(),
            "memberShares": [],
            "metadata": SealedMetadataV1::of(&metadata),
            "links": links,
        })
    };
    let r = post(
        &c,
        &base,
        &ada.user,
        &format!("{calendar}/keys/rotate"),
        rotation(json!([carried(&full, &full_secret)])),
    );
    assert_eq!(code(r), (StatusCode::BAD_REQUEST, "linksIncomplete".into()));
    let r = post(
        &c,
        &base,
        &ada.user,
        &format!("{calendar}/keys/rotate"),
        rotation(json!([
            carried(&full, &full_secret),
            carried(&query, &query_secret)
        ])),
    );
    assert_eq!(
        r.status(),
        StatusCode::NO_CONTENT,
        "{}",
        r.text().unwrap_or_default()
    );
    let info: Value = anonymous
        .get(format!("{base}/api/v1/calendar/links/{full}"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(info["keys"].as_array().unwrap().len(), 2);
    let links = get(&c, &base, &ada.user, &format!("{calendar}/links"));
    assert!(links["links"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|link| link["kind"] != "busy")
        .all(|link| link["secret"]["keyGeneration"] == 2));
    // Still the same feed, opened with both generations.
    let text = anonymous
        .get(format!(
            "{base}/api/v1/calendar/links/{query}/calendar.ics?key={}",
            query_secret.to_url()
        ))
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert!(text.contains("Derby"), "{text}");

    // Deleted, a link opens nothing.
    assert_eq!(
        delete(&c, &base, &ada.user, &format!("{calendar}/links/{full}")),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        anonymous
            .get(format!("{base}/api/v1/calendar/links/{full}"))
            .send()
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        delete(&c, &base, &ada.user, &calendar),
        StatusCode::NO_CONTENT
    );
    assert_eq!(storage(&c, &base, &ada.user), 0);
    assert_eq!(
        anonymous
            .get(format!("{base}/api/v1/calendar/links/{busy_id}"))
            .send()
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[test]
fn busy_times_and_their_switch() {
    let Some(base) = live() else { return };
    let c = client();
    let ada = person(&c, &base);
    let bob = person(&c, &base);
    let made = make_calendar(&c, &base, &ada, "İş");
    let result = create_event(
        &c,
        &base,
        &ada,
        &made.id,
        &made.key,
        &event(
            "work@kutup.test",
            "2026-12-07T09:00:00Z",
            "2026-12-07T12:00:00Z",
            "Planning",
        ),
    );
    assert_eq!(result["status"], 200);
    let busy = |asker: &User| {
        let r = bearer(c.get(format!("{base}/api/v1/calendar/busy")), &asker.token)
            .query(&[
                ("address", ada.address.as_str()),
                ("start", "2026-12-07T00:00:00Z"),
                ("end", "2026-12-14T00:00:00Z"),
            ])
            .send()
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        r.json::<Value>().unwrap()["busy"].as_array().unwrap().len()
    };
    // Off by default: nothing, even to herself.
    assert_eq!(busy(&ada.user), 0);
    let r = bearer(
        c.put(format!("{base}/api/v1/calendar/calendars/{}", made.id)),
        &ada.user.token,
    )
    .json(&json!({ "shareBusy": true }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.json::<Value>().unwrap()["shareBusy"], true);
    assert_eq!(busy(&ada.user), 1);
    // Someone outside her organization is told nothing (Proton's rule).
    assert_eq!(busy(&bob.user), 0);
    // A window past the setting is refused.
    let r = bearer(
        c.get(format!("{base}/api/v1/calendar/busy")),
        &ada.user.token,
    )
    .query(&[
        ("address", ada.address.as_str()),
        ("start", "2026-01-01T00:00:00Z"),
        ("end", "2027-01-01T00:00:00Z"),
    ])
    .send()
    .unwrap();
    assert_eq!(
        code(r),
        (StatusCode::BAD_REQUEST, "busyWindowTooLong".into())
    );
    // The settings say what the app may offer.
    let settings: Value = client()
        .get(format!("{base}/api/v1/auth/settings"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(settings["calendar"]["membersPerCalendar"], 49);
    assert_eq!(settings["calendar"]["linksPerCalendar"], 5);
    assert_eq!(settings["calendar"]["busyWindowDays"], 31);
    assert!(settings["calendar"]["queryLinksAllowed"].is_boolean());
    assert_eq!(
        delete(
            &c,
            &base,
            &ada.user,
            &format!("/api/v1/calendar/calendars/{}", made.id)
        ),
        StatusCode::NO_CONTENT
    );
}
