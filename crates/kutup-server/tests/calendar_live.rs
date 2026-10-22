//! Calendars (docs/plans/calendar.md, E1) against a live server. Needs
//! `KUTUP_LIVE_SERVER` and `KUTUP_LIVE_ADMIN` (`username:password`). The
//! client side is the Rust core, as the browser runs it through WASM.

use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

use kutup_crypto::calendar::{
    self as cal, EventPartV1, Passphrase, SealedEventV1, SealedMetadataV1, SessionKey,
    UnlockedCalendarKey,
};
use kutup_crypto::calendar_event::{EventFieldsV1, TimeV1};
use kutup_crypto::mail_key::{self, MailKeyEntryV1, MailKeyListV1, DEFAULT_FLAGS};

mod common;
use common::*;

/// The account's address and key, as the browser holds them.
struct Owner {
    user: User,
    address_id: String,
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
}

/// A user with an address key, as the Account app sets one up.
fn owner(c: &Client, base: &str) -> Owner {
    let user = register(c, base);
    let addresses: Value = bearer(c.get(format!("{base}/api/mail/addresses")), &user.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let id = addresses[0]["id"].as_str().unwrap().to_string();
    let address = addresses[0]["address"].as_str().unwrap().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let key = mail_key::generate_address_key(&address, now).unwrap();
    let envelope =
        mail_key::seal_address_key(&user.master_key, &user.binding, &address, &key.secret_key)
            .unwrap();
    let hex32 = |value: String| -> [u8; 32] { hex::decode(value).unwrap().try_into().unwrap() };
    let list = MailKeyListV1 {
        incarnation_id: hex32(user.identity.incarnation_id()),
        authority_key_id: hex32(user.identity.authority_key_id()),
        address: address.clone(),
        sequence: 1,
        previous_hash: None,
        issued_at: "2026-10-21T12:00:00Z".into(),
        keys: vec![MailKeyEntryV1 {
            fingerprint: key.fingerprint,
            sha256_fingerprint: key.sha256_fingerprint,
            primary: true,
            flags: DEFAULT_FLAGS,
        }],
    }
    .sign(user.identity.authority_signing_key())
    .unwrap();
    let r = bearer(
        c.post(format!("{base}/api/mail/addresses/{id}/keys")),
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
    Owner {
        user,
        address_id: id,
        secret_key: key.secret_key.to_vec(),
        public_key: key.public_key,
    }
}

/// A new calendar's body, its passphrase and its key as made.
fn new_calendar(owner: &Owner, name: &str) -> (Value, Passphrase, UnlockedCalendarKey) {
    let id = uuid::Uuid::new_v4();
    let passphrase = Passphrase::generate();
    let key = cal::generate_calendar_key(&passphrase, 1_790_000_000).unwrap();
    let sealed = cal::seal_passphrase(&passphrase, &owner.secret_key).unwrap();
    let metadata = key
        .unlocked
        .seal_metadata(&id.to_string(), name, "Family", &owner.secret_key)
        .unwrap();
    (
        json!({
            "id": id,
            "addressId": owner.address_id,
            "publicKey": b64(&key.public_key),
            "lockedSecretKey": b64(&key.locked_secret_key),
            "passphrase": {
                "dataPacket": b64(&sealed.data_packet),
                "signature": sealed.signature,
                "keyPacket": b64(&sealed.key_packets[0]),
            },
            "metadata": SealedMetadataV1::of(&metadata),
            "color": "#3E7BFA",
        }),
        passphrase,
        key.unlocked,
    )
}

fn fields(uid: &str, start: &str, end: &str, summary: &str) -> EventFieldsV1 {
    EventFieldsV1 {
        uid: uid.into(),
        dtstamp: "2026-10-21T08:00:00Z".into(),
        created: None,
        start: TimeV1::Zoned {
            local: start.into(),
            tzid: "Europe/Istanbul".into(),
        },
        end: Some(TimeV1::Zoned {
            local: end.into(),
            tzid: "Europe/Istanbul".into(),
        }),
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
    }
}

fn seal(fields: &EventFieldsV1, calendar: &UnlockedCalendarKey, author_secret: &[u8]) -> Value {
    let sealed = calendar
        .seal_event(&fields.to_parts().unwrap(), author_secret, None, None)
        .unwrap();
    serde_json::to_value(SealedEventV1::of(&sealed)).unwrap()
}

fn sync(c: &Client, base: &str, owner: &Owner, calendar: &str, changes: Value) -> Vec<Value> {
    let r = bearer(
        c.post(format!(
            "{base}/api/calendar/calendars/{calendar}/events/sync"
        )),
        &owner.user.token,
    )
    .json(&json!({ "addressId": owner.address_id, "changes": changes }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    r.json::<Value>().unwrap()["results"]
        .as_array()
        .unwrap()
        .clone()
}

fn storage(c: &Client, base: &str, user: &User) -> i64 {
    let usage: Value = bearer(c.get(format!("{base}/api/user/storage")), &user.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    usage["calendar"]["bytes"].as_i64().unwrap()
}

#[test]
fn calendars_and_events() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = crate::common::client();
    let ada = owner(&c, &base);
    let eve = owner(&c, &base);

    // A calendar: its key, the passphrase sealed to Ada's address key and
    // signed, the name sealed to the calendar.
    let (body, passphrase, key) = new_calendar(&ada, "Ev");
    let r = bearer(
        c.post(format!("{base}/api/calendar/calendars")),
        &ada.user.token,
    )
    .json(&body)
    .send()
    .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::CREATED,
        "{}",
        r.text().unwrap_or_default()
    );
    let created: Value = r.json().unwrap();
    let id = created["id"].as_str().unwrap().to_owned();
    assert_eq!(created["permissions"], 127);
    assert_eq!(created["color"], "#3e7bfa");
    assert_eq!(created["revision"], 1);
    assert_eq!(
        decode(created["publicKey"].as_str().unwrap()),
        key.public_key()
    );

    // What the server hands back opens: the passphrase, the key, the name.
    let opened = cal::open_passphrase(
        &decode(created["passphrase"]["keyPacket"].as_str().unwrap()),
        &decode(created["passphrase"]["dataPacket"].as_str().unwrap()),
        created["passphrase"]["signature"]
            .as_str()
            .unwrap()
            .as_bytes(),
        &ada.secret_key,
        &[&ada.public_key],
    )
    .unwrap();
    assert_eq!(opened.as_str(), passphrase.as_str());
    let unlocked = cal::unlock_calendar_key(
        &decode(created["lockedSecretKey"].as_str().unwrap()),
        &opened,
    )
    .unwrap();
    let metadata: SealedMetadataV1 = serde_json::from_value(created["metadata"].clone()).unwrap();
    let (metadata, verified) = unlocked
        .open_metadata(&metadata.to_sealed().unwrap(), &id, &[&ada.public_key])
        .unwrap();
    assert_eq!(unlocked.fingerprint(), key.fingerprint());
    assert!(verified);
    assert_eq!(metadata.name, "Ev");
    let charged = storage(&c, &base, &ada.user);
    assert!(charged > 0);

    // Listed by the account head's calendars scope at revision 1.
    let index: Value = bearer(
        c.get(format!("{base}/api/account/index/calendars")),
        &ada.user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert!(index["values"].to_string().contains(&id), "{index}");

    // A second calendar with the same id: refused.
    let (mut again, _, _) = new_calendar(&ada, "Again");
    again["id"] = json!(id);
    let r = bearer(
        c.post(format!("{base}/api/calendar/calendars")),
        &ada.user.token,
    )
    .json(&again)
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(r.json::<Value>().unwrap()["code"], "calendarExists");

    // Refused calendars: a passphrase to someone else's key, a locked key
    // that isn't the calendar's, another account's address.
    let (mut bad, _, _) = new_calendar(&ada, "Bad");
    let (other, _, _) = new_calendar(&eve, "Other");
    bad["passphrase"] = other["passphrase"].clone();
    assert_status(
        &c,
        &base,
        &ada.user,
        "POST",
        "/api/calendar/calendars",
        &bad,
        StatusCode::BAD_REQUEST,
    );
    let (mut bad, _, _) = new_calendar(&ada, "Bad");
    bad["lockedSecretKey"] = other["lockedSecretKey"].clone();
    assert_status(
        &c,
        &base,
        &ada.user,
        "POST",
        "/api/calendar/calendars",
        &bad,
        StatusCode::BAD_REQUEST,
    );
    let (mut bad, _, _) = new_calendar(&ada, "Bad");
    bad["addressId"] = json!(eve.address_id);
    assert_status(
        &c,
        &base,
        &ada.user,
        "POST",
        "/api/calendar/calendars",
        &bad,
        StatusCode::BAD_REQUEST,
    );

    // An event: the server reads its times from the signed part only.
    let uid = format!("{}@kutup.test", uuid::Uuid::new_v4());
    let first = fields(&uid, "2026-10-29T09:30:00", "2026-10-29T11:00:00", "Lunch");
    let results = sync(
        &c,
        &base,
        &ada,
        &id,
        json!([{ "create": { "id": uuid::Uuid::new_v4().to_string(), "event": seal(&first, &key, &ada.secret_key) } }]),
    );
    assert_eq!(results[0]["status"], 200, "{results:?}");
    let event = &results[0]["event"];
    let event_id = event["id"].as_str().unwrap().to_owned();
    assert_eq!(event["startUtc"], "2026-10-29T06:30:00Z");
    assert_eq!(event["endUtc"], "2026-10-29T08:00:00Z");
    assert_eq!(event["fullDay"], false);

    // In its window, and opened by the calendar's key.
    let page: Value = bearer(
        c.get(format!(
            "{base}/api/calendar/calendars/{id}/events?start=2026-10-26T00:00:00Z&end=2026-11-02T00:00:00Z"
        )),
        &ada.user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert_eq!(page["events"].as_array().unwrap().len(), 1, "{page}");
    let stored: SealedEventV1 = serde_json::from_value(page["events"][0]["event"].clone()).unwrap();
    let opened = unlocked
        .open_event(&stored.to_event().unwrap(), &[&ada.public_key])
        .unwrap();
    assert!(opened.verified);
    assert_eq!(EventFieldsV1::of(&opened.parts), first);
    let outside: Value = bearer(
        c.get(format!(
            "{base}/api/calendar/calendars/{id}/events?start=2026-11-02T00:00:00Z&end=2026-11-09T00:00:00Z"
        )),
        &ada.user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert_eq!(outside["events"].as_array().unwrap().len(), 0);

    // Refused events, each alone in one sync: signed by someone else, a key
    // packet not to the calendar, a repeating one (E2), the same UID again.
    let by_eve = seal(
        &fields(
            "e1@kutup.test",
            "2026-10-30T09:00:00",
            "2026-10-30T10:00:00",
            "x",
        ),
        &key,
        &eve.secret_key,
    );
    let mut elsewhere: SealedEventV1 = serde_json::from_value(seal(
        &fields(
            "e2@kutup.test",
            "2026-10-30T09:00:00",
            "2026-10-30T10:00:00",
            "x",
        ),
        &key,
        &ada.secret_key,
    ))
    .unwrap();
    elsewhere.shared_key_packet =
        b64(&cal::testing::key_packet_to(&SessionKey::generate(), &eve.public_key).unwrap());
    let mut repeating = fields(
        "e3@kutup.test",
        "2026-10-30T09:00:00",
        "2026-10-30T10:00:00",
        "x",
    );
    repeating.rrule = Some("FREQ=WEEKLY".into());
    let results = sync(
        &c,
        &base,
        &ada,
        &id,
        json!([
            { "create": { "id": uuid::Uuid::new_v4().to_string(), "event": by_eve } },
            { "create": { "id": uuid::Uuid::new_v4().to_string(), "event": elsewhere } },
            { "create": { "id": uuid::Uuid::new_v4().to_string(), "event": seal(&repeating, &key, &ada.secret_key) } },
            { "create": { "id": uuid::Uuid::new_v4().to_string(), "event": seal(&first, &key, &ada.secret_key) } },
        ]),
    );
    let statuses: Vec<_> = results
        .iter()
        .map(|r| r["status"].as_u64().unwrap())
        .collect();
    // A weekly event is taken now (E2); the others are refused.
    assert_eq!(statuses, [400, 400, 200, 409], "{results:?}");
    assert_eq!(results[3]["code"], "uidTaken");
    // A signed part changed after signing: refused.
    let mut moved: SealedEventV1 = serde_json::from_value(seal(
        &fields(
            "e4@kutup.test",
            "2026-10-30T09:00:00",
            "2026-10-30T10:00:00",
            "x",
        ),
        &key,
        &ada.secret_key,
    ))
    .unwrap();
    let text = String::from_utf8(decode(&moved.shared_signed.data))
        .unwrap()
        .replace("20261030T090000", "20261031T090000");
    moved.shared_signed = EventPartV1 {
        data: b64(text.as_bytes()),
        signature: moved.shared_signed.signature,
    };
    let results = sync(
        &c,
        &base,
        &ada,
        &id,
        json!([{ "create": { "id": uuid::Uuid::new_v4().to_string(), "event": moved } }]),
    );
    assert_eq!(results[0]["status"], 400);

    // Changed: the same UID, new times read again.
    let later = fields(
        &uid,
        "2026-10-29T12:00:00",
        "2026-10-29T13:00:00",
        "Late lunch",
    );
    let results = sync(
        &c,
        &base,
        &ada,
        &id,
        json!([{ "update": { "id": event_id, "baseRevision": 1, "event": seal(&later, &key, &ada.secret_key) } }]),
    );
    assert_eq!(results[0]["status"], 200, "{results:?}");
    assert_eq!(results[0]["event"]["startUtc"], "2026-10-29T09:00:00Z");
    assert_eq!(results[0]["event"]["revision"], 2);
    // From a version no longer stored (a replay, or another device saved
    // first): refused, nothing changed.
    let results = sync(
        &c,
        &base,
        &ada,
        &id,
        json!([{ "update": { "id": event_id, "baseRevision": 1, "event": seal(&later, &key, &ada.secret_key) } }]),
    );
    assert_eq!(
        (results[0]["status"].as_u64(), results[0]["code"].as_str()),
        (Some(409), Some("revision_conflict")),
        "{results:?}"
    );
    // A SEQUENCE lower than the stored one: refused.
    let mut ahead = later.clone();
    ahead.sequence = 2;
    let results = sync(
        &c,
        &base,
        &ada,
        &id,
        json!([{ "update": { "id": event_id, "baseRevision": 2, "event": seal(&ahead, &key, &ada.secret_key) } }]),
    );
    assert_eq!(results[0]["event"]["revision"], 3, "{results:?}");
    let results = sync(
        &c,
        &base,
        &ada,
        &id,
        json!([{ "update": { "id": event_id, "baseRevision": 3, "event": seal(&later, &key, &ada.secret_key) } }]),
    );
    assert_eq!(
        (results[0]["status"].as_u64(), results[0]["code"].as_str()),
        (Some(409), Some("sequenceBehind")),
        "{results:?}"
    );

    // Pages: the cursor is the last event's (start, id), held by the client.
    let results = sync(
        &c,
        &base,
        &ada,
        &id,
        json!([{ "create": { "id": uuid::Uuid::new_v4().to_string(), "event": seal(&fields("paged@kutup.test", "2026-10-30T09:00:00", "2026-10-30T10:00:00", "Paged"), &key, &ada.secret_key) } }]),
    );
    assert_eq!(results[0]["status"], 200, "{results:?}");
    let window = "start=2026-10-26T00:00:00Z&end=2026-11-02T00:00:00Z";
    let page = |query: &str| -> Value {
        bearer(
            c.get(format!(
                "{base}/api/calendar/calendars/{id}/events?{window}&limit=1{query}"
            )),
            &ada.user.token,
        )
        .send()
        .unwrap()
        .json()
        .unwrap()
    };
    let one = page("");
    assert_eq!(one["events"].as_array().unwrap().len(), 1, "{one}");
    assert_eq!(one["events"][0]["id"], event_id, "{one}");
    let next = &one["next"];
    let two = page(&format!(
        "&afterStart={}&afterId={}",
        next["afterStart"].as_str().unwrap().replace('+', "%2B"),
        next["afterId"].as_str().unwrap()
    ));
    assert_eq!(two["events"].as_array().unwrap().len(), 1, "{two}");
    assert_ne!(two["events"][0]["id"], event_id, "{two}");
    assert!(two["next"].is_null(), "the last page: {two}");
    // Half a cursor: refused.
    let r = bearer(
        c.get(format!(
            "{base}/api/calendar/calendars/{id}/events?{window}&afterId={event_id}"
        )),
        &ada.user.token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let other_uid = fields(
        "other@kutup.test",
        "2026-10-29T12:00:00",
        "2026-10-29T13:00:00",
        "x",
    );
    let results = sync(
        &c,
        &base,
        &ada,
        &id,
        json!([{ "update": { "id": event_id, "baseRevision": 3, "event": seal(&other_uid, &key, &ada.secret_key) } }]),
    );
    assert_eq!(results[0]["status"], 400, "an event keeps its UID");

    // Strangers see nothing; a sync over the batch is refused.
    let r = bearer(
        c.get(format!(
            "{base}/api/calendar/calendars/{id}/events/{event_id}"
        )),
        &eve.user.token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let r = bearer(
        c.post(format!("{base}/api/calendar/calendars/{id}/events/sync")),
        &eve.user.token,
    )
    .json(&json!({ "addressId": eve.address_id, "changes": [{ "delete": { "id": event_id, "baseRevision": 3 } }] }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let eleven: Vec<Value> = (0..11)
        .map(|_| json!({ "delete": { "id": event_id, "baseRevision": 3 } }))
        .collect();
    let r = bearer(
        c.post(format!("{base}/api/calendar/calendars/{id}/events/sync")),
        &ada.user.token,
    )
    .json(&json!({ "addressId": ada.address_id, "changes": eleven }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    // The member's own colour, by revision; a stale one conflicts.
    let r = bearer(
        c.put(format!("{base}/api/calendar/calendars/{id}")),
        &ada.user.token,
    )
    .json(&json!({ "color": "#00aa55", "baseRevision": 1, "revision": 2 }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.json::<Value>().unwrap()["color"], "#00aa55");
    let r = bearer(
        c.put(format!("{base}/api/calendar/calendars/{id}")),
        &ada.user.token,
    )
    .json(&json!({ "display": false, "baseRevision": 1, "revision": 2 }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);

    // A delete from an older revision: refused, the event kept.
    let results = sync(
        &c,
        &base,
        &ada,
        &id,
        json!([{ "delete": { "id": event_id, "baseRevision": 2 } }]),
    );
    assert_eq!(results[0]["code"], "revision_conflict", "{results:?}");
    // Deleted with its events; the storage goes back.
    let results = sync(
        &c,
        &base,
        &ada,
        &id,
        json!([{ "delete": { "id": event_id, "baseRevision": 3 } }]),
    );
    assert_eq!(results[0]["status"], 200);
    let r = bearer(
        c.delete(format!("{base}/api/calendar/calendars/{id}")),
        &eve.user.token,
    )
    .json(&json!({}))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let r = bearer(
        c.delete(format!("{base}/api/calendar/calendars/{id}")),
        &ada.user.token,
    )
    .json(&json!({}))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert_eq!(storage(&c, &base, &ada.user), 0);
    let listed: Value = bearer(
        c.get(format!("{base}/api/calendar/calendars")),
        &ada.user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert_eq!(listed["calendars"].as_array().unwrap().len(), 0);
}

/// The calendar limit is the administrators' (`calendarsPerAccount`).
/// A calendar of Ada's, made through the API: its id and key.
fn made_calendar(c: &Client, base: &str, ada: &Owner, name: &str) -> (String, UnlockedCalendarKey) {
    let (body, _, key) = new_calendar(ada, name);
    let r = bearer(
        c.post(format!("{base}/api/calendar/calendars")),
        &ada.user.token,
    )
    .json(&body)
    .send()
    .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::CREATED,
        "{}",
        r.text().unwrap_or_default()
    );
    let created: Value = r.json().unwrap();
    (created["id"].as_str().unwrap().to_owned(), key)
}

fn create(event: Value) -> Value {
    json!({ "create": { "id": uuid::Uuid::new_v4().to_string(), "event": event } })
}

fn berlin(local: &str) -> TimeV1 {
    TimeV1::Zoned {
        local: local.into(),
        tzid: "Europe/Berlin".into(),
    }
}

/// Repeating events on the server (docs/plans/calendar.md, E2b): the range
/// end of a series across a DST change, the window of an endless one, the
/// COUNT setting, the calendar part's EXDATEs held to the series, changed
/// occurrences held to their series, and creates that land once however
/// often they are sent.
#[test]
fn repeating_events() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = crate::common::client();
    let ada = owner(&c, &base);
    let (id, key) = made_calendar(&c, &base, &ada, "Tekrar");
    let window = |start: &str, end: &str| -> Vec<String> {
        let page: Value = bearer(
            c.get(format!(
                "{base}/api/calendar/calendars/{id}/events?start={start}&end={end}"
            )),
            &ada.user.token,
        )
        .send()
        .unwrap()
        .json()
        .unwrap();
        page["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["uid"].as_str().unwrap().to_owned())
            .collect()
    };
    let sealed = |fields: &EventFieldsV1| seal(fields, &key, &ada.secret_key);

    // Mondays at 09:00 in Berlin, five times, across the end of summer time
    // (25 October): the last ends 16 November 10:00 CET, 09:00 UTC.
    let mut weekly = fields(
        "weekly@kutup.test",
        "2026-10-19T09:00:00",
        "2026-10-19T10:00:00",
        "Weekly",
    );
    weekly.start = berlin("2026-10-19T09:00:00");
    weekly.end = Some(berlin("2026-10-19T10:00:00"));
    weekly.rrule = Some("FREQ=WEEKLY;COUNT=5".into());
    let results = sync(&c, &base, &ada, &id, json!([create(sealed(&weekly))]));
    assert_eq!(results[0]["status"], 200, "{results:?}");
    assert_eq!(results[0]["event"]["rangeEndUtc"], "2026-11-16T09:00:00Z");
    assert!(window("2026-11-16T00:00:00Z", "2026-11-17T00:00:00Z")
        .contains(&"weekly@kutup.test".to_owned()));
    assert!(!window("2026-11-17T00:00:00Z", "2026-11-30T00:00:00Z")
        .contains(&"weekly@kutup.test".to_owned()));

    // Without end: no range end, in every later window.
    let mut daily = fields(
        "daily@kutup.test",
        "2026-10-20T09:00:00",
        "2026-10-20T09:30:00",
        "Daily",
    );
    daily.rrule = Some("FREQ=DAILY".into());
    let results = sync(&c, &base, &ada, &id, json!([create(sealed(&daily))]));
    assert_eq!(results[0]["status"], 200, "{results:?}");
    assert!(results[0]["event"]["rangeEndUtc"].is_null());
    assert!(window("2030-01-01T00:00:00Z", "2030-01-02T00:00:00Z")
        .contains(&"daily@kutup.test".to_owned()));

    // A COUNT past the site's (49 by default).
    let mut long = fields(
        "long@kutup.test",
        "2026-10-20T09:00:00",
        "2026-10-20T09:30:00",
        "Long",
    );
    long.rrule = Some("FREQ=DAILY;COUNT=50".into());
    let results = sync(&c, &base, &ada, &id, json!([create(sealed(&long))]));
    assert_eq!(
        (results[0]["status"].as_u64(), results[0]["code"].as_str()),
        (Some(400), Some("countTooLarge"))
    );

    // This calendar's own EXDATE: an occurrence of the series (the last
    // one, so the range ends a week earlier), never another time.
    let mut own = weekly.clone();
    own.uid = "own@kutup.test".into();
    let mut parts = own.to_parts().unwrap();
    parts.calendar_signed.exdates = vec![berlin("2026-11-16T09:00:00").to_time().unwrap()];
    let removed = key.seal_event(&parts, &ada.secret_key, None, None).unwrap();
    let results = sync(
        &c,
        &base,
        &ada,
        &id,
        json!([create(
            serde_json::to_value(SealedEventV1::of(&removed)).unwrap()
        )]),
    );
    assert_eq!(results[0]["status"], 200, "{results:?}");
    assert_eq!(results[0]["event"]["rangeEndUtc"], "2026-11-09T09:00:00Z");
    let mut off = weekly.clone();
    off.uid = "off@kutup.test".into();
    let mut parts = off.to_parts().unwrap();
    // A Tuesday: no occurrence there.
    parts.calendar_signed.exdates = vec![berlin("2026-10-20T09:00:00").to_time().unwrap()];
    let wrong = key.seal_event(&parts, &ada.secret_key, None, None).unwrap();
    let results = sync(
        &c,
        &base,
        &ada,
        &id,
        json!([create(
            serde_json::to_value(SealedEventV1::of(&wrong)).unwrap()
        )]),
    );
    assert_eq!(
        (results[0]["status"].as_u64(), results[0]["code"].as_str()),
        (Some(400), Some("exdateNotAnOccurrence")),
        "{results:?}"
    );

    // A changed occurrence: one of its series' (26 October, in summer time
    // no longer), not another time, not without its series.
    let child = |uid: &str, at: &str| {
        let mut f = fields(uid, "2026-10-26T11:00:00", "2026-10-26T12:00:00", "Moved");
        f.start = berlin("2026-10-26T11:00:00");
        f.end = Some(berlin("2026-10-26T12:00:00"));
        f.recurrence_id = Some(berlin(at));
        sealed(&f)
    };
    let results = sync(
        &c,
        &base,
        &ada,
        &id,
        json!([
            create(child("weekly@kutup.test", "2026-10-26T09:00:00")),
            create(child("weekly@kutup.test", "2026-10-27T09:00:00")),
            create(child("nobody@kutup.test", "2026-10-26T09:00:00")),
        ]),
    );
    let outcome: Vec<_> = results
        .iter()
        .map(|r| {
            (
                r["status"].as_u64().unwrap(),
                r["code"].as_str().map(str::to_owned),
            )
        })
        .collect();
    assert_eq!(
        outcome,
        [
            (200, None),
            (400, Some("notAnOccurrence".into())),
            (400, Some("parentMissing".into()))
        ],
        "{results:?}"
    );

    // "This and following" from 2 November, Proton's three changes, each
    // landing once however often it is sent: cut the series to two, then
    // the new series from the 2nd (its own UID).
    let stored: Value = bearer(
        c.get(format!("{base}/api/calendar/calendars/{id}/events?start=2026-10-19T00:00:00Z&end=2026-10-20T00:00:00Z")),
        &ada.user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    let parent = stored["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["uid"] == "weekly@kutup.test" && e["event"].is_object())
        .unwrap()
        .clone();
    let mut cut = weekly.clone();
    cut.rrule = Some("FREQ=WEEKLY;COUNT=2".into());
    cut.sequence = 1;
    let cut_change = json!({ "update": {
        "id": parent["id"], "baseRevision": parent["revision"], "event": sealed(&cut),
    } });
    let mut following = weekly.clone();
    following.uid = "weekly_R20261102T090000@kutup.test".into();
    following.start = berlin("2026-11-02T09:00:00");
    following.end = Some(berlin("2026-11-02T10:00:00"));
    following.rrule = Some("FREQ=WEEKLY;COUNT=3".into());
    let new_series = json!({ "create": {
        "id": uuid::Uuid::new_v4().to_string(), "event": sealed(&following),
    } });
    for round in 0..2 {
        let results = sync(
            &c,
            &base,
            &ada,
            &id,
            json!([cut_change.clone(), new_series.clone()]),
        );
        if round == 0 {
            assert_eq!(results[0]["status"], 200, "{results:?}");
            assert_eq!(results[0]["event"]["rangeEndUtc"], "2026-10-26T09:00:00Z");
        } else {
            // Sent again: the cut is a conflict the app reads as done.
            assert_eq!(results[0]["code"], "revision_conflict", "{results:?}");
        }
        assert_eq!(results[1]["status"], 200, "{results:?}");
    }
    let november = window("2026-11-02T00:00:00Z", "2026-11-30T00:00:00Z");
    assert_eq!(
        november
            .iter()
            .filter(|uid| uid.contains("_R20261102"))
            .count(),
        1,
        "one new series however often it was sent: {november:?}"
    );
}

#[test]
fn the_calendar_limit_is_a_setting() {
    let (Ok(base), Ok(admin)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_ADMIN"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_ADMIN not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = crate::common::client();
    let (name, password) = admin.split_once(':').unwrap();
    let admin_token = admin_token(&c, &base, password, name);
    let set = |value: Value| {
        let r = bearer(c.put(format!("{base}/api/admin/settings")), &admin_token)
            .json(&json!({ "calendarsPerAccount": value }))
            .send()
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    };
    let ada = owner(&c, &base);
    set(json!(1));
    let first = bearer(
        c.post(format!("{base}/api/calendar/calendars")),
        &ada.user.token,
    )
    .json(&new_calendar(&ada, "One").0)
    .send()
    .unwrap();
    let second = bearer(
        c.post(format!("{base}/api/calendar/calendars")),
        &ada.user.token,
    )
    .json(&new_calendar(&ada, "Two").0)
    .send()
    .unwrap();
    set(Value::Null);
    assert_eq!(first.status(), StatusCode::CREATED);
    // Nothing stays charged after the test (the gate checks every account's
    // storage comes back to zero).
    let id = first.json::<Value>().unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let r = bearer(
        c.delete(format!("{base}/api/calendar/calendars/{id}")),
        &ada.user.token,
    )
    .json(&json!({}))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert_eq!(storage(&c, &base, &ada.user), 0);
    assert_eq!(second.status(), StatusCode::CONFLICT);
    assert_eq!(second.json::<Value>().unwrap()["code"], "calendarLimit");
}

fn assert_status(
    c: &Client,
    base: &str,
    user: &User,
    method: &str,
    path: &str,
    body: &Value,
    status: StatusCode,
) {
    let request = match method {
        "POST" => c.post(format!("{base}{path}")),
        _ => c.put(format!("{base}{path}")),
    };
    let r = bearer(request, &user.token).json(body).send().unwrap();
    assert_eq!(
        r.status(),
        status,
        "{method} {path}: {}",
        r.text().unwrap_or_default()
    );
}

fn decode(value: &str) -> Vec<u8> {
    b64_decode(value)
}
