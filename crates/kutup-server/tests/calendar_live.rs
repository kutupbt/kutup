//! Calendars (docs/plans/calendar.md, E1) against a live server. Needs
//! `KUTUP_LIVE_SERVER` and `KUTUP_LIVE_ADMIN` (`username:password`). The
//! client side is the Rust core, as the browser runs it through WASM.

use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

use kutup_crypto::calendar::{
    self as cal, CalendarMetadataV1, EventPartV1, Passphrase, SealedEventV1, SealedMetadataV1,
    SessionKey,
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

/// A new calendar's body, and its passphrase.
fn new_calendar(owner: &Owner, name: &str) -> (Value, Passphrase) {
    let passphrase = Passphrase::generate();
    let key = cal::generate_calendar_key(&passphrase, 1_790_000_000).unwrap();
    let sealed =
        cal::seal_passphrase(&passphrase, &[&owner.public_key], &owner.secret_key).unwrap();
    let metadata = cal::seal_metadata(
        &CalendarMetadataV1 {
            version: 1,
            name: name.into(),
            description: "Family".into(),
        },
        &key.public_key,
        &owner.secret_key,
    )
    .unwrap();
    (
        json!({
            "id": uuid::Uuid::new_v4(),
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

fn seal(fields: &EventFieldsV1, calendar_public_key: &[u8], author_secret: &[u8]) -> Value {
    let sealed = cal::seal_event(
        &fields.to_parts().unwrap(),
        calendar_public_key,
        author_secret,
        None,
        None,
    )
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
    let (body, passphrase) = new_calendar(&ada, "Ev");
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
    let calendar_public = decode(created["publicKey"].as_str().unwrap());

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
    let secret = cal::unlock_calendar_key(
        &decode(created["lockedSecretKey"].as_str().unwrap()),
        &opened,
    )
    .unwrap();
    let metadata: SealedMetadataV1 = serde_json::from_value(created["metadata"].clone()).unwrap();
    let (metadata, verified) =
        cal::open_metadata(&metadata.to_sealed().unwrap(), &secret, &[&ada.public_key]).unwrap();
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
    let (mut again, _) = new_calendar(&ada, "Again");
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
    let (mut bad, _) = new_calendar(&ada, "Bad");
    let (other, _) = new_calendar(&eve, "Other");
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
    let (mut bad, _) = new_calendar(&ada, "Bad");
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
    let (mut bad, _) = new_calendar(&ada, "Bad");
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
        json!([{ "create": seal(&first, &calendar_public, &ada.secret_key) }]),
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
    let opened = cal::open_event(&stored.to_event().unwrap(), &secret, &[&ada.public_key]).unwrap();
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
        &calendar_public,
        &eve.secret_key,
    );
    let mut elsewhere: SealedEventV1 = serde_json::from_value(seal(
        &fields(
            "e2@kutup.test",
            "2026-10-30T09:00:00",
            "2026-10-30T10:00:00",
            "x",
        ),
        &calendar_public,
        &ada.secret_key,
    ))
    .unwrap();
    elsewhere.shared_key_packet =
        b64(&cal::key_packet_to(&SessionKey::generate(), &eve.public_key).unwrap());
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
            { "create": by_eve },
            { "create": elsewhere },
            { "create": seal(&repeating, &calendar_public, &ada.secret_key) },
            { "create": seal(&first, &calendar_public, &ada.secret_key) },
        ]),
    );
    let statuses: Vec<_> = results
        .iter()
        .map(|r| r["status"].as_u64().unwrap())
        .collect();
    assert_eq!(statuses, [400, 400, 400, 409], "{results:?}");
    assert_eq!(results[3]["code"], "uidTaken");
    // A signed part changed after signing: refused.
    let mut moved: SealedEventV1 = serde_json::from_value(seal(
        &fields(
            "e4@kutup.test",
            "2026-10-30T09:00:00",
            "2026-10-30T10:00:00",
            "x",
        ),
        &calendar_public,
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
    let results = sync(&c, &base, &ada, &id, json!([{ "create": moved }]));
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
        json!([{ "update": { "id": event_id, "event": seal(&later, &calendar_public, &ada.secret_key) } }]),
    );
    assert_eq!(results[0]["status"], 200, "{results:?}");
    assert_eq!(results[0]["event"]["startUtc"], "2026-10-29T09:00:00Z");
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
        json!([{ "update": { "id": event_id, "event": seal(&other_uid, &calendar_public, &ada.secret_key) } }]),
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
    .json(&json!({ "addressId": eve.address_id, "changes": [{ "delete": { "id": event_id } }] }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let eleven: Vec<Value> = (0..11)
        .map(|_| json!({ "delete": { "id": event_id } }))
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

    // Deleted with its events; the storage goes back.
    let results = sync(
        &c,
        &base,
        &ada,
        &id,
        json!([{ "delete": { "id": event_id } }]),
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
