//! Checked-in vectors for calendars (docs/plans/calendar.md, E1;
//! docs/plans/wipe-unification.md, W4): a fixed owner (account, identity
//! root and address key), calendar key and passphrase, the owner's share of
//! the passphrase on its account key, metadata and an event that must open
//! as written, and refused cases. OpenPGP and HPKE output is random, so the
//! vectors are fixed ciphertexts that must open (in Rust here and in the
//! browser through `scripts/test-crypto-wasm.mjs`).
//! Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_CALENDAR_VECTORS=1 cargo test -p kutup-crypto --features calendar --test calendar_vectors -- --ignored`

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::account_ref::AccountRef;
use kutup_crypto::account_roots::IdentityRoot;
use kutup_crypto::calendar::{
    check_signed_parts, generate_calendar_key, inspect_calendar_public_key, open_own_passphrase,
    seal_own_passphrase, unlock_calendar_key, CalendarShareEnvelopeV1, EventPart, EventParts,
    Passphrase, SealedEvent, SealedMetadata, SessionKey, FIRST_KEY_GENERATION,
};
use kutup_crypto::calendar_event::{
    CalendarEncrypted, CalendarSigned, EventFieldsV1, EventTime, SharedEncrypted, SharedSigned,
    Status, Transp,
};
use kutup_crypto::identity::AccountIdentityKeysV1;
use kutup_crypto::mail_key::{generate_address_key, sign_detached};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/calendar-v1.json"
);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    /// The calendar the metadata and the share name.
    calendar_id: String,
    /// The owner: `aci:<uuid>@<server>`, its identity root (base64) and the
    /// public address key that signed the metadata and the event (the mail
    /// vectors' key).
    owner_account: String,
    owner_identity_root: String,
    owner_public_key: String,
    passphrase: String,
    calendar_public_key: String,
    calendar_locked_secret_key: String,
    calendar_fingerprint: String,
    key_generation: u32,
    /// The owner's own copy of the passphrase (`CalendarShareEnvelopeV1`,
    /// base64).
    passphrase_share: String,
    /// Shares the owner must refuse.
    refused_shares: Vec<RefusedShare>,
    metadata: Metadata,
    event: Event,
    /// The parts' texts, as the event must open.
    shared_signed_text: String,
    shared_encrypted_text: String,
    calendar_signed_text: String,
    calendar_encrypted_text: String,
    /// The event's fields as a client reads them (`EventFieldsV1`).
    fields: serde_json::Value,
    /// The start and end as UTC instants (RFC 3339).
    start_utc: String,
    end_utc: String,
    refused: Vec<Refused>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Metadata {
    key_packet: String,
    data_packet: String,
    signature: String,
    name: String,
    description: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Event {
    shared_key_packet: String,
    calendar_key_packet: String,
    shared_signed: Part,
    shared_encrypted: Part,
    calendar_signed: Part,
    calendar_encrypted: Part,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Part {
    data: String,
    signature: String,
}

/// A share the owner must refuse, and why.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RefusedShare {
    why: String,
    share: String,
}

/// An event a server or client must refuse, and why.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Refused {
    why: String,
    event: Event,
}

const OWNER_ACCOUNT: &str = "aci:3b0f6a52-7c1e-4d8a-9f2b-5e6c7d8a9b0c@kutup.dev";

fn owner_identity(root: &[u8]) -> AccountIdentityKeysV1 {
    AccountIdentityKeysV1::derive(&IdentityRoot::from_bytes(root.try_into().unwrap())).unwrap()
}

fn b64(value: &str) -> Vec<u8> {
    STANDARD.decode(value).expect("base64")
}

fn part_in(part: &EventPart) -> Part {
    Part {
        data: STANDARD.encode(&part.data),
        signature: part.signature.clone(),
    }
}

fn part_out(part: &Part) -> EventPart {
    EventPart {
        data: b64(&part.data),
        signature: part.signature.clone(),
    }
}

fn event_in(event: &SealedEvent) -> Event {
    Event {
        shared_key_packet: STANDARD.encode(&event.shared_key_packet),
        calendar_key_packet: STANDARD.encode(&event.calendar_key_packet),
        shared_signed: part_in(&event.shared_signed),
        shared_encrypted: part_in(&event.shared_encrypted),
        calendar_signed: part_in(&event.calendar_signed),
        calendar_encrypted: part_in(event.calendar_encrypted.as_ref().unwrap()),
    }
}

fn event_out(event: &Event) -> SealedEvent {
    SealedEvent {
        shared_key_packet: b64(&event.shared_key_packet),
        calendar_key_packet: b64(&event.calendar_key_packet),
        shared_signed: part_out(&event.shared_signed),
        shared_encrypted: part_out(&event.shared_encrypted),
        calendar_signed: part_out(&event.calendar_signed),
        calendar_encrypted: Some(part_out(&event.calendar_encrypted)),
    }
}

fn parts() -> EventParts {
    let uid = "9f0c4d2e-5b1a-4e7c-8d3f-2a6b1c0e9d84@kutup.dev".to_owned();
    let stamp = "2026-10-21T08:00:00Z".parse().unwrap();
    EventParts {
        shared_signed: SharedSigned {
            uid: uid.clone(),
            dtstamp: stamp,
            dtstart: EventTime::Zoned {
                local: "2026-10-29T09:30:00".parse().unwrap(),
                tzid: "Europe/Istanbul".into(),
            },
            dtend: Some(EventTime::Zoned {
                local: "2026-10-29T11:00:00".parse().unwrap(),
                tzid: "Europe/Istanbul".into(),
            }),
            recurrence_id: None,
            rrule: None,
            exdates: Vec::new(),
            organizer: None,
            sequence: 0,
            other: Vec::new(),
        },
        shared_encrypted: SharedEncrypted {
            uid: uid.clone(),
            dtstamp: Some(stamp),
            created: Some(stamp),
            summary: Some("Republic Day lunch; with friends, family".into()),
            description: Some("Bring dessert.\nTable for 8 — ü, ş, ğ".into()),
            location: Some("Moda, İstanbul".into()),
            other: Vec::new(),
        },
        calendar_signed: CalendarSigned {
            uid: uid.clone(),
            dtstamp: stamp,
            exdates: Vec::new(),
            status: Some(Status::Confirmed),
            transp: Some(Transp::Opaque),
            other: Vec::new(),
        },
        calendar_encrypted: Some(CalendarEncrypted {
            uid,
            dtstamp: stamp,
            comment: Some("Booked".into()),
            other: Vec::new(),
        }),
    }
}

#[test]
#[ignore = "writes the vectors"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_CALENDAR_VECTORS").is_err() {
        return;
    }
    // The owner is the mail vectors' address key, whose sealed envelope the
    // browser check opens.
    let mail: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/mail-address-key-v1.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let owner_secret = b64(mail["secretKey"].as_str().unwrap());
    let owner_public = b64(mail["publicKey"].as_str().unwrap());
    let stranger = generate_address_key("eve@kutup.dev", 1_790_000_000).unwrap();
    let passphrase = Passphrase::generate();
    let calendar = generate_calendar_key(&passphrase, 1_790_000_000).unwrap();
    let calendar_id = "6f1d3c2a-8b4e-4f7a-9c1d-2e3f4a5b6c7d";
    let owner_root = [0x5au8; 32];
    let owner: AccountRef = OWNER_ACCOUNT.parse().unwrap();
    let identity = owner_identity(&owner_root);
    let seal = |id: &str, generation: u32, account: &AccountRef, keys: &AccountIdentityKeysV1| {
        seal_own_passphrase(&passphrase, id, generation, account, keys)
            .unwrap()
            .encode_b64()
            .unwrap()
    };
    let share = seal(calendar_id, FIRST_KEY_GENERATION, &owner, &identity);
    let someone: AccountRef = "aci:3b0f6a52-7c1e-4d8a-9f2b-5e6c7d8a9b0d@kutup.dev"
        .parse()
        .unwrap();
    let refused_shares = vec![
        RefusedShare {
            why: "another calendar's share".into(),
            share: seal(
                "7f1d3c2a-8b4e-4f7a-9c1d-2e3f4a5b6c7d",
                FIRST_KEY_GENERATION,
                &owner,
                &identity,
            ),
        },
        RefusedShare {
            why: "another key generation's share".into(),
            share: seal(calendar_id, FIRST_KEY_GENERATION + 1, &owner, &identity),
        },
        RefusedShare {
            why: "another account's own share".into(),
            share: seal(
                calendar_id,
                FIRST_KEY_GENERATION,
                &someone,
                &owner_identity(&[0xa5; 32]),
            ),
        },
    ];
    let sealed_metadata = calendar
        .unlocked
        .seal_metadata(calendar_id, "Ev", "Family, İstanbul", &owner_secret)
        .unwrap();
    let parts = parts();
    let event = calendar
        .unlocked
        .seal_event(&parts, &owner_secret, None, None)
        .unwrap();

    let mut refused = Vec::new();
    // The time moved after signing.
    let mut moved = event.clone();
    moved.shared_signed.data = String::from_utf8(moved.shared_signed.data)
        .unwrap()
        .replace("20261029T093000", "20261030T093000")
        .into_bytes();
    refused.push(("a signed part changed after signing", moved));
    // A property of another part, signed by the author: not this part's.
    let mut stray = event.clone();
    let text = String::from_utf8(stray.shared_signed.data.clone())
        .unwrap()
        .replace("SEQUENCE:0", "SUMMARY:in the clear\r\nSEQUENCE:0");
    stray.shared_signed = EventPart {
        signature: sign_detached(&owner_secret, text.as_bytes()).unwrap(),
        data: text.into_bytes(),
    };
    refused.push(("a property of another part, signed", stray));
    // A second spelling (LF line ends), signed by the author.
    let mut respelled = event.clone();
    let text = String::from_utf8(respelled.calendar_signed.data.clone())
        .unwrap()
        .replace("\r\n", "\n");
    respelled.calendar_signed = EventPart {
        signature: sign_detached(&owner_secret, text.as_bytes()).unwrap(),
        data: text.into_bytes(),
    };
    refused.push(("a part not in its canonical form, signed", respelled));
    // A key packet to another key: the calendar can't open it.
    let mut elsewhere = event.clone();
    elsewhere.shared_key_packet = kutup_crypto::calendar::testing::key_packet_to(
        &SessionKey::generate(),
        &stranger.public_key,
    )
    .unwrap();
    refused.push(("a key packet for another key", elsewhere));

    let text = |part: &EventPart| String::from_utf8(part.data.clone()).unwrap();
    let vectors = Vectors {
        calendar_id: calendar_id.into(),
        owner_account: OWNER_ACCOUNT.into(),
        owner_identity_root: STANDARD.encode(owner_root),
        owner_public_key: STANDARD.encode(&owner_public),
        passphrase: passphrase.as_str().to_owned(),
        calendar_public_key: STANDARD.encode(&calendar.public_key),
        calendar_locked_secret_key: STANDARD.encode(&calendar.locked_secret_key),
        calendar_fingerprint: hex::encode(calendar.fingerprint),
        key_generation: FIRST_KEY_GENERATION,
        passphrase_share: share,
        refused_shares,
        metadata: Metadata {
            key_packet: STANDARD.encode(&sealed_metadata.key_packet),
            data_packet: STANDARD.encode(&sealed_metadata.data_packet),
            signature: sealed_metadata.signature,
            name: "Ev".into(),
            description: "Family, İstanbul".into(),
        },
        shared_signed_text: text(&event.shared_signed),
        shared_encrypted_text: parts.shared_encrypted.build().unwrap(),
        calendar_signed_text: text(&event.calendar_signed),
        calendar_encrypted_text: parts.calendar_encrypted.as_ref().unwrap().build().unwrap(),
        fields: serde_json::to_value(EventFieldsV1::of(&parts)).unwrap(),
        start_utc: parts.shared_signed.dtstart.instant().unwrap().to_string(),
        end_utc: parts
            .shared_signed
            .dtend
            .as_ref()
            .unwrap()
            .instant()
            .unwrap()
            .to_string(),
        event: event_in(&event),
        refused: refused
            .into_iter()
            .map(|(why, event)| Refused {
                why: why.into(),
                event: event_in(&event),
            })
            .collect(),
    };
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

fn vectors() -> Vectors {
    serde_json::from_str(&std::fs::read_to_string(PATH).expect("vectors")).expect("JSON")
}

#[test]
fn calendar_vectors_open() {
    let v = vectors();
    let owner_public = b64(&v.owner_public_key);
    let calendar_public = b64(&v.calendar_public_key);
    assert_eq!(
        hex::encode(inspect_calendar_public_key(&calendar_public).unwrap()),
        v.calendar_fingerprint
    );

    // The passphrase: the owner's own share, opened with its identity.
    let owner: AccountRef = v.owner_account.parse().unwrap();
    let identity = owner_identity(&b64(&v.owner_identity_root));
    let open = |share: &str| {
        open_own_passphrase(
            &CalendarShareEnvelopeV1::decode_b64(share)?,
            &v.calendar_id,
            v.key_generation,
            &owner,
            &identity,
        )
    };
    let passphrase = open(&v.passphrase_share).unwrap();
    assert_eq!(passphrase.as_str(), v.passphrase);
    assert!(!v.refused_shares.is_empty());
    for case in &v.refused_shares {
        assert!(open(&case.share).is_err(), "{} was accepted", case.why);
    }
    let unlocked = unlock_calendar_key(&b64(&v.calendar_locked_secret_key), &passphrase).unwrap();
    assert_eq!(hex::encode(unlocked.fingerprint()), v.calendar_fingerprint);

    let sealed_metadata = SealedMetadata {
        key_packet: b64(&v.metadata.key_packet),
        data_packet: b64(&v.metadata.data_packet),
        signature: v.metadata.signature.clone(),
    };
    let (metadata, verified) = unlocked
        .open_metadata(&sealed_metadata, &v.calendar_id, &[&owner_public])
        .unwrap();
    // The name and description are bound to their calendar.
    assert_eq!(metadata.calendar_id, v.calendar_id);
    assert!(unlocked
        .open_metadata(&sealed_metadata, "another-calendar", &[&owner_public])
        .is_err());
    assert!(verified);
    assert_eq!(
        (metadata.name, metadata.description),
        (v.metadata.name, v.metadata.description)
    );

    // The event: what the server reads, and what a member opens.
    let event = event_out(&v.event);
    let (shared, calendar) = check_signed_parts(&event, &[&owner_public]).unwrap();
    assert_eq!(shared.build().unwrap(), v.shared_signed_text);
    assert_eq!(calendar.build().unwrap(), v.calendar_signed_text);
    assert_eq!(shared.dtstart.instant().unwrap().to_string(), v.start_utc);
    assert_eq!(
        shared.dtend.unwrap().instant().unwrap().to_string(),
        v.end_utc
    );
    // Its key packets name this generation's key (E3: which key opens it).
    assert_eq!(
        kutup_crypto::calendar::event_key_id(&event).unwrap(),
        unlocked.key_id().unwrap()
    );
    let opened = unlocked.open_event(&event, &[&owner_public]).unwrap();
    assert!(opened.verified);
    assert_eq!(
        opened.parts.shared_encrypted.build().unwrap(),
        v.shared_encrypted_text
    );
    assert_eq!(
        opened
            .parts
            .calendar_encrypted
            .as_ref()
            .unwrap()
            .build()
            .unwrap(),
        v.calendar_encrypted_text
    );
    assert_eq!(
        serde_json::to_value(EventFieldsV1::of(&opened.parts)).unwrap(),
        v.fields
    );
    // What the vector says is what the parts build.
    let expected = parts();
    assert_eq!(
        expected.shared_signed.build().unwrap(),
        v.shared_signed_text
    );
    assert_eq!(
        expected.shared_encrypted.build().unwrap(),
        v.shared_encrypted_text
    );

    // Refused, by the server's check or by a member opening it.
    assert!(!v.refused.is_empty());
    for case in &v.refused {
        let event = event_out(&case.event);
        let server = check_signed_parts(&event, &[&owner_public]);
        let member = unlocked.open_event(&event, &[&owner_public]);
        assert!(
            server.is_err() || member.is_err() || !member.unwrap().verified,
            "{} was accepted",
            case.why
        );
    }
}
