//! Checked-in vectors for Drive identity (docs/plans/drive-identity-pins.md):
//! an account's Drive key binding (bound to its address, a statement to
//! others), and a sealed identity pin list (suite 2, bound to the account's
//! key binding), with the values that must be refused, and how every app follows
//! a rename (docs/plans/username-renames.md): `record`, `lookup` and
//! `apply_rename` over plain lists, and the lists the format refuses. Regenerate
//! only for a
//! deliberate format change:
//! `KUTUP_WRITE_IDENTITY_VECTORS=1 cargo test -p kutup-crypto --test identity_pins_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::account_rename::{self, AccountRenameV1};
use kutup_crypto::drive_key_binding;
use kutup_crypto::identity::AccountIdentityKeysV1;
use kutup_crypto::identity_pins::{
    self, IdentityPinV1, IdentityPinsV1, PinMatch, PinState, PinUpdate, RenameAnchorV1,
};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/identity-pins-v2.json"
);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    master_key: String,
    account: String,
    /// The owner's key binding, which the sealed list binds.
    binding: String,
    authority_public_key: String,
    drive_hpke_public_key: String,
    drive_signing_public_key: String,
    drive_key_binding: String,
    pins_key: String,
    revision: u64,
    pins: String,
    nonce: String,
    sealed: String,
    /// Values that must not open: each with the binding and revision tried.
    refused: Vec<Refused>,
    renames: RenameVectors,
}

/// A rename followed: plain (unsealed) canonical lists.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RenameVectors {
    /// The renamed account's authority.
    authority_public_key: String,
    chain: Vec<AccountRenameV1>,
    before: String,
    after: String,
    /// `apply_rename`'s answer, as JSON.
    applied: serde_json::Value,
    /// Applied to `after`, refused: the first statement alone rolls the
    /// second back.
    rollback: Vec<AccountRenameV1>,
    /// `lookup` against `after`.
    lookups: Vec<LookupCase>,
    records: Vec<RecordCase>,
    /// Lists the format refuses.
    refused_lists: Vec<RefusedList>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LookupCase {
    address: String,
    published: Option<String>,
    /// `lookup`'s answer, as JSON.
    result: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecordCase {
    case: String,
    before: String,
    account: String,
    authority: String,
    update: PinUpdate,
    since: String,
    after: String,
    changed: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RefusedList {
    case: String,
    pins: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Refused {
    case: String,
    binding: String,
    revision: u64,
    sealed: String,
}

const BINDING: &str = "3f2a6c1e-8b4d-4e7a-9c5f-1d2e3a4b5c6d";
const OTHER_BINDING: &str = "9e8d7c6b-5a49-4382-a716-05f4e3d2c1b0";
/// The same list as suite 1 sealed it (bound to `alice@kutup.dev`, revision 7):
/// no longer read.
const SUITE_1_SEALED: &str = "S1VUSVAxAAAAAUREREREREREREREREREREREREREREREROUZuOGzIGeJ+2idGGW9o5mztCqfGsWL09FEhMBoOCd+VuGuFcWXQEfc0V1Jt641IDC3je2OLpq3JjHBld+CeSRn0VX20dpk4Y5zBADJDOQUlTqMnal4XnidpixX5i7dWl/IDTWQyY92EBc70OrE7DV6axGTzCXIba5g0Ed7BTCmY3WwmqZTL5NGLnFLZYsfLznsBLlFk5g30uNbU54LL7WJTsqbxR4AB1Y0u9HqOsm62PYtD9W67uk/qRVoDILdzcieXIbgK5zfaHnTNAkZcv3KLIYlZlS7JljpgRAGe13rCJHwW8miT37mu2VMiLghR4XoXLbaH1eVcu7rpnTac4MBqxvXN/S7ezuc3tdJWv5LAbPT2UpZC2cex3NGIG+jbQMJrVUn43JTYjF9iN7bsA6Jr5aRlA2I+Y/akTiq8vNbCKI51+VJtc1ukFtkoFJasFhn+RSFlBkV7AHCG3HaF8c1bRXkI9QjUcaQxfHo6tHU3OehWcVH0+QWOXryok64bcnGI32szt2Ok9+VqY3i0ASW0Q==";

fn refused(sealed: &[u8]) -> Vec<Refused> {
    let case = |case: &str, binding: &str, revision: u64, sealed: &[u8]| Refused {
        case: case.into(),
        binding: binding.into(),
        revision,
        sealed: STANDARD.encode(sealed),
    };
    let mut magic = sealed.to_vec();
    magic[5] = b'1';
    let mut suite = sealed.to_vec();
    suite[9] = 1;
    let mut relabelled = sealed.to_vec();
    relabelled[17] = 8;
    let mut nonce = sealed.to_vec();
    nonce[18] ^= 1;
    let mut tag = sealed.to_vec();
    *tag.last_mut().unwrap() ^= 1;
    let old = STANDARD.decode(SUITE_1_SEALED).unwrap();
    vec![
        case("another account's key binding", OTHER_BINDING, 7, sealed),
        case(
            "the owner's address instead of its binding",
            "alice@kutup.dev",
            7,
            sealed,
        ),
        case("relabelled as another revision", BINDING, 8, &relabelled),
        case("magic changed", BINDING, 7, &magic),
        case("suite changed", BINDING, 7, &suite),
        case("nonce changed", BINDING, 7, &nonce),
        case("ciphertext changed", BINDING, 7, &tag),
        case("suite 1, bound to the address", BINDING, 7, &old),
        case(
            "suite 1, opened with the address",
            "alice@kutup.dev",
            7,
            &old,
        ),
    ]
}

fn b64(identity: &AccountIdentityKeysV1) -> String {
    STANDARD.encode(identity.authority_public_key())
}

fn json(list: &IdentityPinsV1) -> String {
    String::from_utf8(identity_pins::encode(list).unwrap()).unwrap()
}

fn plain(pin: (&str, &AccountIdentityKeysV1, PinState)) -> IdentityPinV1 {
    IdentityPinV1 {
        account: pin.0.into(),
        authority_public_key: b64(pin.1),
        state: pin.2,
        since: "2026-10-12T09:00:00Z".into(),
        replaced: vec![],
        formerly: vec![],
        renames: None,
    }
}

const T: i64 = 1_791_800_000_000;
const SINCE: &str = "2026-10-13T12:00:00Z";

fn renames() -> RenameVectors {
    let dave = AccountIdentityKeysV1::derive(&[0x55u8; 32]).unwrap();
    let erin = AccountIdentityKeysV1::derive(&[0x66u8; 32]).unwrap();
    let frank = AccountIdentityKeysV1::derive(&[0x77u8; 32]).unwrap();
    let stranger = AccountIdentityKeysV1::derive(&[0x88u8; 32]).unwrap();
    let chain = vec![
        account_rename::sign(&dave, 1, "dave@kutup.dev", "davey@kutup.dev", T).unwrap(),
        account_rename::sign(&dave, 2, "davey@kutup.dev", "david@kutup.dev", T + 1000).unwrap(),
    ];
    // Dave is verified; the name he moves to was Erin's, who left it.
    let before = IdentityPinsV1 {
        pins: vec![
            plain(("dave@kutup.dev", &dave, PinState::Verified)),
            plain(("david@kutup.dev", &erin, PinState::Seen)),
            plain(("frank@example.org", &frank, PinState::Seen)),
        ],
    };
    let mut after = before.clone();
    let applied =
        identity_pins::apply_rename(&mut after, &dave.authority_public_key(), &chain).unwrap();
    let lookups = [
        ("david@kutup.dev", Some(b64(&dave))),
        ("dave@kutup.dev", Some(b64(&stranger))),
        ("davey@kutup.dev", None),
        ("frank@example.org", Some(b64(&stranger))),
        ("dave2@kutup.dev", Some(b64(&dave))),
        ("nobody@kutup.dev", Some(b64(&stranger))),
    ]
    .into_iter()
    .map(|(address, published)| LookupCase {
        address: address.into(),
        result: serde_json::to_value(identity_pins::lookup(&after, address, published.as_deref()))
            .unwrap(),
        published,
    })
    .collect();
    let record_case =
        |case: &str, list: &IdentityPinsV1, account: &str, who: &AccountIdentityKeysV1, update| {
            let mut next = list.clone();
            let changed =
                identity_pins::record(&mut next, account, &b64(who), update, SINCE).unwrap();
            RecordCase {
                case: case.into(),
                before: json(list),
                account: account.into(),
                authority: b64(who),
                update,
                since: SINCE.into(),
                after: json(&next),
                changed,
            }
        };
    // The renamed pin as only seen: verifying it keeps its former addresses.
    let mut seen_after = after.clone();
    seen_after.pins[0].state = PinState::Seen;
    let records = vec![
        record_case(
            "first met: pinned",
            &after,
            "gina@kutup.dev",
            &stranger,
            PinUpdate::FirstSeen,
        ),
        record_case(
            "first met again, another authority: kept",
            &after,
            "frank@example.org",
            &stranger,
            PinUpdate::FirstSeen,
        ),
        record_case(
            "verified, same authority: history kept",
            &seen_after,
            "david@kutup.dev",
            &dave,
            PinUpdate::Verified,
        ),
        record_case(
            "first met, the renamed pin: unchanged",
            &after,
            "david@kutup.dev",
            &dave,
            PinUpdate::FirstSeen,
        ),
        record_case(
            "accepted, another authority: replaced",
            &after,
            "frank@example.org",
            &stranger,
            PinUpdate::Accepted,
        ),
    ];
    let anchored = |formerly: &[&str], anchor: Option<(u64, String)>| {
        let mut pin = plain(("david@kutup.dev", &dave, PinState::Seen));
        pin.formerly = formerly.iter().map(|a| a.to_string()).collect();
        pin.renames = anchor.map(|(sequence, digest)| RenameAnchorV1 { sequence, digest });
        // Built by hand: these do not pass `encode`.
        serde_json::to_string(&IdentityPinsV1 { pins: vec![pin] }).unwrap()
    };
    let digest = || "ab".repeat(32);
    let refused_lists = vec![
        RefusedList {
            case: "its own address as a former one".into(),
            pins: anchored(&["david@kutup.dev"], Some((1, digest()))),
        },
        RefusedList {
            case: "a former address on another server".into(),
            pins: anchored(&["dave@other.dev"], Some((1, digest()))),
        },
        RefusedList {
            case: "a former address twice".into(),
            pins: anchored(&["dave@kutup.dev", "dave@kutup.dev"], Some((2, digest()))),
        },
        RefusedList {
            case: "a former address not canonical".into(),
            pins: anchored(&["Dave@kutup.dev"], Some((1, digest()))),
        },
        RefusedList {
            case: "former addresses without an anchor".into(),
            pins: anchored(&["dave@kutup.dev"], None),
        },
        RefusedList {
            case: "an anchor without former addresses".into(),
            pins: anchored(&[], Some((1, digest()))),
        },
        RefusedList {
            case: "anchor sequence 0".into(),
            pins: anchored(&["dave@kutup.dev"], Some((0, digest()))),
        },
        RefusedList {
            case: "anchor digest in capitals".into(),
            pins: anchored(&["dave@kutup.dev"], Some((1, "AB".repeat(32)))),
        },
        RefusedList {
            case: "an unknown field".into(),
            pins: anchored(&["dave@kutup.dev"], Some((1, digest())))
                .replace("\"state\"", "\"later\":1,\"state\""),
        },
    ];
    RenameVectors {
        authority_public_key: b64(&dave),
        rollback: chain[..1].to_vec(),
        chain,
        before: json(&before),
        after: json(&after),
        applied: serde_json::to_value(&applied).unwrap(),
        lookups,
        records,
        refused_lists,
    }
}

fn pins() -> IdentityPinsV1 {
    let bob = AccountIdentityKeysV1::derive(&[0x22u8; 32]).unwrap();
    let carol = AccountIdentityKeysV1::derive(&[0x33u8; 32]).unwrap();
    let carol_before = AccountIdentityKeysV1::derive(&[0x34u8; 32]).unwrap();
    IdentityPinsV1 {
        pins: vec![
            IdentityPinV1 {
                account: "bob@kutup.dev".into(),
                authority_public_key: STANDARD.encode(bob.authority_public_key()),
                state: PinState::Seen,
                since: "2026-10-10T12:00:00Z".into(),
                replaced: vec![],
                formerly: vec![],
                renames: None,
            },
            IdentityPinV1 {
                account: "cara@kutup.dev".into(),
                authority_public_key: STANDARD.encode(
                    AccountIdentityKeysV1::derive(&[0x23u8; 32])
                        .unwrap()
                        .authority_public_key(),
                ),
                state: PinState::Verified,
                since: "2026-10-12T09:00:00Z".into(),
                replaced: vec![],
                formerly: vec!["cora@kutup.dev".into(), "corinne@kutup.dev".into()],
                renames: Some(RenameAnchorV1 {
                    sequence: 2,
                    digest: "5f".repeat(32),
                }),
            },
            IdentityPinV1 {
                account: "carol@example.org".into(),
                authority_public_key: STANDARD.encode(carol.authority_public_key()),
                state: PinState::Verified,
                since: "2026-10-11T08:30:00.250Z".into(),
                replaced: vec![carol_before.incarnation_id()],
                formerly: vec![],
                renames: None,
            },
        ],
    }
}

#[test]
#[ignore = "writes the vectors file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_IDENTITY_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let master = [0x11u8; 32];
    let account = "alice@kutup.dev";
    let identity = AccountIdentityKeysV1::derive(&master).unwrap();
    let binding = drive_key_binding::sign(&identity, account).unwrap();
    let key = identity_pins::derive_key(&master).unwrap();
    let nonce = [0x44u8; 24];
    let sealed = identity_pins::seal_with_nonce(&key, BINDING, 7, &pins(), &nonce).unwrap();
    let vectors = Vectors {
        master_key: STANDARD.encode(master),
        account: account.into(),
        binding: BINDING.into(),
        authority_public_key: STANDARD.encode(identity.authority_public_key()),
        drive_hpke_public_key: STANDARD.encode(identity.drive_hpke_public_key()),
        drive_signing_public_key: STANDARD.encode(identity.drive_signing_public_key()),
        drive_key_binding: STANDARD.encode(binding),
        pins_key: STANDARD.encode(*key),
        revision: 7,
        pins: String::from_utf8(identity_pins::encode(&pins()).unwrap()).unwrap(),
        nonce: STANDARD.encode(nonce),
        refused: refused(&sealed),
        sealed: STANDARD.encode(sealed),
        renames: renames(),
    };
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

fn key32(value: &str) -> [u8; 32] {
    STANDARD.decode(value).unwrap().try_into().unwrap()
}

#[test]
fn checked_in_vectors_hold() {
    let v: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    let master = key32(&v.master_key);
    let identity = AccountIdentityKeysV1::derive(&master).unwrap();
    assert_eq!(
        STANDARD.encode(identity.authority_public_key()),
        v.authority_public_key
    );
    assert_eq!(
        STANDARD.encode(identity.drive_hpke_public_key()),
        v.drive_hpke_public_key
    );
    assert_eq!(
        STANDARD.encode(identity.drive_signing_public_key()),
        v.drive_signing_public_key
    );
    assert_eq!(
        STANDARD.encode(drive_key_binding::sign(&identity, &v.account).unwrap()),
        v.drive_key_binding
    );
    drive_key_binding::verify(
        &v.account,
        &key32(&v.authority_public_key),
        &key32(&v.drive_hpke_public_key),
        &key32(&v.drive_signing_public_key),
        &STANDARD.decode(&v.drive_key_binding).unwrap(),
    )
    .unwrap();

    let key = identity_pins::derive_key(&master).unwrap();
    assert_eq!(STANDARD.encode(*key), v.pins_key);
    assert_eq!(
        String::from_utf8(identity_pins::encode(&pins()).unwrap()).unwrap(),
        v.pins
    );
    let nonce: [u8; 24] = STANDARD.decode(&v.nonce).unwrap().try_into().unwrap();
    let sealed =
        identity_pins::seal_with_nonce(&key, &v.binding, v.revision, &pins(), &nonce).unwrap();
    assert_eq!(STANDARD.encode(&sealed), v.sealed);
    assert_eq!(identity_pins::inspect(&sealed).unwrap(), v.revision);
    assert_eq!(
        identity_pins::open(&key, &v.binding, &sealed).unwrap(),
        (pins(), v.revision)
    );
    let expected = refused(&sealed);
    assert_eq!(v.refused.len(), expected.len());
    for (case, want) in v.refused.iter().zip(&expected) {
        assert_eq!(
            (&case.case, &case.binding, case.revision, &case.sealed),
            (&want.case, &want.binding, want.revision, &want.sealed)
        );
        let bytes = STANDARD.decode(&case.sealed).unwrap();
        assert!(
            identity_pins::open(&key, &case.binding, &bytes).is_err(),
            "{} opened",
            case.case
        );
    }
    // The address is not a key binding, so nothing seals to it either.
    assert!(identity_pins::seal_with_nonce(&key, &v.account, v.revision, &pins(), &nonce).is_err());
    check_renames(&v.renames);
}

fn check_renames(r: &RenameVectors) {
    let want = renames();
    let authority = key32(&r.authority_public_key);
    assert_eq!(r.chain, want.chain);
    assert_eq!(r.before, want.before);
    let mut list = identity_pins::decode(r.before.as_bytes()).unwrap();
    let applied = identity_pins::apply_rename(&mut list, &authority, &r.chain).unwrap();
    assert_eq!(serde_json::to_value(&applied).unwrap(), r.applied);
    assert_eq!(json(&list), r.after);
    // Once more: nothing changes; the shorter chain is a rollback.
    let again = identity_pins::apply_rename(&mut list, &authority, &r.chain).unwrap();
    assert!(!again.changed);
    assert_eq!(json(&list), r.after);
    assert!(identity_pins::apply_rename(&mut list, &authority, &r.rollback).is_err());
    for case in &r.lookups {
        let found = identity_pins::lookup(&list, &case.address, case.published.as_deref());
        assert_eq!(
            serde_json::to_value(&found).unwrap(),
            case.result,
            "{}",
            case.address
        );
    }
    assert!(matches!(
        identity_pins::lookup(&list, "dave@kutup.dev", r.lookups[1].published.as_deref()),
        PinMatch::Moved { .. }
    ));
    for case in &r.records {
        let mut next = identity_pins::decode(case.before.as_bytes()).unwrap();
        let changed = identity_pins::record(
            &mut next,
            &case.account,
            &case.authority,
            case.update,
            &case.since,
        )
        .unwrap();
        assert_eq!(
            (changed, json(&next)),
            (case.changed, case.after.clone()),
            "{}",
            case.case
        );
    }
    assert_eq!(r.refused_lists.len(), want.refused_lists.len());
    for case in &r.refused_lists {
        let parsed: Result<IdentityPinsV1, _> = serde_json::from_str(&case.pins);
        assert!(
            parsed.map_or(true, |list| list.validate().is_err()),
            "{} accepted",
            case.case
        );
    }
}
