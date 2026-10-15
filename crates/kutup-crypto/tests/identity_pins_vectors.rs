//! Checked-in vectors for Drive identity (docs/plans/drive-identity-pins.md,
//! docs/plans/account-ids.md): an account's Drive key binding (a statement to
//! others), and a sealed identity pin list (suite 3: pins keyed by account
//! id, bound to the owner's key binding), with the values that must be
//! refused; and how every app records, looks up and follows a rename:
//! `record`, `lookup` and `apply_rename` over plain lists, and the lists the
//! format refuses. Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_IDENTITY_VECTORS=1 cargo test -p kutup-crypto --test identity_pins_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::account_ref::AccountRef;
use kutup_crypto::account_rename::{self, AccountRenameV1};
use kutup_crypto::drive_key_binding;
use kutup_crypto::identity::AccountIdentityKeysV1;
use kutup_crypto::identity_pins::{
    self, AddressLabelV1, IdentityPinV2, IdentityPinsV2, PinState, PinUpdate, RenameAnchorV1,
};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/identity-pins-v3.json"
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
    rules: RuleVectors,
}

/// What every app does with a list: plain (unsealed) canonical lists.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuleVectors {
    /// Dave's rename chain, signed by his pinned authority.
    dave: AccountRef,
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
    /// Valid lists stored in a form that is not canonical: refused when
    /// opened (the stored bytes must be canonical), whatever their content.
    noncanonical: Vec<RefusedList>,
    /// A list with fields from a later version, at every level: read, kept,
    /// and written back unchanged (after the known fields, in name order).
    preserved: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LookupCase {
    case: String,
    account: AccountRef,
    address: Option<String>,
    published: Option<String>,
    /// `lookup`'s answer, as JSON.
    result: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecordCase {
    case: String,
    before: String,
    account: AccountRef,
    address: Option<String>,
    authority: String,
    update: PinUpdate,
    since: String,
    after: String,
    /// `record`'s answer, as JSON.
    result: serde_json::Value,
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

fn refused(sealed: &[u8]) -> Vec<Refused> {
    let case = |case: &str, binding: &str, revision: u64, sealed: &[u8]| Refused {
        case: case.into(),
        binding: binding.into(),
        revision,
        sealed: STANDARD.encode(sealed),
    };
    let mut magic = sealed.to_vec();
    magic[5] = b'2';
    let mut suite = sealed.to_vec();
    suite[9] = 2;
    let mut relabelled = sealed.to_vec();
    relabelled[17] = 8;
    let mut nonce = sealed.to_vec();
    nonce[18] ^= 1;
    let mut tag = sealed.to_vec();
    *tag.last_mut().unwrap() ^= 1;
    vec![
        case("another account's key binding", OTHER_BINDING, 7, sealed),
        case(
            "the owner's address instead of its binding",
            "alice@kutup.dev",
            7,
            sealed,
        ),
        case("relabelled as another revision", BINDING, 8, &relabelled),
        case("magic of suite 2", BINDING, 7, &magic),
        case("suite 2", BINDING, 7, &suite),
        case("nonce changed", BINDING, 7, &nonce),
        case("ciphertext changed", BINDING, 7, &tag),
    ]
}

fn b64(identity: &AccountIdentityKeysV1) -> String {
    STANDARD.encode(identity.authority_public_key())
}

fn json(list: &IdentityPinsV2) -> String {
    String::from_utf8(identity_pins::encode(list).unwrap()).unwrap()
}

fn acct(server: &str, id: &str) -> AccountRef {
    AccountRef::new(server, id).unwrap()
}

fn plain(
    account: &AccountRef,
    who: &AccountIdentityKeysV1,
    state: PinState,
    addresses: &[&str],
) -> IdentityPinV2 {
    IdentityPinV2 {
        account: account.clone(),
        authority_public_key: b64(who),
        state,
        since: "2026-10-12T09:00:00Z".into(),
        replaced: vec![],
        addresses: addresses
            .iter()
            .map(|a| AddressLabelV1 {
                address: a.to_string(),
                seen_at: "2026-10-12T09:00:00Z".into(),
                unknown: Default::default(),
            })
            .collect(),
        renames: None,
        unknown: Default::default(),
    }
}

const T: i64 = 1_791_800_000_000;
const SINCE: &str = "2026-10-13T12:00:00Z";

fn rules() -> RuleVectors {
    let dave_keys = AccountIdentityKeysV1::derive(&[0x55u8; 32]).unwrap();
    let erin_keys = AccountIdentityKeysV1::derive(&[0x66u8; 32]).unwrap();
    let frank_keys = AccountIdentityKeysV1::derive(&[0x77u8; 32]).unwrap();
    let stranger_keys = AccountIdentityKeysV1::derive(&[0x88u8; 32]).unwrap();
    let dave = acct("kutup.dev", "5a1f0c3e-2b4d-4e6f-8a0b-1c2d3e4f5a6b");
    let erin = acct("kutup.dev", "6b2e1d4f-3c5e-4f70-9b1c-2d3e4f5a6b7c");
    let frank = acct("example.org", "7c3f2e50-4d6f-4081-8c2d-3e4f5a6b7c8d");
    let stranger = acct("kutup.dev", "8d40e3f1-5e70-4192-9d3e-4f5a6b7c8d9e");
    let chain = vec![
        account_rename::sign(&dave_keys, 1, "dave@kutup.dev", "davey@kutup.dev", T).unwrap(),
        account_rename::sign(
            &dave_keys,
            2,
            "davey@kutup.dev",
            "david@kutup.dev",
            T + 1000,
        )
        .unwrap(),
    ];
    // Dave is verified; the name he moves to was Erin's, who left it.
    let mut before = IdentityPinsV2 {
        pins: vec![
            plain(&dave, &dave_keys, PinState::Verified, &["dave@kutup.dev"]),
            plain(&erin, &erin_keys, PinState::Seen, &["david@kutup.dev"]),
            plain(&frank, &frank_keys, PinState::Seen, &["frank@example.org"]),
        ],
        ..Default::default()
    };
    before.pins.sort_by(|a, b| a.account.cmp(&b.account));
    let mut after = before.clone();
    let applied = identity_pins::apply_rename(&mut after, &dave, &chain, SINCE).unwrap();
    let lookup_case = |case: &str,
                       list: &IdentityPinsV2,
                       account: &AccountRef,
                       address: Option<&str>,
                       published: Option<String>| LookupCase {
        case: case.into(),
        account: account.clone(),
        address: address.map(str::to_owned),
        result: serde_json::to_value(identity_pins::lookup(
            list,
            account,
            address,
            published.as_deref(),
        ))
        .unwrap(),
        published,
    };
    let lookups = vec![
        lookup_case(
            "Dave at his new name: pinned, the same",
            &after,
            &dave,
            Some("david@kutup.dev"),
            Some(b64(&dave_keys)),
        ),
        lookup_case(
            "Dave by account, no address: pinned",
            &after,
            &dave,
            None,
            Some(b64(&dave_keys)),
        ),
        lookup_case(
            "Dave reset: pinned, changed",
            &after,
            &dave,
            Some("david@kutup.dev"),
            Some(b64(&stranger_keys)),
        ),
        lookup_case(
            "a stranger at a name Dave left: someone else",
            &after,
            &stranger,
            Some("dave@kutup.dev"),
            Some(b64(&stranger_keys)),
        ),
        lookup_case(
            "Frank found at Dave's name: Frank, by his own name, with Dave's notice",
            &after,
            &frank,
            Some("david@kutup.dev"),
            Some(b64(&frank_keys)),
        ),
        lookup_case(
            "Frank found at a name nobody known has: Frank, by his own name",
            &after,
            &frank,
            Some("frankie@kutup.dev"),
            Some(b64(&frank_keys)),
        ),
        lookup_case(
            "a stranger at a name Dave and Erin had: both, Dave first",
            &after,
            &stranger,
            Some("david@kutup.dev"),
            Some(b64(&stranger_keys)),
        ),
        lookup_case(
            "another spelling of a known name: someone else",
            &after,
            &stranger,
            Some("d-a-v-e@kutup.dev"),
            Some(b64(&stranger_keys)),
        ),
        lookup_case(
            "a stranger at a new name: new",
            &after,
            &stranger,
            Some("nobody@kutup.dev"),
            Some(b64(&stranger_keys)),
        ),
        lookup_case(
            "a stranger with no address: new",
            &after,
            &stranger,
            None,
            None,
        ),
        lookup_case(
            "Frank, not looked up: pinned, authority unknown",
            &after,
            &frank,
            Some("frank@example.org"),
            None,
        ),
    ];
    let record_case = |case: &str,
                       list: &IdentityPinsV2,
                       account: &AccountRef,
                       address: Option<&str>,
                       who: &AccountIdentityKeysV1,
                       update| {
        let mut next = list.clone();
        let result =
            identity_pins::record(&mut next, account, address, &b64(who), update, SINCE).unwrap();
        RecordCase {
            case: case.into(),
            before: json(list),
            account: account.clone(),
            address: address.map(str::to_owned),
            authority: b64(who),
            update,
            since: SINCE.into(),
            after: json(&next),
            result: serde_json::to_value(result).unwrap(),
        }
    };
    let mut seen_after = after.clone();
    for pin in &mut seen_after.pins {
        pin.state = PinState::Seen;
    }
    let mut frank_reset = after.clone();
    identity_pins::record(
        &mut frank_reset,
        &frank,
        None,
        &b64(&stranger_keys),
        PinUpdate::Accepted,
        SINCE,
    )
    .unwrap();
    let gina = acct("kutup.dev", "9e51f402-6f81-42a3-8e4f-5a6b7c8d9eaf");
    let gina_keys = AccountIdentityKeysV1::derive(&[0x99u8; 32]).unwrap();
    let records = vec![
        record_case(
            "first met: pinned with its address",
            &after,
            &gina,
            Some("gina@kutup.dev"),
            &gina_keys,
            PinUpdate::FirstSeen,
        ),
        record_case(
            "first met with no address: pinned",
            &after,
            &gina,
            None,
            &gina_keys,
            PinUpdate::FirstSeen,
        ),
        record_case(
            "met again, another authority: kept",
            &after,
            &frank,
            Some("frank@example.org"),
            &gina_keys,
            PinUpdate::FirstSeen,
        ),
        record_case(
            "found at another name: nothing written",
            &after,
            &dave,
            Some("dai@kutup.dev"),
            &dave_keys,
            PinUpdate::FirstSeen,
        ),
        record_case(
            "verified, same authority",
            &seen_after,
            &dave,
            Some("david@kutup.dev"),
            &dave_keys,
            PinUpdate::Verified,
        ),
        record_case(
            "accepted, another authority: replaced, history kept",
            &after,
            &dave,
            Some("david@kutup.dev"),
            &gina_keys,
            PinUpdate::Accepted,
        ),
        record_case(
            "the earlier authority verified again",
            &frank_reset,
            &frank,
            None,
            &frank_keys,
            PinUpdate::Verified,
        ),
        record_case(
            "first met at a name others had: not pinned",
            &after,
            &gina,
            Some("dave@kutup.dev"),
            &gina_keys,
            PinUpdate::FirstSeen,
        ),
        record_case(
            "accepted at a name others had: pinned as itself",
            &after,
            &gina,
            Some("dave@kutup.dev"),
            &gina_keys,
            PinUpdate::Accepted,
        ),
        record_case(
            "a known account accepted at another's name: nothing written",
            &after,
            &frank,
            Some("david@kutup.dev"),
            &frank_keys,
            PinUpdate::Accepted,
        ),
        record_case(
            "an authority pinned for another account: refused",
            &after,
            &gina,
            Some("gina@kutup.dev"),
            &dave_keys,
            PinUpdate::Verified,
        ),
    ];
    let one = |pin: IdentityPinV2| {
        serde_json::to_string(&IdentityPinsV2 {
            pins: vec![pin],
            ..Default::default()
        })
        .unwrap()
    };
    let labels = |addresses: &[&str]| -> Vec<AddressLabelV1> {
        plain(&dave, &dave_keys, PinState::Seen, addresses).addresses
    };
    let with = |change: &dyn Fn(&mut IdentityPinV2)| {
        let mut pin = plain(&dave, &dave_keys, PinState::Seen, &["dave@kutup.dev"]);
        change(&mut pin);
        // Built by hand: these do not pass `encode`.
        one(pin)
    };
    let refused_lists = vec![
        RefusedList {
            case: "an address twice".into(),
            pins: with(&|p| p.addresses = labels(&["dave@kutup.dev", "dave@kutup.dev"])),
        },
        RefusedList {
            case: "an address twice, folded".into(),
            pins: with(&|p| p.addresses = labels(&["dave@kutup.dev", "d_ave@kutup.dev"])),
        },
        RefusedList {
            case: "an address not canonical".into(),
            pins: with(&|p| p.addresses = labels(&["Dave@kutup.dev"])),
        },
        RefusedList {
            case: "an address seen at no valid time".into(),
            pins: with(&|p| p.addresses[0].seen_at = "yesterday".into()),
        },
        RefusedList {
            case: "an account reference as an address".into(),
            pins: with(&|p| p.addresses = labels(&[&dave.to_string()])),
        },
        RefusedList {
            case: "anchor sequence 0".into(),
            pins: with(&|p| {
                p.renames = Some(RenameAnchorV1 {
                    sequence: 0,
                    digest: "ab".repeat(32),
                    unknown: Default::default(),
                })
            }),
        },
        RefusedList {
            case: "anchor digest in capitals".into(),
            pins: with(&|p| {
                p.renames = Some(RenameAnchorV1 {
                    sequence: 1,
                    digest: "AB".repeat(32),
                    unknown: Default::default(),
                })
            }),
        },
        RefusedList {
            case: "its own incarnation as replaced".into(),
            pins: with(&|p| p.replaced = vec![dave_keys.incarnation_id()]),
        },
        RefusedList {
            case: "one authority pinned for two accounts".into(),
            pins: serde_json::to_string(&IdentityPinsV2 {
                pins: vec![
                    plain(&dave, &dave_keys, PinState::Seen, &[]),
                    plain(&erin, &dave_keys, PinState::Seen, &[]),
                ],
                ..Default::default()
            })
            .unwrap(),
        },
        RefusedList {
            case: "one account pinned twice".into(),
            pins: serde_json::to_string(&IdentityPinsV2 {
                pins: vec![
                    plain(&dave, &dave_keys, PinState::Seen, &[]),
                    plain(&dave, &erin_keys, PinState::Seen, &[]),
                ],
                ..Default::default()
            })
            .unwrap(),
        },
        RefusedList {
            case: "pins out of account order".into(),
            pins: serde_json::to_string(&IdentityPinsV2 {
                pins: vec![
                    plain(&erin, &erin_keys, PinState::Seen, &[]),
                    plain(&dave, &dave_keys, PinState::Seen, &[]),
                ],
                ..Default::default()
            })
            .unwrap(),
        },
        RefusedList {
            case: "the account as one string".into(),
            pins: with(&|_| {}).replace(
                &serde_json::to_string(&dave).unwrap(),
                &format!("\"{dave}\""),
            ),
        },
        RefusedList {
            case: "an account id in capitals".into(),
            pins: with(&|_| {}).replace(&dave.account_id, &dave.account_id.to_uppercase()),
        },
        RefusedList {
            case: "for a newer reader".into(),
            pins: r#"{"pins":[],"minReader":2}"#.into(),
        },
        RefusedList {
            case: "minReader 1, which is never written".into(),
            pins: r#"{"pins":[],"minReader":1}"#.into(),
        },
    ];
    let preserved = format!(
        r#"{{"pins":[{{"account":{},"authorityPublicKey":"{}","state":"seen","since":"2026-10-12T09:00:00Z","addresses":[{{"address":"davey@kutup.dev","seenAt":"2026-10-12T09:00:00Z","via":"chain"}}],"renames":{{"sequence":1,"digest":"{}","signedBy":"x"}},"colour":"blue","zone":7}}],"laterList":{{"a":[1,2]}}}}"#,
        serde_json::to_string(&dave).unwrap(),
        b64(&dave_keys),
        "ab".repeat(32),
    );
    let noncanonical = vec![
        RefusedList {
            case: "a later field before the known ones".into(),
            pins: preserved
                .replace(r#","colour":"blue","zone":7"#, r#","zone":7"#)
                .replace(r#"{"account":"#, r#"{"colour":"blue","account":"#),
        },
        RefusedList {
            case: "later fields out of name order".into(),
            pins: preserved.replace(r#""colour":"blue","zone":7"#, r#""zone":7,"colour":"blue""#),
        },
        RefusedList {
            case: "spaces".into(),
            pins: preserved.replace("\":", "\": "),
        },
    ];
    RuleVectors {
        dave,
        rollback: chain[..1].to_vec(),
        chain,
        before: json(&before),
        after: json(&after),
        applied: serde_json::to_value(&applied).unwrap(),
        lookups,
        records,
        refused_lists,
        noncanonical,
        preserved,
    }
}

fn pins() -> IdentityPinsV2 {
    let bob = AccountIdentityKeysV1::derive(&[0x22u8; 32]).unwrap();
    let cara = AccountIdentityKeysV1::derive(&[0x23u8; 32]).unwrap();
    let carol = AccountIdentityKeysV1::derive(&[0x33u8; 32]).unwrap();
    let carol_before = AccountIdentityKeysV1::derive(&[0x34u8; 32]).unwrap();
    let mut cara_pin = plain(
        &acct("kutup.dev", "2c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e6f"),
        &cara,
        PinState::Verified,
        &["cora@kutup.dev", "corinne@kutup.dev", "cara@kutup.dev"],
    );
    cara_pin.renames = Some(RenameAnchorV1 {
        sequence: 2,
        digest: "5f".repeat(32),
        unknown: Default::default(),
    });
    let mut carol_pin = plain(
        &acct("example.org", "3d4e5f6a-7b8c-4d9e-8f1a-2b3c4d5e6f7a"),
        &carol,
        PinState::Verified,
        &["carol@example.org"],
    );
    carol_pin.since = "2026-10-11T08:30:00.250Z".into();
    carol_pin.replaced = vec![carol_before.incarnation_id()];
    let mut list = IdentityPinsV2 {
        pins: vec![
            plain(
                &acct("kutup.dev", "1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e"),
                &bob,
                PinState::Seen,
                &["bob@kutup.dev"],
            ),
            cara_pin,
            carol_pin,
        ],
        ..Default::default()
    };
    list.pins.sort_by(|a, b| a.account.cmp(&b.account));
    list
}

#[test]
#[ignore = "writes the vectors file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_IDENTITY_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let master = [0x11u8; 32];
    // The account the binding names: (server, account id), its string form.
    let account = "aci:00000000-0000-4000-8000-0000000000a1@kutup.dev";
    let identity = AccountIdentityKeysV1::derive(&master).unwrap();
    let binding = drive_key_binding::sign(&identity, &account.parse().unwrap()).unwrap();
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
        pins: json(&pins()),
        nonce: STANDARD.encode(nonce),
        refused: refused(&sealed),
        sealed: STANDARD.encode(sealed),
        rules: rules(),
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
        STANDARD.encode(drive_key_binding::sign(&identity, &v.account.parse().unwrap()).unwrap()),
        v.drive_key_binding
    );
    drive_key_binding::verify(
        &v.account.parse().unwrap(),
        &key32(&v.authority_public_key),
        &key32(&v.drive_hpke_public_key),
        &key32(&v.drive_signing_public_key),
        &STANDARD.decode(&v.drive_key_binding).unwrap(),
    )
    .unwrap();

    let key = identity_pins::derive_key(&master).unwrap();
    assert_eq!(STANDARD.encode(*key), v.pins_key);
    assert_eq!(json(&pins()), v.pins);
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
    check_rules(&v.rules);
}

fn check_rules(r: &RuleVectors) {
    let want = rules();
    assert_eq!(r.chain, want.chain);
    assert_eq!(r.before, want.before);
    let mut list = identity_pins::decode(r.before.as_bytes()).unwrap();
    let applied = identity_pins::apply_rename(&mut list, &r.dave, &r.chain, SINCE).unwrap();
    assert_eq!(serde_json::to_value(&applied).unwrap(), r.applied);
    assert_eq!(json(&list), r.after);
    // Once more: nothing changes; the shorter chain is a rollback.
    assert!(
        !identity_pins::apply_rename(&mut list, &r.dave, &r.chain, SINCE)
            .unwrap()
            .changed
    );
    assert_eq!(json(&list), r.after);
    assert!(identity_pins::apply_rename(&mut list, &r.dave, &r.rollback, SINCE).is_err());
    for case in &r.lookups {
        let list = identity_pins::decode(r.after.as_bytes()).unwrap();
        let found = identity_pins::lookup(
            &list,
            &case.account,
            case.address.as_deref(),
            case.published.as_deref(),
        );
        assert_eq!(
            serde_json::to_value(&found).unwrap(),
            case.result,
            "{}",
            case.case
        );
    }
    assert_eq!(r.records.len(), want.records.len());
    for case in &r.records {
        let mut next = identity_pins::decode(case.before.as_bytes()).unwrap();
        let result = identity_pins::record(
            &mut next,
            &case.account,
            case.address.as_deref(),
            &case.authority,
            case.update,
            &case.since,
        )
        .unwrap();
        assert_eq!(
            (serde_json::to_value(result).unwrap(), json(&next)),
            (case.result.clone(), case.after.clone()),
            "{}",
            case.case
        );
    }
    assert_eq!(r.preserved, want.preserved);
    let kept = identity_pins::decode(r.preserved.as_bytes()).unwrap();
    assert_eq!(
        json(&kept),
        r.preserved,
        "later fields written back unchanged"
    );
    for case in &r.noncanonical {
        assert!(
            identity_pins::decode(case.pins.as_bytes()).is_err(),
            "{} opened",
            case.case
        );
        let parsed: IdentityPinsV2 = serde_json::from_str(&case.pins).unwrap();
        assert_eq!(
            json(&parsed),
            r.preserved,
            "{}: the same content",
            case.case
        );
    }
    assert_eq!(r.refused_lists.len(), want.refused_lists.len());
    for case in &r.refused_lists {
        let parsed: Result<IdentityPinsV2, _> = serde_json::from_str(&case.pins);
        assert!(
            parsed.map_or(true, |list| list.validate().is_err()),
            "{} accepted",
            case.case
        );
    }
}
