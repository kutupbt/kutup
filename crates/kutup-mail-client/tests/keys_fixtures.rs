//! The key lookups of tests/fixtures/keys.json and what `keys::verified`
//! makes of them. `mail-core`'s `keysFixtures.test.ts` runs the same file
//! through the TypeScript `verified`, so the web app and this crate agree.
//!
//! `KUTUP_WRITE_MAIL_CLIENT_FIXTURES=1 cargo test -p kutup-mail-client
//! --test keys_fixtures -- --ignored write_fixtures` writes it again (new
//! keys each time; the expectations are the cases' own).

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::account_roots::IdentityRoot;
use kutup_crypto::identity::AccountIdentityKeysV1;
use kutup_crypto::mail_key::{
    generate_address_key, MailKeyEntryV1, MailKeyListV1, SignedMailKeyListV1,
    FLAG_EMAIL_NO_ENCRYPT, FLAG_NOT_COMPROMISED, FLAG_NOT_OBSOLETE,
};
use kutup_mail_client::keys::{verified, KeyListRow, KeyLookup, PersonKeyLookup, PublicKeyRow};
use serde::{Deserialize, Serialize};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/keys.json");
const OWN_SERVER: &str = "kutup.dev";
const BOTH: u32 = FLAG_NOT_COMPROMISED | FLAG_NOT_OBSOLETE;

/// What a case expects: the checked keys' main facts, or a refusal.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct Expect {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sequence: Option<u64>,
    /// Indexes into the lookup's keys: the primary, then the signature keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    primary: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    all: Option<Vec<usize>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption_disabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disabled: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    name: String,
    asked: String,
    own_server: String,
    lookup: KeyLookup,
    expect: Expect,
}

#[derive(Debug, Serialize, Deserialize)]
struct Fixtures {
    cases: Vec<Case>,
}

fn identity(byte: u8) -> AccountIdentityKeysV1 {
    AccountIdentityKeysV1::derive(&IdentityRoot::from_bytes([byte; 32])).unwrap()
}

fn arr(hex32: &str) -> [u8; 32] {
    hex::decode(hex32).unwrap().try_into().unwrap()
}

struct Key {
    row: PublicKeyRow,
    entry: MailKeyEntryV1,
}

fn key(address: &str, primary: bool, flags: u32) -> Key {
    let generated = generate_address_key(address, 1_760_000_000).unwrap();
    Key {
        row: PublicKeyRow {
            fingerprint: hex::encode(generated.fingerprint),
            sha256_fingerprint: hex::encode(generated.sha256_fingerprint),
            public_key: STANDARD.encode(&generated.public_key),
            primary,
            // The server's word, which counts for nothing.
            flags: BOTH,
        },
        entry: MailKeyEntryV1::v4(
            generated.fingerprint,
            generated.sha256_fingerprint,
            primary,
            flags,
        ),
    }
}

/// The lists of `entries` (each a list's keys) for `listed`, chained.
fn lists(
    identity: &AccountIdentityKeysV1,
    listed: &str,
    entries: &[Vec<MailKeyEntryV1>],
) -> Vec<SignedMailKeyListV1> {
    let mut out: Vec<SignedMailKeyListV1> = Vec::new();
    for (i, keys) in entries.iter().enumerate() {
        let mut keys = keys.clone();
        keys.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        let list = MailKeyListV1 {
            incarnation_id: arr(&identity.incarnation_id()),
            authority_key_id: arr(&identity.authority_key_id()),
            address: listed.into(),
            sequence: i as u64 + 1,
            previous_hash: out.last().map(SignedMailKeyListV1::hash),
            issued_at: format!("2026-10-{:02}T12:00:00Z", 10 + i),
            keys,
        };
        out.push(list.sign(identity.authority_signing_key()).unwrap());
    }
    out
}

fn lookup(
    identity: &AccountIdentityKeysV1,
    address: &str,
    server: &str,
    keys: &[&Key],
    lists: &[SignedMailKeyListV1],
) -> KeyLookup {
    KeyLookup::Person(PersonKeyLookup {
        address: address.into(),
        server: server.into(),
        account_id: "3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70".into(),
        account_authority_public_key: STANDARD.encode(identity.authority_public_key()),
        keys: keys.iter().map(|k| k.row.clone()).collect(),
        key_lists: lists
            .iter()
            .map(|l| KeyListRow {
                data: STANDARD.encode(&l.data),
                signature: STANDARD.encode(l.signature),
            })
            .collect(),
    })
}

fn ok(
    address: &str,
    sequence: u64,
    primary: usize,
    all: &[usize],
    encryption_disabled: bool,
    disabled: bool,
) -> Expect {
    Expect {
        ok: true,
        address: Some(address.into()),
        sequence: Some(sequence),
        primary: Some(primary),
        all: Some(all.to_vec()),
        encryption_disabled: Some(encryption_disabled),
        disabled: Some(disabled),
    }
}

fn refused() -> Expect {
    Expect {
        ok: false,
        address: None,
        sequence: None,
        primary: None,
        all: None,
        encryption_disabled: None,
        disabled: None,
    }
}

fn case(name: &str, asked: &str, lookup: KeyLookup, expect: Expect) -> Case {
    Case {
        name: name.into(),
        asked: asked.into(),
        own_server: OWN_SERVER.into(),
        lookup,
        expect,
    }
}

fn build() -> Vec<Case> {
    let ada = identity(7);
    let eve = identity(9);
    let mut cases = Vec::new();

    let a = key("ada_l@kutup.dev", true, BOTH);
    let one = lists(&ada, "ada_l@kutup.dev", &[vec![a.entry.clone()]]);
    let plain = lookup(&ada, "ada_l@kutup.dev", "kutup.dev", &[&a], &one);
    for asked in [
        "ada_l@kutup.dev",
        "ada.l@kutup.dev",
        "Ada-L@Kutup.dev",
        "adal@kutup.dev",
    ] {
        cases.push(case(
            &format!("asked in any spelling: {asked}"),
            asked,
            plain.clone(),
            ok("ada_l@kutup.dev", 1, 0, &[0], false, false),
        ));
    }
    cases.push(case(
        "another address asked",
        "bob@kutup.dev",
        plain.clone(),
        refused(),
    ));
    cases.push(case(
        "the same name on another domain",
        "ada_l@other.dev",
        plain.clone(),
        refused(),
    ));
    cases.push(case(
        "another server answering for this domain",
        "ada_l@kutup.dev",
        lookup(&ada, "ada_l@kutup.dev", "other.dev", &[&a], &one),
        refused(),
    ));
    // After a rename, a list of the new address served for the old one.
    let renamed = lists(&ada, "ada_lovelace@kutup.dev", &[vec![a.entry.clone()]]);
    cases.push(case(
        "the newest list names another address",
        "ada_l@kutup.dev",
        lookup(&ada, "ada_l@kutup.dev", "kutup.dev", &[&a], &renamed),
        refused(),
    ));
    cases.push(case(
        "lists signed by another authority",
        "ada_l@kutup.dev",
        {
            let KeyLookup::Person(mut p) = plain.clone() else {
                unreachable!()
            };
            p.account_authority_public_key = STANDARD.encode(eve.authority_public_key());
            KeyLookup::Person(p)
        },
        refused(),
    ));

    let w = key("ada@work.example", true, BOTH);
    let work = lists(&ada, "ada@work.example", &[vec![w.entry.clone()]]);
    cases.push(case(
        "a custom domain this server holds",
        "ada@work.example",
        lookup(&ada, "ada@work.example", "kutup.dev", &[&w], &work),
        ok("ada@work.example", 1, 0, &[0], false, false),
    ));
    cases.push(case(
        "a custom domain answered by another server",
        "ada@work.example",
        lookup(&ada, "ada@work.example", "other.dev", &[&w], &work),
        refused(),
    ));

    let off = key("ada_l@kutup.dev", true, BOTH | FLAG_EMAIL_NO_ENCRYPT);
    let off_lists = lists(&ada, "ada_l@kutup.dev", &[vec![off.entry.clone()]]);
    cases.push(case(
        "encryption off in the signed list",
        "ada_l@kutup.dev",
        lookup(&ada, "ada_l@kutup.dev", "kutup.dev", &[&off], &off_lists),
        ok("ada_l@kutup.dev", 1, 0, &[0], true, false),
    ));
    cases.push(case(
        "encryption off only in the server's rows",
        "ada_l@kutup.dev",
        {
            let KeyLookup::Person(mut p) = plain.clone() else {
                unreachable!()
            };
            p.keys[0].flags = BOTH | FLAG_EMAIL_NO_ENCRYPT;
            KeyLookup::Person(p)
        },
        ok("ada_l@kutup.dev", 1, 0, &[0], false, false),
    ));

    let gone = key("ada_l@kutup.dev", true, FLAG_NOT_COMPROMISED);
    let gone_lists = lists(&ada, "ada_l@kutup.dev", &[vec![gone.entry.clone()]]);
    cases.push(case(
        "a disabled address (its list encrypts to nothing)",
        "ada_l@kutup.dev",
        lookup(&ada, "ada_l@kutup.dev", "kutup.dev", &[&gone], &gone_lists),
        ok("ada_l@kutup.dev", 1, 0, &[0], false, true),
    ));

    // A rotation: the old key kept, then marked compromised; a key the list
    // doesn't name is dropped whatever the server says.
    let old = key("ada_l@kutup.dev", false, BOTH);
    let new = key("ada_l@kutup.dev", true, BOTH);
    let stray = key("ada_l@kutup.dev", false, BOTH);
    let rotated = lists(
        &ada,
        "ada_l@kutup.dev",
        &[
            vec![MailKeyEntryV1 {
                primary: true,
                ..old.entry.clone()
            }],
            vec![old.entry.clone(), new.entry.clone()],
            vec![
                MailKeyEntryV1 {
                    flags: FLAG_NOT_OBSOLETE,
                    ..old.entry.clone()
                },
                new.entry.clone(),
            ],
        ],
    );
    cases.push(case(
        "a chain of three lists, the old key kept then compromised",
        "ada_l@kutup.dev",
        lookup(
            &ada,
            "ada_l@kutup.dev",
            "kutup.dev",
            &[&old, &new, &stray],
            &rotated,
        ),
        ok("ada_l@kutup.dev", 3, 1, &[1], false, false),
    ));
    cases.push(case(
        "the old key still trusted for signatures before it was compromised",
        "ada_l@kutup.dev",
        lookup(
            &ada,
            "ada_l@kutup.dev",
            "kutup.dev",
            &[&old, &new],
            &rotated[..2],
        ),
        ok("ada_l@kutup.dev", 2, 1, &[1, 0], false, false),
    ));
    cases.push(case(
        "a chain with a list left out",
        "ada_l@kutup.dev",
        lookup(
            &ada,
            "ada_l@kutup.dev",
            "kutup.dev",
            &[&old, &new],
            &[rotated[0].clone(), rotated[2].clone()],
        ),
        refused(),
    ));
    cases.push(case(
        "no list naming the server's key",
        "ada_l@kutup.dev",
        lookup(&ada, "ada_l@kutup.dev", "kutup.dev", &[&stray], &one),
        refused(),
    ));
    cases
}

fn index_of(lookup: &KeyLookup, public_key: &str) -> usize {
    let KeyLookup::Person(p) = lookup else {
        unreachable!()
    };
    p.keys
        .iter()
        .position(|k| k.public_key == public_key)
        .unwrap()
}

#[test]
fn verified_matches_the_fixtures() {
    let fixtures: Fixtures = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    assert!(fixtures.cases.len() >= 15);
    for case in &fixtures.cases {
        let got = match verified(&case.asked, &case.lookup, Some(&case.own_server)) {
            Ok(keys) => ok(
                &keys.address,
                keys.sequence,
                index_of(&case.lookup, &keys.primary),
                &keys
                    .all
                    .iter()
                    .map(|k| index_of(&case.lookup, k))
                    .collect::<Vec<_>>(),
                keys.encryption_disabled,
                keys.disabled,
            ),
            Err(_) => refused(),
        };
        assert_eq!(got, case.expect, "{}", case.name);
    }
}

#[test]
#[ignore = "writes the fixtures file"]
fn write_fixtures() {
    if std::env::var("KUTUP_WRITE_MAIL_CLIENT_FIXTURES").as_deref() != Ok("1") {
        return;
    }
    let json = serde_json::to_string_pretty(&Fixtures { cases: build() }).unwrap();
    std::fs::write(PATH, format!("{json}\n")).unwrap();
}
