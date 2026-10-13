//! Checked-in vectors for the account head (docs/plans/rollback-protection.md):
//! a chain of three sealed heads, the scope digests, every outcome of a check
//! (fresh, current, extends, rollback, fork, too old), the indexes refused, and
//! a re-anchoring record. Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_HEAD_VECTORS=1 cargo test -p kutup-crypto --test account_head_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::account_head::{self, AccountHeadV1, Anchor, HeadKeys, HeadStatus};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/account-head-v1.json"
);
const BINDING: &str = "3f2a6c1e-8b4d-4e7a-9c5f-1d2e3a4b5c6d";
const INCARNATION: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    master_key: String,
    binding: String,
    incarnation_id: String,
    device: String,
    writer: String,
    /// The contacts index after each head (ids and revisions).
    indexes: Vec<Vec<(String, u64)>>,
    /// The heads as JSON, and sealed (fixed nonces).
    heads: Vec<String>,
    sealed: Vec<String>,
    anchors: Vec<Anchor>,
    /// Another history: a head 2 by another device after head 1.
    forked: String,
    checks: Vec<Check>,
    /// Indexes the last head refuses.
    refused_indexes: Vec<RefusedIndex>,
    reanchored: account_head::Reanchored,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
struct Check {
    case: String,
    /// Index into `anchors` (absent: no anchor).
    anchor: Option<usize>,
    /// Index into `sealed`, or "forked".
    current: String,
    /// The chain segment as indexes into `sealed` (absent: the server no longer keeps it).
    segment: Option<Vec<usize>>,
    status: HeadStatus,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
struct RefusedIndex {
    case: String,
    index: Vec<(String, u64)>,
}

fn derive() -> Vectors {
    let master = [0x42u8; 32];
    let keys = HeadKeys::derive(&master).unwrap();
    let device = "device-alpha";
    let writer = keys.writer(device).unwrap();
    let indexes: Vec<Vec<(String, u64)>> = vec![
        vec![("uid-alice".into(), 1_790_000_000_001)],
        vec![
            ("uid-alice".into(), 1_790_000_000_001),
            ("uid-bob".into(), 1_790_000_000_002),
        ],
        vec![
            ("uid-bob".into(), 1_790_000_000_002),
            ("uid-alice".into(), 1_790_000_000_003),
        ],
    ];
    let mut heads: Vec<AccountHeadV1> = Vec::new();
    let mut sealed: Vec<Vec<u8>> = Vec::new();
    for (i, index) in indexes.iter().enumerate() {
        let entry = keys.scope_digest("contacts", index).unwrap();
        let head = if i == 0 {
            AccountHeadV1::first(INCARNATION, &writer, vec![entry]).unwrap()
        } else {
            heads
                .last()
                .cloned()
                .unwrap()
                .next(&sealed[i - 1], &writer, vec![entry])
                .unwrap()
        };
        sealed.push(
            account_head::seal_for_vectors(&keys, BINDING, &head, &[i as u8 + 1; 24]).unwrap(),
        );
        heads.push(head);
    }
    let other = keys.writer("device-beta").unwrap();
    let forked_head = heads[0]
        .next(
            &sealed[0],
            &other,
            vec![keys.scope_digest("contacts", &[]).unwrap()],
        )
        .unwrap();
    let forked = account_head::seal_for_vectors(&keys, BINDING, &forked_head, &[9u8; 24]).unwrap();
    let anchors: Vec<Anchor> = sealed.iter().map(|s| Anchor::of(s).unwrap()).collect();
    let current = |name: &str| {
        if name == "forked" {
            forked.clone()
        } else {
            sealed[name.parse::<usize>().unwrap()].clone()
        }
    };
    let check = |case: &str, anchor: Option<usize>, cur: &str, segment: Option<Vec<usize>>| {
        let segment_bytes: Option<Vec<Vec<u8>>> = segment
            .as_ref()
            .map(|s| s.iter().map(|&i| sealed[i].clone()).collect());
        let status = account_head::check(
            &keys,
            BINDING,
            INCARNATION,
            anchor.map(|i| &anchors[i]),
            &current(cur),
            segment_bytes.as_deref(),
        )
        .unwrap();
        Check {
            case: case.into(),
            anchor,
            current: cur.into(),
            segment,
            status,
        }
    };
    let checks = vec![
        check("no history: trusted from now on", None, "2", None),
        check("the same head", Some(1), "1", None),
        check(
            "a later head descending from the anchor",
            Some(0),
            "2",
            Some(vec![0, 1, 2]),
        ),
        check("an older head: rolled back", Some(2), "0", None),
        check(
            "another head at the anchor's sequence: forked",
            Some(1),
            "forked",
            None,
        ),
        check(
            "the server no longer keeps the chain: too old",
            Some(0),
            "2",
            None,
        ),
    ];
    let last = indexes[2].clone();
    let refused_indexes = vec![
        RefusedIndex {
            case: "a value rolled back".into(),
            index: vec![
                ("uid-bob".into(), 1_790_000_000_002),
                ("uid-alice".into(), 1_790_000_000_001),
            ],
        },
        RefusedIndex {
            case: "a value dropped".into(),
            index: vec![last[0].clone()],
        },
        RefusedIndex {
            case: "a value brought back".into(),
            index: [last.clone(), vec![("uid-carol".into(), 1_790_000_000_000)]].concat(),
        },
    ];
    let reanchored = account_head::reanchor(
        &keys,
        BINDING,
        INCARNATION,
        Some(&anchors[2]),
        &sealed[0],
        &HeadStatus::Rollback,
        1_791_000_000_000,
    )
    .unwrap();
    Vectors {
        master_key: STANDARD.encode(master),
        binding: BINDING.into(),
        incarnation_id: INCARNATION.into(),
        device: device.into(),
        writer,
        indexes,
        heads: heads
            .iter()
            .map(|h| serde_json::to_string(h).unwrap())
            .collect(),
        sealed: sealed.iter().map(|s| STANDARD.encode(s)).collect(),
        anchors,
        forked: STANDARD.encode(&forked),
        checks,
        refused_indexes,
        reanchored,
    }
}

#[test]
#[ignore = "writes the vectors file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_HEAD_VECTORS").as_deref() != Ok("1") {
        return;
    }
    std::fs::write(
        PATH,
        serde_json::to_string_pretty(&derive()).unwrap() + "\n",
    )
    .unwrap();
}

#[test]
fn checked_in_vectors_hold() {
    let v: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    assert_eq!(v, derive());
    let master: [u8; 32] = STANDARD.decode(&v.master_key).unwrap().try_into().unwrap();
    let keys = HeadKeys::derive(&master).unwrap();
    // Every sealed head opens to its JSON; the last head checks its index and
    // refuses the others.
    for (sealed, json) in v.sealed.iter().zip(&v.heads) {
        let head =
            account_head::open(&keys, &v.binding, &STANDARD.decode(sealed).unwrap()).unwrap();
        assert_eq!(&serde_json::to_string(&head).unwrap(), json);
    }
    let last =
        account_head::open(&keys, &v.binding, &STANDARD.decode(&v.sealed[2]).unwrap()).unwrap();
    assert!(account_head::check_index(&keys, &last, "contacts", &v.indexes[2]).unwrap());
    for refused in &v.refused_indexes {
        assert!(
            account_head::check_index(&keys, &last, "contacts", &refused.index).is_err(),
            "{}",
            refused.case
        );
    }
}
