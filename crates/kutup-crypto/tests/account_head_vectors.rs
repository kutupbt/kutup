//! Checked-in vectors for the account head (docs/plans/rollback-protection.md):
//! a chain of three sealed heads, the scope digests, every outcome of a check
//! (fresh, current, extends, rollback, fork in its several shapes, too old),
//! the indexes refused, and a re-anchoring record. Regenerate only for a
//! deliberate format change:
//! `KUTUP_WRITE_HEAD_VECTORS=1 cargo test -p kutup-crypto --test account_head_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::account_head::{
    self, AccountHeadV1, Anchor, HeadKeys, HeadStatus, IndexCheck, LocalHeadStateV1,
};

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
    retention: u64,
    device: String,
    writer: String,
    /// The contacts index after each head (ids and revisions).
    indexes: Vec<Vec<(String, u64)>>,
    /// The heads as JSON, and sealed (fixed nonces), and their anchors.
    heads: Vec<String>,
    sealed: Vec<String>,
    anchors: Vec<Anchor>,
    /// Another history: a head 2 by another device after head 1.
    forked: String,
    /// A head further past the first than the server keeps, and one exactly
    /// the window past it: both shown without their chain.
    far: String,
    near: String,
    checks: Vec<Check>,
    /// Indexes the last head refuses.
    refused_indexes: Vec<RefusedIndex>,
    /// Re-anchoring on head 1 after head 3 was remembered (a rollback the
    /// person confirmed).
    reanchored: account_head::Reanchored,
    /// What a device keeps: the name it stores its state under, the state
    /// (started fresh on head 1, advanced to head 3, then the re-anchoring
    /// above), and that state sealed (a fixed nonce).
    local_name: String,
    local_state: LocalHeadStateV1,
    local_sealed: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
struct Check {
    case: String,
    /// Index into `anchors` (absent: no anchor).
    anchor: Option<usize>,
    /// A name: an index into `sealed`, `forked`, `far` or `near`.
    current: String,
    /// The chain segment as names (absent: the server did not show it).
    segment: Option<Vec<String>>,
    status: HeadStatus,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
struct RefusedIndex {
    case: String,
    index: Vec<(String, u64)>,
}

struct Material {
    keys: HeadKeys,
    sealed: Vec<Vec<u8>>,
    forked: Vec<u8>,
    far: Vec<u8>,
    near: Vec<u8>,
}

impl Material {
    fn named(&self, name: &str) -> Vec<u8> {
        match name {
            "forked" => self.forked.clone(),
            "far" => self.far.clone(),
            "near" => self.near.clone(),
            index => self.sealed[index.parse::<usize>().unwrap()].clone(),
        }
    }

    fn status(
        &self,
        anchor: Option<&Anchor>,
        current: &str,
        segment: Option<&[String]>,
    ) -> HeadStatus {
        let segment: Option<Vec<Vec<u8>>> =
            segment.map(|s| s.iter().map(|name| self.named(name)).collect());
        account_head::check(
            &self.keys,
            BINDING,
            INCARNATION,
            anchor,
            &self.named(current),
            segment.as_deref(),
        )
        .unwrap()
        .status
    }
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
        let head = match heads.last() {
            None => AccountHeadV1::first(INCARNATION, &writer, vec![entry]).unwrap(),
            Some(before) => before.next(&sealed[i - 1], &writer, vec![entry]).unwrap(),
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
    let beyond = |sequence: u64, nonce: u8| {
        let mut head = heads[0].clone();
        head.sequence = sequence;
        head.previous = Some("ab".repeat(32));
        account_head::seal_for_vectors(&keys, BINDING, &head, &[nonce; 24]).unwrap()
    };
    let far = beyond(1 + account_head::RETENTION + 1, 10);
    let near = beyond(1 + account_head::RETENTION, 11);
    let anchors: Vec<Anchor> = sealed
        .iter()
        .map(|s| {
            account_head::check(&keys, BINDING, INCARNATION, None, s, None)
                .unwrap()
                .verified
                .unwrap()
                .anchor()
                .clone()
        })
        .collect();
    let material = Material {
        keys,
        sealed,
        forked,
        far,
        near,
    };
    let check = |case: &str, anchor: Option<usize>, current: &str, segment: Option<&[&str]>| {
        let segment: Option<Vec<String>> =
            segment.map(|s| s.iter().map(|n| n.to_string()).collect());
        Check {
            case: case.into(),
            anchor,
            current: current.into(),
            status: material.status(anchor.map(|i| &anchors[i]), current, segment.as_deref()),
            segment,
        }
    };
    let checks = vec![
        check("no history: trusted from now on", None, "2", None),
        check("the same head", Some(1), "1", None),
        check(
            "a later head descending from the anchor",
            Some(0),
            "2",
            Some(&["0", "1", "2"]),
        ),
        check("an older head: rolled back", Some(2), "0", None),
        check(
            "another head at the anchor's sequence: forked",
            Some(1),
            "forked",
            None,
        ),
        check(
            "a chain withheld within the server's window: forked",
            Some(0),
            "2",
            None,
        ),
        check(
            "a chain withheld beyond the server's window: too old",
            Some(0),
            "far",
            None,
        ),
        check(
            "a gap exactly the window wide, withheld: forked",
            Some(0),
            "near",
            None,
        ),
        check(
            "a segment that starts elsewhere: forked",
            Some(0),
            "2",
            Some(&["forked", "1", "2"]),
        ),
        check(
            "a spliced segment: forked",
            Some(0),
            "2",
            Some(&["0", "forked", "2"]),
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
    let (reanchored, _) = account_head::reanchor(
        &material.keys,
        BINDING,
        INCARNATION,
        &anchors[2],
        &material.sealed[0],
        None,
        true,
        1_791_000_000_000,
    )
    .unwrap();
    let mut local_state = LocalHeadStateV1::with_device(INCARNATION, device).unwrap();
    for (i, at_ms) in [(0, 1_790_500_000_000), (2, 1_790_600_000_000)] {
        let verified = account_head::check(
            &material.keys,
            BINDING,
            INCARNATION,
            None,
            &material.sealed[i],
            None,
        )
        .unwrap()
        .verified
        .unwrap();
        local_state.advance(&verified, at_ms);
    }
    local_state.reanchored(&reanchored);
    let local_sealed = account_head::seal_local_state_for_vectors(
        &material.keys,
        BINDING,
        &local_state,
        &[0x42; 24],
    )
    .unwrap();
    Vectors {
        master_key: STANDARD.encode(master),
        binding: BINDING.into(),
        incarnation_id: INCARNATION.into(),
        retention: account_head::RETENTION,
        device: device.into(),
        writer,
        indexes,
        heads: heads
            .iter()
            .map(|h| serde_json::to_string(h).unwrap())
            .collect(),
        sealed: material.sealed.iter().map(|s| STANDARD.encode(s)).collect(),
        anchors,
        forked: STANDARD.encode(&material.forked),
        far: STANDARD.encode(&material.far),
        near: STANDARD.encode(&material.near),
        checks,
        refused_indexes,
        reanchored,
        local_name: material.keys.local_state_name(INCARNATION).unwrap(),
        local_state,
        local_sealed: STANDARD.encode(local_sealed),
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
    // A device's sealed state opens to the state, for its incarnation only.
    let local = STANDARD.decode(&v.local_sealed).unwrap();
    assert_eq!(
        account_head::open_local_state(&keys, &v.binding, &v.incarnation_id, &local).unwrap(),
        v.local_state
    );
    assert!(account_head::open_local_state(
        &keys,
        &v.binding,
        "6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b",
        &local
    )
    .is_err());
    // Every sealed head opens to its JSON; the last one, verified, checks its
    // index and refuses the others.
    for (sealed, json) in v.sealed.iter().zip(&v.heads) {
        let head =
            account_head::open(&keys, &v.binding, &STANDARD.decode(sealed).unwrap()).unwrap();
        assert_eq!(&serde_json::to_string(&head).unwrap(), json);
    }
    let last = account_head::check(
        &keys,
        &v.binding,
        &v.incarnation_id,
        None,
        &STANDARD.decode(&v.sealed[2]).unwrap(),
        None,
    )
    .unwrap()
    .verified
    .unwrap();
    assert_eq!(
        account_head::check_index(&keys, &last, "contacts", &v.indexes[2]).unwrap(),
        IndexCheck::Matches
    );
    assert_eq!(
        account_head::check_index(&keys, &last, "mailNames", &[]).unwrap(),
        IndexCheck::Uncovered
    );
    for refused in &v.refused_indexes {
        assert!(
            account_head::check_index(&keys, &last, "contacts", &refused.index).is_err(),
            "{}",
            refused.case
        );
    }
}
