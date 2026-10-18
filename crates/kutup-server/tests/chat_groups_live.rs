//! Pairwise groups' anonymous route against a live server
//! (docs/plans/pairwise-groups.md §3): a client fetches the home's signed key
//! config, seals requests to it and relays them through its own server; the
//! home runs the acceptance checks and notarises what it stores.
//!
//! Needs `KUTUP_LIVE_GROUPS_SERVER`: a server with `CHAT_GROUPS=true` and
//! federation configured. Here the client's server is the home, so the relay
//! takes its local path; the federated hop is covered by the two-server gate.

mod common;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use common::*;
use ed25519_dalek::SigningKey;
use kutup_chat_proto::group::{
    check_change, check_genesis, encode_group_id, resulting_genesis_state, resulting_state,
    GroupAccessV1, GroupActionV1, GroupChangeV1, GroupLimits, GroupRole, GroupStateV1,
    GROUP_FORMAT_VERSION,
};
use kutup_chat_proto::group_route::{
    GroupGatewayKeyConfigV1, GroupHomePinV1, GroupJoinInfoV1, GroupLogEntryV1, GroupLogPageV1,
    GroupLogQueryV1, GroupOperationV1, GroupRequestV1, GroupResponseStatusV1, GroupResponseV1,
    GroupStateAnswerV1,
};
use kutup_crypto::chat_group::{GroupKeyPair, GroupMasterKey, SealedField};
use kutup_crypto::oblivious::seal_request;
use kutup_federation_proto::FederationIdentityDocumentV1;
use rand::RngCore;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::Value;

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn server_name(c: &Client, base: &str) -> String {
    let settings: Value = c
        .get(format!("{base}/api/auth/settings"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    settings["chat"]["serverName"]
        .as_str()
        .expect("the chat server name")
        .to_owned()
}

/// The home as a client sees it: its key config, verified from the pin.
struct Home {
    base: String,
    name: String,
    history: Vec<FederationIdentityDocumentV1>,
    pin: GroupHomePinV1,
    config: GroupGatewayKeyConfigV1,
    key_id: u8,
    public_key: [u8; 32],
}

fn home(c: &Client, base: &str, user: &User) -> Home {
    let name = server_name(c, base);
    let answer: Value = bearer(
        c.get(format!(
            "{base}/api/chat/groups/gateway-key?server={name}&fromSequence=0"
        )),
        &user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    let history: Vec<FederationIdentityDocumentV1> =
        serde_json::from_value(answer["identityHistory"].clone()).unwrap();
    let config: GroupGatewayKeyConfigV1 = serde_json::from_value(answer["config"].clone()).unwrap();
    // A new group pins the home's current identity document.
    let pin = GroupHomePinV1::of(history.last().expect("an identity")).unwrap();
    GroupHomePinV1::of(&history[0])
        .unwrap()
        .follow(&history)
        .unwrap();
    let (key_id, public_key) = config.verify(&history, now()).unwrap();
    config.accept_after(None, now()).unwrap();
    Home {
        base: base.to_owned(),
        name,
        history,
        pin,
        config,
        key_id,
        public_key,
    }
}

/// Seals `request`, relays it, and opens the answer.
fn exchange(c: &Client, user: &User, home: &Home, request: &GroupRequestV1) -> GroupResponseV1 {
    let (sealed, context) = seal_request(
        home.key_id,
        &home.public_key,
        &request.canonical_bytes().unwrap(),
    )
    .unwrap();
    let answer = relay(c, user, home, sealed);
    assert_eq!(answer.0, StatusCode::OK);
    GroupResponseV1::from_canonical_bytes(&context.open_response(&answer.1).unwrap()).unwrap()
}

fn relay(c: &Client, user: &User, home: &Home, sealed: Vec<u8>) -> (StatusCode, Vec<u8>) {
    let r = bearer(
        c.post(format!("{}/api/chat/groups/relay/{}", home.base, home.name)),
        &user.token,
    )
    .header("content-type", "message/ohttp-req")
    .body(sealed)
    .send()
    .unwrap();
    (r.status(), r.bytes().unwrap().to_vec())
}

fn signed(
    home: &Home,
    group_id: &[u8; 32],
    operation: GroupOperationV1,
    body: &[u8],
    key: &GroupKeyPair,
) -> GroupRequestV1 {
    GroupRequestV1::sign_with_pseudonym(
        &home.name,
        group_id,
        operation,
        now(),
        &random::<16>(),
        body,
        &SigningKey::from_bytes(key.seed()),
    )
    .unwrap()
}

/// A group as its members track it.
struct Group {
    master: GroupMasterKey,
    id: [u8; 32],
    state: GroupStateV1,
    head: [u8; 32],
    notary_sequence: u64,
}

fn entry(master: &GroupMasterKey, subject: &[u8]) -> String {
    STANDARD.encode(
        master
            .state_key()
            .seal(SealedField::MemberEntry, subject, b"entry")
            .unwrap(),
    )
}

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Signs `change` as an honest author: names the state it results in.
fn author(group: &Group, actor: &GroupKeyPair, actions: Vec<GroupActionV1>) -> GroupChangeV1 {
    let mut change = GroupChangeV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: encode_group_id(&group.id),
        revision: group.state.revision + 1,
        previous_hash: b64(&group.head),
        actor: b64(&actor.public_key()),
        actions,
        resulting_state_hash: Some(b64(&[0; 32])),
        signature: String::new(),
    };
    if change.is_newcomers_change() {
        change.resulting_state_hash = None;
    } else {
        let next = resulting_state(&group.state, &group.head, &change, &GroupLimits::MAX).unwrap();
        change.resulting_state_hash = Some(b64(&next.hash().unwrap()));
    }
    change.signature = b64(&actor.sign_change(&change.signed_bytes().unwrap()));
    change
}

/// Applies a change the home accepted, checking its notary as a client does.
fn apply(group: &mut Group, home: &Home, entry: &GroupLogEntryV1) {
    let change =
        GroupChangeV1::from_canonical_bytes(&STANDARD.decode(&entry.change).unwrap()).unwrap();
    let next = check_change(&group.state, &group.head, &change, &GroupLimits::MAX).unwrap();
    entry
        .notary
        .verify(
            &home.history,
            Some(group.notary_sequence),
            &group.id,
            next.revision,
            &change.hash().unwrap(),
            &next.hash().unwrap(),
        )
        .unwrap();
    assert!(entry.notary.names(&home.config).unwrap());
    group.notary_sequence = entry.notary.identity_sequence;
    group.head = change.hash().unwrap();
    group.state = next;
}

fn create(c: &Client, user: &User, home: &Home, creator: &GroupKeyPair) -> Group {
    let master = GroupMasterKey::generate();
    let id = master.group_id();
    let mut genesis = GroupChangeV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: encode_group_id(&id),
        revision: 0,
        previous_hash: b64(&[0; 32]),
        actor: b64(&creator.public_key()),
        actions: vec![GroupActionV1::Genesis {
            home: home.pin.clone(),
            access: GroupAccessV1::DEFAULT,
            entry: entry(&master, &creator.public_key()),
        }],
        resulting_state_hash: Some(b64(&[0; 32])),
        signature: String::new(),
    };
    let first = resulting_genesis_state(&genesis, &home.pin, &GroupLimits::MAX).unwrap();
    genesis.resulting_state_hash = Some(b64(&first.hash().unwrap()));
    genesis.signature = b64(&creator.sign_change(&genesis.signed_bytes().unwrap()));
    let request = signed(
        home,
        &id,
        GroupOperationV1::Create,
        &genesis.canonical_bytes().unwrap(),
        creator,
    );
    let response = exchange(c, user, home, &request);
    assert_eq!(response.status, GroupResponseStatusV1::Ok, "{response:?}");
    let answer = GroupStateAnswerV1::from_canonical_bytes(&response.body().unwrap()).unwrap();
    let state = check_genesis(&genesis, &home.pin, &GroupLimits::MAX).unwrap();
    assert_eq!(
        GroupStateV1::from_canonical_bytes(&STANDARD.decode(&answer.state).unwrap()).unwrap(),
        state
    );
    answer
        .notary
        .verify(
            &home.history,
            None,
            &id,
            0,
            &genesis.hash().unwrap(),
            &state.hash().unwrap(),
        )
        .unwrap();
    Group {
        master,
        id,
        head: genesis.hash().unwrap(),
        state,
        notary_sequence: answer.notary.identity_sequence,
    }
}

fn submit(
    c: &Client,
    user: &User,
    home: &Home,
    group: &Group,
    change: &GroupChangeV1,
    actor: &GroupKeyPair,
) -> GroupResponseV1 {
    let request = signed(
        home,
        &group.id,
        GroupOperationV1::SubmitChange,
        &change.canonical_bytes().unwrap(),
        actor,
    );
    exchange(c, user, home, &request)
}

fn accepted(response: &GroupResponseV1) -> GroupLogEntryV1 {
    assert_eq!(response.status, GroupResponseStatusV1::Ok, "{response:?}");
    serde_json::from_slice(&response.body().unwrap()).unwrap()
}

fn live() -> Option<String> {
    match std::env::var("KUTUP_LIVE_GROUPS_SERVER") {
        Ok(base) => Some(base.trim_end_matches('/').to_string()),
        Err(_) => {
            eprintln!("KUTUP_LIVE_GROUPS_SERVER not set; skipping");
            None
        }
    }
}

#[test]
fn a_group_is_created_joined_and_read_through_the_anonymous_route() {
    let Some(base) = live() else { return };
    let c = Client::new();
    let alice = register(&c, &base);
    let bob = register(&c, &base);
    let home = home(&c, &base, &alice);
    let alice_key = GroupKeyPair::generate();
    let bob_key = GroupKeyPair::generate();
    let mut group = create(&c, &alice, &home, &alice_key);

    // The creator reads the state; a stranger's pseudonym gets the same
    // answer as an unknown group.
    let state = exchange(
        &c,
        &alice,
        &home,
        &signed(
            &home,
            &group.id,
            GroupOperationV1::GetState,
            b"",
            &alice_key,
        ),
    );
    assert_eq!(state.status, GroupResponseStatusV1::Ok);
    let stranger = GroupKeyPair::generate();
    for id in [group.id, random::<32>()] {
        let refused = exchange(
            &c,
            &bob,
            &home,
            &signed(&home, &id, GroupOperationV1::GetState, b"", &stranger),
        );
        assert_eq!(refused.status, GroupResponseStatusV1::NotFound);
    }

    // Alice adds a slot for Bob; Bob learns where to claim with the claim
    // key alone, then claims it with his new pseudonym.
    let claim_key = GroupKeyPair::generate();
    let slot_id = random::<16>();
    let add = author(
        &group,
        &alice_key,
        vec![GroupActionV1::AddSlot {
            slot_id: b64(&slot_id),
            role: GroupRole::Member,
            claim_key: b64(&claim_key.public_key()),
            entry: entry(&group.master, b"slot"),
        }],
    );
    let added = accepted(&submit(&c, &alice, &home, &group, &add, &alice_key));
    apply(&mut group, &home, &added);
    let info = exchange(
        &c,
        &bob,
        &home,
        &signed(
            &home,
            &group.id,
            GroupOperationV1::GetJoinInfo,
            b"",
            &claim_key,
        ),
    );
    assert_eq!(info.status, GroupResponseStatusV1::Ok, "{info:?}");
    let info = GroupJoinInfoV1::from_canonical_bytes(&info.body().unwrap()).unwrap();
    assert_eq!(info.revision, group.state.revision);
    assert_eq!(info.head, b64(&group.head));
    assert!(info.title.is_none() && info.requires_approval.is_none());

    let slot_revision = group.state.slots[0].created_at_revision;
    let claim_signature =
        claim_key.sign_claim(&group.id, &slot_id, slot_revision, &bob_key.public_key());
    let claim = author(
        &group,
        &bob_key,
        vec![GroupActionV1::Claim {
            slot_id: b64(&slot_id),
            claim_signature: b64(&claim_signature),
            entry: entry(&group.master, &bob_key.public_key()),
        }],
    );
    let claimed = accepted(&submit(&c, &bob, &home, &group, &claim, &bob_key));
    apply(&mut group, &home, &claimed);
    assert!(group.state.member(&b64(&bob_key.public_key())).is_some());

    // Bob reads the log only from the revision he joined at.
    let query = serde_json::to_vec(&GroupLogQueryV1 {
        from_revision: 0,
        limit: 50,
    })
    .unwrap();
    let logs = exchange(
        &c,
        &bob,
        &home,
        &signed(
            &home,
            &group.id,
            GroupOperationV1::GetLogs,
            &query,
            &bob_key,
        ),
    );
    assert_eq!(logs.status, GroupResponseStatusV1::Ok);
    let page = GroupLogPageV1::from_canonical_bytes(&logs.body().unwrap()).unwrap();
    assert_eq!(page.entries.len(), 1, "only the claim, from his join on");
    assert!(!page.more);

    purge_accounts(&c, &base, &[&alice, &bob]);
}

#[test]
fn the_home_refuses_what_its_checks_refuse() {
    let Some(base) = live() else { return };
    let c = Client::new();
    let alice = register(&c, &base);
    let home = home(&c, &base, &alice);
    let alice_key = GroupKeyPair::generate();
    let group = create(&c, &alice, &home, &alice_key);

    // A change at a stale revision is a conflict: refetch and verify.
    let mut stale = author(
        &group,
        &alice_key,
        vec![GroupActionV1::ModifyAnnouncementsOnly { on: true }],
    );
    stale.revision += 1;
    stale.signature = b64(&alice_key.sign_change(&stale.signed_bytes().unwrap()));
    let conflict = submit(&c, &alice, &home, &group, &stale, &alice_key);
    assert_eq!(conflict.status, GroupResponseStatusV1::Conflict);

    // A stranger's change is refused with its check's code.
    let stranger = GroupKeyPair::generate();
    let mut foreign = author(
        &group,
        &alice_key,
        vec![GroupActionV1::ModifyAnnouncementsOnly { on: true }],
    );
    foreign.actor = b64(&stranger.public_key());
    foreign.signature = b64(&stranger.sign_change(&foreign.signed_bytes().unwrap()));
    let refused = submit(&c, &alice, &home, &group, &foreign, &stranger);
    assert_eq!(
        refused.status,
        GroupResponseStatusV1::Refused,
        "{refused:?}"
    );

    // A request signed by someone other than the change's actor is refused.
    let honest = author(
        &group,
        &alice_key,
        vec![GroupActionV1::ModifyAnnouncementsOnly { on: true }],
    );
    let mismatched = submit(&c, &alice, &home, &group, &honest, &stranger);
    assert_eq!(mismatched.status, GroupResponseStatusV1::Refused);
    assert_eq!(mismatched.code.as_deref(), Some("wrongActor"));

    // The same sealed request twice: the second is a replay.
    let request = signed(
        &home,
        &group.id,
        GroupOperationV1::GetState,
        b"",
        &alice_key,
    );
    let (sealed, first) = seal_request(
        home.key_id,
        &home.public_key,
        &request.canonical_bytes().unwrap(),
    )
    .unwrap();
    let (status, body) = relay(&c, &alice, &home, sealed.clone());
    assert_eq!(status, StatusCode::OK);
    let once = GroupResponseV1::from_canonical_bytes(&first.open_response(&body).unwrap()).unwrap();
    assert_eq!(once.status, GroupResponseStatusV1::Ok);
    let (status, body) = relay(&c, &alice, &home, sealed);
    assert_eq!(status, StatusCode::OK);
    let twice =
        GroupResponseV1::from_canonical_bytes(&first.open_response(&body).unwrap()).unwrap();
    assert_eq!(twice.status, GroupResponseStatusV1::Replayed);

    // A clock far off is told the home's time.
    let late = GroupRequestV1::sign_with_pseudonym(
        &home.name,
        &group.id,
        GroupOperationV1::GetState,
        now() - 3600,
        &random::<16>(),
        b"",
        &SigningKey::from_bytes(alice_key.seed()),
    )
    .unwrap();
    let skewed = exchange(&c, &alice, &home, &late);
    assert_eq!(skewed.status, GroupResponseStatusV1::ClockSkew);
    assert!(skewed.server_time.abs_diff(now()) < 60);

    // Another home's request is an unknown group's.
    let elsewhere = GroupRequestV1::sign_with_pseudonym(
        "elsewhere.example",
        &group.id,
        GroupOperationV1::GetState,
        now(),
        &random::<16>(),
        b"",
        &SigningKey::from_bytes(alice_key.seed()),
    )
    .unwrap();
    assert_eq!(
        exchange(&c, &alice, &home, &elsewhere).status,
        GroupResponseStatusV1::NotFound
    );

    // Bytes sealed to no key of this gateway can't be answered.
    let (status, body) = relay(&c, &alice, &home, vec![7u8; 2048]);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.is_empty());

    // A second genesis for the same group is a conflict, not a new group.
    let again = create_again(&c, &alice, &home, &alice_key, &group);
    assert_eq!(again, GroupResponseStatusV1::Conflict);

    purge_accounts(&c, &base, &[&alice]);
}

fn create_again(
    c: &Client,
    user: &User,
    home: &Home,
    creator: &GroupKeyPair,
    group: &Group,
) -> GroupResponseStatusV1 {
    let mut genesis = GroupChangeV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: encode_group_id(&group.id),
        revision: 0,
        previous_hash: b64(&[0; 32]),
        actor: b64(&creator.public_key()),
        actions: vec![GroupActionV1::Genesis {
            home: home.pin.clone(),
            access: GroupAccessV1::DEFAULT,
            entry: entry(&group.master, &creator.public_key()),
        }],
        resulting_state_hash: Some(b64(&[0; 32])),
        signature: String::new(),
    };
    let first = resulting_genesis_state(&genesis, &home.pin, &GroupLimits::MAX).unwrap();
    genesis.resulting_state_hash = Some(b64(&first.hash().unwrap()));
    genesis.signature = b64(&creator.sign_change(&genesis.signed_bytes().unwrap()));
    let request = signed(
        home,
        &group.id,
        GroupOperationV1::Create,
        &genesis.canonical_bytes().unwrap(),
        creator,
    );
    exchange(c, user, home, &request).status
}
