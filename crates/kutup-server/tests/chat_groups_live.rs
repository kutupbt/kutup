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
    GroupAccessV1, GroupActionV1, GroupAttribute, GroupChangeV1, GroupLimits, GroupRole,
    GroupStateV1, GROUP_FORMAT_VERSION,
};
use kutup_chat_proto::group_route::{
    pad_group_avatar, unpad_group_avatar, GroupGatewayKeyConfigV1, GroupHomePinV1, GroupJoinInfoV1,
    GroupLogEntryV1, GroupLogPageV1, GroupLogQueryV1, GroupOperationV1, GroupRequestStateV1,
    GroupRequestStatusV1, GroupRequestV1, GroupResponseStatusV1, GroupResponseV1,
    GroupStateAnswerV1, PSEUDONYM_USED,
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
    public_key: [u8; kutup_crypto::oblivious::PUBLIC_KEY_LEN],
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
    let master = GroupMasterKey::generate(kutup_crypto::chat_group::GroupHome {
        server: &home.pin.server,
        identity_sequence: home.pin.identity_sequence,
        identity_document_hash: &home.pin.identity_document_hash,
    })
    .unwrap();
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
    let c = crate::common::client();
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
    let c = crate::common::client();
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

    // A stranger's change gets the answer an unknown group gets: no code or
    // conflict tells a stranger the group exists.
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
        GroupResponseStatusV1::NotFound,
        "{refused:?}"
    );
    // Even at a stale revision, where a member would get a conflict.
    let mut stale_foreign = foreign.clone();
    stale_foreign.revision += 5;
    stale_foreign.signature = b64(&stranger.sign_change(&stale_foreign.signed_bytes().unwrap()));
    assert_eq!(
        submit(&c, &alice, &home, &group, &stale_foreign, &stranger).status,
        GroupResponseStatusV1::NotFound
    );
    // A member's change that its checks refuse still says why.
    let mut not_allowed = author(
        &group,
        &alice_key,
        vec![GroupActionV1::ModifyAnnouncementsOnly { on: true }],
    );
    not_allowed.resulting_state_hash = Some(b64(&[1; 32]));
    not_allowed.signature = b64(&alice_key.sign_change(&not_allowed.signed_bytes().unwrap()));
    let mismatch = submit(&c, &alice, &home, &group, &not_allowed, &alice_key);
    assert_eq!(
        mismatch.status,
        GroupResponseStatusV1::Refused,
        "{mismatch:?}"
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

#[test]
fn removed_members_and_strangers_learn_nothing() {
    let Some(base) = live() else { return };
    let c = crate::common::client();
    let alice = register(&c, &base);
    let bob = register(&c, &base);
    let home = home(&c, &base, &alice);
    let alice_key = GroupKeyPair::generate();
    let bob_key = GroupKeyPair::generate();
    let mut group = create(&c, &alice, &home, &alice_key);
    join(&c, &alice, &bob, &home, &mut group, &alice_key, &bob_key);

    // Alice removes Bob.
    let remove = author(
        &group,
        &alice_key,
        vec![GroupActionV1::RemoveMember {
            pseudonym: b64(&bob_key.public_key()),
        }],
    );
    let removed = accepted(&submit(&c, &alice, &home, &group, &remove, &alice_key));
    apply(&mut group, &home, &removed);

    // Bob reads nothing, and his changes meet an unknown group.
    let query = serde_json::to_vec(&GroupLogQueryV1 {
        from_revision: 0,
        limit: 10,
    })
    .unwrap();
    for (operation, body) in [
        (GroupOperationV1::GetState, Vec::new()),
        (GroupOperationV1::GetLogs, query),
    ] {
        let answer = exchange(
            &c,
            &bob,
            &home,
            &signed(&home, &group.id, operation, &body, &bob_key),
        );
        assert_eq!(
            answer.status,
            GroupResponseStatusV1::NotFound,
            "{operation:?}"
        );
    }
    // A removed member's pseudonym is answered exactly as one asking about a
    // group that doesn't exist: a device looking for its account's place
    // (pairwise-groups.md §2, "A device that lost its group list") tells the
    // home nothing.
    let unknown_group: [u8; 32] = random();
    let as_unknown = exchange(
        &c,
        &bob,
        &home,
        &signed(
            &home,
            &unknown_group,
            GroupOperationV1::GetState,
            b"",
            &bob_key,
        ),
    );
    let as_removed = exchange(
        &c,
        &bob,
        &home,
        &signed(&home, &group.id, GroupOperationV1::GetState, b"", &bob_key),
    );
    assert_eq!(
        (&as_removed.status, &as_removed.code, &as_removed.body),
        (&as_unknown.status, &as_unknown.code, &as_unknown.body)
    );
    let leave = GroupChangeV1 {
        actor: b64(&bob_key.public_key()),
        ..author(&group, &alice_key, vec![GroupActionV1::Leave])
    };
    let mut leave = leave;
    leave.signature = b64(&bob_key.sign_change(&leave.signed_bytes().unwrap()));
    assert_eq!(
        submit(&c, &bob, &home, &group, &leave, &bob_key).status,
        GroupResponseStatusV1::NotFound
    );

    // A request with a bad signature is an unknown group's too.
    let mut forged = signed(
        &home,
        &group.id,
        GroupOperationV1::GetState,
        b"",
        &alice_key,
    );
    if let kutup_chat_proto::group_route::GroupRequestAuthV1::Pseudonym { signature, .. } =
        &mut forged.auth
    {
        *signature = b64(&[7u8; 64]);
    }
    assert_eq!(
        exchange(&c, &alice, &home, &forged).status,
        GroupResponseStatusV1::NotFound
    );

    // A newcomer's join with a wrong link password, or with the link off,
    // learns nothing either.
    let wrong = GroupKeyPair::generate();
    let join = GroupChangeV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: encode_group_id(&group.id),
        revision: group.state.revision + 1,
        previous_hash: b64(&group.head),
        actor: b64(&wrong.public_key()),
        actions: vec![GroupActionV1::RequestToJoin {
            password: b64(&[3u8; 16]),
            entry: entry(&group.master, &wrong.public_key()),
        }],
        resulting_state_hash: None,
        signature: String::new(),
    };
    let mut join = join;
    join.signature = b64(&wrong.sign_change(&join.signed_bytes().unwrap()));
    assert_eq!(
        submit(&c, &bob, &home, &group, &join, &wrong).status,
        GroupResponseStatusV1::NotFound
    );
    purge_accounts(&c, &base, &[&alice, &bob]);
}

/// Turns the group's link on with a fresh password, for anyone
/// (`AccessRequired::Any`) or by request (`Administrator`).
fn link_on(
    c: &Client,
    user: &User,
    home: &Home,
    group: &mut Group,
    admin: &GroupKeyPair,
    required: kutup_chat_proto::group::AccessRequired,
) -> [u8; 16] {
    let password = random::<16>();
    let mut access = group.state.access;
    access.add_from_invite_link = required;
    let link = author(
        group,
        admin,
        vec![
            GroupActionV1::ModifyInviteLink {
                password: Some(b64(&password)),
            },
            GroupActionV1::ModifyAccess { access },
        ],
    );
    let linked = accepted(&submit(c, user, home, group, &link, admin));
    apply(group, home, &linked);
    password
}

/// A newcomer's change through the link: a join or a request.
fn through_link(
    group: &Group,
    key: &GroupKeyPair,
    password: &[u8; 16],
    request: bool,
) -> GroupChangeV1 {
    let (password, entry) = (b64(password), entry(&group.master, &key.public_key()));
    let action = if request {
        GroupActionV1::RequestToJoin { password, entry }
    } else {
        GroupActionV1::JoinFromLink { password, entry }
    };
    author(group, key, vec![action])
}

fn assert_used(answer: &GroupResponseV1) {
    assert_eq!(answer.status, GroupResponseStatusV1::Refused, "{answer:?}");
    assert_eq!(answer.code.as_deref(), Some(PSEUDONYM_USED), "{answer:?}");
}

#[test]
fn a_former_members_pseudonym_never_joins_again() {
    let Some(base) = live() else { return };
    let c = crate::common::client();
    let alice = register(&c, &base);
    let bob = register(&c, &base);
    let home = home(&c, &base, &alice);
    let alice_key = GroupKeyPair::generate();
    let bob_key = GroupKeyPair::generate();
    let mut group = create(&c, &alice, &home, &alice_key);
    join(&c, &alice, &bob, &home, &mut group, &alice_key, &bob_key);
    let remove = author(
        &group,
        &alice_key,
        vec![GroupActionV1::RemoveMember {
            pseudonym: b64(&bob_key.public_key()),
        }],
    );
    let removed = accepted(&submit(&c, &alice, &home, &group, &remove, &alice_key));
    apply(&mut group, &home, &removed);

    // Alice invites Bob again. A claim by a key that isn't the slot's meets
    // an unknown group, before any word on the pseudonym.
    let (slot_id, claim_key) = add_slot(&c, &alice, &home, &mut group, &alice_key);
    let forged = claim(&group, &slot_id, &GroupKeyPair::generate(), &bob_key);
    assert_eq!(
        submit(&c, &bob, &home, &group, &forged, &bob_key).status,
        GroupResponseStatusV1::NotFound
    );
    // With the slot's own signature, his old pseudonym is refused as used.
    let again = claim(&group, &slot_id, &claim_key, &bob_key);
    assert_used(&submit(&c, &bob, &home, &group, &again, &bob_key));

    // The link refuses it the same way once its password holds.
    let password = link_on(
        &c,
        &alice,
        &home,
        &mut group,
        &alice_key,
        kutup_chat_proto::group::AccessRequired::Any,
    );
    let from_link = through_link(&group, &bob_key, &password, false);
    assert_used(&submit(&c, &bob, &home, &group, &from_link, &bob_key));

    // The next epoch's pseudonym claims the same slot, which is still open.
    let bob_next = GroupKeyPair::generate();
    let next = claim(&group, &slot_id, &claim_key, &bob_next);
    let claimed = accepted(&submit(&c, &bob, &home, &group, &next, &bob_next));
    apply(&mut group, &home, &claimed);
    assert!(group.state.member(&b64(&bob_next.public_key())).is_some());
    purge_accounts(&c, &base, &[&alice, &bob]);
}

/// The creator is recorded by the genesis alone: no later change records a
/// member who didn't join at it.
#[test]
fn the_creators_pseudonym_counts_from_genesis_on() {
    let Some(base) = live() else { return };
    let c = crate::common::client();
    let alice = register(&c, &base);
    let bob = register(&c, &base);
    let home = home(&c, &base, &alice);
    let alice_key = GroupKeyPair::generate();
    let bob_key = GroupKeyPair::generate();
    let mut group = create(&c, &alice, &home, &alice_key);
    let password = link_on(
        &c,
        &alice,
        &home,
        &mut group,
        &alice_key,
        kutup_chat_proto::group::AccessRequired::Any,
    );
    let joins = through_link(&group, &bob_key, &password, false);
    let joined = accepted(&submit(&c, &bob, &home, &group, &joins, &bob_key));
    apply(&mut group, &home, &joined);
    let promote = author(
        &group,
        &alice_key,
        vec![GroupActionV1::ModifyRole {
            pseudonym: b64(&bob_key.public_key()),
            role: GroupRole::Administrator,
        }],
    );
    let promoted = accepted(&submit(&c, &alice, &home, &group, &promote, &alice_key));
    apply(&mut group, &home, &promoted);
    let leave = author(&group, &alice_key, vec![GroupActionV1::Leave]);
    let left = accepted(&submit(&c, &alice, &home, &group, &leave, &alice_key));
    apply(&mut group, &home, &left);

    let back = through_link(&group, &alice_key, &password, false);
    assert_used(&submit(&c, &alice, &home, &group, &back, &alice_key));
    purge_accounts(&c, &base, &[&alice, &bob]);
}

/// A requester counts as seen, and so does a member an administrator
/// approved: neither comes back under the same pseudonym.
#[test]
fn requesters_and_approved_members_count_as_seen() {
    let Some(base) = live() else { return };
    let c = crate::common::client();
    let alice = register(&c, &base);
    let bob = register(&c, &base);
    let home = home(&c, &base, &alice);
    let alice_key = GroupKeyPair::generate();
    let mut group = create(&c, &alice, &home, &alice_key);
    let password = link_on(
        &c,
        &alice,
        &home,
        &mut group,
        &alice_key,
        kutup_chat_proto::group::AccessRequired::Administrator,
    );

    // A request, cancelled, then made again under the same pseudonym.
    let carol_key = GroupKeyPair::generate();
    let asks = through_link(&group, &carol_key, &password, true);
    let asked = accepted(&submit(&c, &bob, &home, &group, &asks, &carol_key));
    apply(&mut group, &home, &asked);
    let cancel = author(&group, &carol_key, vec![GroupActionV1::CancelRequest]);
    let cancelled = accepted(&submit(&c, &bob, &home, &group, &cancel, &carol_key));
    apply(&mut group, &home, &cancelled);
    let again = through_link(&group, &carol_key, &password, true);
    assert_used(&submit(&c, &bob, &home, &group, &again, &carol_key));

    // A request approved, the member removed, then a claim under it.
    let dave_key = GroupKeyPair::generate();
    let asks = through_link(&group, &dave_key, &password, true);
    let asked = accepted(&submit(&c, &bob, &home, &group, &asks, &dave_key));
    apply(&mut group, &home, &asked);
    let approve = author(
        &group,
        &alice_key,
        vec![GroupActionV1::ApproveRequest {
            pseudonym: b64(&dave_key.public_key()),
        }],
    );
    let approved = accepted(&submit(&c, &alice, &home, &group, &approve, &alice_key));
    apply(&mut group, &home, &approved);
    assert!(group.state.member(&b64(&dave_key.public_key())).is_some());
    let remove = author(
        &group,
        &alice_key,
        vec![GroupActionV1::RemoveMember {
            pseudonym: b64(&dave_key.public_key()),
        }],
    );
    let removed = accepted(&submit(&c, &alice, &home, &group, &remove, &alice_key));
    apply(&mut group, &home, &removed);
    let (slot_id, claim_key) = add_slot(&c, &alice, &home, &mut group, &alice_key);
    let reclaim = claim(&group, &slot_id, &claim_key, &dave_key);
    assert_used(&submit(&c, &bob, &home, &group, &reclaim, &dave_key));
    purge_accounts(&c, &base, &[&alice, &bob]);
}

/// The signer's own request status, as the home answers it.
fn request_status(
    c: &Client,
    user: &User,
    home: &Home,
    group_id: &[u8; 32],
    key: &GroupKeyPair,
) -> GroupRequestStatusV1 {
    let request = signed(home, group_id, GroupOperationV1::GetRequestStatus, b"", key);
    let answer = exchange(c, user, home, &request);
    assert_eq!(answer.status, GroupResponseStatusV1::Ok, "{answer:?}");
    GroupRequestStatusV1::from_canonical_bytes(&answer.body().unwrap()).unwrap()
}

/// A requester follows its request: pending (with what a cancel names),
/// member once approved, denied once denied or cancelled, and unknown for
/// a pseudonym the group never saw or a group that doesn't exist.
#[test]
fn a_requester_learns_where_its_request_stands() {
    let Some(base) = live() else { return };
    let c = crate::common::client();
    let alice = register(&c, &base);
    let bob = register(&c, &base);
    let home = home(&c, &base, &alice);
    let alice_key = GroupKeyPair::generate();
    let mut group = create(&c, &alice, &home, &alice_key);
    let password = link_on(
        &c,
        &alice,
        &home,
        &mut group,
        &alice_key,
        kutup_chat_proto::group::AccessRequired::Administrator,
    );
    let group_id = group.id;
    let status = |key: &GroupKeyPair| request_status(&c, &bob, &home, &group_id, key);

    let stranger = GroupKeyPair::generate();
    assert_eq!(status(&stranger).status, GroupRequestStateV1::Unknown);
    let nowhere = request_status(&c, &bob, &home, &random::<32>(), &stranger);
    assert_eq!(nowhere.status, GroupRequestStateV1::Unknown);
    assert_eq!(nowhere.revision, None);

    // Carol asks; she is pending at the group's revision and head.
    let carol_key = GroupKeyPair::generate();
    let asks = through_link(&group, &carol_key, &password, true);
    let asked = accepted(&submit(&c, &bob, &home, &group, &asks, &carol_key));
    apply(&mut group, &home, &asked);
    let pending = status(&carol_key);
    assert_eq!(pending.status, GroupRequestStateV1::Pending);
    assert_eq!(pending.revision, Some(group.state.revision));
    assert_eq!(pending.head, Some(b64(&group.head)));

    // Alice approves her: a member.
    let approve = author(
        &group,
        &alice_key,
        vec![GroupActionV1::ApproveRequest {
            pseudonym: b64(&carol_key.public_key()),
        }],
    );
    let approved = accepted(&submit(&c, &alice, &home, &group, &approve, &alice_key));
    apply(&mut group, &home, &approved);
    assert_eq!(status(&carol_key).status, GroupRequestStateV1::Member);

    // Dave asks and is denied (and so banned).
    let dave_key = GroupKeyPair::generate();
    let asks = through_link(&group, &dave_key, &password, true);
    let asked = accepted(&submit(&c, &bob, &home, &group, &asks, &dave_key));
    apply(&mut group, &home, &asked);
    let deny = author(
        &group,
        &alice_key,
        vec![GroupActionV1::DenyRequest {
            pseudonym: b64(&dave_key.public_key()),
        }],
    );
    let denied = accepted(&submit(&c, &alice, &home, &group, &deny, &alice_key));
    apply(&mut group, &home, &denied);
    let answer = status(&dave_key);
    assert_eq!(answer.status, GroupRequestStateV1::Denied);
    assert_eq!((answer.revision, answer.head), (None, None));

    // Erin asks and cancels: neither requesting nor a member any more.
    let erin_key = GroupKeyPair::generate();
    let asks = through_link(&group, &erin_key, &password, true);
    let asked = accepted(&submit(&c, &bob, &home, &group, &asks, &erin_key));
    apply(&mut group, &home, &asked);
    let cancel = author(&group, &erin_key, vec![GroupActionV1::CancelRequest]);
    let cancelled = accepted(&submit(&c, &bob, &home, &group, &cancel, &erin_key));
    apply(&mut group, &home, &cancelled);
    assert_eq!(status(&erin_key).status, GroupRequestStateV1::Denied);
    purge_accounts(&c, &base, &[&alice, &bob]);
}

/// A newcomer's cancel built from what `GetRequestStatus` answered alone:
/// the revision and head it named, not a state the newcomer never sees.
fn cancel_from(
    group_id: &[u8; 32],
    status: &GroupRequestStatusV1,
    key: &GroupKeyPair,
) -> GroupChangeV1 {
    let mut change = GroupChangeV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: encode_group_id(group_id),
        revision: status.revision.expect("pending names its revision") + 1,
        previous_hash: status.head.clone().expect("pending names its head"),
        actor: b64(&key.public_key()),
        actions: vec![GroupActionV1::CancelRequest],
        resulting_state_hash: None,
        signature: String::new(),
    };
    change.signature = b64(&key.sign_change(&change.signed_bytes().unwrap()));
    change
}

/// A requester cancels from its status alone, after the link was reset
/// (so it can't build anything from the link); the cancel is done once:
/// sent again it meets an unknown group, and the status says denied. A
/// client that lost the answer to its cancel asks the status the same way.
#[test]
fn a_requester_cancels_from_its_status_after_a_link_reset() {
    let Some(base) = live() else { return };
    let c = crate::common::client();
    let alice = register(&c, &base);
    let bob = register(&c, &base);
    let home = home(&c, &base, &alice);
    let alice_key = GroupKeyPair::generate();
    let mut group = create(&c, &alice, &home, &alice_key);
    let password = link_on(
        &c,
        &alice,
        &home,
        &mut group,
        &alice_key,
        kutup_chat_proto::group::AccessRequired::Administrator,
    );
    let carol_key = GroupKeyPair::generate();
    let asks = through_link(&group, &carol_key, &password, true);
    let asked = accepted(&submit(&c, &bob, &home, &group, &asks, &carol_key));
    apply(&mut group, &home, &asked);
    // Alice resets the link: the old password no longer reads anything.
    let reset = author(
        &group,
        &alice_key,
        vec![GroupActionV1::ModifyInviteLink {
            password: Some(b64(&random::<16>())),
        }],
    );
    let reset = accepted(&submit(&c, &alice, &home, &group, &reset, &alice_key));
    apply(&mut group, &home, &reset);

    let pending = request_status(&c, &bob, &home, &group.id, &carol_key);
    assert_eq!(pending.status, GroupRequestStateV1::Pending);
    assert_eq!(pending.revision, Some(group.state.revision));
    let cancel = cancel_from(&group.id, &pending, &carol_key);
    let cancelled = accepted(&submit(&c, &bob, &home, &group, &cancel, &carol_key));
    apply(&mut group, &home, &cancelled);
    assert!(group.state.requesting.is_empty());

    let again = cancel_from(&group.id, &pending, &carol_key);
    assert_eq!(
        submit(&c, &bob, &home, &group, &again, &carol_key).status,
        GroupResponseStatusV1::NotFound
    );
    let after = request_status(&c, &bob, &home, &group.id, &carol_key);
    assert_eq!(after.status, GroupRequestStateV1::Denied);
    purge_accounts(&c, &base, &[&alice, &bob]);
}

/// An administrator's session, which puts the group settings (the link-join
/// budgets, the avatar limits) back to their first values when dropped (a
/// failing test too).
struct LinkJoinBudgets {
    c: Client,
    base: String,
    token: String,
}

impl LinkJoinBudgets {
    /// `None` without an administrator (`KUTUP_LIVE_ADMIN`).
    fn take(c: &Client, base: &str) -> Option<Self> {
        let Ok(admin) = std::env::var("KUTUP_LIVE_ADMIN") else {
            eprintln!("KUTUP_LIVE_ADMIN unset; skipping");
            return None;
        };
        let (name, password) = admin.split_once(':').unwrap();
        Some(Self {
            c: c.clone(),
            base: base.to_owned(),
            token: admin_token(c, base, password, name),
        })
    }

    fn put(&self, body: Value) -> (StatusCode, Value) {
        let r = bearer(
            self.c.put(format!("{}/api/admin/settings", self.base)),
            &self.token,
        )
        .json(&body)
        .send()
        .unwrap();
        let status = r.status();
        (status, r.json().unwrap_or(Value::Null))
    }

    /// Sets the budgets: per relay server and group, and per relay server.
    fn set(&self, per_group: i64, per_relay: i64) {
        let (status, settings) = self.put(serde_json::json!({
            "chatGroupLinkJoinsPerRelayGroupPerMin": per_group,
            "chatGroupLinkJoinsPerRelayPerMin": per_relay,
        }));
        assert_eq!(status, StatusCode::OK, "{settings}");
        assert_eq!(settings["chatGroupLinkJoinsPerRelayGroupPerMin"], per_group);
        assert_eq!(settings["chatGroupLinkJoinsPerRelayPerMin"], per_relay);
    }
}

impl Drop for LinkJoinBudgets {
    fn drop(&mut self) {
        let (status, _) = self.put(serde_json::json!({
            "chatGroupLinkJoinsPerRelayGroupPerMin": null,
            "chatGroupLinkJoinsPerRelayPerMin": null,
            "chatGroupAvatarMaxBytes": null,
            "chatGroupAvatarStoragePerGroupBytes": null,
        }));
        if status != StatusCode::OK && !std::thread::panicking() {
            panic!("the link-join budgets were not reset: {status}");
        }
    }
}

/// Joins and requests through a link are budgeted per relay server and
/// group, and per relay server, as administrators set them; charged once
/// the link's password holds, so junk without it spends nothing, and one
/// link's holders crowd only that group. (The gate runs these tests one at
/// a time, so the budgets are this test's alone while it runs.)
#[test]
fn link_joins_are_budgeted_per_relay_server_and_group() {
    let Some(base) = live() else { return };
    let c = crate::common::client();
    let Some(budgets) = LinkJoinBudgets::take(&c, &base) else {
        return;
    };
    let (status, _) = budgets.put(serde_json::json!({ "chatGroupLinkJoinsPerRelayPerMin": 0 }));
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let alice = register(&c, &base);
    let bob = register(&c, &base);
    let home = home(&c, &base, &alice);
    let alice_key = GroupKeyPair::generate();
    let mut first = create(&c, &alice, &home, &alice_key);
    let first_password = link_on(
        &c,
        &alice,
        &home,
        &mut first,
        &alice_key,
        kutup_chat_proto::group::AccessRequired::Administrator,
    );
    let mut second = create(&c, &alice, &home, &alice_key);
    let second_password = link_on(
        &c,
        &alice,
        &home,
        &mut second,
        &alice_key,
        kutup_chat_proto::group::AccessRequired::Administrator,
    );
    budgets.set(3, 5);
    // Past the window of the joins earlier tests made through this relay.
    std::thread::sleep(std::time::Duration::from_secs(61));

    let ask = |group: &mut Group, password: &[u8; 16]| {
        let key = GroupKeyPair::generate();
        let change = through_link(group, &key, password, true);
        let answer = submit(&c, &bob, &home, group, &change, &key);
        if answer.status == GroupResponseStatusV1::Ok {
            apply(group, &home, &accepted(&answer));
        }
        answer.status
    };
    for _ in 0..3 {
        assert_eq!(ask(&mut first, &first_password), GroupResponseStatusV1::Ok);
    }
    // The group's budget is spent: the right password meets it.
    assert_eq!(
        ask(&mut first, &first_password),
        GroupResponseStatusV1::RateLimited
    );
    // A wrong password is an unknown group, as ever, and spends nothing.
    assert_eq!(
        ask(&mut first, &random::<16>()),
        GroupResponseStatusV1::NotFound
    );
    // Another group has its own budget, under the relay's: 3 + 2 = 5.
    for _ in 0..2 {
        assert_eq!(
            ask(&mut second, &second_password),
            GroupResponseStatusV1::Ok
        );
    }
    assert_eq!(
        ask(&mut second, &second_password),
        GroupResponseStatusV1::RateLimited
    );
    // A member's own change isn't charged.
    let deny = author(
        &first,
        &alice_key,
        vec![GroupActionV1::DenyRequest {
            pseudonym: first.state.requesting[0].pseudonym.clone(),
        }],
    );
    accepted(&submit(&c, &alice, &home, &first, &deny, &alice_key));
    drop(budgets);
    purge_accounts(&c, &base, &[&alice, &bob]);
}

/// A sealed avatar blob of `length` bytes (the home sees only its length
/// and hash).
fn avatar_blob(length: usize) -> Vec<u8> {
    let mut blob = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut blob);
    blob
}

fn put_avatar(
    c: &Client,
    user: &User,
    home: &Home,
    group: &Group,
    key: &GroupKeyPair,
    body: &[u8],
) -> GroupResponseV1 {
    let request = signed(home, &group.id, GroupOperationV1::PutAvatar, body, key);
    exchange(c, user, home, &request)
}

fn get_avatar(
    c: &Client,
    user: &User,
    home: &Home,
    group: &Group,
    key: &GroupKeyPair,
) -> GroupResponseV1 {
    let request = signed(home, &group.id, GroupOperationV1::GetAvatar, b"", key);
    exchange(c, user, home, &request)
}

/// The blob a `GetAvatar` answer carries.
fn avatar_of(answer: &GroupResponseV1) -> Vec<u8> {
    assert_eq!(answer.status, GroupResponseStatusV1::Ok, "{answer:?}");
    unpad_group_avatar(&answer.body().unwrap()).unwrap()
}

fn assert_refused(answer: &GroupResponseV1, code: &str) {
    assert_eq!(answer.status, GroupResponseStatusV1::Refused, "{answer:?}");
    assert_eq!(answer.code.as_deref(), Some(code), "{answer:?}");
}

/// A change setting the avatar to the blob `hash` (or removing it).
fn set_avatar(group: &Group, key: &GroupKeyPair, hash: Option<[u8; 32]>) -> GroupChangeV1 {
    let value = hash.map(|_| {
        b64(&group
            .master
            .state_key()
            .seal(SealedField::Avatar, b"", b"key and type")
            .unwrap())
    });
    author(
        group,
        key,
        vec![GroupActionV1::ModifyAttribute {
            attribute: GroupAttribute::Avatar,
            value,
            avatar_hash: hash.map(|hash| b64(&hash)),
        }],
    )
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes).into()
}

/// A member uploads an avatar, then names it in a change: the home refuses
/// a change naming a blob it doesn't hold, swaps the named one in, serves
/// it padded to one size to members and to the link's holders, and keeps at
/// most the current blob and one pending upload, within its settings.
#[test]
fn a_groups_avatar_is_uploaded_named_and_served() {
    let Some(base) = live() else { return };
    let c = crate::common::client();
    let alice = register(&c, &base);
    let bob = register(&c, &base);
    let home = home(&c, &base, &alice);
    let alice_key = GroupKeyPair::generate();
    let bob_key = GroupKeyPair::generate();
    let mut group = create(&c, &alice, &home, &alice_key);
    let password = link_on(
        &c,
        &alice,
        &home,
        &mut group,
        &alice_key,
        kutup_chat_proto::group::AccessRequired::Any,
    );
    let joins = through_link(&group, &bob_key, &password, false);
    let joined = accepted(&submit(&c, &bob, &home, &group, &joins, &bob_key));
    apply(&mut group, &home, &joined);

    // Nothing yet; an upload not padded to the one size is malformed.
    assert_refused(
        &get_avatar(&c, &bob, &home, &group, &bob_key),
        "avatarMissing",
    );
    let first = avatar_blob(8_233);
    assert_refused(
        &put_avatar(&c, &alice, &home, &group, &alice_key, &first),
        "malformed",
    );
    // A stranger's upload meets an unknown group.
    let stranger = GroupKeyPair::generate();
    let body = pad_group_avatar(&first).unwrap();
    assert_eq!(
        put_avatar(&c, &bob, &home, &group, &stranger, &body).status,
        GroupResponseStatusV1::NotFound
    );
    let uploaded = put_avatar(&c, &alice, &home, &group, &alice_key, &body);
    assert_eq!(uploaded.status, GroupResponseStatusV1::Ok, "{uploaded:?}");
    // Still not the avatar: no change named it.
    assert_refused(
        &get_avatar(&c, &bob, &home, &group, &bob_key),
        "avatarMissing",
    );

    // A change naming a blob the home doesn't hold is refused.
    let wrong = set_avatar(&group, &alice_key, Some(sha256(&avatar_blob(8_233))));
    assert_refused(
        &submit(&c, &alice, &home, &group, &wrong, &alice_key),
        "avatarMissing",
    );
    let named = set_avatar(&group, &alice_key, Some(sha256(&first)));
    let named = accepted(&submit(&c, &alice, &home, &group, &named, &alice_key));
    apply(&mut group, &home, &named);
    assert_eq!(
        avatar_of(&get_avatar(&c, &bob, &home, &group, &bob_key)),
        first
    );

    // The link's holders see it too (the link's preview), and a wrong
    // password meets an unknown group.
    let link_read = |password: &[u8]| {
        let request = GroupRequestV1::with_link_password(
            &home.name,
            &group.id,
            GroupOperationV1::GetAvatar,
            now(),
            &random::<16>(),
            password,
        )
        .unwrap();
        exchange(&c, &bob, &home, &request)
    };
    assert_eq!(avatar_of(&link_read(&password)), first);
    assert_eq!(
        link_read(&random::<16>()).status,
        GroupResponseStatusV1::NotFound
    );

    // A second upload replaces nothing until named; then the old one goes.
    let second = avatar_blob(16_425);
    let uploaded = put_avatar(
        &c,
        &bob,
        &home,
        &group,
        &bob_key,
        &pad_group_avatar(&second).unwrap(),
    );
    assert_eq!(uploaded.status, GroupResponseStatusV1::Ok, "{uploaded:?}");
    assert_eq!(
        avatar_of(&get_avatar(&c, &bob, &home, &group, &bob_key)),
        first
    );
    let renamed = set_avatar(&group, &bob_key, Some(sha256(&second)));
    let renamed = accepted(&submit(&c, &bob, &home, &group, &renamed, &bob_key));
    apply(&mut group, &home, &renamed);
    assert_eq!(
        avatar_of(&get_avatar(&c, &alice, &home, &group, &alice_key)),
        second
    );
    // The first blob is gone: naming it again finds nothing.
    let back = set_avatar(&group, &alice_key, Some(sha256(&first)));
    assert_refused(
        &submit(&c, &alice, &home, &group, &back, &alice_key),
        "avatarMissing",
    );

    // Only administrators change attributes now: Bob's upload is refused.
    let mut access = group.state.access;
    access.attributes = kutup_chat_proto::group::AccessRequired::Administrator;
    let restrict = author(
        &group,
        &alice_key,
        vec![GroupActionV1::ModifyAccess { access }],
    );
    let restricted = accepted(&submit(&c, &alice, &home, &group, &restrict, &alice_key));
    apply(&mut group, &home, &restricted);
    assert_refused(
        &put_avatar(
            &c,
            &bob,
            &home,
            &group,
            &bob_key,
            &pad_group_avatar(&avatar_blob(8_233)).unwrap(),
        ),
        "notAllowed",
    );

    // The home's limits, as its administrators set them.
    if let Some(settings) = LinkJoinBudgets::take(&c, &base) {
        let (status, body) = settings.put(serde_json::json!({ "chatGroupAvatarMaxBytes": 40_000 }));
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let (status, body) = settings.put(serde_json::json!({
            "chatGroupAvatarMaxBytes": 16_425,
            "chatGroupAvatarStoragePerGroupBytes": 16_425 + 8_233,
        }));
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_refused(
            &put_avatar(
                &c,
                &alice,
                &home,
                &group,
                &alice_key,
                &pad_group_avatar(&avatar_blob(32_809)).unwrap(),
            ),
            "avatarTooLarge",
        );
        // 16,425 current + 16,425 pending is over 24,658.
        assert_refused(
            &put_avatar(
                &c,
                &alice,
                &home,
                &group,
                &alice_key,
                &pad_group_avatar(&avatar_blob(16_425)).unwrap(),
            ),
            "avatarStorageFull",
        );
        let fits = put_avatar(
            &c,
            &alice,
            &home,
            &group,
            &alice_key,
            &pad_group_avatar(&avatar_blob(8_233)).unwrap(),
        );
        assert_eq!(fits.status, GroupResponseStatusV1::Ok, "{fits:?}");
        drop(settings);
    }

    // Removing the avatar drops its blob.
    let removed = set_avatar(&group, &alice_key, None);
    let removed = accepted(&submit(&c, &alice, &home, &group, &removed, &alice_key));
    apply(&mut group, &home, &removed);
    assert_refused(
        &get_avatar(&c, &bob, &home, &group, &bob_key),
        "avatarMissing",
    );
    purge_accounts(&c, &base, &[&alice, &bob]);
}

#[test]
fn link_join_info_needs_the_link_on_and_its_password() {
    let Some(base) = live() else { return };
    let c = crate::common::client();
    let alice = register(&c, &base);
    let home = home(&c, &base, &alice);
    let alice_key = GroupKeyPair::generate();
    let mut group = create(&c, &alice, &home, &alice_key);
    let password = random::<16>();
    let group_id = group.id;
    let join_info = |password: &[u8]| {
        let request = GroupRequestV1::with_link_password(
            &home.name,
            &group_id,
            GroupOperationV1::GetJoinInfo,
            now(),
            &random::<16>(),
            password,
        )
        .unwrap();
        exchange(&c, &alice, &home, &request)
    };
    // No link yet.
    assert_eq!(join_info(&password).status, GroupResponseStatusV1::NotFound);

    // Alice turns the link on (anyone may join) with a password.
    let mut access = group.state.access;
    access.add_from_invite_link = kutup_chat_proto::group::AccessRequired::Any;
    let link = author(
        &group,
        &alice_key,
        vec![
            GroupActionV1::ModifyInviteLink {
                password: Some(b64(&password)),
            },
            GroupActionV1::ModifyAccess { access },
        ],
    );
    let linked = accepted(&submit(&c, &alice, &home, &group, &link, &alice_key));
    apply(&mut group, &home, &linked);

    let answer = join_info(&password);
    assert_eq!(answer.status, GroupResponseStatusV1::Ok, "{answer:?}");
    let info = GroupJoinInfoV1::from_canonical_bytes(&answer.body().unwrap()).unwrap();
    assert_eq!(info.revision, group.state.revision);
    assert_eq!(info.requires_approval, Some(false));
    assert_eq!(
        join_info(&random::<16>()).status,
        GroupResponseStatusV1::NotFound
    );
    purge_accounts(&c, &base, &[&alice]);
}

#[test]
fn the_relay_needs_a_signed_in_account() {
    let Some(base) = live() else { return };
    let c = crate::common::client();
    let name = server_name(&c, &base);
    let r = c
        .post(format!("{base}/api/chat/groups/relay/{name}"))
        .body(vec![0u8; 64])
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let r = c
        .get(format!(
            "{base}/api/chat/groups/gateway-key?server={name}&fromSequence=0"
        ))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

/// A slot `adder` adds; returns its id and claim key.
fn add_slot(
    c: &Client,
    adder_user: &User,
    home: &Home,
    group: &mut Group,
    adder: &GroupKeyPair,
) -> ([u8; 16], GroupKeyPair) {
    let claim_key = GroupKeyPair::generate();
    let slot_id = random::<16>();
    let add = author(
        group,
        adder,
        vec![GroupActionV1::AddSlot {
            slot_id: b64(&slot_id),
            role: GroupRole::Member,
            claim_key: b64(&claim_key.public_key()),
            entry: entry(&group.master, b"slot"),
        }],
    );
    let added = accepted(&submit(c, adder_user, home, group, &add, adder));
    apply(group, home, &added);
    (slot_id, claim_key)
}

/// `member`'s claim of the slot, signed by `claim_key`.
fn claim(
    group: &Group,
    slot_id: &[u8; 16],
    claim_key: &GroupKeyPair,
    member: &GroupKeyPair,
) -> GroupChangeV1 {
    let slot_revision = group
        .state
        .slots
        .iter()
        .find(|slot| slot.slot_id == b64(slot_id))
        .unwrap()
        .created_at_revision;
    let claim_signature =
        claim_key.sign_claim(&group.id, slot_id, slot_revision, &member.public_key());
    author(
        group,
        member,
        vec![GroupActionV1::Claim {
            slot_id: b64(slot_id),
            claim_signature: b64(&claim_signature),
            entry: entry(&group.master, &member.public_key()),
        }],
    )
}

/// Adds `member` (signed in as `user`) through a slot `adder` makes.
fn join(
    c: &Client,
    adder_user: &User,
    user: &User,
    home: &Home,
    group: &mut Group,
    adder: &GroupKeyPair,
    member: &GroupKeyPair,
) {
    let (slot_id, claim_key) = add_slot(c, adder_user, home, group, adder);
    let change = claim(group, &slot_id, &claim_key, member);
    let claimed = accepted(&submit(c, user, home, group, &change, member));
    apply(group, home, &claimed);
}
