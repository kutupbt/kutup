use kutup_crypto::chat_group::{GroupKeyPair, GroupMasterKey, SealedField, HASH_LEN};

use super::*;

const HOME: &str = "home.example";

struct Group {
    master: GroupMasterKey,
    state: GroupStateV1,
    head: [u8; HASH_LEN],
}

fn sealed_entry(master: &GroupMasterKey, subject: &[u8]) -> String {
    encode(
        &master
            .state_key()
            .seal(SealedField::MemberEntry, subject, b"entry")
            .unwrap(),
    )
}

/// A change by `actor`, named and signed as an honest author would.
fn author(group: &Group, actor: &GroupKeyPair, actions: Vec<GroupActionV1>) -> GroupChangeV1 {
    let mut change = GroupChangeV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: group.state.group_id.clone(),
        revision: group.state.revision + 1,
        previous_hash: encode(&group.head),
        actor: encode(&actor.public_key()),
        actions,
        resulting_state_hash: encode(&[0u8; 32]),
        signature: String::new(),
    };
    let next = resulting_state(&group.state, &group.head, &change, &GroupLimits::MAX)
        .expect("an honest author's change");
    sign(&mut change, actor, &next);
    change
}

fn sign(change: &mut GroupChangeV1, actor: &GroupKeyPair, next: &GroupStateV1) {
    change.resulting_state_hash = encode(&next.hash().unwrap());
    change.signature = encode(&actor.sign_change(&change.signed_bytes().unwrap()));
}

fn apply(group: &mut Group, change: &GroupChangeV1) {
    group.state = check_change(&group.state, &group.head, change, &GroupLimits::MAX).unwrap();
    group.head = change.hash().unwrap();
}

fn create(creator: &GroupKeyPair) -> Group {
    let master = GroupMasterKey::from_bytes(&[5u8; 32]).unwrap();
    let mut change = GroupChangeV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: encode_group_id(&master.group_id()),
        revision: 0,
        previous_hash: encode(&[0u8; 32]),
        actor: encode(&creator.public_key()),
        actions: vec![GroupActionV1::Genesis {
            home: GroupHomePinV1 {
                server: HOME.into(),
                identity_sequence: 1,
                identity_document_hash: "9".repeat(64),
            },
            access: GroupAccessV1::DEFAULT,
            entry: sealed_entry(&master, &creator.public_key()),
        }],
        resulting_state_hash: encode(&[0u8; 32]),
        signature: String::new(),
    };
    let first = resulting_genesis_state(&change, HOME, &GroupLimits::MAX).unwrap();
    sign(&mut change, creator, &first);
    let state = check_genesis(&change, HOME, &GroupLimits::MAX).unwrap();
    Group {
        head: change.hash().unwrap(),
        master,
        state,
    }
}

/// Adds `member` through a slot claimed with its one-time key.
fn add(group: &mut Group, adder: &GroupKeyPair, member: &GroupKeyPair, role: GroupRole) {
    let slot_id = encode(&rand_slot(member));
    let claim_key = GroupKeyPair::generate();
    let add = author(
        group,
        adder,
        vec![GroupActionV1::AddSlot {
            slot_id: slot_id.clone(),
            role,
            claim_key: encode(&claim_key.public_key()),
            entry: sealed_entry(&group.master, b"slot"),
        }],
    );
    apply(group, &add);
    let claim = claim_change(group, member, &claim_key, &slot_id);
    apply(group, &claim);
}

fn rand_slot(member: &GroupKeyPair) -> [u8; 16] {
    member.public_key()[..16].try_into().unwrap()
}

fn claim_change(
    group: &Group,
    member: &GroupKeyPair,
    claim_key: &GroupKeyPair,
    slot_id: &str,
) -> GroupChangeV1 {
    let group_id = decode_group_id(&group.state.group_id).unwrap();
    let slot = decode_exact::<16>("slotId", slot_id).unwrap();
    let claim_signature = claim_key.sign_claim(&group_id, &slot, &member.public_key());
    author(
        group,
        member,
        vec![GroupActionV1::Claim {
            slot_id: slot_id.to_string(),
            claim_signature: encode(&claim_signature),
            entry: sealed_entry(&group.master, &member.public_key()),
        }],
    )
}

fn refused(group: &Group, change: &GroupChangeV1) -> GroupChangeError {
    check_change(&group.state, &group.head, change, &GroupLimits::MAX).unwrap_err()
}

/// A change built without the author-side checks, to see the acceptance check refuse it.
fn forced(group: &Group, actor: &GroupKeyPair, actions: Vec<GroupActionV1>) -> GroupChangeV1 {
    let mut change = GroupChangeV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: group.state.group_id.clone(),
        revision: group.state.revision + 1,
        previous_hash: encode(&group.head),
        actor: encode(&actor.public_key()),
        actions,
        resulting_state_hash: encode(&group.state.hash().unwrap()),
        signature: String::new(),
    };
    change.signature = encode(&actor.sign_change(&change.signed_bytes().unwrap()));
    change
}

#[test]
fn a_group_is_created_and_members_claim_their_slots() {
    let creator = GroupKeyPair::generate();
    let mut group = create(&creator);
    assert_eq!(group.state.members.len(), 1);
    assert!(group.state.is_administrator(&encode(&creator.public_key())));

    let bob = GroupKeyPair::generate();
    add(&mut group, &creator, &bob, GroupRole::Member);
    assert_eq!(group.state.revision, 2);
    let member = group.state.member(&encode(&bob.public_key())).unwrap();
    assert_eq!(member.role, GroupRole::Member);
    assert_eq!(member.joined_at_revision, 2);
    assert!(group.state.slots.is_empty());

    // The state survives its canonical encoding, and no account is in it.
    let bytes = group.state.canonical_bytes().unwrap();
    assert_eq!(
        GroupStateV1::from_canonical_bytes(&bytes).unwrap(),
        group.state
    );
}

#[test]
fn the_home_cannot_claim_a_slot_without_the_claim_key() {
    let creator = GroupKeyPair::generate();
    let mut group = create(&creator);
    let claim_key = GroupKeyPair::generate();
    let slot_id = encode(&[1u8; 16]);
    let add = author(
        &group,
        &creator,
        vec![GroupActionV1::AddSlot {
            slot_id: slot_id.clone(),
            role: GroupRole::Administrator,
            claim_key: encode(&claim_key.public_key()),
            entry: sealed_entry(&group.master, b"slot"),
        }],
    );
    apply(&mut group, &add);

    // The invitee's claim, as the home saw it: its signature binds the
    // invitee's pseudonym, so the home can't reuse it for its own.
    let invitee = GroupKeyPair::generate();
    let honest = claim_change(&group, &invitee, &claim_key, &slot_id);
    let GroupActionV1::Claim {
        claim_signature, ..
    } = &honest.actions[0]
    else {
        unreachable!()
    };
    let home_key = GroupKeyPair::generate();
    let mut stolen = forced(
        &group,
        &home_key,
        vec![GroupActionV1::Claim {
            slot_id: slot_id.clone(),
            claim_signature: claim_signature.clone(),
            entry: sealed_entry(&group.master, &home_key.public_key()),
        }],
    );
    stolen.resulting_state_hash = honest.resulting_state_hash.clone();
    stolen.signature = encode(&home_key.sign_change(&stolen.signed_bytes().unwrap()));
    assert_eq!(refused(&group, &stolen), GroupChangeError::BadSignature);

    // The invitee's own claim is taken, once.
    apply(&mut group, &honest);
    assert!(group.state.is_administrator(&encode(&invitee.public_key())));
    let late = GroupKeyPair::generate();
    let group_id = decode_group_id(&group.state.group_id).unwrap();
    let slot = decode_exact::<16>("slotId", &slot_id).unwrap();
    let again = forced(
        &group,
        &late,
        vec![GroupActionV1::Claim {
            slot_id: slot_id.clone(),
            claim_signature: encode(&claim_key.sign_claim(&group_id, &slot, &late.public_key())),
            entry: sealed_entry(&group.master, &late.public_key()),
        }],
    );
    assert_eq!(refused(&group, &again), GroupChangeError::UnknownTarget);
}

#[test]
fn the_last_administrator_cannot_leave_or_step_down_while_others_remain() {
    let creator = GroupKeyPair::generate();
    let mut group = create(&creator);
    let bob = GroupKeyPair::generate();
    add(&mut group, &creator, &bob, GroupRole::Member);

    let leave = forced(&group, &creator, vec![GroupActionV1::Leave]);
    assert_eq!(refused(&group, &leave), GroupChangeError::LastAdministrator);
    let demote = forced(
        &group,
        &creator,
        vec![GroupActionV1::ModifyRole {
            pseudonym: encode(&creator.public_key()),
            role: GroupRole::Member,
        }],
    );
    assert_eq!(
        refused(&group, &demote),
        GroupChangeError::LastAdministrator
    );

    // After naming a successor, both may happen.
    let promote = author(
        &group,
        &creator,
        vec![GroupActionV1::ModifyRole {
            pseudonym: encode(&bob.public_key()),
            role: GroupRole::Administrator,
        }],
    );
    apply(&mut group, &promote);
    let leave = author(&group, &creator, vec![GroupActionV1::Leave]);
    apply(&mut group, &leave);
    assert_eq!(group.state.members.len(), 1);
}

#[test]
fn signals_access_rules_decide_who_edits_and_adds() {
    let creator = GroupKeyPair::generate();
    let mut group = create(&creator);
    let bob = GroupKeyPair::generate();
    add(&mut group, &creator, &bob, GroupRole::Member);
    let title = encode(
        &group
            .master
            .state_key()
            .seal(SealedField::Title, b"", b"T")
            .unwrap(),
    );

    // Members may edit by default; a member may not make an administrator slot.
    let edit = author(
        &group,
        &bob,
        vec![GroupActionV1::ModifyAttribute {
            attribute: GroupAttribute::Title,
            value: Some(title.clone()),
        }],
    );
    apply(&mut group, &edit);
    let admin_slot = forced(
        &group,
        &bob,
        vec![GroupActionV1::AddSlot {
            slot_id: encode(&[2u8; 16]),
            role: GroupRole::Administrator,
            claim_key: encode(&[3u8; 32]),
            entry: sealed_entry(&group.master, b"slot"),
        }],
    );
    assert_eq!(refused(&group, &admin_slot), GroupChangeError::NotAllowed);

    // Administrators only: the member's edit is refused, as is any member's
    // change of the rules, a removal or ending the group.
    let restrict = author(
        &group,
        &creator,
        vec![GroupActionV1::ModifyAccess {
            access: GroupAccessV1 {
                attributes: AccessRequired::Administrator,
                members: AccessRequired::Administrator,
                add_from_invite_link: AccessRequired::Unsatisfiable,
            },
        }],
    );
    apply(&mut group, &restrict);
    for action in [
        GroupActionV1::ModifyAttribute {
            attribute: GroupAttribute::Title,
            value: None,
        },
        GroupActionV1::ModifyAccess {
            access: GroupAccessV1::DEFAULT,
        },
        GroupActionV1::RemoveMember {
            pseudonym: encode(&creator.public_key()),
        },
        GroupActionV1::Terminate,
    ] {
        let change = forced(&group, &bob, vec![action]);
        assert_eq!(refused(&group, &change), GroupChangeError::NotAllowed);
    }
}

#[test]
fn the_link_joins_or_asks_and_a_ban_removes() {
    let creator = GroupKeyPair::generate();
    let mut group = create(&creator);
    let password = encode(&[4u8; 16]);
    let open = author(
        &group,
        &creator,
        vec![
            GroupActionV1::ModifyInviteLink {
                password: Some(password.clone()),
            },
            GroupActionV1::ModifyAccess {
                access: GroupAccessV1 {
                    add_from_invite_link: AccessRequired::Any,
                    ..GroupAccessV1::DEFAULT
                },
            },
        ],
    );
    apply(&mut group, &open);

    let joiner = GroupKeyPair::generate();
    let wrong = forced(
        &group,
        &joiner,
        vec![GroupActionV1::JoinFromLink {
            password: encode(&[5u8; 16]),
            entry: sealed_entry(&group.master, &joiner.public_key()),
        }],
    );
    assert_eq!(refused(&group, &wrong), GroupChangeError::WrongPassword);
    let join = author(
        &group,
        &joiner,
        vec![GroupActionV1::JoinFromLink {
            password: password.clone(),
            entry: sealed_entry(&group.master, &joiner.public_key()),
        }],
    );
    apply(&mut group, &join);
    assert!(group.state.member(&encode(&joiner.public_key())).is_some());

    // Banned with the link reset: removed, and can't come back as that pseudonym.
    let ban = author(
        &group,
        &creator,
        vec![
            GroupActionV1::Ban {
                pseudonym: encode(&joiner.public_key()),
            },
            GroupActionV1::ModifyInviteLink {
                password: Some(encode(&[6u8; 16])),
            },
        ],
    );
    apply(&mut group, &ban);
    assert!(group.state.member(&encode(&joiner.public_key())).is_none());
    let back = forced(
        &group,
        &joiner,
        vec![GroupActionV1::JoinFromLink {
            password: encode(&[6u8; 16]),
            entry: sealed_entry(&group.master, &joiner.public_key()),
        }],
    );
    assert_eq!(refused(&group, &back), GroupChangeError::Banned);
}

#[test]
fn the_chain_and_the_named_state_are_checked() {
    let creator = GroupKeyPair::generate();
    let mut group = create(&creator);
    let bob = GroupKeyPair::generate();
    add(&mut group, &creator, &bob, GroupRole::Member);
    let change = author(
        &group,
        &creator,
        vec![GroupActionV1::ModifyAnnouncementsOnly { on: true }],
    );

    let mut wrong_previous = change.clone();
    wrong_previous.previous_hash = encode(&[1u8; 32]);
    wrong_previous.signature =
        encode(&creator.sign_change(&wrong_previous.signed_bytes().unwrap()));
    assert_eq!(
        refused(&group, &wrong_previous),
        GroupChangeError::WrongPrevious
    );

    let mut wrong_state = change.clone();
    wrong_state.resulting_state_hash = encode(&[1u8; 32]);
    wrong_state.signature = encode(&creator.sign_change(&wrong_state.signed_bytes().unwrap()));
    assert_eq!(
        refused(&group, &wrong_state),
        GroupChangeError::StateMismatch
    );

    // Signed by someone else than its actor.
    let mut forged = change.clone();
    forged.signature = encode(&bob.sign_change(&forged.signed_bytes().unwrap()));
    assert_eq!(refused(&group, &forged), GroupChangeError::BadSignature);

    // A stranger's change, even well signed.
    let stranger = GroupKeyPair::generate();
    let theirs = forced(&group, &stranger, vec![GroupActionV1::Leave]);
    assert_eq!(refused(&group, &theirs), GroupChangeError::NotMember);

    apply(&mut group, &change);
    assert!(group.state.announcements_only);
    // The same change again is not the next revision.
    assert_eq!(refused(&group, &change), GroupChangeError::WrongRevision);
    let bytes = change.canonical_bytes().unwrap();
    assert_eq!(GroupChangeV1::from_canonical_bytes(&bytes).unwrap(), change);
}

#[test]
fn an_ended_group_takes_no_change() {
    let creator = GroupKeyPair::generate();
    let mut group = create(&creator);
    let end = author(&group, &creator, vec![GroupActionV1::Terminate]);
    apply(&mut group, &end);
    let after = forced(
        &group,
        &creator,
        vec![GroupActionV1::ModifyAnnouncementsOnly { on: true }],
    );
    assert_eq!(refused(&group, &after), GroupChangeError::Terminated);
}

#[test]
fn a_newcomers_change_carries_one_action() {
    let creator = GroupKeyPair::generate();
    let group = create(&creator);
    let joiner = GroupKeyPair::generate();
    let change = GroupChangeV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: group.state.group_id.clone(),
        revision: 1,
        previous_hash: encode(&group.head),
        actor: encode(&joiner.public_key()),
        actions: vec![GroupActionV1::CancelRequest, GroupActionV1::Leave],
        resulting_state_hash: encode(&[0u8; 32]),
        signature: encode(&[0u8; 64]),
    };
    assert!(matches!(
        refused(&group, &change),
        GroupChangeError::Malformed(_)
    ));
}
