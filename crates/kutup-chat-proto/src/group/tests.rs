use kutup_crypto::chat_group::{GroupKeyPair, GroupMasterKey, SealedField, HASH_LEN};

use super::*;

const HOME: &str = "home.example";

fn home_pin() -> GroupHomePinV1 {
    GroupHomePinV1 {
        server: HOME.into(),
        identity_sequence: 1,
        identity_document_hash: "9".repeat(64),
    }
}

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
        resulting_state_hash: Some(encode(&[0u8; 32])),
        signature: String::new(),
    };
    if change.is_newcomers_change() {
        change.resulting_state_hash = None;
    }
    let next = resulting_state(&group.state, &group.head, &change, &GroupLimits::MAX)
        .expect("an honest author's change");
    sign(&mut change, actor, &next);
    change
}

fn sign(change: &mut GroupChangeV1, actor: &GroupKeyPair, next: &GroupStateV1) {
    if !change.is_newcomers_change() {
        change.resulting_state_hash = Some(encode(&next.hash().unwrap()));
    }
    change.signature = encode(&actor.sign_change(&change.signed_bytes().unwrap()));
}

fn apply(group: &mut Group, change: &GroupChangeV1) {
    group.state = check_change(&group.state, &group.head, change, &GroupLimits::MAX).unwrap();
    group.head = change.hash().unwrap();
}

fn create(creator: &GroupKeyPair) -> Group {
    let pin = home_pin();
    let master = GroupMasterKey::from_bytes(
        &[5u8; 32],
        kutup_crypto::chat_group::GroupHome {
            server: &pin.server,
            identity_sequence: pin.identity_sequence,
            identity_document_hash: &pin.identity_document_hash,
        },
    )
    .unwrap();
    let mut change = GroupChangeV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: encode_group_id(&master.group_id()),
        revision: 0,
        previous_hash: encode(&[0u8; 32]),
        actor: encode(&creator.public_key()),
        actions: vec![GroupActionV1::Genesis {
            home: home_pin(),
            access: GroupAccessV1::DEFAULT,
            entry: sealed_entry(&master, &creator.public_key()),
        }],
        resulting_state_hash: Some(encode(&[0u8; 32])),
        signature: String::new(),
    };
    let first = resulting_genesis_state(&change, &home_pin(), &GroupLimits::MAX).unwrap();
    sign(&mut change, creator, &first);
    let state = check_genesis(&change, &home_pin(), &GroupLimits::MAX).unwrap();
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
    let slot_revision = group
        .state
        .slots
        .iter()
        .find(|s| s.slot_id == slot_id)
        .map_or(0, |s| s.created_at_revision);
    let claim_signature =
        claim_key.sign_claim(&group_id, &slot, slot_revision, &member.public_key());
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
        resulting_state_hash: Some(encode(&group.state.hash().unwrap())),
        signature: String::new(),
    };
    if change.is_newcomers_change() {
        change.resulting_state_hash = None;
    }
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
            claim_signature: encode(&claim_key.sign_claim(&group_id, &slot, 1, &late.public_key())),
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
            avatar_hash: None,
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
            avatar_hash: None,
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
    wrong_state.resulting_state_hash = Some(encode(&[1u8; 32]));
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
        resulting_state_hash: None,
        signature: encode(&[0u8; 64]),
    };
    assert!(matches!(
        refused(&group, &change),
        GroupChangeError::Malformed(_)
    ));
}

fn admins(group: &Group) -> usize {
    group
        .state
        .members
        .iter()
        .filter(|m| m.role == GroupRole::Administrator)
        .count()
}

/// Admins A and B, member C.
fn three(a: &GroupKeyPair, b: &GroupKeyPair, c: &GroupKeyPair) -> Group {
    let mut group = create(a);
    add(&mut group, a, b, GroupRole::Administrator);
    add(&mut group, a, c, GroupRole::Member);
    assert_eq!(admins(&group), 2);
    group
}

#[test]
fn no_change_can_leave_the_group_without_an_administrator() {
    let (a, b, c) = (
        GroupKeyPair::generate(),
        GroupKeyPair::generate(),
        GroupKeyPair::generate(),
    );
    let group = three(&a, &b, &c);
    let pb = encode(&b.public_key());
    let pa = encode(&a.public_key());
    for actions in [
        // Leave, then act on the rights just given up.
        vec![
            GroupActionV1::Leave,
            GroupActionV1::ModifyRole {
                pseudonym: pb.clone(),
                role: GroupRole::Member,
            },
        ],
        vec![
            GroupActionV1::Leave,
            GroupActionV1::RemoveMember {
                pseudonym: pb.clone(),
            },
        ],
        // Demote both administrators in one change.
        vec![
            GroupActionV1::ModifyRole {
                pseudonym: pa.clone(),
                role: GroupRole::Member,
            },
            GroupActionV1::ModifyRole {
                pseudonym: pb.clone(),
                role: GroupRole::Member,
            },
        ],
    ] {
        let change = forced(&group, &a, actions);
        let error = refused(&group, &change);
        assert!(
            matches!(
                error,
                GroupChangeError::NotMember
                    | GroupChangeError::NotAllowed
                    | GroupChangeError::LastAdministrator
            ),
            "{error:?}"
        );
    }
    // Nothing runs after a leave, whatever it is.
    let after_leave = forced(
        &group,
        &a,
        vec![
            GroupActionV1::Leave,
            GroupActionV1::AddSlot {
                slot_id: encode(&[7u8; 16]),
                role: GroupRole::Administrator,
                claim_key: encode(&[8u8; 32]),
                entry: sealed_entry(&group.master, b"slot"),
            },
        ],
    );
    assert_eq!(refused(&group, &after_leave), GroupChangeError::NotMember);
    // Demoting oneself then demoting the other: refused on the second.
    let self_then_other = forced(
        &group,
        &a,
        vec![
            GroupActionV1::ModifyRole {
                pseudonym: pa,
                role: GroupRole::Member,
            },
            GroupActionV1::ModifyRole {
                pseudonym: pb,
                role: GroupRole::Member,
            },
        ],
    );
    assert_eq!(
        refused(&group, &self_then_other),
        GroupChangeError::NotAllowed
    );
}

#[test]
fn the_last_administrator_cannot_leave_pending_slots_behind() {
    let creator = GroupKeyPair::generate();
    let mut group = create(&creator);
    let slot = author(
        &group,
        &creator,
        vec![GroupActionV1::AddSlot {
            slot_id: encode(&[1u8; 16]),
            role: GroupRole::Member,
            claim_key: encode(&GroupKeyPair::generate().public_key()),
            entry: sealed_entry(&group.master, b"slot"),
        }],
    );
    apply(&mut group, &slot);
    let leave = forced(&group, &creator, vec![GroupActionV1::Leave]);
    assert_eq!(refused(&group, &leave), GroupChangeError::LastAdministrator);
    // Revoking the slot in the same change lets the last member go.
    let revoke_and_leave = author(
        &group,
        &creator,
        vec![
            GroupActionV1::RevokeSlot {
                slot_id: encode(&[1u8; 16]),
            },
            GroupActionV1::Leave,
        ],
    );
    apply(&mut group, &revoke_and_leave);
    assert!(group.state.members.is_empty());
}

#[test]
fn a_valid_claim_still_needs_the_pseudonyms_own_signature() {
    let creator = GroupKeyPair::generate();
    let mut group = create(&creator);
    let claim_key = GroupKeyPair::generate();
    let slot_id = encode(&[1u8; 16]);
    let add = author(
        &group,
        &creator,
        vec![GroupActionV1::AddSlot {
            slot_id: slot_id.clone(),
            role: GroupRole::Member,
            claim_key: encode(&claim_key.public_key()),
            entry: sealed_entry(&group.master, b"slot"),
        }],
    );
    apply(&mut group, &add);
    let invitee = GroupKeyPair::generate();
    let mut claim = claim_change(&group, &invitee, &claim_key, &slot_id);
    claim.signature = encode(&GroupKeyPair::generate().sign_change(&claim.signed_bytes().unwrap()));
    assert_eq!(refused(&group, &claim), GroupChangeError::BadSignature);
}

#[test]
fn a_removed_member_can_change_nothing() {
    let (a, b, c) = (
        GroupKeyPair::generate(),
        GroupKeyPair::generate(),
        GroupKeyPair::generate(),
    );
    let mut group = three(&a, &b, &c);
    let remove = author(
        &group,
        &a,
        vec![GroupActionV1::RemoveMember {
            pseudonym: encode(&b.public_key()),
        }],
    );
    apply(&mut group, &remove);
    let late = forced(
        &group,
        &b,
        vec![GroupActionV1::ModifyAnnouncementsOnly { on: true }],
    );
    assert_eq!(refused(&group, &late), GroupChangeError::NotMember);
}

#[test]
fn members_and_slots_together_stop_at_the_limit() {
    let creator = GroupKeyPair::generate();
    let mut group = create(&creator);
    let limits = GroupLimits {
        max_members: 3,
        max_requesting: 3,
    };
    let slots = |from: u8| -> Vec<GroupActionV1> {
        (from..from + 2)
            .map(|i| GroupActionV1::AddSlot {
                slot_id: encode(&[i; 16]),
                role: GroupRole::Member,
                claim_key: encode(&[i; 32]),
                entry: sealed_entry(&group.master, b"slot"),
            })
            .collect()
    };
    let two = author(&group, &creator, slots(1));
    group.state = check_change(&group.state, &group.head, &two, &limits).unwrap();
    group.head = two.hash().unwrap();
    // One member and two slots fill three places; a fourth is refused.
    let mut more = forced(&group, &creator, slots(10)[..1].to_vec());
    more.resulting_state_hash = Some(encode(&[0u8; 32]));
    more.signature = encode(&creator.sign_change(&more.signed_bytes().unwrap()));
    assert_eq!(
        check_change(&group.state, &group.head, &more, &limits).unwrap_err(),
        GroupChangeError::LimitReached
    );
    // A server can't promise more than the protocol's 256.
    let too_many = GroupLimits {
        max_members: MAX_GROUP_MEMBERS + 1,
        max_requesting: 1,
    };
    assert!(matches!(
        check_change(&group.state, &group.head, &more, &too_many).unwrap_err(),
        GroupChangeError::Malformed(_)
    ));
    let too_many_requests = GroupLimits {
        max_members: 1,
        max_requesting: MAX_GROUP_MEMBERS + 1,
    };
    assert!(matches!(
        check_change(&group.state, &group.head, &more, &too_many_requests).unwrap_err(),
        GroupChangeError::Malformed(_)
    ));
}

#[test]
fn oversized_sealed_attributes_are_refused() {
    let creator = GroupKeyPair::generate();
    let group = create(&creator);
    let key = group.master.state_key();
    for (attribute, field, plain_len) in [
        (
            GroupAttribute::Title,
            SealedField::Title,
            MAX_SEALED_TITLE_BYTES,
        ),
        (
            GroupAttribute::Description,
            SealedField::Description,
            MAX_SEALED_DESCRIPTION_BYTES,
        ),
    ] {
        let value = encode(&key.seal(field, b"", &vec![b'x'; plain_len]).unwrap());
        let change = forced(
            &group,
            &creator,
            vec![GroupActionV1::ModifyAttribute {
                attribute,
                value: Some(value),
                avatar_hash: None,
            }],
        );
        assert!(matches!(
            refused(&group, &change),
            GroupChangeError::Malformed(_)
        ));
    }
}

#[test]
fn a_claim_is_bound_to_its_slots_revision() {
    let creator = GroupKeyPair::generate();
    let mut group = create(&creator);
    let claim_key = GroupKeyPair::generate();
    let slot_id = encode(&[1u8; 16]);
    let add_slot = |group: &Group| {
        author(
            group,
            &creator,
            vec![GroupActionV1::AddSlot {
                slot_id: slot_id.clone(),
                role: GroupRole::Member,
                claim_key: encode(&claim_key.public_key()),
                entry: sealed_entry(&group.master, b"slot"),
            }],
        )
    };
    let first = add_slot(&group);
    apply(&mut group, &first);
    let invitee = GroupKeyPair::generate();
    let old_claim = claim_change(&group, &invitee, &claim_key, &slot_id);
    let GroupActionV1::Claim {
        claim_signature, ..
    } = old_claim.actions[0].clone()
    else {
        unreachable!()
    };
    // The slot is revoked and added again with the same id and key.
    let revoke = author(
        &group,
        &creator,
        vec![GroupActionV1::RevokeSlot {
            slot_id: slot_id.clone(),
        }],
    );
    apply(&mut group, &revoke);
    let again = add_slot(&group);
    apply(&mut group, &again);
    // The old claim signature doesn't take the new slot.
    let replay = forced(
        &group,
        &invitee,
        vec![GroupActionV1::Claim {
            slot_id,
            claim_signature,
            entry: sealed_entry(&group.master, &invitee.public_key()),
        }],
    );
    assert_eq!(refused(&group, &replay), GroupChangeError::BadSignature);
}

#[test]
fn a_newcomers_change_names_no_state_and_others_must() {
    let creator = GroupKeyPair::generate();
    let group = create(&creator);
    let joiner = GroupKeyPair::generate();
    let mut join = forced(
        &group,
        &joiner,
        vec![GroupActionV1::RequestToJoin {
            password: encode(&[1u8; 16]),
            entry: sealed_entry(&group.master, &joiner.public_key()),
        }],
    );
    join.resulting_state_hash = Some(encode(&[0u8; 32]));
    assert!(join.validate_shape().is_err());
    let mut member_change = forced(
        &group,
        &creator,
        vec![GroupActionV1::ModifyAnnouncementsOnly { on: true }],
    );
    member_change.resulting_state_hash = None;
    assert!(member_change.validate_shape().is_err());
}

#[test]
fn a_genesis_must_name_the_expected_home() {
    let creator = GroupKeyPair::generate();
    let pin = home_pin();
    let master = GroupMasterKey::from_bytes(
        &[5u8; 32],
        kutup_crypto::chat_group::GroupHome {
            server: &pin.server,
            identity_sequence: pin.identity_sequence,
            identity_document_hash: &pin.identity_document_hash,
        },
    )
    .unwrap();
    let mut change = GroupChangeV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: encode_group_id(&master.group_id()),
        revision: 0,
        previous_hash: encode(&[0u8; 32]),
        actor: encode(&creator.public_key()),
        actions: vec![GroupActionV1::Genesis {
            home: home_pin(),
            access: GroupAccessV1::DEFAULT,
            entry: sealed_entry(&master, &creator.public_key()),
        }],
        resulting_state_hash: Some(encode(&[0u8; 32])),
        signature: String::new(),
    };
    let first = resulting_genesis_state(&change, &home_pin(), &GroupLimits::MAX).unwrap();
    sign(&mut change, &creator, &first);
    let other = GroupHomePinV1 {
        identity_sequence: 2,
        ..home_pin()
    };
    assert_eq!(
        check_genesis(&change, &other, &GroupLimits::MAX).unwrap_err(),
        GroupChangeError::WrongGroup
    );
}

#[test]
fn a_group_context_rides_inside_content_and_never_prints_its_key() {
    let context = GroupContextV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: encode_group_id(&[5u8; 32]),
        master_key: encode(&[6u8; 32]),
        home: home_pin(),
        revision: 3,
        chain_hash: encode(&[7u8; 32]),
        recipient_pseudonym: None,
    };
    let content = crate::ChatContent::text_with_id(
        "00000000-0000-4000-8000-000000000001",
        "2026-10-18T10:00:00.000Z",
        1,
        "hi",
    )
    .with_group_context(&context);
    let back: crate::ChatContent =
        serde_json::from_slice(&serde_json::to_vec(&content).unwrap()).unwrap();
    assert_eq!(back.group_context().unwrap(), context);
    assert!(!format!("{context:?}").contains(&context.master_key));
    // A plain message has none.
    let plain = crate::ChatContent::text_with_id(
        "00000000-0000-4000-8000-000000000002",
        "2026-10-18T10:00:00.000Z",
        2,
        "hi",
    );
    assert!(plain.group_context().is_none());
}

#[test]
fn distribution_and_invite_kinds_read_back_only_when_valid() {
    use crate::content::SenderKeyDistributionBody;
    let body = SenderKeyDistributionBody {
        group_id: encode_group_id(&[5u8; 32]),
        distribution_id: "00000000-0000-4000-8000-000000000009".into(),
        message: encode(&[1u8; 80]),
    };
    let content = crate::ChatContent::sender_key_distribution_with_id(
        "00000000-0000-4000-8000-000000000003",
        "2026-10-18T10:00:00.000Z",
        1,
        &body,
    );
    assert_eq!(content.as_sender_key_distribution().unwrap(), body);
    let bad = SenderKeyDistributionBody {
        distribution_id: "not-a-uuid".into(),
        ..body.clone()
    };
    let content = crate::ChatContent::sender_key_distribution_with_id(
        "00000000-0000-4000-8000-000000000004",
        "2026-10-18T10:00:00.000Z",
        2,
        &bad,
    );
    assert!(content.as_sender_key_distribution().is_none());
}

#[test]
fn an_invitation_a_context_and_a_list_entry_carry_only_a_canonical_home() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let b64 = |len: usize| STANDARD.encode(vec![7u8; len]);
    let invite = |home: GroupHomePinV1| GroupInviteV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: crate::group_route::encode_group_id(&[7; 32]),
        master_key: b64(kutup_crypto::chat_group::MASTER_KEY_LEN),
        home,
        slot_id: b64(kutup_crypto::chat_group::SLOT_ID_LEN),
        slot_revision: 1,
        claim_key_seed: b64(32),
        title: None,
    };
    let context = |home: GroupHomePinV1| GroupContextV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: crate::group_route::encode_group_id(&[7; 32]),
        master_key: b64(kutup_crypto::chat_group::MASTER_KEY_LEN),
        home,
        revision: 1,
        chain_hash: b64(32),
        recipient_pseudonym: None,
    };
    let entry = |home: GroupHomePinV1| GroupListEntryV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: crate::group_route::encode_group_id(&[7; 32]),
        master_key: b64(kutup_crypto::chat_group::MASTER_KEY_LEN),
        home,
        join_epoch: 0,
        status: GroupListStatus::Member,
        verified_revision: 1,
        chain_hash: b64(32),
    };
    assert!(invite(home_pin()).validate().is_ok());
    assert!(context(home_pin()).validate().is_ok());
    assert!(entry(home_pin()).validate().is_ok());
    let other_spellings = [
        GroupHomePinV1 {
            server: "Home.Example".into(),
            ..home_pin()
        },
        GroupHomePinV1 {
            server: "home.example.".into(),
            ..home_pin()
        },
        GroupHomePinV1 {
            identity_document_hash: "A".repeat(64),
            ..home_pin()
        },
        GroupHomePinV1 {
            identity_document_hash: "9".repeat(63),
            ..home_pin()
        },
    ];
    for home in other_spellings {
        assert!(invite(home.clone()).validate().is_err(), "{home:?}");
        assert!(context(home.clone()).validate().is_err(), "{home:?}");
        assert!(entry(home.clone()).validate().is_err(), "{home:?}");
    }
}

#[test]
fn an_avatar_and_its_clear_hash_come_together() {
    let hash = Some(encode(&[9u8; 32]));
    let sealed = Some(encode(&[1u8; 64]));
    assert!(check_avatar_hash(GroupAttribute::Avatar, &sealed, &hash).is_ok());
    assert!(check_avatar_hash(GroupAttribute::Avatar, &None, &None).is_ok());
    // One without the other, a hash of another length, a hash on the title.
    assert!(check_avatar_hash(GroupAttribute::Avatar, &sealed, &None).is_err());
    assert!(check_avatar_hash(GroupAttribute::Avatar, &None, &hash).is_err());
    assert!(check_avatar_hash(GroupAttribute::Avatar, &sealed, &Some(encode(&[9u8; 31]))).is_err());
    assert!(check_avatar_hash(GroupAttribute::Title, &sealed, &hash).is_err());
    assert!(check_avatar_hash(GroupAttribute::Title, &sealed, &None).is_ok());
}

#[test]
fn a_ban_list_stays_sorted_and_canonical() {
    use super::entry::GroupBanListV1;
    use kutup_crypto::account_ref::AccountRef;
    let account = |id: &str| AccountRef::new("home.example", id).unwrap();
    let pseudonym = |byte: u8| super::encode(&[byte; 32]);
    let mut list = GroupBanListV1 {
        version: super::GROUP_FORMAT_VERSION,
        banned: Vec::new(),
    };
    let b = account("00000000-0000-4000-8000-00000000000b");
    let a = account("00000000-0000-4000-8000-00000000000a");
    list.ban(&b, Some(&pseudonym(9)));
    list.ban(&a, None);
    list.ban(&b, Some(&pseudonym(3)));
    list.ban(&b, Some(&pseudonym(9)));
    assert_eq!(list.banned[0].account, a);
    assert_eq!(
        list.get(&b).unwrap().pseudonyms,
        vec![pseudonym(3), pseudonym(9)]
    );
    let bytes = list.canonical_bytes().unwrap();
    assert_eq!(GroupBanListV1::from_canonical_bytes(&bytes).unwrap(), list);
    // 150 accounts with a pseudonym each fit the sealed cap.
    let mut full = GroupBanListV1 {
        version: super::GROUP_FORMAT_VERSION,
        banned: Vec::new(),
    };
    for i in 0..150u32 {
        full.ban(
            &account(&format!("00000000-0000-4000-8000-{i:012x}")),
            Some(&pseudonym(i as u8)),
        );
    }
    assert!(
        kutup_crypto::chat_group::sealed_len(full.canonical_bytes().unwrap().len())
            <= super::MAX_SEALED_BAN_LIST_BYTES
    );
    let removed = list.unban(&b).unwrap();
    assert_eq!(removed.pseudonyms.len(), 2);
    assert!(list.get(&b).is_none());
    // Out of order: refused.
    let mut unsorted = list.clone();
    unsorted.ban(&b, None);
    unsorted.banned.swap(0, 1);
    assert!(unsorted.canonical_bytes().is_err());
}

#[test]
fn an_avatar_attribute_fits_its_sealed_cap_and_names_an_image_type() {
    use super::entry::GroupAvatarV1;
    let avatar = GroupAvatarV1 {
        version: super::GROUP_FORMAT_VERSION,
        key: super::encode(&[9u8; 32]),
        content_type: "image/webp".into(),
    };
    let bytes = avatar.canonical_bytes().unwrap();
    assert!(kutup_crypto::chat_group::sealed_len(bytes.len()) <= super::MAX_SEALED_AVATAR_BYTES);
    assert_eq!(GroupAvatarV1::from_canonical_bytes(&bytes).unwrap(), avatar);
    assert!(!format!("{avatar:?}").contains(&avatar.key));
    let gif = GroupAvatarV1 {
        content_type: "image/gif".into(),
        ..avatar
    };
    assert!(gif.canonical_bytes().is_err());
}
