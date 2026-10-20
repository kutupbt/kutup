use ed25519_dalek::SigningKey;
use kutup_chat_proto::group::{
    check_change, check_genesis, GroupActionV1, GroupAttribute, GroupChangeV1, GroupLimits,
    GroupRole, GroupStateV1,
};
use kutup_chat_proto::group_route::{GroupGatewayKeyConfigV1, GroupHomePinV1, GroupNotaryV1};
use kutup_crypto::account_ref::AccountRef;
use kutup_federation_proto::FederationIdentityDocumentV1;

use super::*;

/// Who the tests' invitations come from.
const INVITER: &str = "aci:00000000-0000-4000-8000-2bd806c97f0e@home.example";

/// The group's home, as far as these tests need one: it runs the shared
/// check and notarises what it accepts.
struct Home {
    identity: FederationIdentityDocumentV1,
    key: SigningKey,
    config: GroupGatewayKeyConfigV1,
    state: Option<GroupStateV1>,
    head: [u8; 32],
    /// Every state the home held, by revision, to serve stale ones.
    states: Vec<(GroupStateV1, GroupChangeV1, GroupNotaryV1)>,
}

impl Home {
    fn new() -> Self {
        Self::with_key(1, "home.example")
    }

    fn with_key(byte: u8, server: &str) -> Self {
        let key = SigningKey::from_bytes(&[byte; 32]);
        let identity = FederationIdentityDocumentV1::genesis(server, 10, &key).unwrap();
        let config = GroupGatewayKeyConfigV1::sign(
            &identity,
            &key,
            1,
            &[9u8; kutup_crypto::oblivious::PUBLIC_KEY_LEN],
            100,
            200,
        )
        .unwrap();
        Self {
            identity,
            key,
            config,
            state: None,
            head: [0u8; 32],
            states: Vec::new(),
        }
    }

    fn pin(&self) -> GroupHomePinV1 {
        GroupHomePinV1::of(&self.identity).unwrap()
    }

    fn history(&self) -> Vec<FederationIdentityDocumentV1> {
        vec![self.identity.clone()]
    }

    fn accept(&mut self, change: &GroupChangeV1) -> Result<GroupNotaryV1, GroupChangeError> {
        let next = match &self.state {
            None => check_genesis(change, &self.pin(), &GroupLimits::MAX)?,
            Some(state) => check_change(state, &self.head, change, &GroupLimits::MAX)?,
        };
        let change_hash = change.hash().unwrap();
        let group = decode_group_id(&change.group_id).unwrap();
        let notary = GroupNotaryV1::sign(
            &self.identity,
            &self.key,
            &self.config,
            &group,
            change.revision,
            &change_hash,
            &next.hash().unwrap(),
        )
        .unwrap();
        self.states
            .push((next.clone(), change.clone(), notary.clone()));
        self.state = Some(next);
        self.head = change_hash;
        Ok(notary)
    }

    fn join_basis(&self) -> ClaimBasis {
        ClaimBasis {
            revision: self.state.as_ref().unwrap().revision,
            head: self.head,
        }
    }
}

/// A person: their account, the group keys its master key gives (the
/// self-authority that binds, the pseudonyms) and their profile key.
struct Person {
    account: AccountRef,
    keys: GroupAccountKeys,
    profile_key: [u8; 32],
}

impl Person {
    fn new(n: u8) -> Self {
        Self {
            account: AccountRef::new(
                "people.example",
                &format!("00000000-0000-4000-8000-0000000000{n:02}"),
            )
            .unwrap(),
            keys: GroupAccountKeys::derive(&[n; 32]).unwrap(),
            profile_key: [n; 32],
        }
    }
}

/// The self-authority of each of `people`'s verified manifests.
fn verifier<'a>(people: &'a [&'a Person]) -> impl Fn(&AccountRef) -> Option<[u8; 32]> + 'a {
    move |account| {
        people
            .iter()
            .find(|p| &p.account == account)
            .map(|person| person.keys.authority.public_key())
    }
}

fn created(home: &mut Home, alice: &Person) -> GroupRecordV1 {
    let (mut record, genesis) = create_group(NewGroup {
        home: home.pin(),
        me: &alice.account,
        profile_key: &alice.profile_key,
        keys: &alice.keys,
    })
    .unwrap();
    record.gateway.identity_history = home.history();
    let notary = home.accept(&genesis).unwrap();
    accept_change(&mut record, &genesis, &notary).unwrap();
    record
}

fn apply_at(home: &mut Home, record: &mut GroupRecordV1, change: &GroupChangeV1) {
    let notary = home.accept(change).unwrap();
    accept_change(record, change, &notary).unwrap();
}

/// Alice invites Bob; Bob claims from the join info, then takes the state.
fn invited(
    home: &mut Home,
    alice: &mut GroupRecordV1,
    bob: &Person,
    role: GroupRole,
) -> GroupRecordV1 {
    let (action, invitation, _) = invite(alice, &bob.account, role).unwrap();
    let add = author_change(alice, vec![action]).unwrap();
    apply_at(home, alice, &add);

    let mut record = record_from_invite(invitation, INVITER, None, None, &bob.keys).unwrap();
    record.gateway.identity_history = home.history();
    assert!(matches!(record.status, GroupStatus::Invited { .. }));
    let claim_change = claim(
        &mut record,
        &home.join_basis(),
        &bob.account,
        &bob.profile_key,
        &bob.keys.authority,
    )
    .unwrap();
    let notary = home.accept(&claim_change).unwrap();
    // Alice applies the claim with the notary (her own check, the home's state).
    accept_change(alice, &claim_change, &notary).unwrap();
    // Bob, now a member, takes the whole state once.
    let state = home.state.clone().unwrap();
    accept_state(&mut record, &state, &claim_change, &notary).unwrap();
    assert_eq!(record.status, GroupStatus::Member);
    record
}

#[test]
fn a_group_is_created_and_an_invitee_joins_with_verified_members() {
    let mut home = Home::new();
    let (alice, bob) = (Person::new(1), Person::new(2));
    let mut alice_record = created(&mut home, &alice);
    assert_eq!(alice_record.status, GroupStatus::Member);
    let bob_record = invited(&mut home, &mut alice_record, &bob, GroupRole::Member);

    for record in [&alice_record, &bob_record] {
        let members = members(record, &verifier(&[&alice, &bob])).unwrap();
        assert_eq!(members.len(), 2);
        let accounts: Vec<_> = members
            .iter()
            .map(|m| m.verified.as_ref().unwrap().account.clone())
            .collect();
        assert!(accounts.contains(&alice.account) && accounts.contains(&bob.account));
    }
    assert_eq!(alice_record.state, bob_record.state);
    assert_eq!(alice_record.head, bob_record.head);
    // The claim key went with the status, in the same record.
    assert!(claim_key_seed(&bob_record).is_err());
    assert_eq!(member_accounts(&alice_record).unwrap().len(), 2);
}

#[test]
fn a_binding_that_doesnt_verify_makes_the_member_unverified() {
    let mut home = Home::new();
    let (alice, bob) = (Person::new(1), Person::new(2));
    let mut alice_record = created(&mut home, &alice);
    let _ = invited(&mut home, &mut alice_record, &bob, GroupRole::Member);
    let members = members(&alice_record, &verifier(&[&alice])).unwrap();
    let bob_view = members
        .iter()
        .find(|m| m.verified.as_ref().map(|v| &v.account) != Some(&alice.account))
        .unwrap();
    assert!(bob_view.verified.is_none());
}

#[test]
fn a_binding_counts_only_under_the_accounts_own_authority() {
    let mut home = Home::new();
    let (alice, bob, mallory) = (Person::new(1), Person::new(2), Person::new(3));
    let mut alice_record = created(&mut home, &alice);
    let _ = invited(&mut home, &mut alice_record, &bob, GroupRole::Member);
    // Bob's manifest names his authority: verified, whatever his devices.
    let bobs = |record: &GroupRecordV1, authority: [u8; 32]| {
        let alices = alice.keys.authority.public_key();
        members(record, &|account: &AccountRef| {
            if *account == alice.account {
                Some(alices)
            } else if *account == bob.account {
                Some(authority)
            } else {
                None
            }
        })
        .unwrap()
        .into_iter()
        .filter(|member| member.verified.is_some())
        .count()
    };
    assert_eq!(bobs(&alice_record, bob.keys.authority.public_key()), 2);
    // Checked against any other key (another account's authority, or a
    // device's), his binding doesn't count.
    assert_eq!(bobs(&alice_record, mallory.keys.authority.public_key()), 1);
    let device = SigningKey::from_bytes(&[2u8; 32])
        .verifying_key()
        .to_bytes();
    assert_eq!(bobs(&alice_record, device), 1);
}

#[test]
fn a_rejoin_takes_the_next_join_epoch() {
    let mut home = Home::new();
    let (alice, bob) = (Person::new(1), Person::new(2));
    let alice_record = created(&mut home, &alice);
    let (_, invitation, _) = invite(&alice_record, &bob.account, GroupRole::Member).unwrap();
    let first = record_from_invite(invitation.clone(), INVITER, None, None, &bob.keys).unwrap();
    assert_eq!(first.join_epoch, 0);
    // An older invitation, never claimed: the same epoch.
    let mut newer = invitation.clone();
    newer.slot_revision += 1;
    let again = record_from_invite(newer.clone(), INVITER, Some(&first), None, &bob.keys).unwrap();
    assert_eq!(again.join_epoch, 0);
    assert_eq!(again.pseudonym_seed, first.pseudonym_seed);
    // After a membership ended, here or in the list: the next.
    let mut ended = first.clone();
    ended.status = GroupStatus::Gone;
    let rejoin = record_from_invite(newer.clone(), INVITER, Some(&ended), None, &bob.keys).unwrap();
    assert_eq!(rejoin.join_epoch, 1);
    assert_ne!(rejoin.pseudonym_seed, first.pseudonym_seed);
    let listed = record_from_invite(
        newer,
        INVITER,
        None,
        Some((GroupListStatus::Gone, 4)),
        &bob.keys,
    )
    .unwrap();
    assert_eq!(listed.join_epoch, 5);
    // A current membership there is another device's: its own epoch.
    let current = record_from_invite(
        invitation.clone(),
        INVITER,
        None,
        Some((GroupListStatus::Member, 4)),
        &bob.keys,
    )
    .unwrap();
    assert_eq!(current.join_epoch, 4);
    // Never past the last epoch recovery searches.
    let last = crate::group::MAX_JOIN_EPOCHS - 1;
    let at_last = record_from_invite(
        invitation.clone(),
        INVITER,
        None,
        Some((GroupListStatus::Gone, last - 1)),
        &bob.keys,
    )
    .unwrap();
    assert_eq!(at_last.join_epoch, last);
    assert!(record_from_invite(
        invitation,
        INVITER,
        None,
        Some((GroupListStatus::Gone, last)),
        &bob.keys
    )
    .is_err());
}

#[test]
fn a_rejoiner_takes_only_a_state_newer_than_the_one_it_kept() {
    let mut home = Home::new();
    let (alice, bob) = (Person::new(1), Person::new(2));
    let mut alice_record = created(&mut home, &alice);
    let bob_record = invited(&mut home, &mut alice_record, &bob, GroupRole::Member);
    let kept = home.states.last().unwrap().clone();
    // Bob is invited again (his membership ended): his record keeps the
    // state he verified.
    let (_, invitation, _) = invite(&alice_record, &bob.account, GroupRole::Member).unwrap();
    let mut ended = bob_record.clone();
    ended.status = GroupStatus::Gone;
    let rejoin = record_from_invite(invitation, INVITER, Some(&ended), None, &bob.keys).unwrap();
    // The state he kept, or an older one, is a rollback: refused.
    let (state, change, notary) = kept;
    assert_eq!(
        accept_state(&mut rejoin.clone(), &state, &change, &notary).unwrap_err(),
        GroupError::Change(GroupChangeError::WrongRevision)
    );
    let (state, change, notary) = home.states[0].clone();
    assert!(accept_state(&mut rejoin.clone(), &state, &change, &notary).is_err());
}

fn titled(record: &GroupRecordV1) -> GroupChangeV1 {
    let title = seal_attribute(record, GroupAttribute::Title, b"Kutup").unwrap();
    author_change(
        record,
        vec![GroupActionV1::ModifyAttribute {
            attribute: GroupAttribute::Title,
            value: Some(title),
        }],
    )
    .unwrap()
}

#[test]
fn a_change_without_the_homes_notary_is_not_applied() {
    let mut home = Home::new();
    let alice = Person::new(1);
    let mut record = created(&mut home, &alice);
    let change = titled(&record);
    // A notary by another identity (a relay's, say) is refused.
    let mut other = Home::with_key(2, "relay.example");
    other.state = home.state.clone();
    other.head = home.head;
    let forged = other.accept(&change).unwrap();
    let before = record.clone();
    assert_eq!(
        accept_change(&mut record, &change, &forged).unwrap_err(),
        GroupError::Notary
    );
    assert_eq!(record, before, "nothing applied");

    apply_at(&mut home, &mut record, &change);
    assert_eq!(
        attribute(&record, GroupAttribute::Title).unwrap().unwrap(),
        b"Kutup"
    );
}

#[test]
fn a_forged_identity_history_is_refused() {
    let mut home = Home::new();
    let alice = Person::new(1);
    let mut record = created(&mut home, &alice);
    let change = titled(&record);
    // A relay replaces the history with its own document for the same server
    // and notarises with it: it doesn't follow from the group's pin.
    let mut forger = Home::with_key(3, "home.example");
    forger.state = home.state.clone();
    forger.head = home.head;
    let forged = forger.accept(&change).unwrap();
    record.gateway.identity_history = forger.history();
    assert_eq!(
        accept_change(&mut record, &change, &forged).unwrap_err(),
        GroupError::Notary
    );
}

#[test]
fn a_joiner_takes_no_snapshot_older_than_its_claim_or_without_it() {
    let mut home = Home::new();
    let (alice, bob) = (Person::new(1), Person::new(2));
    let mut alice_record = created(&mut home, &alice);
    let (action, invitation, _) = invite(&alice_record, &bob.account, GroupRole::Member).unwrap();
    let add = author_change(&alice_record, vec![action]).unwrap();
    apply_at(&mut home, &mut alice_record, &add);
    let before_claim = home.states.last().unwrap().clone();

    let mut record = record_from_invite(invitation, INVITER, None, None, &bob.keys).unwrap();
    record.gateway.identity_history = home.history();
    let claim_change = claim(
        &mut record,
        &home.join_basis(),
        &bob.account,
        &bob.profile_key,
        &bob.keys.authority,
    )
    .unwrap();
    home.accept(&claim_change).unwrap();
    // The state from before the claim: older than the claim, and Bob isn't in it.
    let (state, change, notary) = before_claim;
    assert!(accept_state(&mut record.clone(), &state, &change, &notary).is_err());
    // A notarised state that Bob isn't a member of, even if new enough.
    let mut stranger = record.clone();
    stranger.pseudonym_seed = SecretText(encode(&[42u8; 32]));
    let (state, change, notary) = home.states.last().unwrap().clone();
    assert_eq!(
        accept_state(&mut stranger, &state, &change, &notary).unwrap_err(),
        GroupError::Change(GroupChangeError::NotMember)
    );
    accept_state(&mut record, &state, &change, &notary).unwrap();
}

#[test]
fn a_member_never_takes_a_whole_state_over_the_log() {
    let mut home = Home::new();
    let alice = Person::new(1);
    let mut record = created(&mut home, &alice);
    let (state, change, notary) = home.states.last().unwrap().clone();
    assert!(accept_state(&mut record, &state, &change, &notary).is_err());
}

#[test]
fn a_genesis_of_another_group_cant_start_this_one() {
    let mut home = Home::new();
    let alice = Person::new(1);
    let (_, theirs) = create_group(NewGroup {
        home: home.pin(),
        me: &alice.account,
        profile_key: &alice.profile_key,
        keys: &alice.keys,
    })
    .unwrap();
    let (mut mine, _) = create_group(NewGroup {
        home: home.pin(),
        me: &alice.account,
        profile_key: &alice.profile_key,
        keys: &alice.keys,
    })
    .unwrap();
    mine.gateway.identity_history = home.history();
    let notary = home.accept(&theirs).unwrap();
    assert!(accept_change(&mut mine, &theirs, &notary).is_err());
}

#[test]
fn an_invitation_whose_key_isnt_its_groups_is_refused() {
    let mut home = Home::new();
    let (alice, bob) = (Person::new(1), Person::new(2));
    let alice_record = created(&mut home, &alice);
    let (_, mut invitation, _) = invite(&alice_record, &bob.account, GroupRole::Member).unwrap();
    invitation.master_key = encode(&[9u8; 32]);
    assert!(record_from_invite(invitation, INVITER, None, None, &bob.keys).is_err());
}

#[test]
fn a_stored_record_is_never_replaced_by_an_older_or_forked_state() {
    let mut home = Home::new();
    let alice = Person::new(1);
    let mut record = created(&mut home, &alice);
    let at_zero = record.clone();
    let change = titled(&record);
    apply_at(&mut home, &mut record, &change);
    assert!(record.may_replace(&at_zero).is_ok());
    assert!(at_zero.may_replace(&record).is_err(), "older");
    // Another state at the same revision.
    let mut fork = record.clone();
    fork.head = Some(encode(&[7u8; 32]));
    assert!(fork.may_replace(&record).is_err(), "fork");
    assert!(record.may_replace(&record).is_ok(), "the same");
}

#[test]
fn a_message_context_is_compared_with_the_verified_state() {
    let mut home = Home::new();
    let alice = Person::new(1);
    let record = created(&mut home, &alice);
    let head: [u8; 32] = decode_exact::<32>("head", record.head.as_ref().unwrap()).unwrap();
    assert_eq!(
        compare_context(&record, 0, &head).unwrap(),
        ContextCheck::Current
    );
    assert_eq!(
        compare_context(&record, 1, &[0u8; 32]).unwrap(),
        ContextCheck::Behind
    );
    assert_eq!(
        compare_context(&record, 0, &[1u8; 32]).unwrap(),
        ContextCheck::Fork
    );
    let mut later = record.clone();
    apply_at(&mut home, &mut later, &titled(&record));
    assert_eq!(
        compare_context(&later, 0, &head).unwrap(),
        ContextCheck::SenderBehind
    );
}

#[test]
fn secrets_never_print() {
    let mut home = Home::new();
    let (alice, bob) = (Person::new(1), Person::new(2));
    let record = created(&mut home, &alice);
    let printed = format!("{record:?}");
    assert!(!printed.contains(&record.master_key.0));
    assert!(!printed.contains(&record.pseudonym_seed.0));
    let (_, invitation, _) = invite(&record, &bob.account, GroupRole::Member).unwrap();
    let printed = format!("{invitation:?}");
    assert!(!printed.contains(&invitation.claim_key_seed));
    assert!(!printed.contains(&invitation.master_key));
}

fn device(account: &str, device_id: u32, registration_id: u32) -> BookDevice {
    BookDevice {
        account: account.into(),
        device_id,
        registration_id,
    }
}

#[test]
fn a_sender_key_rotates_on_a_removal_a_departed_device_a_new_registration_or_age() {
    let now = 1_000_000;
    let mut book = SenderBook::new(now);
    let current = vec![device("a", 1, 10), device("b", 1, 20), device("b", 2, 21)];
    // A new key reaches every current device.
    assert_eq!(book.missing(&current, now), current);
    book.devices = current.clone();
    assert!(book.missing(&current, now).is_empty());
    assert!(!book.must_rotate(now + 1, &current));
    // A member's new device only needs the key; nothing rotates.
    let grown = [current.clone(), vec![device("c", 1, 30)]].concat();
    assert!(!book.must_rotate(now, &grown));
    assert_eq!(book.missing(&grown, now), vec![device("c", 1, 30)]);
    // Its key queued for its server: not handed out again within the hour.
    book.queued.push(QueuedKey {
        device: device("c", 1, 30),
        at_ms: now,
    });
    assert!(book.missing(&grown, now + 1).is_empty());
    assert_eq!(
        book.missing(&grown, now + QUEUED_KEY_WAIT_MS),
        vec![device("c", 1, 30)]
    );
    book.queued.clear();
    // A removed member, a device gone from a manifest, a reinstalled device.
    assert!(book.must_rotate(now, &[device("a", 1, 10)]));
    assert!(book.must_rotate(now, &[device("a", 1, 10), device("b", 1, 20)]));
    assert!(book.must_rotate(
        now,
        &[device("a", 1, 10), device("b", 1, 99), device("b", 2, 21)]
    ));
    // Ninety days.
    assert!(book.must_rotate(now + SENDER_KEY_MAX_AGE_MS, &current));
    // A new book has a new distribution id.
    assert_ne!(SenderBook::new(now).distribution_id, book.distribution_id);
}
