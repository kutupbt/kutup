use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
use kutup_chat_proto::group::{
    check_change, check_genesis, GroupActionV1, GroupAttribute, GroupChangeV1, GroupLimits,
    GroupRole, GroupStateV1,
};
use kutup_chat_proto::group_route::{GroupGatewayKeyConfigV1, GroupHomePinV1, GroupNotaryV1};
use kutup_crypto::account_ref::AccountRef;
use kutup_federation_proto::FederationIdentityDocumentV1;

use super::*;

/// The group's home, as far as these tests need one: it runs the shared
/// check and notarises what it accepts.
struct Home {
    identity: FederationIdentityDocumentV1,
    key: SigningKey,
    config: GroupGatewayKeyConfigV1,
    state: Option<GroupStateV1>,
    head: [u8; 32],
}

impl Home {
    fn new() -> Self {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let identity = FederationIdentityDocumentV1::genesis("home.example", 10, &key).unwrap();
        let config =
            GroupGatewayKeyConfigV1::sign(&identity, &key, 1, &[9u8; 32], 100, 200).unwrap();
        Self {
            identity,
            key,
            config,
            state: None,
            head: [0u8; 32],
        }
    }

    fn pin(&self) -> GroupHomePinV1 {
        GroupHomePinV1::of(&self.identity).unwrap()
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

/// A person with one device whose Ed25519 key stands in for the libsignal
/// identity key (the binding's signature scheme is the session's).
struct Person {
    account: AccountRef,
    device: SigningKey,
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
            device: SigningKey::from_bytes(&[n; 32]),
            profile_key: [n; 32],
        }
    }

    fn sign(&self) -> impl Fn(&[u8]) -> Result<Vec<u8>, String> + '_ {
        move |bytes| Ok(self.device.sign(bytes).to_bytes().to_vec())
    }
}

fn verifier<'a>(people: &'a [&'a Person]) -> impl Fn(&AccountRef, u32, &[u8], &[u8]) -> bool + 'a {
    move |account, device_id, bytes, signature| {
        let Some(person) = people.iter().find(|p| &p.account == account) else {
            return false;
        };
        let Ok(signature) = ed25519_dalek::Signature::from_slice(signature) else {
            return false;
        };
        device_id == 1
            && person
                .device
                .verifying_key()
                .verify(bytes, &signature)
                .is_ok()
    }
}

fn created(home: &mut Home, alice: &Person) -> GroupRecordV1 {
    let sign = alice.sign();
    let (mut record, genesis) = create_group(NewGroup {
        home: home.pin(),
        me: &alice.account,
        device_id: 1,
        profile_key: &alice.profile_key,
        sign_binding: &sign,
    })
    .unwrap();
    let notary = home.accept(&genesis).unwrap();
    accept_change(
        &mut record,
        &genesis,
        &notary,
        std::slice::from_ref(&home.identity),
    )
    .unwrap();
    record
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
    let notary = home.accept(&add).unwrap();
    accept_change(alice, &add, &notary, std::slice::from_ref(&home.identity)).unwrap();

    let sign = bob.sign();
    let (mut record, claim_change) = claim(
        &invitation,
        &home.join_basis(),
        &bob.account,
        1,
        &bob.profile_key,
        &sign,
    )
    .unwrap();
    assert!(matches!(record.status, GroupStatus::Invited { .. }));
    let notary = home.accept(&claim_change).unwrap();
    // Alice applies the claim with the notary (her own check, the home's state).
    accept_change(
        alice,
        &claim_change,
        &notary,
        std::slice::from_ref(&home.identity),
    )
    .unwrap();
    // Bob, now a member, takes the whole state once.
    let state = home.state.clone().unwrap();
    accept_state(
        &mut record,
        &state,
        &claim_change,
        &notary,
        std::slice::from_ref(&home.identity),
    )
    .unwrap();
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
    // Both devices hold the same verified state.
    assert_eq!(alice_record.state, bob_record.state);
    assert_eq!(alice_record.head, bob_record.head);
}

#[test]
fn a_binding_that_doesnt_verify_makes_the_member_unverified() {
    let mut home = Home::new();
    let (alice, bob) = (Person::new(1), Person::new(2));
    let mut alice_record = created(&mut home, &alice);
    let _ = invited(&mut home, &mut alice_record, &bob, GroupRole::Member);
    // A verifier that knows only Alice's manifest: Bob stays, unverified.
    let members = members(&alice_record, &verifier(&[&alice])).unwrap();
    let bob_view = members
        .iter()
        .find(|m| m.verified.as_ref().map(|v| &v.account) != Some(&alice.account))
        .unwrap();
    assert!(bob_view.verified.is_none());
}

#[test]
fn a_change_without_the_homes_notary_is_not_applied() {
    let mut home = Home::new();
    let alice = Person::new(1);
    let mut record = created(&mut home, &alice);
    let title = seal_attribute(&record, GroupAttribute::Title, b"Kutup").unwrap();
    let change = author_change(
        &record,
        vec![GroupActionV1::ModifyAttribute {
            attribute: GroupAttribute::Title,
            value: Some(title),
        }],
    )
    .unwrap();
    // A notary by another identity (a relay's, say) is refused.
    let other_key = SigningKey::from_bytes(&[2u8; 32]);
    let other = FederationIdentityDocumentV1::genesis("relay.example", 3, &other_key).unwrap();
    let group = decode_group_id(&record.group_id).unwrap();
    let other_config =
        GroupGatewayKeyConfigV1::sign(&other, &other_key, 1, &[9u8; 32], 100, 200).unwrap();
    let forged = GroupNotaryV1::sign(
        &other,
        &other_key,
        &other_config,
        &group,
        1,
        &change.hash().unwrap(),
        &[0u8; 32],
    )
    .unwrap();
    let before = record.clone();
    assert_eq!(
        accept_change(
            &mut record,
            &change,
            &forged,
            std::slice::from_ref(&home.identity)
        )
        .unwrap_err(),
        GroupError::Notary
    );
    assert_eq!(record, before, "nothing applied");

    let notary = home.accept(&change).unwrap();
    accept_change(
        &mut record,
        &change,
        &notary,
        std::slice::from_ref(&home.identity),
    )
    .unwrap();
    assert_eq!(
        attribute(&record, GroupAttribute::Title).unwrap().unwrap(),
        b"Kutup"
    );
}

#[test]
fn a_member_never_takes_a_whole_state_over_the_log() {
    let mut home = Home::new();
    let alice = Person::new(1);
    let mut record = created(&mut home, &alice);
    let state = home.state.clone().unwrap();
    // The genesis is the head; a whole state is refused once one is verified.
    let genesis_change = {
        let (_, change) = create_group(NewGroup {
            home: home.pin(),
            me: &alice.account,
            device_id: 1,
            profile_key: &alice.profile_key,
            sign_binding: &alice.sign(),
        })
        .unwrap();
        change
    };
    let notary = GroupNotaryV1 {
        identity_sequence: 10,
        key_config_hash: encode(&[0u8; 32]),
        signature: encode(&[0u8; 64]),
    };
    assert!(accept_state(
        &mut record,
        &state,
        &genesis_change,
        &notary,
        std::slice::from_ref(&home.identity)
    )
    .is_err());
}

#[test]
fn an_invitation_for_another_group_is_refused() {
    let mut home = Home::new();
    let (alice, bob) = (Person::new(1), Person::new(2));
    let alice_record = created(&mut home, &alice);
    let (_, mut invitation, _) = invite(&alice_record, &bob.account, GroupRole::Member).unwrap();
    // Another group's master key under this group's id.
    invitation.master_key = encode(&[9u8; 32]);
    let sign = bob.sign();
    assert!(claim(
        &invitation,
        &home.join_basis(),
        &bob.account,
        1,
        &bob.profile_key,
        &sign
    )
    .is_err());
}
