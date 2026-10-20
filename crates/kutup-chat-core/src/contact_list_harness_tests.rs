//! The account's Chat contact list end to end (docs/plans/chat-contacts-sync.md),
//! on the group harness's in-memory server: a device that lost everything
//! gets its accepts and blocks back before it takes any message.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::contact_list::{ChatContactEntryV1, ContactEntryControlV1};
use kutup_chat_proto::{ChatContent, ContactState};
use kutup_crypto::chat_contact_list::{self, ContactListKey};

use futures_executor::block_on;

use crate::group_harness_tests::{befriend, rng, Person, World, ISSUED_AT};

/// `from` writes a direct text to `to`.
fn say(from: &mut Person, to: &Person, text: &str) {
    let send_id = uuid::Uuid::new_v4().to_string();
    let seq = block_on(from.engine.session().next_sent_seq()).unwrap();
    let content = ChatContent::text_with_id(&send_id, ISSUED_AT, seq, text);
    block_on(
        from.engine
            .send(&send_id, &to.account, &content, &mut rng()),
    )
    .unwrap();
}

fn state_of(person: &Person, peer: &Person) -> Option<ContactState> {
    block_on(person.engine.session().contact(&peer.account))
        .unwrap()
        .map(|contact| contact.state)
}

fn block(person: &mut Person, peer: &Person) {
    let key = person.wrapping_key;
    block_on(
        person
            .engine
            .block_contact(&peer.account, &key, ISSUED_AT, &mut rng()),
    )
    .unwrap();
}

/// The person's account key and binding, as the harness hands them over.
fn list_key(person: &Person) -> (ContactListKey, String) {
    let seed = person.authority_seed;
    (
        ContactListKey::derive(&[seed; 32]),
        format!("{seed:08x}-0000-4000-8000-{seed:012x}"),
    )
}

/// What the account's contact list holds now, opened.
fn listed(world: &World, person: &Person) -> Vec<(u64, ChatContactEntryV1)> {
    let (key, binding) = list_key(person);
    world
        .contact_lists
        .borrow()
        .get(&person.account)
        .map(|entries| {
            entries
                .iter()
                .map(|(id, (revision, envelope))| {
                    let id = chat_contact_list::decode_entry_id(id).unwrap();
                    let opened = key
                        .open(&binding, &id, &STANDARD.decode(envelope).unwrap())
                        .unwrap();
                    assert_eq!(opened.revision, *revision);
                    (
                        *revision,
                        ChatContactEntryV1::from_bytes(&opened.plain).unwrap(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn listed_about(
    world: &World,
    person: &Person,
    peer: &Person,
) -> Option<(u64, ChatContactEntryV1)> {
    listed(world, person)
        .into_iter()
        .find(|(_, entry)| entry.account.to_string() == peer.account)
}

fn flush(person: &mut Person) -> crate::contact_list::ContactListFlush {
    block_on(person.engine.flush_contact_list(true)).unwrap()
}

#[test]
fn contacts_a_device_that_lost_everything_gets_its_accepts_and_blocks_back() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let mut carol = world.person(0xc3);
    // Alice wrote first, so Bob's reply accepted him on her side (the
    // implicit change is written too, or he'd restore as pending for good).
    befriend(&mut alice, &mut bob);
    say(&mut carol, &alice, "hi, it's carol");
    alice.receive();
    block(&mut alice, &carol);
    // The block went into the list at once (as on the web).
    assert_eq!(
        listed_about(&world, &alice, &carol).map(|(_, entry)| entry.state),
        Some(ContactState::Blocked)
    );
    flush(&mut alice);
    let bob_entry = listed_about(&world, &alice, &bob).unwrap().1;
    assert_eq!(bob_entry.state, ContactState::Accepted);
    assert!(
        bob_entry.profile_key.is_some(),
        "the profile key goes with it"
    );

    // Every device lost: a new one starts clean, reads the list before its
    // mailbox, and has both back, with Bob's profile key.
    let mut alice2 = world.link_device(&alice);
    drop(alice);
    assert!(block_on(alice2.engine.session().contacts())
        .unwrap()
        .is_empty());
    alice2.receive();
    assert_eq!(state_of(&alice2, &bob), Some(ContactState::Accepted));
    assert_eq!(state_of(&alice2, &carol), Some(ContactState::Blocked));
    assert!(block_on(alice2.engine.session().peer_profile(&bob.account))
        .unwrap()
        .is_some());
}

#[test]
fn contacts_the_mailbox_waits_for_the_list_so_a_blocked_person_is_never_taken() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut carol = world.person(0xc3);
    say(&mut carol, &alice, "first");
    alice.receive();
    block(&mut alice, &carol);
    let mut alice2 = world.link_device(&alice);
    drop(alice);
    // Carol writes again; the clean device can't read the list yet.
    say(&mut carol, &alice2, "let me in");
    world.contact_list_down.set(true);
    assert!(block_on(alice2.engine.receive(&mut rng())).is_err());
    assert!(
        !world.mailbox(&alice2.account, alice2.device()).is_empty(),
        "nothing was taken"
    );
    assert!(block_on(alice2.engine.session().history())
        .unwrap()
        .is_empty());
    // Once it can, Carol is blocked before her message is looked at.
    world.contact_list_down.set(false);
    alice2.receive();
    assert_eq!(state_of(&alice2, &carol), Some(ContactState::Blocked));
    assert!(block_on(alice2.engine.session().history())
        .unwrap()
        .iter()
        .all(|message| message.peer != carol.account));
}

#[test]
fn contacts_a_block_wins_a_tie_with_an_accept_in_the_list_and_between_devices() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut alice2 = world.link_device(&alice);
    let mut carol = world.person(0xc3);
    say(&mut carol, &alice, "hello?");
    alice.receive();
    alice2.receive();
    // At the same revision: one device blocks (written at once), the other
    // accepts before hearing of it.
    block(&mut alice2, &carol);
    block_on(
        alice
            .engine
            .accept_contact(&carol.account, ISSUED_AT, &mut rng()),
    )
    .unwrap();
    let (block_order, accept_order) = (
        block_on(alice2.engine.session().contact(&carol.account))
            .unwrap()
            .unwrap(),
        block_on(alice.engine.session().contact(&carol.account))
            .unwrap()
            .unwrap(),
    );
    assert_eq!(block_order.revision, accept_order.revision);
    // The accepting device's write finds the block in the list and takes it.
    flush(&mut alice);
    assert_eq!(state_of(&alice, &carol), Some(ContactState::Blocked));
    assert_eq!(
        listed_about(&world, &alice, &carol).map(|(_, entry)| entry.state),
        Some(ContactState::Blocked)
    );
    // And the contact controls agree, whichever arrives where.
    alice.receive();
    alice2.receive();
    assert_eq!(state_of(&alice, &carol), Some(ContactState::Blocked));
    assert_eq!(state_of(&alice2, &carol), Some(ContactState::Blocked));
}

#[test]
fn contacts_a_new_profile_key_is_written_without_moving_the_control_order() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let mut carol = world.person(0xc3);
    befriend(&mut alice, &mut bob);
    flush(&mut alice);
    let (revision, before) = listed_about(&world, &alice, &bob).unwrap();
    // Bob blocks someone: his profile key rotates, and Alice gets the new one.
    say(&mut carol, &bob, "hi bob");
    bob.receive();
    block(&mut bob, &carol);
    alice.receive();
    let due = block_on(alice.engine.session().contact(&bob.account))
        .unwrap()
        .unwrap()
        .list_due_at_ms;
    assert!(due.is_some(), "the new key is due, lazily");
    flush(&mut alice);
    let (rewritten, after) = listed_about(&world, &alice, &bob).unwrap();
    assert_eq!(rewritten, revision + 1, "a new write revision");
    assert_eq!(after.control, before.control, "the same control order");
    assert_ne!(after.profile_key, before.profile_key);
}

#[test]
fn contacts_fields_of_a_later_version_survive_a_rewrite() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    befriend(&mut alice, &mut bob);
    flush(&mut alice);
    // A later version on another device added a nickname, at a newer order.
    let (revision, mut entry) = listed_about(&world, &alice, &bob).unwrap();
    entry.control = ContactEntryControlV1 {
        revision: entry.control.revision + 1,
        ..entry.control
    };
    entry
        .unknown
        .insert("nickname".into(), serde_json::json!({ "given": "Bobby" }));
    let (key, binding) = list_key(&alice);
    let id = key.entry_id(&entry.account);
    let sealed = key
        .seal(
            &binding,
            &id,
            revision + 1,
            &entry.canonical_bytes().unwrap(),
        )
        .unwrap();
    world
        .contact_lists
        .borrow_mut()
        .get_mut(&alice.account)
        .unwrap()
        .insert(
            chat_contact_list::encode_entry_id(&id),
            (revision + 1, STANDARD.encode(sealed)),
        );
    block_on(alice.engine.sync_contact_list()).unwrap();
    // This device knows nothing of nicknames; its block keeps it anyway.
    block(&mut alice, &bob);
    let (_, written) = listed_about(&world, &alice, &bob).unwrap();
    assert_eq!(written.state, ContactState::Blocked);
    assert_eq!(
        written.unknown.get("nickname"),
        Some(&serde_json::json!({ "given": "Bobby" }))
    );
}

#[test]
fn contacts_a_full_list_evicts_a_rejection_but_never_drops_a_block() {
    let world = World::new();
    world.contact_list_cap.set(2);
    let mut alice = world.person(0xa1);
    let mut carol = world.person(0xc3);
    let mut dave = world.person(0xd4);
    let mut erin = world.person(0xe5);
    let mut frank = world.person(0xf6);
    say(&mut carol, &alice, "hi");
    say(&mut dave, &alice, "hi");
    alice.receive();
    block(&mut alice, &carol);
    block_on(
        alice
            .engine
            .reject_contact(&dave.account, ISSUED_AT, &mut rng()),
    )
    .unwrap();
    flush(&mut alice);
    assert_eq!(listed(&world, &alice).len(), 2);
    // A third block: the rejection goes to make room.
    say(&mut erin, &alice, "hi");
    alice.receive();
    block(&mut alice, &erin);
    let states: Vec<ContactState> = listed(&world, &alice)
        .into_iter()
        .map(|(_, entry)| entry.state)
        .collect();
    assert_eq!(states, vec![ContactState::Blocked, ContactState::Blocked]);
    assert!(!alice.engine.contact_list_full());
    // A fourth: nothing may go. The block holds here, stays due, and the
    // person is told; nothing listed was dropped.
    say(&mut frank, &alice, "hi");
    alice.receive();
    block(&mut alice, &frank);
    assert_eq!(state_of(&alice, &frank), Some(ContactState::Blocked));
    assert!(alice.engine.contact_list_full());
    let frank_record = block_on(alice.engine.session().contact(&frank.account))
        .unwrap()
        .unwrap();
    assert!(frank_record.list_due_at_ms.is_some(), "still due");
    assert_eq!(listed(&world, &alice).len(), 2);
    assert_eq!(flush(&mut alice).refused_full, 1);
}

#[test]
fn contacts_a_first_meeting_reaches_the_pin_list_later_and_together() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let mut carol = world.person(0xc3);
    let (seed, binding) = (alice.authority_seed, list_key(&alice).1);
    alice
        .engine
        .enable_identity_pins(&[seed; 32], &binding)
        .unwrap();
    befriend(&mut alice, &mut bob);
    befriend(&mut alice, &mut carol);
    // Meeting Bob and Carol wrote nothing yet: the pins wait their delay.
    assert_eq!(world.pin_writes.get(), 0);
    assert_eq!(alice.engine.pins_due.len(), 2);
    // Kept with the device, so a reload doesn't lose them.
    let stored: std::collections::BTreeMap<String, i64> = serde_json::from_slice(
        &block_on(alice.engine.session().pins_due())
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(stored.len(), 2);
    // Both in one write (as before signing out).
    assert_eq!(block_on(alice.engine.flush_identity_pins(true)).unwrap(), 2);
    assert_eq!(world.pin_writes.get(), 1);
    assert!(alice.engine.pins_due.is_empty());
}

#[test]
fn contacts_an_older_entry_served_under_the_listed_revision_is_refused() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut carol = world.person(0xc3);
    say(&mut carol, &alice, "hi");
    alice.receive();
    // Accept (written), then block (written at once): two revisions.
    block_on(
        alice
            .engine
            .accept_contact(&carol.account, ISSUED_AT, &mut rng()),
    )
    .unwrap();
    flush(&mut alice);
    let id = world.contact_lists.borrow()[&alice.account]
        .keys()
        .next()
        .unwrap()
        .clone();
    let accepted = world.contact_lists.borrow()[&alice.account][&id].1.clone();
    block(&mut alice, &carol);
    let (listed_revision, _) = world.contact_lists.borrow()[&alice.account][&id].clone();
    // The server hands back the accept's envelope under the block's revision.
    world
        .contact_lists
        .borrow_mut()
        .get_mut(&alice.account)
        .unwrap()
        .insert(id.clone(), (listed_revision, accepted));
    let mut alice2 = world.link_device(&alice);
    assert!(block_on(alice2.engine.sync_contact_list()).is_err());
    // And a clean device holds its mailbox rather than take the old accept.
    assert!(block_on(alice2.engine.receive(&mut rng())).is_err());
    assert_eq!(state_of(&alice2, &carol), None);
}

#[test]
fn contacts_a_listed_entry_that_does_not_open_fails_the_read() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut carol = world.person(0xc3);
    say(&mut carol, &alice, "hi");
    alice.receive();
    block(&mut alice, &carol);
    let id = world.contact_lists.borrow()[&alice.account]
        .keys()
        .next()
        .unwrap()
        .clone();
    world
        .contact_lists
        .borrow_mut()
        .get_mut(&alice.account)
        .unwrap()
        .get_mut(&id)
        .unwrap()
        .1 = STANDARD.encode([0u8; chat_contact_list::SEALED_LEN]);
    let mut alice2 = world.link_device(&alice);
    assert!(block_on(alice2.engine.sync_contact_list()).is_err());
}

#[test]
fn contacts_an_entry_of_a_later_version_is_kept_as_it_is() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut carol = world.person(0xc3);
    say(&mut carol, &alice, "hi");
    alice.receive();
    block(&mut alice, &carol);
    // A later version rewrote Carol's entry in a shape this device can't read.
    let (key, binding) = list_key(&alice);
    let account: kutup_crypto::account_ref::AccountRef = carol.account.parse().unwrap();
    let id = key.entry_id(&account);
    let text = chat_contact_list::encode_entry_id(&id);
    let (revision, _) = world.contact_lists.borrow()[&alice.account][&text].clone();
    let plain =
        serde_json::to_vec(&serde_json::json!({ "version": 2, "anything": "new" })).unwrap();
    let sealed = key.seal(&binding, &id, revision + 1, &plain).unwrap();
    let envelope = STANDARD.encode(sealed);
    world
        .contact_lists
        .borrow_mut()
        .get_mut(&alice.account)
        .unwrap()
        .insert(text.clone(), (revision + 1, envelope.clone()));
    // Reading works; an unblock here leaves the later version's entry alone.
    block_on(alice.engine.sync_contact_list()).unwrap();
    block_on(
        alice
            .engine
            .unblock_contact(&carol.account, ISSUED_AT, &mut rng()),
    )
    .unwrap();
    flush(&mut alice);
    assert_eq!(
        world.contact_lists.borrow()[&alice.account][&text],
        (revision + 1, envelope)
    );
}

#[test]
fn contacts_the_mailbox_waits_until_the_list_was_followed_even_with_contacts_here() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut carol = world.person(0xc3);
    let dave = world.person(0xd4);
    say(&mut carol, &alice, "hi");
    alice.receive();
    block(&mut alice, &carol);
    let mut alice2 = world.link_device(&alice);
    drop(alice);
    // The new device writes to someone first: it has a contact now, but it
    // never followed the list, so its mailbox still waits for it.
    world.contact_list_down.set(true);
    say(&mut alice2, &dave, "hello dave");
    assert!(!block_on(alice2.engine.session().contacts())
        .unwrap()
        .is_empty());
    say(&mut carol, &alice2, "let me in");
    assert!(block_on(alice2.engine.receive(&mut rng())).is_err());
    world.contact_list_down.set(false);
    alice2.receive();
    assert_eq!(state_of(&alice2, &carol), Some(ContactState::Blocked));
    // Followed once: a later outage leaves its own contacts and takes mail.
    world.contact_list_down.set(true);
    alice2.receive();
}
