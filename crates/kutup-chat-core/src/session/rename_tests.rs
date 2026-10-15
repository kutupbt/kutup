//! A peer's rename followed on this device (docs/plans/username-renames.md):
//! its records move to the new address in one transaction, the ratchet
//! carries on there, history follows it to the new thread, and a restart
//! (or a second answer of the same chain) moves nothing twice.

use super::*;
use crate::db::{ContactRecord, InboxMessage};
use crate::renames::tests::{chains, identity, pinned};
use crate::SqliteChatDb;
use futures_executor::block_on;
use kutup_chat_proto::{DeliveredEnvelope, DevicePreKeyBundle, OutgoingEnvelope};
use rand::rngs::OsRng;
use rand::TryRngCore as _;

const OLD: &str = "ada_l@kutup.test";
const NEW: &str = "ada_lovelace@kutup.test";

fn generate(db: Rc<dyn ChatDb>, user: &str) -> Session {
    block_on(Session::generate(db, user, 1, 10, &mut OsRng.unwrap_err())).unwrap()
}

fn bundle(session: &Session) -> DevicePreKeyBundle {
    let reg = session.registration().unwrap();
    DevicePreKeyBundle {
        device_id: 1,
        registration_id: reg.registration_id,
        suite: reg.suite,
        identity_key: reg.identity_key.clone(),
        signed_pre_key: reg.signed_pre_key.clone(),
        kyber_pre_key: reg
            .one_time_kyber_pre_keys
            .first()
            .cloned()
            .unwrap_or_else(|| reg.last_resort_kyber_pre_key.clone()),
        one_time_pre_key: reg.one_time_pre_keys.first().cloned(),
    }
}

fn wrap(env: OutgoingEnvelope, sender: &str, cursor: u64) -> DeliveredEnvelope {
    DeliveredEnvelope {
        id: format!("m{cursor}"),
        cursor,
        sender: Some(sender.to_string()),
        sealed_sender: false,
        sender_device_id: 1,
        envelope_type: env.envelope_type,
        suite: env.suite,
        content: env.content,
        server_timestamp: "2026-10-15T10:00:00Z".into(),
        send_id: None,
    }
}

/// Ada (pinned at `OLD` on Bob's device, accepted, one message in) and Bob,
/// with a session each way.
struct Pair {
    ada: Session,
    bob: Session,
    bob_db: Rc<dyn ChatDb>,
    bob_registration: u32,
}

fn pair() -> Pair {
    let mut rng = OsRng.unwrap_err();
    let mut ada = generate(Rc::new(SqliteChatDb::open_in_memory().unwrap()), OLD);
    let bob_db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open_in_memory().unwrap());
    let mut bob = generate(Rc::clone(&bob_db), "bob@kutup.test");
    block_on(crate::timeline::ensure_built(&*bob_db)).unwrap();
    let bob_address = ChatAddress::from_sender("bob@kutup.test", 1).unwrap();
    let bob_registration = bob.registration().unwrap().registration_id;
    block_on(ada.establish(&bob_address, &bundle(&bob), &mut rng)).unwrap();
    let hello = ChatContent::text_with_id("m1", "2026-10-15T10:00:00Z", 1, "hello");
    let envelope = block_on(ada.encrypt(&bob_address, bob_registration, &hello, &mut rng)).unwrap();
    let from_ada = ChatAddress::from_sender(OLD, 1).unwrap();
    block_on(bob.decrypt(&from_ada, &wrap(envelope, OLD, 1), &mut rng)).unwrap();
    // What Bob keeps of Ada: her pin, her contact, a message in history.
    bob.store.stage_manifest_trust(pinned(&identity(1), OLD));
    bob.store.stage_contact(ContactRecord {
        peer: OLD.into(),
        state: ContactState::Accepted,
        previous_state: None,
        revision: 1,
        source_device_id: 1,
        updated_at_ms: 1,
        sync_pending: false,
        sync_send_id: None,
    });
    bob.store.stage_message(InboxMessage {
        id: "m1".into(),
        peer: OLD.into(),
        sender_device_id: 1,
        cursor: 1,
        content: serde_json::to_vec(&ChatContent::text_with_id(
            "m1",
            "2026-10-15T10:00:00Z",
            1,
            "hello",
        ))
        .unwrap(),
        received_at: 1,
    });
    block_on(bob.store.commit()).unwrap();
    Pair {
        ada,
        bob,
        bob_db,
        bob_registration,
    }
}

fn follow(bob: &mut Session) -> bool {
    let trust = block_on(bob.manifest_trust(OLD)).unwrap();
    let Some(trust) = trust else { return false };
    let found = crate::renames::select(&trust, &chains(&identity(1), &[OLD, NEW]))
        .unwrap()
        .unwrap();
    block_on(bob.move_peer(&found.from, &found.to, found.known, &[1])).unwrap()
}

fn conversations(db: &Rc<dyn ChatDb>) -> Vec<String> {
    block_on(crate::timeline::load_directory(&**db))
        .unwrap()
        .unwrap()
        .conversations
        .into_keys()
        .collect()
}

fn rename_lines(db: &Rc<dyn ChatDb>) -> usize {
    block_on(db.list_sent_messages())
        .unwrap()
        .iter()
        .filter(|m| {
            serde_json::from_slice::<ChatContent>(&m.content)
                .is_ok_and(|c| c.as_peer_renamed().is_some())
        })
        .count()
}

#[test]
fn a_followed_rename_moves_the_peer_and_the_ratchet_carries_on() {
    let Pair {
        mut ada,
        mut bob,
        bob_db,
        bob_registration,
    } = pair();
    assert!(follow(&mut bob));

    assert!(block_on(bob.manifest_trust(OLD)).unwrap().is_none());
    let moved = block_on(bob.manifest_trust(NEW)).unwrap().unwrap();
    assert_eq!(moved.peer, NEW);
    assert_eq!(moved.renames.as_ref().unwrap().sequence, 1);
    assert!(block_on(bob.contact(OLD)).unwrap().is_none());
    assert_eq!(
        block_on(bob.contact(NEW)).unwrap().unwrap().state,
        ContactState::Accepted
    );
    assert!(block_on(bob_db.load_session(&format!("{OLD}.1")))
        .unwrap()
        .is_none());
    assert!(block_on(bob_db.load_session(&format!("{NEW}.1")))
        .unwrap()
        .is_some());
    assert!(block_on(bob_db.load_identity(&format!("{OLD}.1")))
        .unwrap()
        .is_none());

    // The thread is the new address's, with its history and the line.
    assert_eq!(conversations(&bob_db), vec![format!("direct:{NEW}")]);
    assert_eq!(rename_lines(&bob_db), 1);

    // Ada's next message arrives from her new address and opens.
    let mut rng = OsRng.unwrap_err();
    let bob_address = ChatAddress::from_sender("bob@kutup.test", 1).unwrap();
    let next = ChatContent::text_with_id("m2", "2026-10-15T10:01:00Z", 2, "renamed");
    let envelope = block_on(ada.encrypt(&bob_address, bob_registration, &next, &mut rng)).unwrap();
    let from_new = ChatAddress::from_sender(NEW, 1).unwrap();
    let opened = block_on(bob.decrypt(&from_new, &wrap(envelope, NEW, 2), &mut rng)).unwrap();
    assert_eq!(opened.as_text().unwrap().text, "renamed");
}

#[test]
fn following_again_moves_nothing_and_writes_no_second_line() {
    let Pair {
        mut bob, bob_db, ..
    } = pair();
    assert!(follow(&mut bob));
    // A restart re-runs the follow with the same chain: nothing is left at
    // the old address.
    assert!(!follow(&mut bob));
    let trust = block_on(bob.manifest_trust(NEW)).unwrap().unwrap();
    assert_eq!(
        crate::renames::select(&trust, &chains(&identity(1), &[OLD, NEW])).unwrap(),
        None
    );
    assert_eq!(rename_lines(&bob_db), 1);
}

#[test]
fn a_move_that_fails_leaves_everything_where_it_was() {
    let Pair {
        mut bob, bob_db, ..
    } = pair();
    // Someone else is pinned at the new address: never merged.
    bob.store.stage_manifest_trust(pinned(&identity(2), NEW));
    block_on(bob.store.commit()).unwrap();
    let trust = block_on(bob.manifest_trust(OLD)).unwrap().unwrap();
    let found = crate::renames::select(&trust, &chains(&identity(1), &[OLD, NEW]))
        .unwrap()
        .unwrap();
    assert!(block_on(bob.move_peer(&found.from, &found.to, found.known, &[1])).is_err());
    assert!(block_on(bob.manifest_trust(OLD)).unwrap().is_some());
    assert!(block_on(bob_db.load_session(&format!("{OLD}.1")))
        .unwrap()
        .is_some());
    assert_eq!(
        block_on(bob.contact(OLD)).unwrap().unwrap().state,
        ContactState::Accepted
    );
    assert_eq!(rename_lines(&bob_db), 0);
    // Nothing staged survives into the next commit.
    assert!(bob.store.with_pending(|pending| pending.is_empty()));
}
