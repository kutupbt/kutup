//! The receive-orchestration proof: drain, decrypt, then persist the ratchet
//! advance, the plaintext, and the cursor atomically before acking; oldest-first,
//! resuming from the durable cursor. Message history survives a store reopen, and
//! a redelivered cursor (a WS/REST twin) is acked but never re-decrypted. Driven
//! through a mailbox mock whose futures are immediately ready, so `futures_executor`
//! polls them to completion.

use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;

use async_trait::async_trait;
use base64::Engine as _;
use futures_executor::block_on;
use kutup_chat_core::{
    ChatAddress, ChatContent, ChatTransport, ContactState, Engine, EngineState, InboundFailureKind,
    InboundState, Result, SendOutcome, Session, SqliteChatDb,
};
use kutup_chat_proto::{
    DeliveredEnvelope, DevicePreKeyBundle, MailboxPage, OutgoingEnvelope,
    RegisterChatDeviceRequest, SendMessagesRequest, UserPreKeyBundlesResponse,
};
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng, TryRngCore as _};

// ----- helpers -----

fn test_rng() -> impl Rng + CryptoRng {
    OsRng.unwrap_err()
}

fn in_memory<R: Rng + CryptoRng>(user: &str, device_id: u32, rng: &mut R) -> Session {
    block_on(Session::generate(
        Rc::new(SqliteChatDb::open_in_memory().unwrap()),
        user,
        device_id,
        10,
        rng,
    ))
    .unwrap()
}

fn serve_bundle(reg: &RegisterChatDeviceRequest, device_id: u32) -> DevicePreKeyBundle {
    DevicePreKeyBundle {
        device_id,
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

fn deliver(env: &OutgoingEnvelope, sender: &str, id: &str, cursor: u64) -> DeliveredEnvelope {
    DeliveredEnvelope {
        id: id.to_string(),
        cursor,
        sender: Some(sender.to_string()),
        sender_device_id: 1,
        envelope_type: env.envelope_type,
        suite: env.suite,
        content: env.content.clone(),
        server_timestamp: "2026-07-14T10:00:00Z".into(),
    }
}

/// A throwaway file-backed store (so it can be reopened), cleaned up on drop.
struct TempDb(std::path::PathBuf);
impl TempDb {
    fn new() -> Self {
        let n: u64 = test_rng().random();
        TempDb(std::env::temp_dir().join(format!("kutup-chat-recv-{n}.db")))
    }
    fn open(&self) -> Rc<SqliteChatDb> {
        Rc::new(SqliteChatDb::open(&self.0).unwrap())
    }
}
impl Drop for TempDb {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.0.display()));
        }
    }
}

// ----- the mailbox mock -----

/// A minimal server that only serves a device's mailbox: `drain` returns the
/// envelopes past `after` (oldest first, paged), `ack` deletes them. The send-side
/// methods are unused by the receive path.
#[derive(Default)]
struct Mailbox {
    inbox: RefCell<Vec<DeliveredEnvelope>>,
    acked: RefCell<Vec<String>>,
}

impl Mailbox {
    fn deposit(&self, envelopes: Vec<DeliveredEnvelope>) {
        *self.inbox.borrow_mut() = envelopes;
    }
    fn acked(&self) -> Vec<String> {
        self.acked.borrow().clone()
    }
}

#[async_trait(?Send)]
impl ChatTransport for Mailbox {
    async fn register_device(&self, _req: &RegisterChatDeviceRequest) -> Result<u32> {
        unreachable!("receive path does not register")
    }
    async fn fetch_bundles(
        &self,
        _username: &str,
        _transparency_tree_size: u64,
    ) -> Result<UserPreKeyBundlesResponse> {
        unreachable!("receive path does not fetch bundles")
    }
    async fn send(&self, _username: &str, _req: &SendMessagesRequest) -> Result<SendOutcome> {
        unreachable!("receive path does not send")
    }
    async fn drain(&self, _device_id: u32, after: Option<u64>, limit: u32) -> Result<MailboxPage> {
        let inbox = self.inbox.borrow();
        let mut items: Vec<DeliveredEnvelope> = inbox
            .iter()
            .filter(|e| after.is_none_or(|a| e.cursor > a))
            .cloned()
            .collect();
        items.sort_by_key(|e| e.cursor);
        let more = items.len() as u32 > limit;
        items.truncate(limit as usize);
        Ok(MailboxPage {
            envelopes: items,
            more,
        })
    }
    async fn ack(&self, _device_id: u32, ids: &[String]) -> Result<()> {
        let set: HashSet<&String> = ids.iter().collect();
        self.inbox.borrow_mut().retain(|e| !set.contains(&e.id));
        self.acked.borrow_mut().extend(ids.iter().cloned());
        Ok(())
    }
}

// ----- tests -----

#[test]
fn drains_decrypts_persists_and_acks_resuming_from_cursor() {
    let mut rng = test_rng();
    let bob_db = TempDb::new();

    // Alice encrypts two messages to Bob (as the server would have stored them).
    let bob_addr = ChatAddress::local("bob", 1);
    let (env1, env2) = {
        // Generate Bob's device into bob_db (keys persist there); the Session itself
        // is only needed to serve the bundle, then dropped.
        let mut bob = block_on(Session::generate(bob_db.open(), "bob", 1, 10, &mut rng)).unwrap();
        let bundle = serve_bundle(bob.registration().unwrap(), 1);
        block_on(bob.complete_registration(1)).unwrap();

        let mut alice = in_memory("alice", 1, &mut rng);
        block_on(alice.establish(&bob_addr, &bundle, &mut rng)).unwrap();
        let e1 = block_on(alice.encrypt(
            &bob_addr,
            bundle.registration_id,
            &ChatContent::text("t", 1, "first"),
            &mut rng,
        ))
        .unwrap();
        let e2 = block_on(alice.encrypt(
            &bob_addr,
            bundle.registration_id,
            &ChatContent::text("t", 2, "second"),
            &mut rng,
        ))
        .unwrap();
        (e1, e2)
    };

    let server = Rc::new(Mailbox::default());
    server.deposit(vec![
        deliver(&env1, "alice", "mbx-1", 1),
        deliver(&env2, "alice", "mbx-2", 2),
    ]);

    // Bob reopens his device and drains.
    let mut bob = block_on(Engine::open(bob_db.open(), server.clone(), "bob", 1)).unwrap();
    let report = block_on(bob.receive(&mut rng)).unwrap();

    assert_eq!(report.messages.len(), 2);
    assert_eq!(report.messages[0].content.as_text().unwrap().text, "first");
    assert_eq!(report.messages[1].content.as_text().unwrap().text, "second");
    assert_eq!(report.messages[0].from, ChatAddress::local("alice", 1));
    assert!(report.errors.is_empty() && report.undecodable.is_empty());
    assert_eq!(
        server.acked(),
        vec!["mbx-1", "mbx-2"],
        "both acked after persist"
    );

    // Draining again yields nothing — the cursor advanced past both.
    let again = block_on(bob.receive(&mut rng)).unwrap();
    assert!(again.messages.is_empty());
    drop(bob);

    // History (and the drain cursor) survive a reopen.
    let reopened = block_on(Session::open(bob_db.open(), "bob", 1)).unwrap();
    let history = block_on(reopened.history()).unwrap();
    assert_eq!(history.len(), 2);
    let texts: Vec<String> = history
        .iter()
        .map(|m| {
            serde_json::from_slice::<ChatContent>(&m.content)
                .unwrap()
                .as_text()
                .unwrap()
                .text
                .clone()
        })
        .collect();
    assert_eq!(texts, vec!["first", "second"]);
}

#[test]
fn dedups_a_redelivered_cursor() {
    let mut rng = test_rng();
    let bob_addr = ChatAddress::local("bob", 1);

    let bob_session = in_memory("bob", 1, &mut rng);
    let bundle = serve_bundle(bob_session.registration().unwrap(), 1);

    let mut alice = in_memory("alice", 1, &mut rng);
    block_on(alice.establish(&bob_addr, &bundle, &mut rng)).unwrap();
    let env = block_on(alice.encrypt(
        &bob_addr,
        bundle.registration_id,
        &ChatContent::text("t", 1, "once"),
        &mut rng,
    ))
    .unwrap();

    // The same message delivered twice (same cursor, different mailbox ids) — the
    // WS-twin case. The second copy must be acked but never re-decrypted (the
    // ratchet couldn't repeat it).
    let server = Rc::new(Mailbox::default());
    server.deposit(vec![
        deliver(&env, "alice", "twin-a", 1),
        deliver(&env, "alice", "twin-b", 1),
    ]);

    let mut bob = Engine::new(bob_session, server.clone());
    let report = block_on(bob.receive(&mut rng)).unwrap();

    assert_eq!(report.messages.len(), 1, "decrypted exactly once");
    assert_eq!(report.messages[0].content.as_text().unwrap().text, "once");
    assert!(report.errors.is_empty(), "the twin did not fail to decrypt");
    let acked = server.acked();
    assert!(
        acked.contains(&"twin-a".to_string()) && acked.contains(&"twin-b".to_string()),
        "both copies acked"
    );
}

#[test]
fn authenticated_replay_with_a_new_cursor_is_classified_and_acked() {
    let mut rng = test_rng();
    let bob_addr = ChatAddress::local("bob", 1);
    let bob_session = in_memory("bob", 1, &mut rng);
    let bundle = serve_bundle(bob_session.registration().unwrap(), 1);
    let mut alice = in_memory("alice", 1, &mut rng);
    block_on(alice.establish(&bob_addr, &bundle, &mut rng)).unwrap();
    let env = block_on(alice.encrypt(
        &bob_addr,
        bundle.registration_id,
        &ChatContent::text("replay", 1, "once"),
        &mut rng,
    ))
    .unwrap();
    let server = Rc::new(Mailbox::default());
    server.deposit(vec![
        deliver(&env, "alice", "replay-a", 1),
        deliver(&env, "alice", "replay-b", 2),
    ]);

    let mut bob = Engine::new(bob_session, server.clone());
    let report = block_on(bob.receive(&mut rng)).unwrap();
    assert_eq!(report.messages.len(), 1);
    assert!(report.errors.is_empty());
    assert_eq!(report.duplicates, vec!["replay-b"]);
    assert_eq!(server.acked(), vec!["replay-a", "replay-b"]);
}

#[test]
fn decrypt_failure_is_durable_and_never_silently_acked() {
    let mut rng = test_rng();
    let bob = in_memory("bob", 1, &mut rng);
    let server = Rc::new(Mailbox::default());
    server.deposit(vec![DeliveredEnvelope {
        id: "broken-1".into(),
        cursor: 1,
        sender: Some("alice".into()),
        sender_device_id: 1,
        envelope_type: kutup_chat_proto::EnvelopeType::Message,
        suite: kutup_chat_proto::SuiteId::PqxdhTripleRatchetV1,
        content: "not-base64".into(),
        server_timestamp: "2026-07-14T10:00:00Z".into(),
    }]);

    let mut engine = Engine::new(bob, server.clone());
    let first = block_on(engine.receive(&mut rng)).unwrap();
    assert_eq!(first.errors.len(), 1);
    assert_eq!(first.errors[0].kind, InboundFailureKind::MalformedEnvelope);
    assert!(server.acked().is_empty(), "failed ciphertext was not acked");
    assert_eq!(engine.state(), EngineState::Degraded);
    let retained = block_on(engine.inbound_attention()).unwrap();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].id, "broken-1");
    assert_eq!(retained[0].attempts, 1);
    assert_eq!(
        retained[0].failure_kind,
        Some(InboundFailureKind::MalformedEnvelope)
    );

    // The server query resumes after cursor 1, but the local journal retries the
    // ciphertext. It remains unacked and visible rather than disappearing.
    let second = block_on(engine.receive(&mut rng)).unwrap();
    assert_eq!(second.errors.len(), 1);
    assert!(server.acked().is_empty());
    let retained = block_on(engine.inbound_attention()).unwrap();
    assert_eq!(retained[0].attempts, 2);

    // Explicit quarantine commits locally before acking, retains a visible dead
    // letter, and lets the user remove that local record after inspection.
    block_on(engine.quarantine_inbound("broken-1")).unwrap();
    assert_eq!(server.acked(), vec!["broken-1"]);
    let retained = block_on(engine.inbound_attention()).unwrap();
    assert_eq!(retained[0].state, InboundState::DeadLetter);
    block_on(engine.resolve_dead_letter("broken-1")).unwrap();
    assert!(block_on(engine.inbound_attention()).unwrap().is_empty());
}

#[test]
fn a_peer_cannot_turn_a_transcript_shaped_message_into_outgoing_history() {
    let mut rng = test_rng();
    let bob_addr = ChatAddress::local("bob", 1);
    let bob_session = in_memory("bob", 1, &mut rng);
    let bundle = serve_bundle(bob_session.registration().unwrap(), 1);
    let mut alice = in_memory("alice", 1, &mut rng);
    block_on(alice.establish(&bob_addr, &bundle, &mut rng)).unwrap();
    let wrapper = ChatContent::sent_transcript(
        "forged-note",
        "bob",
        1,
        ChatContent::text("2026-07-16T12:00:00Z", 1, "not Bob's note"),
    );
    let encrypted =
        block_on(alice.encrypt(&bob_addr, bundle.registration_id, &wrapper, &mut rng)).unwrap();
    let server = Rc::new(Mailbox::default());
    server.deposit(vec![deliver(&encrypted, "alice", "forged-1", 1)]);

    let mut bob = Engine::new(bob_session, server);
    let report = block_on(bob.receive(&mut rng)).unwrap();
    assert_eq!(report.messages.len(), 1);
    assert!(report.synced.is_empty());
    assert!(block_on(bob.session().sent_history()).unwrap().is_empty());
    assert_eq!(block_on(bob.session().history()).unwrap().len(), 1);
}

#[test]
fn requests_reject_cleanly_and_blocks_advance_the_ratchet_without_plaintext() {
    let mut rng = test_rng();
    let bob_addr = ChatAddress::local("bob", 1);
    let bob_session = in_memory("bob", 1, &mut rng);
    let bundle = serve_bundle(bob_session.registration().unwrap(), 1);
    let mut alice = in_memory("alice", 1, &mut rng);
    block_on(alice.establish(&bob_addr, &bundle, &mut rng)).unwrap();
    let unknown_key = base64::engine::general_purpose::STANDARD.encode([6u8; 32]);
    let first_key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let rotated_key = base64::engine::general_purpose::STANDARD.encode([8u8; 32]);
    let contents = [
        ChatContent::profile_key_update_with_id(
            "profile-from-unknown",
            "2026-07-16T11:59:50Z",
            1,
            &unknown_key,
        ),
        ChatContent::text("2026-07-16T12:00:00Z", 2, "first request").with_profile_key(&first_key),
        ChatContent::profile_key_update_with_id(
            "profile-before-accept",
            "2026-07-16T12:00:10Z",
            3,
            &rotated_key,
        ),
        ChatContent::text("2026-07-16T12:00:20Z", 4, "try again"),
        ChatContent::text("2026-07-16T12:00:30Z", 5, "blocked plaintext"),
    ];
    let encrypted = contents
        .iter()
        .map(|content| {
            block_on(alice.encrypt(&bob_addr, bundle.registration_id, content, &mut rng)).unwrap()
        })
        .collect::<Vec<_>>();

    let server = Rc::new(Mailbox::default());
    let mut bob = Engine::new(bob_session, server.clone());

    // An unsolicited control cannot manufacture an empty message request.
    server.deposit(vec![deliver(&encrypted[0], "alice", "profile-1", 1)]);
    let unknown_profile = block_on(bob.receive(&mut rng)).unwrap();
    assert!(unknown_profile.messages.is_empty());
    assert!(block_on(bob.contacts()).unwrap().is_empty());
    assert!(block_on(bob.peer_profiles()).unwrap().is_empty());

    server.deposit(vec![deliver(&encrypted[1], "alice", "request-2", 2)]);
    let first = block_on(bob.receive(&mut rng)).unwrap();
    assert_eq!(first.messages.len(), 1);
    let contact = block_on(bob.contacts()).unwrap().pop().unwrap();
    assert_eq!(contact.state, ContactState::PendingIncoming);
    let request_profile = block_on(bob.peer_profiles()).unwrap().pop().unwrap();
    assert_eq!(request_profile.peer, "alice");
    assert_eq!(request_profile.key, [7u8; 32]);

    // A dedicated profile update is never a visible message and cannot grant
    // itself permission while the sender is still only an incoming request.
    server.deposit(vec![deliver(&encrypted[2], "alice", "profile-3", 3)]);
    let ignored_profile = block_on(bob.receive(&mut rng)).unwrap();
    assert!(ignored_profile.messages.is_empty());
    assert!(ignored_profile.profile_key_updated.is_empty());
    assert_eq!(block_on(bob.peer_profiles()).unwrap()[0].key, [7u8; 32]);
    assert!(matches!(
        block_on(bob.send(
            "reply-before-accept",
            "alice",
            &ChatContent::text_with_id(
                "reply-before-accept",
                "2026-07-16T12:00:30Z",
                1,
                "must not send",
            ),
            &mut rng,
        )),
        Err(kutup_chat_core::ChatError::Invalid(message))
            if message.contains("accept the message request")
    ));

    let rejected = block_on(bob.reject_contact("alice", "2026-07-16T12:01:00Z", &mut rng)).unwrap();
    assert_eq!(rejected.state, ContactState::Rejected);
    assert!(block_on(bob.session().history()).unwrap().is_empty());

    server.deposit(vec![deliver(&encrypted[3], "alice", "request-4", 4)]);
    let second = block_on(bob.receive(&mut rng)).unwrap();
    assert_eq!(
        second.messages.len(),
        1,
        "a later message creates a new request"
    );
    assert_eq!(
        block_on(bob.contacts()).unwrap()[0].state,
        ContactState::PendingIncoming
    );

    let blocked = block_on(bob.block_contact("alice", "2026-07-16T12:02:00Z", &mut rng)).unwrap();
    assert_eq!(blocked.state, ContactState::Blocked);
    assert_eq!(blocked.previous_state, Some(ContactState::PendingIncoming));
    server.deposit(vec![deliver(&encrypted[4], "alice", "blocked-5", 5)]);
    let third = block_on(bob.receive(&mut rng)).unwrap();
    assert!(third.messages.is_empty());
    assert_eq!(third.suppressed, vec!["blocked-5"]);
    assert_eq!(block_on(bob.session().history()).unwrap().len(), 1);
    assert!(server.acked().contains(&"blocked-5".to_string()));

    let unblocked =
        block_on(bob.unblock_contact("alice", "2026-07-16T12:03:00Z", &mut rng)).unwrap();
    assert_eq!(unblocked.state, ContactState::PendingIncoming);
}
