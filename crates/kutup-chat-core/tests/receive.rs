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
    AccountAuthority, ChatAddress, ChatContent, ChatTransport, ContactState, Engine, EngineState,
    InboundFailureKind, InboundState, Result, SendOutcome, Session, SqliteChatDb,
};
use kutup_chat_proto::{
    AccountPreKeyBundlesResponse, ConversationId, DeliveredEnvelope, DevicePreKeyBundle,
    MailboxPage, OutgoingEnvelope, RegisterChatDeviceRequestV2, SendMessagesRequest,
};
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng, TryRngCore as _};

// ----- helpers -----

fn test_rng() -> impl Rng + CryptoRng {
    OsRng.unwrap_err()
}

fn in_memory<R: Rng + CryptoRng>(user: &str, device_id: u32, rng: &mut R) -> Session {
    let session = block_on(Session::generate(
        Rc::new(SqliteChatDb::open_in_memory().unwrap()),
        user,
        device_id,
        10,
        rng,
    ))
    .unwrap();
    publish_device(
        user,
        serve_bundle(session.published_keys().unwrap(), device_id),
    );
    session
}

thread_local! {
    /// Every sender device a test made, by account: the mock server publishes
    /// them in each account's signed manifest, as the real one would.
    static DEVICES: RefCell<std::collections::BTreeMap<String, Vec<DevicePreKeyBundle>>> =
        const { RefCell::new(std::collections::BTreeMap::new()) };
}

fn publish_device(user: &str, bundle: DevicePreKeyBundle) {
    DEVICES.with(|devices| {
        let mut devices = devices.borrow_mut();
        let list = devices.entry(user.to_string()).or_default();
        list.retain(|known| known.device_id != bundle.device_id);
        list.push(bundle);
        list.sort_by_key(|known| known.device_id);
    });
}

/// The authority of `user`'s account in these tests.
fn authority_of(user: &str) -> AccountAuthority {
    let seed = user
        .bytes()
        .fold(7u8, |acc, b| acc.wrapping_mul(31).wrapping_add(b));
    AccountAuthority::derive(&[seed; 32]).unwrap()
}

/// `user`'s signed manifest and bundles, from the devices a test made: the
/// account's identity once (every device of an account has it).
fn published(user: &str) -> AccountPreKeyBundlesResponse {
    let devices = DEVICES.with(|devices| devices.borrow().get(user).cloned().unwrap_or_default());
    let identity_key = devices
        .first()
        .map(|bundle| bundle.identity_key.clone())
        .expect("a test publishes a device before its bundles are fetched");
    let manifest = authority_of(user)
        .sign_manifest(
            user.parse().unwrap(),
            1,
            None,
            identity_key.clone(),
            devices
                .iter()
                .map(|bundle| kutup_chat_proto::AccountManifestDeviceV2 {
                    device_id: bundle.device_id,
                    direct_chat_suite: kutup_chat_proto::DirectChatSuiteId::PqxdhTripleRatchetV1,
                    registration_id: bundle.registration_id,
                    mls: None,
                })
                .collect(),
            "2026-10-15T10:00:00Z",
        )
        .unwrap();
    AccountPreKeyBundlesResponse {
        account: user.parse().unwrap(),
        identity_key,
        devices: devices
            .into_iter()
            .map(|bundle| kutup_chat_proto::DevicePreKeyBundleV2 {
                device_id: bundle.device_id,
                registration_id: bundle.registration_id,
                suite: bundle.suite,
                signed_pre_key: bundle.signed_pre_key,
                kyber_pre_key: bundle.kyber_pre_key,
                one_time_pre_key: bundle.one_time_pre_key,
            })
            .collect(),
        manifest,
    }
}

fn serve_bundle(reg: &kutup_chat_core::PublishedKeys, device_id: u32) -> DevicePreKeyBundle {
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
        sender: Some(sender.parse().unwrap()),
        sealed_sender: false,
        sender_device_id: 1,
        envelope_type: env.envelope_type,
        suite: env.suite,
        content: env.content.clone(),
        server_timestamp: "2026-07-14T10:00:00Z".into(),
        send_id: None,
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
    /// The manifest this account's device published (its own, signed with
    /// its own authority).
    own_manifest: RefCell<Option<kutup_chat_proto::AccountManifestV2>>,
    /// Every manifest of this account's chain, as the server keeps them.
    own_history: RefCell<Vec<kutup_chat_proto::AccountManifestV2>>,
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
    async fn register_device(&self, _req: &RegisterChatDeviceRequestV2) -> Result<u32> {
        unreachable!("receive path does not register")
    }
    async fn fetch_bundles(&self, account: &str) -> Result<AccountPreKeyBundlesResponse> {
        // Only to verify a sender's devices before anything of theirs is read.
        Ok(published(account))
    }
    async fn fetch_sync_bundles(
        &self,
        account: &str,
        _current_device_id: u32,
    ) -> Result<AccountPreKeyBundlesResponse> {
        // What this server claims about the account's own devices.
        Ok(published(account))
    }
    async fn fetch_manifest(
        &self,
        _account: &str,
    ) -> Result<Option<kutup_chat_proto::AccountManifestV2>> {
        Ok(self.own_manifest.borrow().clone())
    }
    async fn publish_manifest(
        &self,
        manifest: &kutup_chat_proto::AccountManifestV2,
    ) -> Result<kutup_chat_proto::AccountManifestPublicationV2> {
        *self.own_manifest.borrow_mut() = Some(manifest.clone());
        self.own_history.borrow_mut().push(manifest.clone());
        Ok(kutup_chat_proto::AccountManifestPublicationV2 {
            manifest: manifest.clone(),
        })
    }
    async fn fetch_manifest_history(
        &self,
        account: &str,
        _from_sequence: u64,
        to_sequence: u64,
        page_from_sequence: u64,
    ) -> Result<kutup_chat_proto::AccountManifestHistoryPageV2> {
        let manifests: Vec<_> = self
            .own_history
            .borrow()
            .iter()
            .filter(|manifest| {
                manifest.sequence >= page_from_sequence && manifest.sequence <= to_sequence
            })
            .cloned()
            .collect();
        Ok(kutup_chat_proto::AccountManifestHistoryPageV2 {
            account: account.parse().unwrap(),
            from_sequence: page_from_sequence,
            to_sequence,
            manifests,
            next_sequence: None,
        })
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
    let bob_addr =
        ChatAddress::from_sender("aci:00000000-0000-4000-8000-81b637d8fcd2@example.test", 1)
            .unwrap();
    let (env1, env2) = {
        // Generate Bob's device into bob_db (keys persist there); the Session itself
        // is only needed to serve the bundle, then dropped.
        let mut bob = block_on(Session::generate(
            bob_db.open(),
            "aci:00000000-0000-4000-8000-81b637d8fcd2@example.test",
            1,
            10,
            &mut rng,
        ))
        .unwrap();
        let bundle = serve_bundle(bob.published_keys().unwrap(), 1);
        block_on(bob.complete_registration(1)).unwrap();

        let mut alice = in_memory(
            "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
            1,
            &mut rng,
        );
        block_on(alice.establish(&bob_addr, &bundle, &mut rng)).unwrap();
        let e1 = block_on(alice.encrypt(
            &bob_addr,
            bundle.registration_id,
            &ChatContent::text_with_id("m1", "t", 1, "first"),
            &mut rng,
        ))
        .unwrap();
        let e2 = block_on(alice.encrypt(
            &bob_addr,
            bundle.registration_id,
            &ChatContent::text_with_id("m2", "t", 2, "second"),
            &mut rng,
        ))
        .unwrap();
        (e1, e2)
    };

    let server = Rc::new(Mailbox::default());
    server.deposit(vec![
        deliver(
            &env1,
            "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
            "mbx-1",
            1,
        ),
        deliver(
            &env2,
            "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
            "mbx-2",
            2,
        ),
    ]);

    // Bob reopens his device and drains.
    let mut bob = block_on(Engine::open(
        bob_db.open(),
        server.clone(),
        "aci:00000000-0000-4000-8000-81b637d8fcd2@example.test",
        1,
    ))
    .unwrap();
    let report = block_on(bob.receive(&mut rng)).unwrap();

    assert_eq!(report.messages.len(), 2);
    assert_eq!(report.messages[0].content.as_text().unwrap().text, "first");
    assert_eq!(report.messages[1].content.as_text().unwrap().text, "second");
    assert_eq!(
        report.messages[0].from,
        ChatAddress::from_sender("aci:00000000-0000-4000-8000-2bd806c97f0e@example.test", 1)
            .unwrap()
    );
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
    let reopened = block_on(Session::open(
        bob_db.open(),
        "aci:00000000-0000-4000-8000-81b637d8fcd2@example.test",
        1,
    ))
    .unwrap();
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
    let bob_addr =
        ChatAddress::from_sender("aci:00000000-0000-4000-8000-81b637d8fcd2@example.test", 1)
            .unwrap();

    let bob_session = in_memory(
        "aci:00000000-0000-4000-8000-81b637d8fcd2@example.test",
        1,
        &mut rng,
    );
    let bundle = serve_bundle(bob_session.published_keys().unwrap(), 1);

    let mut alice = in_memory(
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        1,
        &mut rng,
    );
    block_on(alice.establish(&bob_addr, &bundle, &mut rng)).unwrap();
    let env = block_on(alice.encrypt(
        &bob_addr,
        bundle.registration_id,
        &ChatContent::text_with_id("m3", "t", 1, "once"),
        &mut rng,
    ))
    .unwrap();

    // The same message delivered twice (same cursor, different mailbox ids) — the
    // WS-twin case. The second copy must be acked but never re-decrypted (the
    // ratchet couldn't repeat it).
    let server = Rc::new(Mailbox::default());
    server.deposit(vec![
        deliver(
            &env,
            "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
            "twin-a",
            1,
        ),
        deliver(
            &env,
            "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
            "twin-b",
            1,
        ),
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
    let bob_addr =
        ChatAddress::from_sender("aci:00000000-0000-4000-8000-81b637d8fcd2@example.test", 1)
            .unwrap();
    let bob_session = in_memory(
        "aci:00000000-0000-4000-8000-81b637d8fcd2@example.test",
        1,
        &mut rng,
    );
    let bundle = serve_bundle(bob_session.published_keys().unwrap(), 1);
    let mut alice = in_memory(
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        1,
        &mut rng,
    );
    block_on(alice.establish(&bob_addr, &bundle, &mut rng)).unwrap();
    let env = block_on(alice.encrypt(
        &bob_addr,
        bundle.registration_id,
        &ChatContent::text_with_id("m4", "replay", 1, "once"),
        &mut rng,
    ))
    .unwrap();
    let server = Rc::new(Mailbox::default());
    server.deposit(vec![
        deliver(
            &env,
            "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
            "replay-a",
            1,
        ),
        deliver(
            &env,
            "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
            "replay-b",
            2,
        ),
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
    let bob = in_memory(
        "aci:00000000-0000-4000-8000-81b637d8fcd2@example.test",
        1,
        &mut rng,
    );
    // Alice's device is real; what it sent is not.
    let _alice = in_memory(
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        1,
        &mut rng,
    );
    let server = Rc::new(Mailbox::default());
    server.deposit(vec![DeliveredEnvelope {
        id: "broken-1".into(),
        cursor: 1,
        sender: Some(
            "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test"
                .parse()
                .unwrap(),
        ),
        sealed_sender: false,
        sender_device_id: 1,
        envelope_type: kutup_chat_proto::EnvelopeType::Message,
        suite: kutup_chat_proto::DirectChatSuiteId::PqxdhTripleRatchetV1,
        content: "not-base64".into(),
        server_timestamp: "2026-07-14T10:00:00Z".into(),
        send_id: None,
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
    let bob_addr =
        ChatAddress::from_sender("aci:00000000-0000-4000-8000-81b637d8fcd2@example.test", 1)
            .unwrap();
    let bob_session = in_memory(
        "aci:00000000-0000-4000-8000-81b637d8fcd2@example.test",
        1,
        &mut rng,
    );
    let bundle = serve_bundle(bob_session.published_keys().unwrap(), 1);
    let mut alice = in_memory(
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        1,
        &mut rng,
    );
    block_on(alice.establish(&bob_addr, &bundle, &mut rng)).unwrap();
    let wrapper = ChatContent::sent_transcript(
        "forged-note",
        "aci:00000000-0000-4000-8000-81b637d8fcd2@example.test"
            .parse()
            .unwrap(),
        1,
        ChatContent::text_with_id("m5", "2026-07-16T12:00:00Z", 1, "not Bob's note"),
    );
    let encrypted =
        block_on(alice.encrypt(&bob_addr, bundle.registration_id, &wrapper, &mut rng)).unwrap();
    let server = Rc::new(Mailbox::default());
    server.deposit(vec![deliver(
        &encrypted,
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        "forged-1",
        1,
    )]);

    let mut bob = Engine::new(bob_session, server);
    let report = block_on(bob.receive(&mut rng)).unwrap();
    assert_eq!(report.messages.len(), 1);
    assert!(report.synced.is_empty());
    assert!(block_on(bob.session().sent_history()).unwrap().is_empty());
    assert_eq!(block_on(bob.session().history()).unwrap().len(), 1);
}

#[test]
fn typing_is_live_only_for_accepted_contacts_and_never_creates_history() {
    let mut rng = test_rng();
    let bob_addr =
        ChatAddress::from_sender("aci:00000000-0000-4000-8000-81b637d8fcd2@example.test", 1)
            .unwrap();
    let bob_session = in_memory(
        "aci:00000000-0000-4000-8000-81b637d8fcd2@example.test",
        1,
        &mut rng,
    );
    let bundle = serve_bundle(bob_session.published_keys().unwrap(), 1);
    let mut alice = in_memory(
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        1,
        &mut rng,
    );
    block_on(alice.establish(&bob_addr, &bundle, &mut rng)).unwrap();
    let contents = [
        ChatContent::typing_with_id(
            "11111111-1111-4111-8111-111111111111",
            "2026-08-10T12:00:00Z",
            1,
            true,
        ),
        ChatContent::text_with_id(
            "22222222-2222-4222-8222-222222222222",
            "2026-08-10T12:00:01Z",
            2,
            "message request",
        ),
        ChatContent::typing_with_id(
            "33333333-3333-4333-8333-333333333333",
            "2026-08-10T12:00:02Z",
            3,
            true,
        ),
    ];
    let encrypted = contents
        .iter()
        .map(|content| {
            block_on(alice.encrypt(&bob_addr, bundle.registration_id, content, &mut rng)).unwrap()
        })
        .collect::<Vec<_>>();
    let server = Rc::new(Mailbox::default());
    let mut bob = Engine::new(bob_session, server.clone());

    server.deposit(vec![deliver(
        &encrypted[0],
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        "typing-1",
        1,
    )]);
    let unknown = block_on(bob.receive(&mut rng)).unwrap();
    assert!(unknown.messages.is_empty());
    assert_eq!(unknown.suppressed, vec!["typing-1"]);
    assert!(block_on(bob.contacts()).unwrap().is_empty());
    assert!(block_on(bob.session().history()).unwrap().is_empty());

    server.deposit(vec![deliver(
        &encrypted[1],
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        "request-2",
        2,
    )]);
    assert_eq!(block_on(bob.receive(&mut rng)).unwrap().messages.len(), 1);
    block_on(bob.accept_contact(
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        "2026-08-10T12:00:02Z",
        &mut rng,
    ))
    .unwrap();

    server.deposit(vec![deliver(
        &encrypted[2],
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        "typing-3",
        3,
    )]);
    let accepted = block_on(bob.receive(&mut rng)).unwrap();
    assert_eq!(accepted.messages.len(), 1);
    assert_eq!(
        accepted.messages[0].content.as_typing(),
        Some(kutup_chat_proto::TypingBody { active: true })
    );
    assert_eq!(
        block_on(bob.session().history()).unwrap().len(),
        1,
        "only the real request is durable history"
    );
}

#[test]
fn a_call_from_someone_not_accepted_does_not_ring() {
    let mut rng = test_rng();
    let bob_addr =
        ChatAddress::from_sender("aci:00000000-0000-4000-8000-81b637d8fcd2@example.test", 1)
            .unwrap();
    let bob_session = in_memory(
        "aci:00000000-0000-4000-8000-81b637d8fcd2@example.test",
        1,
        &mut rng,
    );
    let bundle = serve_bundle(bob_session.published_keys().unwrap(), 1);
    let mut alice = in_memory(
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        1,
        &mut rng,
    );
    block_on(alice.establish(&bob_addr, &bundle, &mut rng)).unwrap();
    let offer = ChatContent::call_with_id(
        "66666666-6666-4666-8666-666666666666",
        "2026-09-25T12:00:00Z",
        1,
        &kutup_chat_proto::CallSignalV1 {
            call_id: uuid::Uuid::from_u128(3),
            caller_device_id: 1,
            callee_device_id: None,
            signal: kutup_chat_proto::CallSignalKindV1::Busy,
        },
    )
    .unwrap();
    let encrypted =
        block_on(alice.encrypt(&bob_addr, bundle.registration_id, &offer, &mut rng)).unwrap();
    let server = Rc::new(Mailbox::default());
    let mut bob = Engine::new(bob_session, server.clone());
    server.deposit(vec![deliver(
        &encrypted,
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        "call-1",
        1,
    )]);
    let report = block_on(bob.receive(&mut rng)).unwrap();
    assert!(report.messages.is_empty());
    assert_eq!(report.suppressed, vec!["call-1"]);
    assert!(block_on(bob.session().history()).unwrap().is_empty());
    assert!(block_on(bob.contacts()).unwrap().is_empty());
}

#[test]
fn disappearing_timer_is_durable_only_for_established_conversations() {
    let mut rng = test_rng();
    let bob_addr =
        ChatAddress::from_sender("aci:00000000-0000-4000-8000-81b637d8fcd2@example.test", 1)
            .unwrap();
    let bob_session = in_memory(
        "aci:00000000-0000-4000-8000-81b637d8fcd2@example.test",
        1,
        &mut rng,
    );
    let bundle = serve_bundle(bob_session.published_keys().unwrap(), 1);
    let mut alice = in_memory(
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        1,
        &mut rng,
    );
    block_on(alice.establish(&bob_addr, &bundle, &mut rng)).unwrap();
    let contents = [
        ChatContent::disappearing_timer_with_id(
            "11111111-1111-4111-8111-111111111111",
            "2026-08-10T12:00:00Z",
            1,
            Some(30),
        )
        .unwrap(),
        ChatContent::text_with_id(
            "22222222-2222-4222-8222-222222222222",
            "2026-08-10T12:00:01Z",
            2,
            "message request",
        ),
        ChatContent::disappearing_timer_with_id(
            "33333333-3333-4333-8333-333333333333",
            "2026-08-10T12:00:02Z",
            3,
            Some(3_600),
        )
        .unwrap(),
    ];
    let encrypted = contents
        .iter()
        .map(|content| {
            block_on(alice.encrypt(&bob_addr, bundle.registration_id, content, &mut rng)).unwrap()
        })
        .collect::<Vec<_>>();
    let server = Rc::new(Mailbox::default());
    let mut bob = Engine::new(bob_session, server.clone());

    server.deposit(vec![deliver(
        &encrypted[0],
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        "timer-1",
        1,
    )]);
    let unknown = block_on(bob.receive(&mut rng)).unwrap();
    assert!(unknown.messages.is_empty());
    assert_eq!(unknown.suppressed, vec!["timer-1"]);
    assert!(block_on(bob.contacts()).unwrap().is_empty());
    assert!(block_on(bob.session().history()).unwrap().is_empty());

    server.deposit(vec![deliver(
        &encrypted[1],
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        "request-2",
        2,
    )]);
    assert_eq!(block_on(bob.receive(&mut rng)).unwrap().messages.len(), 1);
    block_on(bob.accept_contact(
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        "2026-08-10T12:00:02Z",
        &mut rng,
    ))
    .unwrap();

    server.deposit(vec![deliver(
        &encrypted[2],
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        "timer-3",
        3,
    )]);
    let accepted = block_on(bob.receive(&mut rng)).unwrap();
    assert_eq!(accepted.messages.len(), 1);
    assert_eq!(
        accepted.messages[0]
            .content
            .as_disappearing_timer()
            .and_then(|timer| timer.duration_seconds),
        Some(3_600)
    );
    assert_eq!(
        block_on(bob.session().history()).unwrap().len(),
        2,
        "the real request and accepted timer are durable"
    );
}

#[test]
fn a_peer_cannot_inject_a_recipient_disappearing_expiry_start() {
    let mut rng = test_rng();
    let bob_addr =
        ChatAddress::from_sender("aci:00000000-0000-4000-8000-81b637d8fcd2@example.test", 1)
            .unwrap();
    let bob_session = in_memory(
        "aci:00000000-0000-4000-8000-81b637d8fcd2@example.test",
        1,
        &mut rng,
    );
    let bundle = serve_bundle(bob_session.published_keys().unwrap(), 1);
    let mut alice = in_memory(
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        1,
        &mut rng,
    );
    block_on(alice.establish(&bob_addr, &bundle, &mut rng)).unwrap();
    let control = ChatContent::disappearing_expiry_start_with_id(
        "44444444-4444-4444-8444-444444444444",
        "2026-08-10T12:00:03Z",
        1,
        ConversationId::direct(
            "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test"
                .parse::<kutup_chat_core::AccountRef>()
                .unwrap(),
        ),
        "55555555-5555-4555-8555-555555555555",
        1,
    )
    .unwrap();
    let encrypted =
        block_on(alice.encrypt(&bob_addr, bundle.registration_id, &control, &mut rng)).unwrap();
    let server = Rc::new(Mailbox::default());
    server.deposit(vec![deliver(
        &encrypted,
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        "forged-expiry-start",
        1,
    )]);

    let mut bob = Engine::new(bob_session, server.clone());
    let report = block_on(bob.receive(&mut rng)).unwrap();
    assert!(report.messages.is_empty());
    assert_eq!(report.errors.len(), 1);
    assert_eq!(report.errors[0].kind, InboundFailureKind::Unknown);
    assert!(server.acked().is_empty());
    assert!(block_on(bob.session().history()).unwrap().is_empty());
}

#[test]
fn requests_reject_cleanly_and_blocks_advance_the_ratchet_without_plaintext() {
    let mut rng = test_rng();
    let bob_addr =
        ChatAddress::from_sender("aci:00000000-0000-4000-8000-81b637d8fcd2@example.test", 1)
            .unwrap();
    let bob_session = in_memory(
        "aci:00000000-0000-4000-8000-81b637d8fcd2@example.test",
        1,
        &mut rng,
    );
    let bundle = serve_bundle(bob_session.published_keys().unwrap(), 1);
    let mut alice = in_memory(
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        1,
        &mut rng,
    );
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
        ChatContent::text_with_id("m6", "2026-07-16T12:00:00Z", 2, "first request")
            .with_profile_key(&first_key),
        ChatContent::profile_key_update_with_id(
            "profile-before-accept",
            "2026-07-16T12:00:10Z",
            3,
            &rotated_key,
        ),
        ChatContent::text_with_id("m7", "2026-07-16T12:00:20Z", 4, "try again"),
        ChatContent::text_with_id("m8", "2026-07-16T12:00:30Z", 5, "blocked plaintext"),
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
    server.deposit(vec![deliver(
        &encrypted[0],
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        "profile-1",
        1,
    )]);
    let unknown_profile = block_on(bob.receive(&mut rng)).unwrap();
    assert!(unknown_profile.messages.is_empty());
    assert!(block_on(bob.contacts()).unwrap().is_empty());
    assert!(block_on(bob.peer_profiles()).unwrap().is_empty());

    server.deposit(vec![deliver(
        &encrypted[1],
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        "request-2",
        2,
    )]);
    let first = block_on(bob.receive(&mut rng)).unwrap();
    assert_eq!(first.messages.len(), 1);
    let contact = block_on(bob.contacts()).unwrap().pop().unwrap();
    assert_eq!(contact.state, ContactState::PendingIncoming);
    let request_profile = block_on(bob.peer_profiles()).unwrap().pop().unwrap();
    assert_eq!(
        request_profile.peer,
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test"
    );
    assert_eq!(request_profile.key, [7u8; 32]);

    // A dedicated profile update is never a visible message and cannot grant
    // itself permission while the sender is still only an incoming request.
    server.deposit(vec![deliver(
        &encrypted[2],
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        "profile-3",
        3,
    )]);
    let ignored_profile = block_on(bob.receive(&mut rng)).unwrap();
    assert!(ignored_profile.messages.is_empty());
    assert!(ignored_profile.profile_key_updated.is_empty());
    assert_eq!(block_on(bob.peer_profiles()).unwrap()[0].key, [7u8; 32]);
    assert!(matches!(
        block_on(bob.send(
            "reply-before-accept",
            "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
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

    let rejected = block_on(bob.reject_contact(
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        "2026-07-16T12:01:00Z",
        &mut rng,
    ))
    .unwrap();
    assert_eq!(rejected.state, ContactState::Rejected);
    assert!(block_on(bob.session().history()).unwrap().is_empty());

    server.deposit(vec![deliver(
        &encrypted[3],
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        "request-4",
        4,
    )]);
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

    let blocked = block_on(bob.block_contact(
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        &[0; 32],
        "2026-07-16T12:02:00Z",
        &mut rng,
    ))
    .unwrap();
    assert_eq!(blocked.state, ContactState::Blocked);
    assert_eq!(blocked.previous_state, Some(ContactState::PendingIncoming));
    server.deposit(vec![deliver(
        &encrypted[4],
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        "blocked-5",
        5,
    )]);
    let third = block_on(bob.receive(&mut rng)).unwrap();
    assert!(third.messages.is_empty());
    assert_eq!(third.suppressed, vec!["blocked-5"]);
    assert_eq!(block_on(bob.session().history()).unwrap().len(), 1);
    assert!(server.acked().contains(&"blocked-5".to_string()));

    let unblocked = block_on(bob.unblock_contact(
        "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
        "2026-07-16T12:03:00Z",
        &mut rng,
    ))
    .unwrap();
    assert_eq!(unblocked.state, ContactState::PendingIncoming);
}

const ALICE: &str = "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test";
const BOB: &str = "aci:00000000-0000-4000-8000-81b637d8fcd2@example.test";

/// Bob's registered device in a reopenable store, and its bundle.
fn bob_device<R: Rng + CryptoRng>(rng: &mut R) -> (TempDb, DevicePreKeyBundle) {
    let db = TempDb::new();
    let mut bob = block_on(Session::generate(db.open(), BOB, 1, 10, rng)).unwrap();
    let bundle = serve_bundle(bob.published_keys().unwrap(), 1);
    block_on(bob.complete_registration(1)).unwrap();
    (db, bundle)
}

/// Messages to Bob in `sender`'s name from devices nobody published for
/// `sender`: one under device id 2, one under id 1 with another identity key.
fn forged_from<R: Rng + CryptoRng>(
    sender: &str,
    bundle: &DevicePreKeyBundle,
    rng: &mut R,
) -> (Vec<DeliveredEnvelope>, Vec<DevicePreKeyBundle>) {
    let bob_addr = ChatAddress::from_sender(BOB, 1).unwrap();
    let mut envelopes = Vec::new();
    let mut devices = Vec::new();
    for (device, cursor) in [(2u32, 1u64), (1, 2)] {
        let mut mallory = block_on(Session::generate(
            Rc::new(SqliteChatDb::open_in_memory().unwrap()),
            sender,
            device,
            10,
            rng,
        ))
        .unwrap();
        devices.push(serve_bundle(mallory.published_keys().unwrap(), device));
        block_on(mallory.establish(&bob_addr, bundle, rng)).unwrap();
        let env = block_on(mallory.encrypt(
            &bob_addr,
            bundle.registration_id,
            &ChatContent::text_with_id("forged", "t", 1, "it is me"),
            rng,
        ))
        .unwrap();
        let mut delivered = deliver(&env, sender, &format!("forged-{cursor}"), cursor);
        delivered.sender_device_id = device;
        envelopes.push(delivered);
    }
    (envelopes, devices)
}

/// A server sending in a pinned person's name from a device of its own:
/// refused like a sealed envelope from outside the manifest, never a new
/// session, and kept for retry.
#[test]
fn an_identified_message_is_taken_only_from_a_device_of_the_senders_manifest() {
    let mut rng = test_rng();
    let (bob_db, bundle) = bob_device(&mut rng);
    // Alice's real device 1 is in her manifest.
    let _alice = in_memory(ALICE, 1, &mut rng);
    let server = Rc::new(Mailbox::default());
    server.deposit(forged_from(ALICE, &bundle, &mut rng).0);
    let mut engine = block_on(Engine::open(bob_db.open(), server.clone(), BOB, 1)).unwrap();
    let report = block_on(engine.receive(&mut rng)).unwrap();
    assert!(
        report.messages.is_empty(),
        "nothing in Alice's name from devices outside her manifest"
    );
    assert_eq!(report.errors.len(), 2);
    assert!(server.acked().is_empty());
}

/// A "new own device" the server made up: before this device verified its
/// own manifest nothing in this account's name is taken; afterwards only
/// devices of that manifest are, and a server-offered manifest under
/// another authority does not add any.
#[test]
fn an_own_account_message_is_taken_only_from_a_device_of_the_own_verified_manifest() {
    let mut rng = test_rng();
    let (bob_db, bundle) = bob_device(&mut rng);
    let server = Rc::new(Mailbox::default());
    let (forged, devices) = forged_from(BOB, &bundle, &mut rng);
    // The server lists Bob's device and a forged one in a manifest under an
    // authority of its own.
    publish_device(BOB, bundle.clone());
    publish_device(BOB, devices[0].clone());

    // No own manifest verified here yet.
    server.deposit(forged.clone());
    let mut engine = block_on(Engine::open(bob_db.open(), server.clone(), BOB, 1)).unwrap();
    let report = block_on(engine.receive(&mut rng)).unwrap();
    assert!(report.messages.is_empty());
    assert_eq!(report.errors.len(), 2);
    assert!(server.acked().is_empty());

    // Bob's own manifest under his own authority (as his re-registration
    // published it): his identity, device 1 only.
    let authority = AccountAuthority::derive(&[42u8; 32]).unwrap();
    let first = authority
        .sign_manifest(
            BOB.parse().unwrap(),
            1,
            None,
            bundle.identity_key.clone(),
            vec![kutup_chat_proto::AccountManifestDeviceV2 {
                device_id: 1,
                direct_chat_suite: kutup_chat_proto::DirectChatSuiteId::PqxdhTripleRatchetV1,
                registration_id: bundle.registration_id,
                mls: None,
            }],
            "2026-10-16T10:00:00Z",
        )
        .unwrap();
    *server.own_manifest.borrow_mut() = Some(first.clone());
    server.own_history.borrow_mut().push(first);
    block_on(engine.sync_own_manifest(&authority, "2026-10-16T10:00:00Z")).unwrap();
    let report = block_on(engine.receive(&mut rng)).unwrap();
    assert!(
        report.messages.is_empty(),
        "nothing from devices outside Bob's own verified manifest"
    );
    assert!(server.acked().is_empty());
}

/// The line saying a peer changed their username: written once per rename
/// (a second sighting of the same step neither repeats nor moves it), never
/// for anything but an account, and one more for each later rename.
#[test]
fn a_peer_rename_line_is_written_once_per_rename() {
    let mut rng = test_rng();
    let mut bob = in_memory(BOB, 1, &mut rng);
    let first = kutup_chat_proto::PeerRenamedBody {
        previous: "ada@example.test".into(),
        current: "ada.new@example.test".into(),
        sequence: 1,
    };
    assert!(block_on(bob.record_peer_renamed(ALICE, &first)).unwrap());
    let lines = |bob: &Session| -> Vec<(String, i64)> {
        block_on(bob.sent_history())
            .unwrap()
            .into_iter()
            .filter(|message| {
                serde_json::from_slice::<ChatContent>(&message.content)
                    .is_ok_and(|content| content.as_peer_renamed().is_some())
            })
            .map(|message| (message.peer, message.created_at))
            .collect()
    };
    let once = lines(&bob);
    assert_eq!(once.len(), 1);
    assert_eq!(once[0].0, ALICE);
    assert!(!block_on(bob.record_peer_renamed(ALICE, &first)).unwrap());
    assert_eq!(
        lines(&bob),
        once,
        "the same rename neither repeats nor moves"
    );
    let second = kutup_chat_proto::PeerRenamedBody {
        previous: "ada.new@example.test".into(),
        current: "ada.newer@example.test".into(),
        sequence: 2,
    };
    assert!(block_on(bob.record_peer_renamed(ALICE, &second)).unwrap());
    assert_eq!(lines(&bob).len(), 2);
    // Only an account's thread; and only one rename, not a no-op.
    assert!(block_on(bob.record_peer_renamed("ada@example.test", &first)).is_err());
    let same = kutup_chat_proto::PeerRenamedBody {
        current: first.previous.clone(),
        ..first.clone()
    };
    assert!(block_on(bob.record_peer_renamed(ALICE, &same)).is_err());
}
