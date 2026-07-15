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
use futures_executor::block_on;
use kutup_chat_core::{
    ChatAddress, ChatContent, ChatTransport, Engine, Result, SendOutcome, Session, SqliteChatDb,
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
    Session::generate(
        Rc::new(SqliteChatDb::open_in_memory().unwrap()),
        user,
        device_id,
        10,
        rng,
    )
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
    async fn fetch_bundles(&self, _username: &str) -> Result<UserPreKeyBundlesResponse> {
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
    async fn ack(&self, ids: &[String]) -> Result<()> {
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
        let bob = Session::generate(bob_db.open(), "bob", 1, 10, &mut rng).unwrap();
        let bundle = serve_bundle(bob.registration().unwrap(), 1);

        let mut alice = in_memory("alice", 1, &mut rng);
        alice.establish(&bob_addr, &bundle, &mut rng).unwrap();
        let e1 = alice
            .encrypt(
                &bob_addr,
                bundle.registration_id,
                &ChatContent::text("t", 1, "first"),
                &mut rng,
            )
            .unwrap();
        let e2 = alice
            .encrypt(
                &bob_addr,
                bundle.registration_id,
                &ChatContent::text("t", 2, "second"),
                &mut rng,
            )
            .unwrap();
        (e1, e2)
    };

    let server = Rc::new(Mailbox::default());
    server.deposit(vec![
        deliver(&env1, "alice", "mbx-1", 1),
        deliver(&env2, "alice", "mbx-2", 2),
    ]);

    // Bob reopens his device and drains.
    let mut bob = Engine::open(bob_db.open(), server.clone(), "bob", 1).unwrap();
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
    let reopened = Session::open(bob_db.open(), "bob", 1).unwrap();
    let history = reopened.history().unwrap();
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
    alice.establish(&bob_addr, &bundle, &mut rng).unwrap();
    let env = alice
        .encrypt(
            &bob_addr,
            bundle.registration_id,
            &ChatContent::text("t", 1, "once"),
            &mut rng,
        )
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
