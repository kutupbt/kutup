//! The derisking proof: a full 1:1 PQXDH + Triple Ratchet round-trip driven
//! entirely through the `kutup-chat-proto` wire types, now over the durable
//! SQLite store. If this passes, our contract (bundle → establish → encrypt →
//! wire envelope → decrypt → content) works with real libsignal crypto, and the
//! ratchet state persists across a full close/reopen of the device store.

use std::rc::Rc;

use base64::Engine as _;
use futures_executor::block_on;
use kutup_chat_core::{ChatAddress, ChatContent, Session, SqliteChatDb};
use kutup_chat_proto::{DeliveredEnvelope, DevicePreKeyBundle};
use rand::rngs::OsRng;
use rand::Rng as _;
use rand::TryRngCore as _;

/// Simulates the server serving Bob's *published* registration as a per-device
/// bundle: it hands out the signed prekey, the identity, one one-time Kyber
/// prekey, and one one-time EC prekey (consumed). No private material.
fn serve_bundle(
    reg: &kutup_chat_proto::RegisterChatDeviceRequest,
    device_id: u32,
) -> DevicePreKeyBundle {
    DevicePreKeyBundle {
        device_id,
        registration_id: reg.registration_id,
        suite: reg.suite,
        identity_key: reg.identity_key.clone(),
        signed_pre_key: reg.signed_pre_key.clone(),
        // A one-time Kyber prekey when present, else the last-resort (never absent).
        kyber_pre_key: reg
            .one_time_kyber_pre_keys
            .first()
            .cloned()
            .unwrap_or_else(|| reg.last_resort_kyber_pre_key.clone()),
        one_time_pre_key: reg.one_time_pre_keys.first().cloned(),
    }
}

fn wrap(env: kutup_chat_proto::OutgoingEnvelope, sender: &str, cursor: u64) -> DeliveredEnvelope {
    // The server turns an OutgoingEnvelope into a DeliveredEnvelope: same opaque
    // content, plus routing metadata. This is exactly that transform.
    DeliveredEnvelope {
        id: format!("mailbox-{cursor}"),
        cursor,
        sender: Some(sender.to_string()),
        sealed_sender: false,
        sender_device_id: 1,
        envelope_type: env.envelope_type,
        suite: env.suite,
        content: env.content,
        server_timestamp: "2026-07-13T10:00:00Z".into(),
    }
}

/// A device store on a throwaway file path, deleted (with its WAL/SHM siblings)
/// when the returned guard drops. Needed for the reopen test — `:memory:` can't
/// be reopened.
struct TempDb(std::path::PathBuf);
impl TempDb {
    fn new(tag: &str) -> Self {
        let mut rng = OsRng.unwrap_err();
        let path =
            std::env::temp_dir().join(format!("kutup-chat-{tag}-{}.db", rng.random::<u64>()));
        TempDb(path)
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

#[test]
fn one_to_one_text_round_trip_through_wire_types() {
    let mut rng = OsRng.unwrap_err();

    // Both parties generate + "register" (device id 1 each, assigned by server).
    let mut alice = block_on(Session::generate(
        Rc::new(SqliteChatDb::open_in_memory().unwrap()),
        "alice",
        1,
        20,
        &mut rng,
    ))
    .unwrap();
    let mut bob = block_on(Session::generate(
        Rc::new(SqliteChatDb::open_in_memory().unwrap()),
        "bob",
        1,
        20,
        &mut rng,
    ))
    .unwrap();

    let bob_addr = ChatAddress::local("bob", 1);
    let alice_addr = ChatAddress::local("alice", 1);
    let bob_reg = bob.registration().unwrap().registration_id;
    let alice_reg = alice.registration().unwrap().registration_id;

    // Sanity: Bob's published bundle carries a PQ prekey and a signed prekey.
    let bob_bundle = serve_bundle(bob.registration().unwrap(), 1);
    assert!(
        !bob_bundle.kyber_pre_key.public_key.is_empty(),
        "PQ prekey present"
    );
    assert!(bob_bundle.signed_pre_key.signature.is_some());

    // Alice establishes to Bob's bundle and sends a text.
    block_on(alice.establish(&bob_addr, &bob_bundle, &mut rng)).unwrap();
    let msg1 = ChatContent::text("2026-07-13T10:00:00Z", 1, "hello bob 👋");
    let env1 = block_on(alice.encrypt(&bob_addr, bob_reg, &msg1, &mut rng)).unwrap();
    // The first message must be a session-establishing PreKey envelope.
    assert_eq!(env1.envelope_type, kutup_chat_proto::EnvelopeType::PreKey);
    assert_eq!(env1.device_id, 1);
    assert_eq!(env1.registration_id, bob_reg);

    // Bob decrypts it straight off the wire.
    let delivered1 = wrap(env1, "alice", 1);
    let got1 = block_on(bob.decrypt(&alice_addr, &delivered1, &mut rng)).unwrap();
    assert_eq!(got1.as_text().unwrap().text, "hello bob 👋");
    assert_eq!(got1.seq, 1);

    // Bob replies; steady-state messages are Message envelopes.
    let msg2 = ChatContent::text("2026-07-13T10:00:01Z", 1, "hi alice");
    let env2 = block_on(bob.encrypt(&alice_addr, alice_reg, &msg2, &mut rng)).unwrap();
    assert_eq!(env2.envelope_type, kutup_chat_proto::EnvelopeType::Message);
    let delivered2 = wrap(env2, "bob", 2);
    let got2 = block_on(alice.decrypt(&bob_addr, &delivered2, &mut rng)).unwrap();
    assert_eq!(got2.as_text().unwrap().text, "hi alice");

    // Several more rounds to tick the ratchet in both directions.
    for round in 2..8u64 {
        let m = ChatContent::text("t", round, format!("a->b {round}"));
        let e = block_on(alice.encrypt(&bob_addr, bob_reg, &m, &mut rng)).unwrap();
        let d =
            block_on(bob.decrypt(&alice_addr, &wrap(e, "alice", round + 10), &mut rng)).unwrap();
        assert_eq!(d.as_text().unwrap().text, format!("a->b {round}"));

        let m = ChatContent::text("t", round, format!("b->a {round}"));
        let e = block_on(bob.encrypt(&alice_addr, alice_reg, &m, &mut rng)).unwrap();
        let d = block_on(alice.decrypt(&bob_addr, &wrap(e, "bob", round + 20), &mut rng)).unwrap();
        assert_eq!(d.as_text().unwrap().text, format!("b->a {round}"));
    }
}

#[test]
fn device_state_survives_reopen() {
    let mut rng = OsRng.unwrap_err();
    let alice_db = TempDb::new("alice");
    let bob_db = TempDb::new("bob");

    let bob_addr = ChatAddress::local("bob", 1);
    let alice_addr = ChatAddress::local("alice", 1);

    // Session 1: establish and exchange one message each way, then drop both
    // sessions (closing their SQLite connections).
    let (bob_reg, alice_reg) = {
        let mut alice =
            block_on(Session::generate(alice_db.open(), "alice", 1, 10, &mut rng)).unwrap();
        let mut bob = block_on(Session::generate(bob_db.open(), "bob", 1, 10, &mut rng)).unwrap();
        let bob_reg = bob.registration().unwrap().registration_id;
        let alice_reg = alice.registration().unwrap().registration_id;

        let bundle = serve_bundle(bob.registration().unwrap(), 1);
        block_on(alice.complete_registration(1)).unwrap();
        block_on(bob.complete_registration(1)).unwrap();
        block_on(alice.establish(&bob_addr, &bundle, &mut rng)).unwrap();

        let e = block_on(alice.encrypt(
            &bob_addr,
            bob_reg,
            &ChatContent::text("t", 1, "before restart"),
            &mut rng,
        ))
        .unwrap();
        let got = block_on(bob.decrypt(&alice_addr, &wrap(e, "alice", 1), &mut rng)).unwrap();
        assert_eq!(got.as_text().unwrap().text, "before restart");

        (bob_reg, alice_reg)
    };

    // Session 2: reopen both devices from disk. Their ratchet state must continue
    // seamlessly — a message encrypted after reopen decrypts after reopen.
    {
        let mut alice = block_on(Session::open(alice_db.open(), "alice", 1)).unwrap();
        let mut bob = block_on(Session::open(bob_db.open(), "bob", 1)).unwrap();
        // Opened devices don't carry a fresh registration payload.
        assert!(alice.registration().is_none());
        assert!(bob.registration().is_none());

        // Alice → Bob continues her sender ratchet loaded from disk.
        let e = block_on(alice.encrypt(
            &bob_addr,
            bob_reg,
            &ChatContent::text("t", 2, "after restart"),
            &mut rng,
        ))
        .unwrap();
        let got = block_on(bob.decrypt(&alice_addr, &wrap(e, "alice", 2), &mut rng)).unwrap();
        assert_eq!(got.as_text().unwrap().text, "after restart");

        // And the reverse direction, proving Bob's state persisted too.
        let e = block_on(bob.encrypt(
            &alice_addr,
            alice_reg,
            &ChatContent::text("t", 3, "reply after restart"),
            &mut rng,
        ))
        .unwrap();
        let got = block_on(alice.decrypt(&bob_addr, &wrap(e, "bob", 3), &mut rng)).unwrap();
        assert_eq!(got.as_text().unwrap().text, "reply after restart");
    }
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let mut rng = OsRng.unwrap_err();
    let mut alice = block_on(Session::generate(
        Rc::new(SqliteChatDb::open_in_memory().unwrap()),
        "alice",
        1,
        5,
        &mut rng,
    ))
    .unwrap();
    let mut bob = block_on(Session::generate(
        Rc::new(SqliteChatDb::open_in_memory().unwrap()),
        "bob",
        1,
        5,
        &mut rng,
    ))
    .unwrap();
    let bob_addr = ChatAddress::local("bob", 1);
    let alice_addr = ChatAddress::local("alice", 1);

    let bundle = serve_bundle(bob.registration().unwrap(), 1);
    block_on(alice.establish(&bob_addr, &bundle, &mut rng)).unwrap();
    let msg = ChatContent::text("t", 1, "secret");
    let mut env = block_on(alice.encrypt(
        &bob_addr,
        bob.registration().unwrap().registration_id,
        &msg,
        &mut rng,
    ))
    .unwrap();

    // Flip a byte in the ciphertext: decryption must fail (never returns
    // unauthenticated plaintext).
    let mut raw = base64::engine::general_purpose::STANDARD
        .decode(&env.content)
        .unwrap();
    let n = raw.len();
    raw[n / 2] ^= 0x01;
    env.content = base64::engine::general_purpose::STANDARD.encode(&raw);

    let delivered = wrap(env, "alice", 1);
    assert!(
        block_on(bob.decrypt(&alice_addr, &delivered, &mut rng)).is_err(),
        "tampered ciphertext must be rejected"
    );
}
