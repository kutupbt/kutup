//! Two-party PQXDH + Triple Ratchet round-trip, runnable natively and under wasm.
//!
//! Mirrors the canonical setup in libsignal's own `protocol/test-support/src/lib.rs`:
//! Bob publishes a PQXDH prekey bundle (signed prekey + one-time prekey + Kyber1024
//! prekey), Alice processes it, both sides exchange messages in both directions, and we
//! assert the sessions satisfy `SessionUsabilityRequirements::all()` — i.e. established
//! with PQXDH *and* carrying live SPQR (post-quantum ratchet) state.
//!
//! All libsignal futures resolve immediately with the in-memory stores, so
//! `now_or_never()` drives them without an executor — the same trick works in a browser.

use std::time::SystemTime;

use futures_util::FutureExt as _;
use libsignal_protocol::*;
use rand::rngs::OsRng;
use rand::TryRngCore as _;

/// Number of round-trip message pairs. Multiple rounds tick both the symmetric-key and
/// DH ratchets, and (per SPQR's "sparse" design) exercise PQ epoch advancement.
const ROUNDS: usize = 8;

struct Party {
    address: ProtocolAddress,
    store: InMemSignalProtocolStore,
}

impl Party {
    fn new(name: &str, rng: &mut (impl rand::Rng + rand::CryptoRng)) -> Self {
        Self {
            address: ProtocolAddress::new(name.to_owned(), DeviceId::new(1).unwrap()),
            store: InMemSignalProtocolStore::new(IdentityKeyPair::generate(rng), rng.random())
                .expect("store"),
        }
    }

    /// Build a PQXDH prekey bundle for this party (Bob's role). Follows
    /// test-support's `process_pre_key` step by step.
    fn make_pqxdh_bundle(&mut self, rng: &mut (impl rand::Rng + rand::CryptoRng)) -> PreKeyBundle {
        let identity = self
            .store
            .get_identity_key_pair()
            .now_or_never()
            .expect("sync")
            .expect("identity");

        // Signed (EC) prekey
        let signed_pre_key_pair = KeyPair::generate(rng);
        let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
        let signed_pre_key_signature = identity
            .private_key()
            .calculate_signature(&signed_pre_key_public, rng)
            .expect("sign");
        let signed_pre_key_id: SignedPreKeyId = 1.into();
        self.store
            .save_signed_pre_key(
                signed_pre_key_id,
                &SignedPreKeyRecord::new(
                    signed_pre_key_id,
                    Timestamp::from_epoch_millis(42),
                    &signed_pre_key_pair,
                    &signed_pre_key_signature,
                ),
            )
            .now_or_never()
            .expect("sync")
            .expect("save signed prekey");

        // One-time (EC) prekey
        let one_time_pre_key = KeyPair::generate(rng);
        let pre_key_id: PreKeyId = 2.into();
        self.store
            .save_pre_key(pre_key_id, &PreKeyRecord::new(pre_key_id, &one_time_pre_key))
            .now_or_never()
            .expect("sync")
            .expect("save prekey");

        // Kyber1024 prekey — this is what upgrades X3DH to PQXDH.
        let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);
        let kyber_pre_key_public = kyber_pre_key_pair.public_key.serialize();
        let kyber_pre_key_signature = identity
            .private_key()
            .calculate_signature(&kyber_pre_key_public, rng)
            .expect("sign kyber");
        let kyber_pre_key_id: KyberPreKeyId = 3.into();
        self.store
            .save_kyber_pre_key(
                kyber_pre_key_id,
                &KyberPreKeyRecord::new(
                    kyber_pre_key_id,
                    Timestamp::from_epoch_millis(42),
                    &kyber_pre_key_pair,
                    &kyber_pre_key_signature,
                ),
            )
            .now_or_never()
            .expect("sync")
            .expect("save kyber prekey");

        PreKeyBundle::new(
            self.store
                .get_local_registration_id()
                .now_or_never()
                .expect("sync")
                .expect("registration id"),
            DeviceId::new(1).unwrap(),
            Some((pre_key_id, one_time_pre_key.public_key)),
            signed_pre_key_id,
            signed_pre_key_pair.public_key,
            signed_pre_key_signature.into_vec(),
            kyber_pre_key_id,
            kyber_pre_key_pair.public_key,
            kyber_pre_key_signature.into_vec(),
            *identity.identity_key(),
        )
        .expect("bundle")
    }

    fn encrypt(
        &mut self,
        to: &ProtocolAddress,
        plaintext: &[u8],
        rng: &mut (impl rand::Rng + rand::CryptoRng),
    ) -> CiphertextMessage {
        message_encrypt(
            plaintext,
            to,
            &self.address.clone(),
            &mut self.store.session_store,
            &mut self.store.identity_store,
            SystemTime::UNIX_EPOCH,
            rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("encrypt")
    }

    fn decrypt(
        &mut self,
        from: &ProtocolAddress,
        wire: &CiphertextMessage,
        rng: &mut (impl rand::Rng + rand::CryptoRng),
    ) -> Vec<u8> {
        // Re-parse from serialized bytes: proves wire-format round-tripping, like
        // test-support's send_message does.
        let reparsed = match wire.message_type() {
            CiphertextMessageType::PreKey => CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(wire.serialize()).expect("reparse prekey msg"),
            ),
            CiphertextMessageType::Whisper => CiphertextMessage::SignalMessage(
                SignalMessage::try_from(wire.serialize()).expect("reparse msg"),
            ),
            other => panic!("unexpected message type {other:?}"),
        };
        message_decrypt(
            &reparsed,
            from,
            &self.address.clone(),
            &mut self.store.session_store,
            &mut self.store.identity_store,
            &mut self.store.pre_key_store,
            &self.store.signed_pre_key_store,
            &mut self.store.kyber_pre_key_store,
            rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("decrypt")
    }

    fn assert_fully_pq_session(&self, with: &ProtocolAddress) {
        let session = self
            .store
            .load_session(with)
            .now_or_never()
            .expect("sync")
            .expect("load")
            .expect("session exists");
        assert!(
            session
                .has_usable_sender_chain(
                    SystemTime::UNIX_EPOCH,
                    SessionUsabilityRequirements::all(),
                )
                .expect("valid session"),
            "session must satisfy NotStale | EstablishedWithPqxdh | Spqr"
        );
    }
}

fn main() {
    let mut rng = OsRng.unwrap_err();

    let mut alice = Party::new("alice", &mut rng);
    let mut bob = Party::new("bob", &mut rng);

    // Alice fetches Bob's PQXDH bundle and initiates.
    let bundle = bob.make_pqxdh_bundle(&mut rng);
    process_prekey_bundle(
        &bob.address,
        &alice.address.clone(),
        &mut alice.store.session_store,
        &mut alice.store.identity_store,
        &bundle,
        SystemTime::UNIX_EPOCH,
        &mut rng,
    )
    .now_or_never()
    .expect("sync")
    .expect("process bundle");
    alice.assert_fully_pq_session(&bob.address);

    let mut prekey_msg_size = 0usize;
    let mut msg_size = 0usize;

    for round in 0..ROUNDS {
        let a2b = format!("a->b round {round}");
        let wire = alice.encrypt(&bob.address, a2b.as_bytes(), &mut rng);
        match round {
            0 => {
                assert_eq!(wire.message_type(), CiphertextMessageType::PreKey);
                prekey_msg_size = wire.serialize().len();
            }
            _ => msg_size = wire.serialize().len(),
        }
        assert_eq!(bob.decrypt(&alice.address, &wire, &mut rng), a2b.as_bytes());

        let b2a = format!("b->a round {round}");
        let wire = bob.encrypt(&alice.address, b2a.as_bytes(), &mut rng);
        assert_eq!(
            alice.decrypt(&bob.address, &wire, &mut rng),
            b2a.as_bytes()
        );
    }

    // Both directions confirmed; both sessions must still be fully PQ
    // (PQXDH-established AND live SPQR state) after ratcheting.
    alice.assert_fully_pq_session(&bob.address);
    bob.assert_fully_pq_session(&alice.address);

    println!("PASS: {ROUNDS} PQXDH+TripleRatchet round-trips (both directions)");
    println!("      sessions satisfy SessionUsabilityRequirements::all() on both sides");
    println!("      wire sizes: PreKeySignalMessage={prekey_msg_size}B, SignalMessage={msg_size}B (13B plaintext)");
    println!("      arch: {}", std::env::consts::ARCH);
}
