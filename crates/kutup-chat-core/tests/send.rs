//! The send-orchestration proof: multi-device fan-out, `409 DeviceListMismatch`
//! recovery (missing / extra / stale-reinstall), the safety-number-change signal,
//! and the durable `sendId` outbox (crash-then-resend), all driven through a mock
//! transport. The mock's futures are immediately ready, so `futures_executor`
//! polls the engine's async methods to completion with no real runtime.

use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;

use async_trait::async_trait;
use futures_executor::block_on;
use kutup_chat_core::{
    AccountAuthority, ChatAddress, ChatContent, ChatDb, ChatError, ChatTransport, Engine, Result,
    SendOutcome, Session, SqliteChatDb,
};
use kutup_chat_proto::{
    DeliveredEnvelope, DeviceListMismatch, DeviceManifest, DevicePreKeyBundle, MailboxPage,
    ManifestDevice, RegisterChatDeviceRequest, SendMessagesRequest, UserPreKeyBundlesResponse,
};
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng, TryRngCore as _};

// ----- test helpers -----

fn test_rng() -> impl Rng + CryptoRng {
    OsRng.unwrap_err()
}

fn device<R: Rng + CryptoRng>(user: &str, device_id: u32, rng: &mut R) -> Session {
    block_on(Session::generate(
        Rc::new(SqliteChatDb::open_in_memory().unwrap()),
        user,
        device_id,
        10,
        rng,
    ))
    .unwrap()
}

/// A per-device bundle served from a device's published registration.
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

fn bundle_of(s: &Session, device_id: u32) -> DevicePreKeyBundle {
    serve_bundle(s.registration().unwrap(), device_id)
}

fn reg_id(s: &Session) -> u32 {
    s.registration().unwrap().registration_id
}

/// Turn a delivered ciphertext back into a `DeliveredEnvelope` a recipient decrypts.
fn wrap(env: &kutup_chat_proto::OutgoingEnvelope, sender: &str) -> DeliveredEnvelope {
    DeliveredEnvelope {
        id: format!("m-{}", env.device_id),
        cursor: 1,
        sender: Some(sender.to_string()),
        sender_device_id: 1,
        envelope_type: env.envelope_type,
        suite: env.suite,
        content: env.content.clone(),
        server_timestamp: "2026-07-14T10:00:00Z".into(),
    }
}

// ----- the mock server -----

/// A crypto-blind mailbox server. Scriptable between top-level send calls: what
/// `fetch_bundles` returns, the true active `(deviceId, registrationId)` set the
/// device-list contract is enforced against, and forced transport failures.
#[derive(Default)]
struct MockServer {
    /// Each `fetch_bundles` pops the front; the last entry repeats.
    fetch_script: RefCell<Vec<Vec<DevicePreKeyBundle>>>,
    manifest_script: RefCell<Vec<Option<DeviceManifest>>>,
    own_manifest: RefCell<Option<DeviceManifest>>,
    active: RefCell<Vec<(u32, u32)>>,
    fail_sends: RefCell<u32>,
    delivered: RefCell<Vec<(String, Vec<kutup_chat_proto::OutgoingEnvelope>)>>,
    seen_send_ids: RefCell<HashSet<String>>,
}

impl MockServer {
    fn script(&self, pages: Vec<Vec<DevicePreKeyBundle>>) {
        *self.fetch_script.borrow_mut() = pages;
    }
    fn set_active(&self, active: Vec<(u32, u32)>) {
        *self.active.borrow_mut() = active;
    }
    fn script_manifests(&self, manifests: Vec<Option<DeviceManifest>>) {
        *self.manifest_script.borrow_mut() = manifests;
    }
    /// The envelopes of the most recent accepted send.
    fn last_delivered(&self) -> Vec<kutup_chat_proto::OutgoingEnvelope> {
        self.delivered.borrow().last().unwrap().1.clone()
    }
}

#[async_trait(?Send)]
impl ChatTransport for MockServer {
    async fn register_device(&self, _req: &RegisterChatDeviceRequest) -> Result<u32> {
        Ok(1)
    }

    async fn fetch_bundles(&self, username: &str) -> Result<UserPreKeyBundlesResponse> {
        let mut script = self.fetch_script.borrow_mut();
        let devices = if script.len() > 1 {
            script.remove(0)
        } else {
            script.first().cloned().unwrap_or_default()
        };
        let mut manifests = self.manifest_script.borrow_mut();
        let manifest = if manifests.len() > 1 {
            manifests.remove(0)
        } else {
            manifests.first().cloned().unwrap_or(None)
        };
        Ok(UserPreKeyBundlesResponse {
            username: username.to_string(),
            devices,
            manifest,
        })
    }

    async fn fetch_manifest(&self, _username: &str) -> Result<Option<DeviceManifest>> {
        Ok(self.own_manifest.borrow().clone())
    }

    async fn publish_manifest(&self, manifest: &DeviceManifest) -> Result<DeviceManifest> {
        *self.own_manifest.borrow_mut() = Some(manifest.clone());
        Ok(manifest.clone())
    }

    async fn send(&self, _username: &str, req: &SendMessagesRequest) -> Result<SendOutcome> {
        {
            let mut fail = self.fail_sends.borrow_mut();
            if *fail > 0 {
                *fail -= 1;
                return Err(ChatError::Transport("simulated network failure".into()));
            }
        }
        let active = self.active.borrow().clone();
        let req_ids: Vec<u32> = req.envelopes.iter().map(|e| e.device_id).collect();
        let active_ids: Vec<u32> = active.iter().map(|(d, _)| *d).collect();
        let missing_devices: Vec<u32> = active_ids
            .iter()
            .copied()
            .filter(|d| !req_ids.contains(d))
            .collect();
        let extra_devices: Vec<u32> = req_ids
            .iter()
            .copied()
            .filter(|d| !active_ids.contains(d))
            .collect();
        let stale_devices: Vec<u32> = req
            .envelopes
            .iter()
            .filter(|e| {
                active
                    .iter()
                    .any(|(d, r)| *d == e.device_id && *r != e.registration_id)
            })
            .map(|e| e.device_id)
            .collect();

        if missing_devices.is_empty() && extra_devices.is_empty() && stale_devices.is_empty() {
            let deduplicated = !self.seen_send_ids.borrow_mut().insert(req.send_id.clone());
            self.delivered
                .borrow_mut()
                .push((req.send_id.clone(), req.envelopes.clone()));
            Ok(SendOutcome::Delivered { deduplicated })
        } else {
            Ok(SendOutcome::Mismatch(DeviceListMismatch {
                missing_devices,
                stale_devices,
                extra_devices,
            }))
        }
    }

    async fn drain(
        &self,
        _device_id: u32,
        _after: Option<u64>,
        _limit: u32,
    ) -> Result<MailboxPage> {
        Ok(MailboxPage {
            envelopes: vec![],
            more: false,
        })
    }

    async fn ack(&self, _device_id: u32, _ids: &[String]) -> Result<()> {
        Ok(())
    }
}

/// Decrypt the ciphertext addressed to `dst` out of a delivered set.
fn decrypt_for<R: Rng + CryptoRng>(
    dst: &mut Session,
    from: &ChatAddress,
    envelopes: &[kutup_chat_proto::OutgoingEnvelope],
    device_id: u32,
    rng: &mut R,
) -> ChatContent {
    let env = envelopes
        .iter()
        .find(|e| e.device_id == device_id)
        .expect("an envelope for the device");
    block_on(dst.decrypt(from, &wrap(env, &from.user), rng)).unwrap()
}

fn signed_manifest(bundle: &DevicePreKeyBundle) -> DeviceManifest {
    AccountAuthority::derive(&[11; 32])
        .unwrap()
        .sign_manifest(
            1,
            None,
            vec![ManifestDevice {
                device_id: bundle.device_id,
                identity_key: bundle.identity_key.clone(),
                registration_id: bundle.registration_id,
            }],
            "2026-07-15T12:00:00Z",
        )
        .unwrap()
}

// ----- the tests -----

#[test]
fn local_devices_extend_only_the_prior_account_signed_manifest() {
    let mut rng = test_rng();
    let server = Rc::new(MockServer::default());
    let authority = AccountAuthority::derive(&[12; 32]).unwrap();

    let mut first = Engine::new(device("alice", 1, &mut rng), server.clone());
    let v1 = block_on(first.sync_own_manifest(&authority, "2026-07-15T12:00:00Z")).unwrap();
    assert_eq!(v1.version, 1);
    assert_eq!(v1.devices, vec![first.session().manifest_device()]);

    let mut second = Engine::new(device("alice", 2, &mut rng), server);
    let v2 = block_on(second.sync_own_manifest(&authority, "2026-07-15T12:01:00Z")).unwrap();
    assert_eq!(v2.version, 2);
    assert_eq!(
        v2.previous_hash.as_deref(),
        Some(v1.manifest_hash().unwrap().as_str())
    );
    assert_eq!(v2.devices.len(), 2);
    assert_eq!(v2.devices[0], v1.devices[0]);
    assert_eq!(v2.devices[1], second.session().manifest_device());
}

#[test]
fn production_engine_requires_and_persists_a_matching_signed_manifest() {
    let mut rng = test_rng();
    let bob = device("bob", 1, &mut rng);
    let bundle = bundle_of(&bob, 1);
    let manifest = signed_manifest(&bundle);
    let server = Rc::new(MockServer::default());
    server.script(vec![vec![bundle.clone()], vec![bundle.clone()]]);
    server.script_manifests(vec![None, Some(manifest.clone())]);
    server.set_active(vec![(1, reg_id(&bob))]);

    let alice_db = Rc::new(SqliteChatDb::open_in_memory().unwrap());
    let alice_session = block_on(Session::generate(
        alice_db.clone(),
        "alice",
        1,
        10,
        &mut rng,
    ))
    .unwrap();
    let mut alice = Engine::new(alice_session, server);
    let msg = ChatContent::text("secure-1", 1, "manifest required");

    assert!(matches!(
        block_on(alice.send("secure-1", "bob", &msg, &mut rng)),
        Err(ChatError::Trust(_))
    ));
    assert_eq!(block_on(alice.pending_send_count()).unwrap(), 0);

    let summary = block_on(alice.send("secure-2", "bob", &msg, &mut rng)).unwrap();
    assert!(summary.delivered);
    let pin = block_on(alice_db.load_manifest_trust("bob"))
        .unwrap()
        .unwrap();
    assert_eq!(pin.highest_version, 1);
    assert_eq!(pin.authority_key_id, manifest.authority_key_id);
}

#[test]
fn production_engine_rejects_a_bundle_device_not_in_the_manifest() {
    let mut rng = test_rng();
    let bob1 = device("bob", 1, &mut rng);
    let bob2 = device("bob", 2, &mut rng);
    let b1 = bundle_of(&bob1, 1);
    let b2 = bundle_of(&bob2, 2);
    let server = Rc::new(MockServer::default());
    server.script(vec![vec![b1.clone(), b2]]);
    server.script_manifests(vec![Some(signed_manifest(&b1))]);
    server.set_active(vec![(1, reg_id(&bob1)), (2, reg_id(&bob2))]);

    let mut alice = Engine::new(device("alice", 1, &mut rng), server);
    let msg = ChatContent::text("secure-injection", 1, "reject injection");
    assert!(matches!(
        block_on(alice.send("secure-injection", "bob", &msg, &mut rng)),
        Err(ChatError::Trust(_))
    ));
    assert_eq!(block_on(alice.pending_send_count()).unwrap(), 0);
}

#[test]
fn fans_out_to_two_devices_and_recovers_missing() {
    let mut rng = test_rng();
    let mut bob1 = device("bob", 1, &mut rng);
    let mut bob2 = device("bob", 2, &mut rng);
    let (b1, b2) = (bundle_of(&bob1, 1), bundle_of(&bob2, 2));

    let server = Rc::new(MockServer::default());
    // First fetch is stale (only device 1); the re-fetch after the 409 reveals both.
    server.script(vec![vec![b1.clone()], vec![b1.clone(), b2.clone()]]);
    server.set_active(vec![(1, reg_id(&bob1)), (2, reg_id(&bob2))]);

    let mut alice = Engine::new_for_development(device("alice", 1, &mut rng), server.clone());
    let msg = ChatContent::text("t", 1, "hi both devices");
    let summary = block_on(alice.send("s1", "bob", &msg, &mut rng)).unwrap();

    assert!(summary.delivered);
    assert_eq!(summary.attempts, 2, "one 409 recovery round, then success");
    assert!(summary.safety_number_changes.is_empty());
    assert_eq!(
        block_on(alice.pending_send_count()).unwrap(),
        0,
        "outbox drained"
    );

    let alice_addr = ChatAddress::local("alice", 1);
    let delivered = server.last_delivered();
    assert_eq!(delivered.len(), 2, "both devices addressed");
    assert_eq!(
        decrypt_for(&mut bob1, &alice_addr, &delivered, 1, &mut rng)
            .as_text()
            .unwrap()
            .text,
        "hi both devices"
    );
    assert_eq!(
        decrypt_for(&mut bob2, &alice_addr, &delivered, 2, &mut rng)
            .as_text()
            .unwrap()
            .text,
        "hi both devices"
    );
}

#[test]
fn drops_extra_device() {
    let mut rng = test_rng();
    let mut bob1 = device("bob", 1, &mut rng);
    let bob2 = device("bob", 2, &mut rng);
    let (b1, b2) = (bundle_of(&bob1, 1), bundle_of(&bob2, 2));

    let server = Rc::new(MockServer::default());
    // First fetch is stale (shows a device the peer removed); re-fetch shows only 1.
    server.script(vec![vec![b1.clone(), b2.clone()], vec![b1.clone()]]);
    server.set_active(vec![(1, reg_id(&bob1))]);

    let mut alice = Engine::new_for_development(device("alice", 1, &mut rng), server.clone());
    let msg = ChatContent::text("t", 1, "only device one is real");
    let summary = block_on(alice.send("s2", "bob", &msg, &mut rng)).unwrap();

    assert!(summary.delivered);
    assert_eq!(summary.attempts, 2);
    let delivered = server.last_delivered();
    assert_eq!(delivered.len(), 1, "the extra device was dropped");
    assert_eq!(delivered[0].device_id, 1);
    assert_eq!(
        decrypt_for(
            &mut bob1,
            &ChatAddress::local("alice", 1),
            &delivered,
            1,
            &mut rng
        )
        .as_text()
        .unwrap()
        .text,
        "only device one is real"
    );
}

#[test]
fn reinstalled_peer_rekeys_and_flags_safety_number() {
    let mut rng = test_rng();
    let mut bob_v1 = device("bob", 1, &mut rng);
    let b_v1 = bundle_of(&bob_v1, 1);

    let server = Rc::new(MockServer::default());
    server.script(vec![vec![b_v1.clone()]]);
    server.set_active(vec![(1, reg_id(&bob_v1))]);

    let mut alice = Engine::new_for_development(device("alice", 1, &mut rng), server.clone());
    let alice_addr = ChatAddress::local("alice", 1);

    // First conversation with the original install.
    let s1 = block_on(alice.send(
        "r1",
        "bob",
        &ChatContent::text("t", 1, "hello v1"),
        &mut rng,
    ))
    .unwrap();
    assert!(s1.delivered && s1.safety_number_changes.is_empty());
    assert_eq!(
        decrypt_for(
            &mut bob_v1,
            &alice_addr,
            &server.last_delivered(),
            1,
            &mut rng
        )
        .as_text()
        .unwrap()
        .text,
        "hello v1"
    );

    // Bob reinstalls: brand-new identity + registration id, same device id.
    let mut bob_v2 = device("bob", 1, &mut rng);
    let b_v2 = bundle_of(&bob_v2, 1);
    // Alice's directory view is still stale (v1) until the 409 makes her re-fetch.
    server.script(vec![vec![b_v1.clone()], vec![b_v2.clone()]]);
    server.set_active(vec![(1, reg_id(&bob_v2))]);

    let s2 = block_on(alice.send(
        "r2",
        "bob",
        &ChatContent::text("t", 2, "hello v2"),
        &mut rng,
    ))
    .unwrap();
    assert!(s2.delivered);
    assert_eq!(s2.attempts, 2, "stale 409 → re-key → resend");
    assert_eq!(
        s2.safety_number_changes,
        vec![ChatAddress::local("bob", 1)],
        "the reinstall surfaces a safety-number change"
    );
    // The re-keyed message decrypts on the NEW install.
    assert_eq!(
        decrypt_for(
            &mut bob_v2,
            &alice_addr,
            &server.last_delivered(),
            1,
            &mut rng
        )
        .as_text()
        .unwrap()
        .text,
        "hello v2"
    );
}

#[test]
fn outbox_persists_across_failure_and_flush_resends() {
    let mut rng = test_rng();
    let mut bob1 = device("bob", 1, &mut rng);
    let b1 = bundle_of(&bob1, 1);

    let server = Rc::new(MockServer::default());
    server.script(vec![vec![b1.clone()]]);
    server.set_active(vec![(1, reg_id(&bob1))]);
    *server.fail_sends.borrow_mut() = 1; // the first network send fails after enqueue

    let mut alice = Engine::new_for_development(device("alice", 1, &mut rng), server.clone());
    let msg = ChatContent::text("t", 1, "survives a crash");

    // The send fails at the transport, but the ciphertext is already durably queued.
    let err = block_on(alice.send("s4", "bob", &msg, &mut rng));
    assert!(matches!(err, Err(ChatError::Transport(_))));
    assert_eq!(
        block_on(alice.pending_send_count()).unwrap(),
        1,
        "outbox retained"
    );

    // Later (or after restart) the outbox flush resends the stored ciphertext.
    let summaries = block_on(alice.flush_outbox(&mut rng)).unwrap();
    assert_eq!(summaries.len(), 1);
    assert!(summaries[0].delivered);
    assert_eq!(
        block_on(alice.pending_send_count()).unwrap(),
        0,
        "outbox cleared"
    );
    let history = block_on(alice.session().sent_history()).unwrap();
    assert_eq!(history.len(), 1);
    assert!(history[0].delivered);
    assert_eq!(
        serde_json::from_slice::<ChatContent>(&history[0].content)
            .unwrap()
            .as_text()
            .unwrap()
            .text,
        "survives a crash"
    );

    let delivery_count = server.delivered.borrow().len();
    let repeated = block_on(alice.send("s4", "bob", &msg, &mut rng)).unwrap();
    assert!(repeated.delivered && repeated.deduplicated);
    assert_eq!(repeated.attempts, 0);
    assert_eq!(server.delivered.borrow().len(), delivery_count);

    assert_eq!(
        decrypt_for(
            &mut bob1,
            &ChatAddress::local("alice", 1),
            &server.last_delivered(),
            1,
            &mut rng
        )
        .as_text()
        .unwrap()
        .text,
        "survives a crash"
    );
}
