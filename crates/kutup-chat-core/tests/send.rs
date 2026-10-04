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
    AccountAuthority, AuthorityTrust, ChatAddress, ChatContent, ChatDb, ChatError, ChatTransport,
    ContactState, Engine, Result, SendOutcome, Session, SqliteChatDb,
};
use kutup_chat_proto::{
    AccountManifestDeviceV1, AccountManifestHistoryPageV1, AccountManifestPublicationV1,
    AccountManifestV1, DeliveredEnvelope, DeviceListMismatch, DevicePreKeyBundle,
    DirectChatSuiteId, MailboxPage, OwnChatProfileResponse, PutChatProfileRequest, ReceiptState,
    RegisterChatDeviceRequest, SendMessagesRequest, UserPreKeyBundlesResponse,
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
        sealed_sender: false,
        sender_device_id: 1,
        envelope_type: env.envelope_type,
        suite: env.suite,
        content: env.content.clone(),
        server_timestamp: "2026-07-14T10:00:00Z".into(),
        send_id: None,
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
    manifest_script: RefCell<Vec<Option<AccountManifestV1>>>,
    sync_fetch_script: RefCell<Vec<Vec<DevicePreKeyBundle>>>,
    sync_manifest_script: RefCell<Vec<Option<AccountManifestV1>>>,
    own_manifest: RefCell<Option<AccountManifestV1>>,
    manifest_history: RefCell<Vec<AccountManifestV1>>,
    active: RefCell<Vec<(u32, u32)>>,
    sync_active: RefCell<Vec<(u32, u32)>>,
    fail_sends: RefCell<u32>,
    fail_sync_sends: RefCell<u32>,
    fail_profile_uploads: RefCell<u32>,
    own_profile: RefCell<Option<PutChatProfileRequest>>,
    delivered: RefCell<Vec<(String, Vec<kutup_chat_proto::OutgoingEnvelope>)>>,
    synced: RefCell<Vec<(String, Vec<kutup_chat_proto::OutgoingEnvelope>)>>,
    sync_mailbox: RefCell<Vec<DeliveredEnvelope>>,
    seen_send_ids: RefCell<HashSet<String>>,
    seen_sync_ids: RefCell<HashSet<String>>,
}

impl MockServer {
    fn script(&self, pages: Vec<Vec<DevicePreKeyBundle>>) {
        *self.fetch_script.borrow_mut() = pages;
    }
    fn set_active(&self, active: Vec<(u32, u32)>) {
        *self.active.borrow_mut() = active;
    }
    fn script_sync(&self, pages: Vec<Vec<DevicePreKeyBundle>>) {
        *self.sync_fetch_script.borrow_mut() = pages;
    }
    fn set_sync_active(&self, active: Vec<(u32, u32)>) {
        *self.sync_active.borrow_mut() = active;
    }
    fn script_manifests(&self, manifests: Vec<Option<AccountManifestV1>>) {
        *self.manifest_script.borrow_mut() = manifests;
    }
    fn script_sync_manifests(&self, manifests: Vec<Option<AccountManifestV1>>) {
        *self.sync_manifest_script.borrow_mut() = manifests;
    }
    /// The envelopes of the most recent accepted send.
    fn last_delivered(&self) -> Vec<kutup_chat_proto::OutgoingEnvelope> {
        self.delivered.borrow().last().unwrap().1.clone()
    }
    fn last_synced(&self) -> Vec<kutup_chat_proto::OutgoingEnvelope> {
        self.synced.borrow().last().unwrap().1.clone()
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
            username: manifest
                .as_ref()
                .map_or_else(|| username.to_string(), |manifest| manifest.account.clone()),
            devices,
            manifest,
        })
    }

    async fn fetch_sync_bundles(
        &self,
        username: &str,
        _current_device_id: u32,
    ) -> Result<UserPreKeyBundlesResponse> {
        let mut script = self.sync_fetch_script.borrow_mut();
        let devices = if script.len() > 1 {
            script.remove(0)
        } else {
            script.first().cloned().unwrap_or_default()
        };
        let mut manifests = self.sync_manifest_script.borrow_mut();
        let manifest = if manifests.len() > 1 {
            manifests.remove(0)
        } else {
            manifests.first().cloned().unwrap_or(None)
        };
        Ok(UserPreKeyBundlesResponse {
            username: manifest
                .as_ref()
                .map_or_else(|| username.to_string(), |manifest| manifest.account.clone()),
            devices,
            manifest,
        })
    }

    async fn fetch_manifest(&self, _username: &str) -> Result<Option<AccountManifestV1>> {
        Ok(self.own_manifest.borrow().clone())
    }

    async fn fetch_manifest_history(
        &self,
        _username: &str,
        _from_sequence: u64,
        to_sequence: u64,
        page_from_sequence: u64,
    ) -> Result<AccountManifestHistoryPageV1> {
        let manifests = self
            .manifest_history
            .borrow()
            .iter()
            .filter(|manifest| {
                manifest.sequence >= page_from_sequence && manifest.sequence <= to_sequence
            })
            .cloned()
            .collect::<Vec<_>>();
        Ok(AccountManifestHistoryPageV1 {
            account: manifests
                .first()
                .map(|manifest| manifest.account.clone())
                .unwrap_or_default(),
            from_sequence: page_from_sequence,
            to_sequence,
            manifests,
            next_sequence: None,
        })
    }

    async fn publish_manifest(
        &self,
        manifest: &AccountManifestV1,
    ) -> Result<AccountManifestPublicationV1> {
        *self.own_manifest.borrow_mut() = Some(manifest.clone());
        let mut history = self.manifest_history.borrow_mut();
        if history
            .last()
            .is_none_or(|prior| prior.sequence < manifest.sequence)
        {
            history.push(manifest.clone());
        }
        Ok(AccountManifestPublicationV1 {
            manifest: manifest.clone(),
        })
    }

    async fn fetch_own_profile(&self) -> Result<Option<OwnChatProfileResponse>> {
        Ok(self.own_profile.borrow().clone())
    }

    async fn publish_profile(
        &self,
        profile: &PutChatProfileRequest,
    ) -> Result<OwnChatProfileResponse> {
        let mut failures = self.fail_profile_uploads.borrow_mut();
        if *failures > 0 {
            *failures -= 1;
            return Err(ChatError::Transport(
                "simulated profile publication failure".into(),
            ));
        }
        *self.own_profile.borrow_mut() = Some(profile.clone());
        Ok(profile.clone())
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

    async fn send_sync(&self, req: &SendMessagesRequest) -> Result<SendOutcome> {
        {
            let mut fail = self.fail_sync_sends.borrow_mut();
            if *fail > 0 {
                *fail -= 1;
                return Err(ChatError::Transport(
                    "simulated sync network failure".into(),
                ));
            }
        }
        let active: Vec<(u32, u32)> = self
            .sync_active
            .borrow()
            .iter()
            .copied()
            .filter(|(device_id, _)| *device_id != req.sender_device_id)
            .collect();
        let req_ids: Vec<u32> = req.envelopes.iter().map(|e| e.device_id).collect();
        let missing_devices: Vec<u32> = active
            .iter()
            .map(|(device_id, _)| *device_id)
            .filter(|device_id| !req_ids.contains(device_id))
            .collect();
        let extra_devices: Vec<u32> = req_ids
            .iter()
            .copied()
            .filter(|device_id| !active.iter().any(|(active, _)| active == device_id))
            .collect();
        let stale_devices: Vec<u32> = req
            .envelopes
            .iter()
            .filter(|envelope| {
                active.iter().any(|(device_id, registration_id)| {
                    *device_id == envelope.device_id && *registration_id != envelope.registration_id
                })
            })
            .map(|envelope| envelope.device_id)
            .collect();
        if !missing_devices.is_empty() || !stale_devices.is_empty() || !extra_devices.is_empty() {
            return Ok(SendOutcome::Mismatch(DeviceListMismatch {
                missing_devices,
                stale_devices,
                extra_devices,
            }));
        }

        let deduplicated = !self.seen_sync_ids.borrow_mut().insert(req.send_id.clone());
        self.synced
            .borrow_mut()
            .push((req.send_id.clone(), req.envelopes.clone()));
        if !deduplicated {
            let mut mailbox = self.sync_mailbox.borrow_mut();
            let first_cursor = mailbox.len() as u64 + 1;
            for (offset, envelope) in req.envelopes.iter().enumerate() {
                mailbox.push(DeliveredEnvelope {
                    id: format!("sync-{}-{}", req.send_id, envelope.device_id),
                    cursor: first_cursor + offset as u64,
                    sender: Some("alice".into()),
                    sealed_sender: false,
                    sender_device_id: req.sender_device_id,
                    envelope_type: envelope.envelope_type,
                    suite: envelope.suite,
                    content: envelope.content.clone(),
                    server_timestamp: "2026-07-16T10:00:00Z".into(),
                    send_id: None,
                });
            }
        }
        Ok(SendOutcome::Delivered { deduplicated })
    }

    async fn drain(&self, device_id: u32, after: Option<u64>, limit: u32) -> Result<MailboxPage> {
        let mut envelopes: Vec<_> = self
            .sync_mailbox
            .borrow()
            .iter()
            .filter(|envelope| {
                envelope.sender_device_id != device_id
                    && after.is_none_or(|cursor| envelope.cursor > cursor)
            })
            .take(limit as usize)
            .cloned()
            .collect();
        let more = envelopes.len() > limit as usize;
        envelopes.truncate(limit as usize);
        Ok(MailboxPage { envelopes, more })
    }

    async fn ack(&self, _device_id: u32, ids: &[String]) -> Result<()> {
        self.sync_mailbox
            .borrow_mut()
            .retain(|envelope| !ids.contains(&envelope.id));
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

fn signed_manifest(account: &str, bundle: &DevicePreKeyBundle) -> AccountManifestV1 {
    signed_manifest_with_authority(
        account,
        bundle,
        &AccountAuthority::derive(&[11; 32]).unwrap(),
    )
}

fn signed_manifest_with_authority(
    account: &str,
    bundle: &DevicePreKeyBundle,
    authority: &AccountAuthority,
) -> AccountManifestV1 {
    authority
        .sign_manifest(
            account,
            1,
            None,
            vec![AccountManifestDeviceV1 {
                device_id: bundle.device_id,
                direct_chat_suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
                identity_key: bundle.identity_key.clone(),
                registration_id: bundle.registration_id,
                mls: None,
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
    first.set_local_server("example.test").unwrap();
    let v1 = block_on(first.sync_own_manifest(&authority, "2026-07-15T12:00:00Z")).unwrap();
    assert_eq!(v1.sequence, 1);
    assert_eq!(v1.devices.len(), 1);
    assert_eq!(v1.devices[0].device_id, 1);
    assert!(v1.devices[0].mls.is_some());

    let mut second = Engine::new(device("alice", 2, &mut rng), server);
    second.set_local_server("example.test").unwrap();
    let v2 = block_on(second.sync_own_manifest(&authority, "2026-07-15T12:01:00Z")).unwrap();
    assert_eq!(v2.sequence, 2);
    assert_eq!(
        v2.previous_hash.as_deref(),
        Some(v1.manifest_hash().unwrap().as_str())
    );
    assert_eq!(v2.devices.len(), 2);
    assert_eq!(v2.devices[0], v1.devices[0]);
    assert_eq!(v2.devices[1].device_id, 2);
    assert!(v2.devices[1].mls.is_some());

    let v3 =
        block_on(second.revoke_manifest_device(&authority, 1, "2026-07-15T12:02:00Z")).unwrap();
    assert_eq!(v3.sequence, 3);
    assert_eq!(
        v3.previous_hash.as_deref(),
        Some(v2.manifest_hash().unwrap().as_str())
    );
    assert_eq!(v3.devices.len(), 1);
    assert_eq!(v3.devices[0].device_id, 2);
}

#[test]
fn production_engine_requires_and_persists_a_matching_signed_manifest() {
    let mut rng = test_rng();
    let bob = device("bob", 1, &mut rng);
    let bundle = bundle_of(&bob, 1);
    let manifest = signed_manifest("bob@example.test", &bundle);
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
    let alice_bundle = bundle_of(&alice_session, 1);
    server.script_sync(vec![vec![alice_bundle.clone()]]);
    server.script_sync_manifests(vec![Some(signed_manifest(
        "alice@example.test",
        &alice_bundle,
    ))]);
    server.set_sync_active(vec![(1, reg_id(&alice_session))]);
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
    assert_eq!(pin.highest_sequence, 1);
    assert_eq!(pin.authority_key_id, manifest.authority_key_id);
    assert_eq!(pin.account, "bob@example.test");
}

#[test]
fn a_message_from_a_newer_device_list_makes_the_next_send_fetch_again() {
    let mut rng = test_rng();
    let mut bob = device("bob", 2, &mut rng);
    let bundle = bundle_of(&bob, 2);
    let server = Rc::new(MockServer::default());
    // One fetch is scripted; a second gets no devices and the send fails.
    server.script(vec![vec![bundle.clone()], vec![]]);
    server.script_manifests(vec![Some(signed_manifest("bob@example.test", &bundle))]);
    server.set_active(vec![(2, reg_id(&bob))]);
    let alice_session = device("alice", 1, &mut rng);
    let alice_reg = reg_id(&alice_session);
    let alice_bundle = bundle_of(&alice_session, 1);
    server.script_sync(vec![vec![alice_bundle.clone()]]);
    server.script_sync_manifests(vec![Some(signed_manifest(
        "alice@example.test",
        &alice_bundle,
    ))]);
    server.set_sync_active(vec![(1, alice_reg)]);
    let mut alice = Engine::new(alice_session, server.clone());
    let alice_addr = ChatAddress::local("alice", 1);

    block_on(alice.send("v1", "bob", &ChatContent::text("t", 1, "one"), &mut rng)).unwrap();
    decrypt_for(&mut bob, &alice_addr, &server.last_delivered(), 2, &mut rng);

    // Bob writes from the device list Alice already holds: nothing changes.
    let mut same = ChatContent::text("t", 1, "same list");
    same.set_device_list_version(1);
    let envelope = block_on(bob.encrypt(&alice_addr, alice_reg, &same, &mut rng)).unwrap();
    deposit(&server, &envelope, "bob", 2, 1);
    assert_eq!(block_on(alice.receive(&mut rng)).unwrap().messages.len(), 1);
    assert!(
        block_on(alice.send("v2", "bob", &ChatContent::text("t", 2, "two"), &mut rng))
            .unwrap()
            .delivered
    );

    // Bob writes from a newer one: Alice stops trusting the list she holds.
    let mut newer = ChatContent::text("t", 2, "new list");
    newer.set_device_list_version(2);
    let envelope = block_on(bob.encrypt(&alice_addr, alice_reg, &newer, &mut rng)).unwrap();
    deposit(&server, &envelope, "bob", 2, 2);
    assert_eq!(block_on(alice.receive(&mut rng)).unwrap().messages.len(), 1);
    assert!(
        block_on(alice.send("v3", "bob", &ChatContent::text("t", 3, "three"), &mut rng)).is_err(),
        "the send fetched the list again, and the mock had none to give"
    );
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
    server.script_manifests(vec![Some(signed_manifest("bob@example.test", &b1))]);
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
fn first_contact_safety_number_authenticates_and_pins_the_remote_manifest() {
    let mut rng = test_rng();
    let local_authority = AccountAuthority::derive(&[30; 32]).unwrap();
    let peer_authority = AccountAuthority::derive(&[40; 32]).unwrap();
    let bob = device("bob", 1, &mut rng);
    let manifest =
        signed_manifest_with_authority("bob@example.test", &bundle_of(&bob, 1), &peer_authority);
    let server = Rc::new(MockServer::default());
    *server.own_manifest.borrow_mut() = Some(manifest.clone());

    let mut alice = Engine::new(device("alice", 1, &mut rng), server.clone());
    alice.set_local_server("example.test").unwrap();
    let safety = block_on(alice.safety_number(&local_authority, "bob")).unwrap();
    assert_eq!(safety.trust, AuthorityTrust::Tofu);
    assert_eq!(safety.authority_key_id, manifest.authority_key_id);

    // The pin is durable: a later safety-number render does not depend on the
    // remote server continuing to return the manifest.
    *server.own_manifest.borrow_mut() = None;
    let repeated = block_on(alice.safety_number(&local_authority, "bob")).unwrap();
    assert_eq!(repeated.qr_payload, safety.qr_payload);
}

#[test]
fn account_replacement_is_restart_safe_and_requires_the_exact_new_qr() {
    let mut rng = test_rng();
    let path = std::env::temp_dir().join(format!(
        "kutup-chat-account-reset-{}.db",
        OsRng.unwrap_err().try_next_u64().unwrap()
    ));
    let local_authority = AccountAuthority::derive(&[31; 32]).unwrap();
    let old_authority = AccountAuthority::derive(&[41; 32]).unwrap();
    let new_authority = AccountAuthority::derive(&[42; 32]).unwrap();
    let bob_old = device("bob", 1, &mut rng);
    let bob_new = device("bob", 1, &mut rng);
    let old_bundle = bundle_of(&bob_old, 1);
    let new_bundle = bundle_of(&bob_new, 1);
    let old_manifest =
        signed_manifest_with_authority("bob@example.test", &old_bundle, &old_authority);
    let new_manifest =
        signed_manifest_with_authority("bob@example.test", &new_bundle, &new_authority);
    let server = Rc::new(MockServer::default());
    server.script(vec![vec![old_bundle.clone()]]);
    server.script_manifests(vec![Some(old_manifest.clone())]);
    server.set_active(vec![(1, old_bundle.registration_id)]);

    let alice_db = Rc::new(SqliteChatDb::open(&path).unwrap());
    let mut alice_session =
        block_on(Session::generate(alice_db, "alice", 1, 10, &mut rng)).unwrap();
    let alice_bundle = bundle_of(&alice_session, 1);
    block_on(alice_session.complete_registration(1)).unwrap();
    server.script_sync(vec![vec![alice_bundle.clone()]]);
    server.script_sync_manifests(vec![Some(signed_manifest_with_authority(
        "alice@example.test",
        &alice_bundle,
        &local_authority,
    ))]);
    server.set_sync_active(vec![(1, alice_bundle.registration_id)]);
    let mut alice = Engine::new(alice_session, server.clone());
    alice.set_local_server("example.test").unwrap();
    block_on(alice.send(
        "identity-old",
        "bob",
        &ChatContent::text("identity-old", 1, "old identity"),
        &mut rng,
    ))
    .unwrap();
    let old_qr = block_on(alice.safety_number(&local_authority, "bob"))
        .unwrap()
        .qr_payload;

    server.script(vec![vec![new_bundle.clone()]]);
    server.script_manifests(vec![Some(new_manifest.clone())]);
    server.set_active(vec![(1, new_bundle.registration_id)]);
    let delivered_before_replacement = server.delivered.borrow().len();
    assert!(matches!(
        block_on(alice.send(
            "identity-replaced",
            "bob",
            &ChatContent::text("identity-replaced", 2, "must remain blocked"),
            &mut rng,
        )),
        Err(ChatError::Trust(_))
    ));
    // Alice held a session with the old identity, so the message was sealed
    // for it and queued before the server refused it (a re-registered
    // device) and the fetch that followed met the replaced account. Nothing
    // was delivered, and nothing is until the new identity is verified: the
    // queued message can only be re-sealed through that same trust check.
    assert_eq!(block_on(alice.pending_send_count()).unwrap(), 1);
    assert_eq!(
        server.delivered.borrow().len(),
        delivered_before_replacement
    );
    drop(alice);

    let reopened_db = Rc::new(SqliteChatDb::open(&path).unwrap());
    let mut reopened = block_on(Engine::open(reopened_db.clone(), server, "alice", 1)).unwrap();
    reopened.set_local_server("example.test").unwrap();
    let quarantined = block_on(reopened.safety_number(&local_authority, "bob")).unwrap();
    assert_eq!(quarantined.trust, AuthorityTrust::Quarantined);
    assert_eq!(quarantined.authority_key_id, new_manifest.authority_key_id);
    assert_eq!(
        quarantined.retained_authority_key_id.as_deref(),
        Some(old_manifest.authority_key_id.as_str())
    );
    assert!(matches!(
        block_on(reopened.verify_safety_number(&local_authority, "bob", &old_qr)),
        Err(ChatError::Trust(_))
    ));

    let verified =
        block_on(reopened.verify_safety_number(&local_authority, "bob", &quarantined.qr_payload))
            .unwrap();
    assert_eq!(verified.trust, AuthorityTrust::Verified);
    assert_eq!(verified.authority_key_id, new_manifest.authority_key_id);
    assert!(
        block_on(reopened_db.load_manifest_history("bob", &old_manifest.incarnation_id, 1,))
            .unwrap()
            .is_some()
    );
    assert!(
        block_on(reopened_db.load_manifest_history("bob", &new_manifest.incarnation_id, 1,))
            .unwrap()
            .is_some()
    );

    block_on(reopened.send(
        "identity-new",
        "bob",
        &ChatContent::text("identity-new", 3, "new identity accepted"),
        &mut rng,
    ))
    .unwrap();
    drop(reopened);
    std::fs::remove_file(path).unwrap();
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
fn a_second_message_does_not_fetch_keys_again() {
    let mut rng = test_rng();
    let mut bob = device("bob", 1, &mut rng);
    let bundle = bundle_of(&bob, 1);
    let server = Rc::new(MockServer::default());
    // One fetch is scripted with Bob's bundle; a second would get no devices
    // at all and the send would fail.
    server.script(vec![vec![bundle], vec![]]);
    server.set_active(vec![(1, reg_id(&bob))]);
    let mut alice = Engine::new_for_development(device("alice", 1, &mut rng), server.clone());
    let alice_addr = ChatAddress::local("alice", 1);

    for (send_id, seq, text) in [("k1", 1, "first"), ("k2", 2, "second"), ("k3", 3, "third")] {
        let summary =
            block_on(alice.send(send_id, "bob", &ChatContent::text("t", seq, text), &mut rng))
                .unwrap();
        assert!(summary.delivered);
        assert_eq!(summary.attempts, 1);
        assert_eq!(
            decrypt_for(&mut bob, &alice_addr, &server.last_delivered(), 1, &mut rng)
                .as_text()
                .unwrap()
                .text,
            text
        );
    }
}

/// Put `env`, sent by `sender`'s device `sender_device_id`, in the mailbox
/// `server` drains.
fn deposit(
    server: &MockServer,
    env: &kutup_chat_proto::OutgoingEnvelope,
    sender: &str,
    sender_device_id: u32,
    cursor: u64,
) -> String {
    let id = format!("in-{cursor}");
    server.sync_mailbox.borrow_mut().push(DeliveredEnvelope {
        id: id.clone(),
        cursor,
        sender: Some(sender.to_string()),
        sealed_sender: false,
        sender_device_id,
        envelope_type: env.envelope_type,
        suite: env.suite,
        content: env.content.clone(),
        server_timestamp: "2026-10-04T10:00:00Z".into(),
        send_id: None,
    });
    id
}

/// The same ciphertext with one byte of its body changed: it still parses,
/// and no session can authenticate it.
fn corrupted(env: &kutup_chat_proto::OutgoingEnvelope) -> kutup_chat_proto::OutgoingEnvelope {
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::STANDARD;
    let mut bytes = engine.decode(&env.content).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    let mut env = env.clone();
    env.content = engine.encode(bytes);
    env
}

#[test]
fn an_unreadable_message_refreshes_the_session_and_leaves_a_record() {
    let mut rng = test_rng();
    let alice_session = device("alice", 1, &mut rng);
    let bob_session = device("bob", 2, &mut rng);
    let alice_server = Rc::new(MockServer::default());
    alice_server.script(vec![vec![bundle_of(&bob_session, 2)]]);
    alice_server.set_active(vec![(2, reg_id(&bob_session))]);
    let bob_server = Rc::new(MockServer::default());
    bob_server.script(vec![vec![bundle_of(&alice_session, 1)]]);
    bob_server.set_active(vec![(1, reg_id(&alice_session))]);
    let mut alice = Engine::new_for_development(alice_session, alice_server.clone());
    let mut bob = Engine::new_for_development(bob_session, bob_server.clone());

    // An established conversation: Alice writes, Bob accepts and answers.
    block_on(alice.send("r1", "bob", &ChatContent::text("t", 1, "hello"), &mut rng)).unwrap();
    deposit(
        &bob_server,
        &alice_server.last_delivered()[0],
        "alice",
        1,
        1,
    );
    assert_eq!(block_on(bob.receive(&mut rng)).unwrap().messages.len(), 1);
    block_on(bob.accept_contact("alice", "t", &mut rng)).unwrap();
    block_on(bob.send("r2", "alice", &ChatContent::text("t", 1, "hi"), &mut rng)).unwrap();
    deposit(&alice_server, &bob_server.last_delivered()[0], "bob", 2, 1);
    assert_eq!(block_on(alice.receive(&mut rng)).unwrap().messages.len(), 1);
    let sent_before = bob_server.delivered.borrow().len();
    let sent_history_before = block_on(bob.session().sent_history()).unwrap().len();

    // Alice's next message reaches Bob unreadable.
    block_on(alice.send("r3", "bob", &ChatContent::text("t", 2, "lost"), &mut rng)).unwrap();
    let broken = deposit(
        &bob_server,
        &corrupted(&alice_server.last_delivered()[0]),
        "alice",
        1,
        2,
    );
    let report = block_on(bob.receive(&mut rng)).unwrap();
    assert!(report.errors.is_empty(), "nothing is left to retry forever");
    assert_eq!(report.repaired, vec![broken.clone()]);
    assert_eq!(report.messages.len(), 1);
    assert!(report.messages[0].content.is_undecryptable());
    assert_eq!(report.messages[0].from, ChatAddress::local("alice", 1));
    assert!(bob_server.sync_mailbox.borrow().is_empty(), "it was acked");
    assert!(block_on(bob.inbound_attention()).unwrap().is_empty());
    let history = block_on(bob.session().history()).unwrap();
    assert_eq!(history.len(), 2, "the record stands where the message was");
    assert_eq!(history[1].id, broken);

    // Bob handed Alice a fresh session without anyone writing anything: an
    // invisible message that is neither history nor a transcript.
    assert_eq!(bob_server.delivered.borrow().len(), sent_before + 1);
    assert_eq!(block_on(bob.pending_send_count()).unwrap(), 0);
    assert_eq!(
        block_on(bob.session().sent_history()).unwrap().len(),
        sent_history_before
    );
    let refresh = bob_server.last_delivered();
    assert_eq!(
        refresh[0].envelope_type,
        kutup_chat_proto::EnvelopeType::PreKey
    );
    deposit(&alice_server, &refresh[0], "bob", 2, 2);
    let report = block_on(alice.receive(&mut rng)).unwrap();
    assert!(report.messages.is_empty() && report.errors.is_empty());
    assert_eq!(report.suppressed.len(), 1);
    assert_eq!(block_on(alice.session().history()).unwrap().len(), 1);

    // What Alice writes next travels under the fresh session and reads.
    block_on(alice.send("r4", "bob", &ChatContent::text("t", 3, "again"), &mut rng)).unwrap();
    deposit(
        &bob_server,
        &alice_server.last_delivered()[0],
        "alice",
        1,
        3,
    );
    let report = block_on(bob.receive(&mut rng)).unwrap();
    assert_eq!(report.messages[0].content.as_text().unwrap().text, "again");

    // A second unreadable message within the hour is dropped quietly: no
    // second reset, no second record, nothing more sent.
    block_on(alice.send(
        "r5",
        "bob",
        &ChatContent::text("t", 4, "lost too"),
        &mut rng,
    ))
    .unwrap();
    let broken = deposit(
        &bob_server,
        &corrupted(&alice_server.last_delivered()[0]),
        "alice",
        1,
        4,
    );
    let report = block_on(bob.receive(&mut rng)).unwrap();
    assert_eq!(report.repaired, vec![broken]);
    assert!(report.messages.is_empty() && report.errors.is_empty());
    assert_eq!(bob_server.delivered.borrow().len(), sent_before + 1);
    assert_eq!(block_on(bob.session().history()).unwrap().len(), 3);
    block_on(alice.send(
        "r6",
        "bob",
        &ChatContent::text("t", 5, "still fine"),
        &mut rng,
    ))
    .unwrap();
    deposit(
        &bob_server,
        &alice_server.last_delivered()[0],
        "alice",
        1,
        5,
    );
    let report = block_on(bob.receive(&mut rng)).unwrap();
    assert_eq!(
        report.messages[0].content.as_text().unwrap().text,
        "still fine"
    );
}

/// Carry the last thing `from` delivered into `to`'s mailbox, with the send
/// id the server passes along, optionally damaged on the way.
fn relay(
    from: &MockServer,
    to: &MockServer,
    sender: &str,
    sender_device_id: u32,
    cursor: u64,
    damage: bool,
) -> String {
    let (send_id, envelopes) = from.delivered.borrow().last().unwrap().clone();
    let env = if damage {
        corrupted(&envelopes[0])
    } else {
        envelopes[0].clone()
    };
    let id = deposit(to, &env, sender, sender_device_id, cursor);
    to.sync_mailbox.borrow_mut().last_mut().unwrap().send_id = Some(send_id);
    id
}

fn undecryptable_records(engine: &Engine) -> Vec<Option<String>> {
    block_on(engine.session().history())
        .unwrap()
        .iter()
        .filter_map(|message| {
            serde_json::from_slice::<ChatContent>(&message.content)
                .ok()?
                .as_undecryptable()
                .map(|body| body.send_id)
        })
        .collect()
}

#[test]
fn an_unreadable_message_is_asked_for_again_and_fills_in() {
    let mut rng = test_rng();
    let alice_session = device("alice", 1, &mut rng);
    let bob_session = device("bob", 2, &mut rng);
    let alice_server = Rc::new(MockServer::default());
    alice_server.script(vec![vec![bundle_of(&bob_session, 2)]]);
    alice_server.set_active(vec![(2, reg_id(&bob_session))]);
    let bob_server = Rc::new(MockServer::default());
    bob_server.script(vec![vec![bundle_of(&alice_session, 1)]]);
    bob_server.set_active(vec![(1, reg_id(&alice_session))]);
    let mut alice = Engine::new_for_development(alice_session, alice_server.clone());
    let mut bob = Engine::new_for_development(bob_session, bob_server.clone());

    block_on(alice.send("f1", "bob", &ChatContent::text("t", 1, "hello"), &mut rng)).unwrap();
    relay(&alice_server, &bob_server, "alice", 1, 1, false);
    assert_eq!(block_on(bob.receive(&mut rng)).unwrap().messages.len(), 1);
    block_on(bob.accept_contact("alice", "t", &mut rng)).unwrap();
    block_on(bob.send("f2", "alice", &ChatContent::text("t", 1, "hi"), &mut rng)).unwrap();
    relay(&bob_server, &alice_server, "bob", 2, 1, false);
    assert_eq!(block_on(alice.receive(&mut rng)).unwrap().messages.len(), 1);

    // Alice's message reaches Bob unreadable. A record waits in its place
    // and Bob asks for exactly that message.
    let lost = "11111111-1111-4111-8111-111111111111";
    let content = ChatContent::text_with_id(lost, "2026-10-04T09:00:00.000Z", 2, "lost");
    block_on(alice.send(lost, "bob", &content, &mut rng)).unwrap();
    relay(&alice_server, &bob_server, "alice", 1, 2, true);
    let report = block_on(bob.receive(&mut rng)).unwrap();
    assert_eq!(report.repaired.len(), 1);
    assert_eq!(undecryptable_records(&bob), vec![Some(lost.to_string())]);

    // Alice answers from her sent history, without anyone doing anything.
    let alice_sent = alice_server.delivered.borrow().len();
    relay(&bob_server, &alice_server, "bob", 2, 2, false);
    let report = block_on(alice.receive(&mut rng)).unwrap();
    assert!(report.messages.is_empty() && report.errors.is_empty());
    assert_eq!(alice_server.delivered.borrow().len(), alice_sent + 1);
    assert_eq!(block_on(alice.pending_send_count()).unwrap(), 0);
    let alice_history = block_on(alice.session().sent_history()).unwrap().len();

    // The message arrives as itself, where it belongs, and the record goes.
    relay(&alice_server, &bob_server, "alice", 1, 3, false);
    let report = block_on(bob.receive(&mut rng)).unwrap();
    assert_eq!(report.messages.len(), 1);
    assert_eq!(report.messages[0].content.as_text().unwrap().text, "lost");
    assert_eq!(report.messages[0].content.message_id.as_deref(), Some(lost));
    assert_eq!(
        report.messages[0].content.sent_at,
        "2026-10-04T09:00:00.000Z"
    );
    assert!(undecryptable_records(&bob).is_empty());
    assert_eq!(block_on(bob.session().history()).unwrap().len(), 2);

    // Asked a second time within the hour, Alice does not send it again.
    relay(&bob_server, &alice_server, "bob", 2, 2, false);
    alice_server
        .sync_mailbox
        .borrow_mut()
        .last_mut()
        .unwrap()
        .cursor = 3;
    let before = alice_server.delivered.borrow().len();
    let _ = block_on(alice.receive(&mut rng));
    assert_eq!(alice_server.delivered.borrow().len(), before);
    assert_eq!(
        block_on(alice.session().sent_history()).unwrap().len(),
        alice_history
    );
}

#[test]
fn a_record_stops_waiting_for_something_that_was_never_a_message() {
    let mut rng = test_rng();
    let alice_session = device("alice", 1, &mut rng);
    let bob_session = device("bob", 2, &mut rng);
    let alice_server = Rc::new(MockServer::default());
    alice_server.script(vec![vec![bundle_of(&bob_session, 2)]]);
    alice_server.set_active(vec![(2, reg_id(&bob_session))]);
    let bob_server = Rc::new(MockServer::default());
    bob_server.script(vec![vec![bundle_of(&alice_session, 1)]]);
    bob_server.set_active(vec![(1, reg_id(&alice_session))]);
    let mut alice = Engine::new_for_development(alice_session, alice_server.clone());
    let mut bob = Engine::new_for_development(bob_session, bob_server.clone());

    block_on(alice.send("g1", "bob", &ChatContent::text("t", 1, "hello"), &mut rng)).unwrap();
    relay(&alice_server, &bob_server, "alice", 1, 1, false);
    block_on(bob.receive(&mut rng)).unwrap();
    block_on(bob.accept_contact("alice", "t", &mut rng)).unwrap();
    block_on(bob.send("g2", "alice", &ChatContent::text("t", 1, "hi"), &mut rng)).unwrap();
    relay(&bob_server, &alice_server, "bob", 2, 1, false);
    block_on(alice.receive(&mut rng)).unwrap();

    // A typing indicator arrives unreadable. Bob cannot tell it from a
    // message, so a record waits; Alice has nothing to send again and says
    // so, and the record goes.
    let typing_id = "22222222-2222-4222-8222-222222222222";
    let typing = ChatContent::typing_with_id(typing_id, "2026-10-04T09:00:00Z", 2, true);
    block_on(alice.send(typing_id, "bob", &typing, &mut rng)).unwrap();
    relay(&alice_server, &bob_server, "alice", 1, 2, true);
    block_on(bob.receive(&mut rng)).unwrap();
    assert_eq!(
        undecryptable_records(&bob),
        vec![Some(typing_id.to_string())]
    );

    relay(&bob_server, &alice_server, "bob", 2, 2, false);
    block_on(alice.receive(&mut rng)).unwrap();
    relay(&alice_server, &bob_server, "alice", 1, 3, false);
    let report = block_on(bob.receive(&mut rng)).unwrap();
    assert!(report.messages.is_empty() && report.errors.is_empty());
    assert!(undecryptable_records(&bob).is_empty());
    assert_eq!(block_on(bob.session().history()).unwrap().len(), 1);
}

#[test]
fn an_unreadable_message_from_a_stranger_is_dropped_without_a_reply() {
    let mut rng = test_rng();
    let alice_session = device("alice", 1, &mut rng);
    let bob_session = device("bob", 2, &mut rng);
    let alice_server = Rc::new(MockServer::default());
    alice_server.script(vec![vec![bundle_of(&bob_session, 2)]]);
    alice_server.set_active(vec![(2, reg_id(&bob_session))]);
    let bob_server = Rc::new(MockServer::default());
    let mut alice = Engine::new_for_development(alice_session, alice_server.clone());
    let mut bob = Engine::new_for_development(bob_session, bob_server.clone());

    block_on(alice.send("s1", "bob", &ChatContent::text("t", 1, "hello"), &mut rng)).unwrap();
    let broken = deposit(
        &bob_server,
        &corrupted(&alice_server.last_delivered()[0]),
        "alice",
        1,
        1,
    );
    let report = block_on(bob.receive(&mut rng)).unwrap();
    assert_eq!(report.repaired, vec![broken]);
    assert!(report.messages.is_empty() && report.errors.is_empty());
    assert!(bob_server.delivered.borrow().is_empty());
    assert!(block_on(bob.session().history()).unwrap().is_empty());
    assert!(block_on(bob.contacts()).unwrap().is_empty());
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
    // Alice still holds her session with v1 and sends with it, without
    // fetching; the 409 makes her fetch, and that fetch serves v2.
    server.script(vec![vec![b_v2.clone()]]);
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

#[test]
fn a_failing_send_is_reported_and_holds_back_only_its_own_peer() {
    let mut rng = test_rng();
    let bob = device("bob", 1, &mut rng);
    let bundle = bundle_of(&bob, 1);
    let server = Rc::new(MockServer::default());
    server.script(vec![vec![bundle.clone()], vec![bundle]]);
    server.set_active(vec![(1, reg_id(&bob))]);
    let mut alice = Engine::new_for_development(device("alice", 1, &mut rng), server.clone());

    // Two messages to Bob are queued; the server takes neither.
    *server.fail_sends.borrow_mut() = 2;
    for (send_id, text) in [("first", "one"), ("second", "two")] {
        assert!(matches!(
            block_on(alice.send(send_id, "bob", &ChatContent::text("t", 1, text), &mut rng)),
            Err(ChatError::Transport(_))
        ));
    }
    assert_eq!(block_on(alice.pending_send_count()).unwrap(), 2);

    // The server refuses once more. The pass reports the failure instead of
    // returning it, and does not try the second message ahead of the first:
    // had it, that one would have gone through and left a single entry.
    *server.fail_sends.borrow_mut() = 1;
    let flush = block_on(alice.flush_outbox_collecting_failures(&mut rng)).unwrap();
    assert!(flush.delivered.is_empty());
    assert_eq!(flush.failed.len(), 1);
    assert_eq!(flush.failed[0].send_id, "first");
    assert_eq!(flush.failed[0].peer, "bob");
    assert!(matches!(flush.failed[0].error, ChatError::Transport(_)));
    assert_eq!(block_on(alice.pending_send_count()).unwrap(), 2);

    // The server answers again: both go out, in order.
    let flush = block_on(alice.flush_outbox_collecting_failures(&mut rng)).unwrap();
    assert!(flush.failed.is_empty());
    assert_eq!(flush.delivered.len(), 2);
    assert!(flush.delivered.iter().all(|summary| summary.delivered));
    assert_eq!(block_on(alice.pending_send_count()).unwrap(), 0);
}

#[test]
fn receipt_retry_failure_does_not_block_reconciliation_flush() {
    let mut rng = test_rng();
    let bob = device("bob", 1, &mut rng);
    let bundle = bundle_of(&bob, 1);
    let server = Rc::new(MockServer::default());
    server.script(vec![vec![bundle]]);
    server.set_active(vec![(1, reg_id(&bob))]);
    let mut alice = Engine::new_for_development(device("alice", 1, &mut rng), server.clone());
    let send_id = "33333333-3333-4333-8333-333333333333";
    let target = "11111111-1111-4111-8111-111111111111";
    let receipt = ChatContent::receipt_with_id(
        send_id,
        "2026-08-10T00:00:00Z",
        1,
        vec![target.to_string()],
        ReceiptState::Delivered,
    )
    .unwrap();

    *server.fail_sends.borrow_mut() = 2;
    assert!(matches!(
        block_on(alice.send(send_id, "bob", &receipt, &mut rng)),
        Err(ChatError::Transport(_))
    ));
    assert!(
        block_on(alice.flush_outbox_deferring_optional_failures(&mut rng))
            .unwrap()
            .is_empty()
    );
    assert_eq!(block_on(alice.pending_send_count()).unwrap(), 1);

    let summaries = block_on(alice.flush_outbox(&mut rng)).unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(block_on(alice.pending_send_count()).unwrap(), 0);
}

#[test]
fn typing_is_delivered_without_history_or_linked_device_transcript() {
    let mut rng = test_rng();
    let mut bob = device("bob", 1, &mut rng);
    let bundle = bundle_of(&bob, 1);
    let server = Rc::new(MockServer::default());
    server.script(vec![vec![bundle]]);
    server.set_active(vec![(1, reg_id(&bob))]);
    let mut alice = Engine::new_for_development(device("alice", 1, &mut rng), server.clone());
    let send_id = "44444444-4444-4444-8444-444444444444";
    let typing = ChatContent::typing_with_id(send_id, "2026-08-10T00:00:00Z", 1, true);

    let summary = block_on(alice.send(send_id, "bob", &typing, &mut rng)).unwrap();
    assert!(summary.delivered);
    assert!(block_on(alice.session().sent_history()).unwrap().is_empty());
    assert!(server.synced.borrow().is_empty());
    assert_eq!(
        decrypt_for(
            &mut bob,
            &ChatAddress::local("alice", 1),
            &server.last_delivered(),
            1,
            &mut rng,
        )
        .as_typing(),
        Some(kutup_chat_proto::TypingBody { active: true })
    );
}

#[test]
fn call_signals_are_delivered_without_history_or_linked_device_transcript() {
    let mut rng = test_rng();
    let mut bob = device("bob", 1, &mut rng);
    let bundle = bundle_of(&bob, 1);
    let server = Rc::new(MockServer::default());
    server.script(vec![vec![bundle]]);
    server.set_active(vec![(1, reg_id(&bob))]);
    let mut alice = Engine::new_for_development(device("alice", 1, &mut rng), server.clone());
    let send_id = "55555555-5555-4555-8555-555555555555";
    let signal = kutup_chat_proto::CallSignalV1 {
        call_id: uuid::Uuid::from_u128(9),
        caller_device_id: 1,
        callee_device_id: None,
        signal: kutup_chat_proto::CallSignalKindV1::Offer {
            media: kutup_chat_proto::CallMediaV1::Audio,
            sdp: "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\n".into(),
        },
    };
    let offer = ChatContent::call_with_id(send_id, "2026-09-25T00:00:00Z", 1, &signal).unwrap();

    let summary = block_on(alice.send(send_id, "bob", &offer, &mut rng)).unwrap();
    assert!(summary.delivered);
    assert!(block_on(alice.session().sent_history()).unwrap().is_empty());
    assert!(server.synced.borrow().is_empty());
    assert_eq!(
        decrypt_for(
            &mut bob,
            &ChatAddress::local("alice", 1),
            &server.last_delivered(),
            1,
            &mut rng,
        )
        .as_call(),
        Some(signal)
    );

    // Calls are not for Note to Self.
    assert!(block_on(alice.send(send_id, "alice", &offer, &mut rng)).is_err());
}

#[test]
fn a_call_record_is_local_history_that_replaces_itself() {
    let mut rng = test_rng();
    let mut alice = device("alice", 1, &mut rng);
    let record = |outcome, duration_seconds| {
        ChatContent::call_log_with_id(
            "00000000-0000-4000-8000-000000000009",
            "",
            &kutup_chat_proto::CallLogBody {
                call_id: uuid::Uuid::from_u128(9),
                incoming: true,
                media: kutup_chat_proto::CallMediaV1::Video,
                outcome,
                started_at_ms: 1,
                duration_seconds,
            },
        )
        .unwrap()
    };
    block_on(alice.record_local_notice(
        "bob",
        &record(kutup_chat_proto::CallOutcomeV1::Missed, None),
    ))
    .unwrap();
    block_on(alice.record_local_notice(
        "bob",
        &record(kutup_chat_proto::CallOutcomeV1::Answered, Some(30)),
    ))
    .unwrap();
    let history = block_on(alice.sent_history()).unwrap();
    assert_eq!(history.len(), 1);
    let content: ChatContent = serde_json::from_slice(&history[0].content).unwrap();
    assert_eq!(content.as_call_log().unwrap().duration_seconds, Some(30));
    // Only local-only records are written this way.
    let text = ChatContent::text_with_id("x", "", 1, "hi");
    assert!(block_on(alice.record_local_notice("bob", &text)).is_err());
}

#[test]
fn direct_recipient_and_linked_transcript_retry_independently_across_restart() {
    let mut rng = test_rng();
    let alice_db = Rc::new(SqliteChatDb::open_in_memory().unwrap());
    let mut alice1 = block_on(Session::generate(
        alice_db.clone(),
        "alice",
        1,
        10,
        &mut rng,
    ))
    .unwrap();
    let alice1_bundle = bundle_of(&alice1, 1);
    block_on(alice1.complete_registration(1)).unwrap();
    let alice2 = device("alice", 2, &mut rng);
    let mut bob1 = device("bob", 1, &mut rng);
    let bob_bundle = bundle_of(&bob1, 1);

    let server = Rc::new(MockServer::default());
    server.script(vec![vec![bob_bundle]]);
    server.set_active(vec![(1, reg_id(&bob1))]);
    server.script_sync(vec![vec![alice1_bundle.clone(), bundle_of(&alice2, 2)]]);
    server.set_sync_active(vec![
        (1, alice1_bundle.registration_id),
        (2, reg_id(&alice2)),
    ]);
    *server.fail_sync_sends.borrow_mut() = 1;

    let content = ChatContent::text_with_id(
        "direct-linked",
        "2026-07-16T10:02:00Z",
        1,
        "hello from my other device",
    );
    let mut first = Engine::new_for_development(alice1, server.clone());
    let summary = block_on(first.send("direct-linked", "bob", &content, &mut rng)).unwrap();
    assert!(summary.delivered, "recipient delivery succeeds");
    assert_eq!(server.delivered.borrow().len(), 1);
    assert!(
        server.synced.borrow().is_empty(),
        "first sync attempt failed"
    );
    assert_eq!(block_on(first.pending_send_count()).unwrap(), 1);
    let sent = block_on(first.session().sent_history()).unwrap();
    assert!(
        sent[0].delivered,
        "recipient status is not downgraded by sync"
    );
    let received = decrypt_for(
        &mut bob1,
        &ChatAddress::local("alice", 1),
        &server.last_delivered(),
        1,
        &mut rng,
    );
    assert_eq!(received.message_id.as_deref(), Some("direct-linked"));
    assert_eq!(
        received.as_text().unwrap().text,
        "hello from my other device"
    );
    drop(first);

    // A process restart reopens the exact ratchet/outbox state. Only the sync
    // leg is retried; the already-confirmed recipient ciphertext is untouched.
    let reopened = block_on(Session::open(alice_db, "alice", 1)).unwrap();
    let mut restarted = Engine::new_for_development(reopened, server.clone());
    let flushed = block_on(restarted.flush_outbox(&mut rng)).unwrap();
    assert_eq!(flushed.len(), 1);
    assert!(flushed[0].delivered);
    assert_eq!(server.delivered.borrow().len(), 1, "recipient not resent");
    assert_eq!(server.synced.borrow().len(), 1);
    assert_eq!(block_on(restarted.pending_send_count()).unwrap(), 0);

    let mut linked = Engine::new_for_development(alice2, server.clone());
    let report = block_on(linked.receive(&mut rng)).unwrap();
    assert_eq!(report.synced, vec!["direct-linked"]);
    let linked_history = block_on(linked.session().sent_history()).unwrap();
    assert_eq!(linked_history.len(), 1);
    assert_eq!(linked_history[0].peer, "bob");
    let linked_content = serde_json::from_slice::<ChatContent>(&linked_history[0].content).unwrap();
    assert_eq!(linked_content.message_id.as_deref(), Some("direct-linked"));
    assert_eq!(
        linked_content.as_text().unwrap().text,
        "hello from my other device"
    );

    let direct_count = server.delivered.borrow().len();
    let sync_count = server.synced.borrow().len();
    let repeated = block_on(restarted.send("direct-linked", "bob", &content, &mut rng)).unwrap();
    assert!(repeated.delivered && repeated.deduplicated);
    assert_eq!(server.delivered.borrow().len(), direct_count);
    assert_eq!(server.synced.borrow().len(), sync_count);

    let mismatched = ChatContent::text_with_id("content-id", "t", 2, "must not send");
    assert!(matches!(
        block_on(restarted.send("transport-id", "bob", &mismatched, &mut rng)),
        Err(ChatError::Invalid(message))
            if message.contains("messageId must match transport sendId")
    ));
}

#[test]
fn single_device_note_to_self_is_local_and_never_posts_an_envelope() {
    let mut rng = test_rng();
    let alice = device("alice", 1, &mut rng);
    let bundle = bundle_of(&alice, 1);
    let server = Rc::new(MockServer::default());
    server.script_sync(vec![vec![bundle]]);
    server.set_sync_active(vec![(1, reg_id(&alice))]);
    let mut engine = Engine::new_for_development(alice, server.clone());

    let summary = block_on(engine.send(
        "note-local",
        "alice",
        &ChatContent::text("2026-07-16T10:00:00Z", 1, "remember this"),
        &mut rng,
    ))
    .unwrap();

    assert!(summary.delivered);
    assert_eq!(summary.attempts, 0);
    assert!(server.synced.borrow().is_empty());
    assert_eq!(block_on(engine.pending_send_count()).unwrap(), 0);
    let history = block_on(engine.session().sent_history()).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].peer, "alice");
    assert_eq!(
        serde_json::from_slice::<ChatContent>(&history[0].content)
            .unwrap()
            .as_text()
            .unwrap()
            .text,
        "remember this"
    );
}

#[test]
fn canonical_single_device_note_to_self_does_not_loop_back_as_incoming() {
    let mut rng = test_rng();
    let alice = device("alice", 1, &mut rng);
    let bundle = bundle_of(&alice, 1);
    let server = Rc::new(MockServer::default());
    server.script_sync(vec![vec![bundle.clone()]]);
    server.script_sync_manifests(vec![Some(signed_manifest("alice@example.test", &bundle))]);
    server.set_sync_active(vec![(1, reg_id(&alice))]);
    let mut engine = Engine::new_for_development(alice, server.clone());
    engine.set_local_server("example.test").unwrap();

    assert_eq!(engine.session().user(), "alice@example.test");
    let summary = block_on(engine.send(
        "note-canonical-local",
        "alice@example.test",
        &ChatContent::text("2026-07-16T10:00:00Z", 1, "canonical note"),
        &mut rng,
    ))
    .unwrap();

    assert!(summary.delivered);
    assert_eq!(summary.attempts, 0);
    assert!(server.synced.borrow().is_empty());
    assert_eq!(block_on(engine.session().sent_history()).unwrap().len(), 1);
    assert!(block_on(engine.session().history()).unwrap().is_empty());
}

#[test]
fn linked_device_note_arrives_as_outgoing_history_via_encrypted_transcript() {
    let mut rng = test_rng();
    let alice1 = device("alice", 1, &mut rng);
    let alice2 = device("alice", 2, &mut rng);
    let bundles = vec![bundle_of(&alice1, 1), bundle_of(&alice2, 2)];
    let server = Rc::new(MockServer::default());
    server.script_sync(vec![bundles]);
    server.set_sync_active(vec![(1, reg_id(&alice1)), (2, reg_id(&alice2))]);

    let mut first = Engine::new_for_development(alice1, server.clone());
    let summary = block_on(first.send(
        "note-linked",
        "alice",
        &ChatContent::text("2026-07-16T10:01:00Z", 1, "sync this note"),
        &mut rng,
    ))
    .unwrap();
    assert!(summary.delivered);
    assert_eq!(summary.attempts, 1);
    assert_eq!(server.last_synced().len(), 1);
    assert_eq!(server.last_synced()[0].device_id, 2);

    let mut second = Engine::new_for_development(alice2, server.clone());
    let report = block_on(second.receive(&mut rng)).unwrap();
    assert!(
        report.messages.is_empty(),
        "a transcript is not incoming chat"
    );
    assert_eq!(report.synced, vec!["note-linked"]);
    let history = block_on(second.session().sent_history()).unwrap();
    assert_eq!(history.len(), 1);
    assert!(history[0].delivered);
    assert_eq!(history[0].peer, "alice");
    assert_eq!(
        serde_json::from_slice::<ChatContent>(&history[0].content)
            .unwrap()
            .as_text()
            .unwrap()
            .text,
        "sync this note"
    );
    assert!(block_on(second.session().history()).unwrap().is_empty());
}

#[test]
fn canonical_linked_device_accepts_bare_local_sender_from_server() {
    let mut rng = test_rng();
    let alice1 = device("alice", 1, &mut rng);
    let alice2 = device("alice", 2, &mut rng);
    let bundles = vec![bundle_of(&alice1, 1), bundle_of(&alice2, 2)];
    let server = Rc::new(MockServer::default());
    server.script_sync(vec![bundles]);
    server.set_sync_active(vec![(1, reg_id(&alice1)), (2, reg_id(&alice2))]);

    let mut first = Engine::new_for_development(alice1, server.clone());
    first.set_local_server("example.test").unwrap();
    let summary = block_on(first.send(
        "note-canonical-linked",
        "alice@example.test",
        &ChatContent::text("2026-07-16T10:02:00Z", 1, "sync canonical note"),
        &mut rng,
    ))
    .unwrap();
    assert!(summary.delivered);
    assert_eq!(server.last_synced().len(), 1);

    let mut second = Engine::new_for_development(alice2, server);
    second.set_local_server("example.test").unwrap();
    let report = block_on(second.receive(&mut rng)).unwrap();
    assert_eq!(report.synced, vec!["note-canonical-linked"]);
    assert!(report.errors.is_empty());
    let history = block_on(second.session().sent_history()).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].peer, "alice@example.test");
    assert_eq!(history[0].sender_device_id, 1);
}

#[test]
fn explicit_contact_state_converges_over_authenticated_linked_device_sync() {
    let mut rng = test_rng();
    let alice1 = device("alice", 1, &mut rng);
    let alice2 = device("alice", 2, &mut rng);
    let bundles = vec![bundle_of(&alice1, 1), bundle_of(&alice2, 2)];
    let server = Rc::new(MockServer::default());
    server.script_sync(vec![bundles]);
    server.set_sync_active(vec![(1, reg_id(&alice1)), (2, reg_id(&alice2))]);

    let mut first = Engine::new_for_development(alice1, server.clone());
    let local =
        block_on(first.block_contact("bob", &[0; 32], "2026-07-16T10:05:00Z", &mut rng)).unwrap();
    assert_eq!(local.state, ContactState::Blocked);
    assert!(!local.sync_pending);
    assert_eq!(server.synced.borrow().len(), 1);

    let mut second = Engine::new_for_development(alice2, server);
    let report = block_on(second.receive(&mut rng)).unwrap();
    assert_eq!(report.contact_synced.len(), 1);
    assert!(report.messages.is_empty() && report.synced.is_empty());
    let linked = block_on(second.contacts()).unwrap().pop().unwrap();
    assert_eq!(linked.peer, "bob");
    assert_eq!(linked.state, ContactState::Blocked);
    assert_eq!(linked.revision, local.revision);
    assert_eq!(linked.source_device_id, 1);
    assert!(block_on(second.session().history()).unwrap().is_empty());
    assert!(block_on(second.session().sent_history())
        .unwrap()
        .is_empty());
}

#[test]
fn pending_profile_key_is_withheld_until_its_ciphertext_is_published() {
    let mut rng = test_rng();
    let mut bob = device("bob", 1, &mut rng);
    let bob_bundle = bundle_of(&bob, 1);
    let server = Rc::new(MockServer::default());
    server.script(vec![vec![bob_bundle.clone()]]);
    server.set_active(vec![(1, bob_bundle.registration_id)]);
    *server.fail_profile_uploads.borrow_mut() = 1;

    let mut alice = Engine::new_for_development(device("alice", 1, &mut rng), server.clone());
    alice.set_local_server("chat.example").unwrap();
    let wrapping = kutup_chat_core::derive_wrapping_key(&[42; 32]).unwrap();
    assert!(block_on(alice.initialize_profile(&wrapping, "Alice", &mut rng)).is_err());

    let first = ChatContent::text_with_id(
        "profile-pending-text",
        "2026-07-16T11:00:00Z",
        1,
        "before publication",
    );
    block_on(alice.send("profile-pending-text", "bob", &first, &mut rng)).unwrap();
    let alice_address = ChatAddress::local("alice", 1);
    let received = decrypt_for(
        &mut bob,
        &alice_address,
        &server.last_delivered(),
        1,
        &mut rng,
    );
    assert!(received.profile_key.is_none());

    block_on(alice.flush_profile(&wrapping, "2026-07-16T11:01:00Z", &mut rng)).unwrap();
    let update = decrypt_for(
        &mut bob,
        &alice_address,
        &server.last_delivered(),
        1,
        &mut rng,
    );
    assert_eq!(
        update.kind,
        kutup_chat_proto::content::kind::PROFILE_KEY_UPDATE
    );
    assert!(update.profile_key.is_some());

    let second = ChatContent::text_with_id(
        "profile-published-text",
        "2026-07-16T11:02:00Z",
        3,
        "after publication",
    );
    block_on(alice.send("profile-published-text", "bob", &second, &mut rng)).unwrap();
    let received = decrypt_for(
        &mut bob,
        &alice_address,
        &server.last_delivered(),
        1,
        &mut rng,
    );
    assert!(received.profile_key.is_some());
}

fn list_state(source_device_id: u32) -> kutup_chat_proto::ConversationStateBody {
    kutup_chat_proto::ConversationStateBody {
        conversation: kutup_chat_proto::ConversationId::direct("bob@example.test".parse().unwrap()),
        revision: 1,
        source_device_id,
        updated_at_ms: 1_000,
        pinned: true,
        archived: false,
        muted_until_ms: None,
        marked_unread: false,
    }
}

#[test]
fn conversation_state_syncs_to_a_linked_device_as_hidden_note_to_self_history() {
    let mut rng = test_rng();
    let alice1 = device("alice", 1, &mut rng);
    let alice2 = device("alice", 2, &mut rng);
    let bundles = vec![bundle_of(&alice1, 1), bundle_of(&alice2, 2)];
    let server = Rc::new(MockServer::default());
    server.script_sync(vec![bundles]);
    server.set_sync_active(vec![(1, reg_id(&alice1)), (2, reg_id(&alice2))]);

    let id = "0b0f6a8e-35f5-4a8e-9f5a-0a8f3c2d1e4b";
    let content =
        ChatContent::conversation_state_with_id(id, "2026-09-25T10:00:00Z", 1, list_state(1))
            .unwrap();
    let mut first = Engine::new_for_development(alice1, server.clone());
    assert!(
        block_on(first.send(id, "alice", &content, &mut rng))
            .unwrap()
            .delivered
    );

    let mut second = Engine::new_for_development(alice2, server.clone());
    let report = block_on(second.receive(&mut rng)).unwrap();
    assert!(report.messages.is_empty());
    let history = block_on(second.session().sent_history()).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].peer, "alice");
    let synced = serde_json::from_slice::<ChatContent>(&history[0].content).unwrap();
    assert_eq!(synced.as_conversation_state(), Some(list_state(1)));
}

#[test]
fn same_account_controls_go_only_to_note_to_self_from_their_named_device() {
    let mut rng = test_rng();
    let alice = device("alice", 1, &mut rng);
    let server = Rc::new(MockServer::default());
    let mut engine = Engine::new_for_development(alice, server);

    let id = "6c1d7e2f-9a3b-4c5d-8e7f-1a2b3c4d5e6f";
    let to_bob = ChatContent::conversation_state_with_id(id, "t", 1, list_state(1)).unwrap();
    assert!(matches!(
        block_on(engine.send(id, "bob", &to_bob, &mut rng)),
        Err(ChatError::Invalid(message)) if message.contains("same-account control")
    ));
    let other_device = ChatContent::conversation_state_with_id(id, "t", 1, list_state(7)).unwrap();
    assert!(matches!(
        block_on(engine.send(id, "alice", &other_device, &mut rng)),
        Err(ChatError::Invalid(message)) if message.contains("name this device")
    ));
    let delete = ChatContent::delete_for_me_with_id(
        id,
        "t",
        1,
        kutup_chat_proto::DeleteForMeBody {
            conversation: kutup_chat_proto::ConversationId::direct(
                "bob@example.test".parse().unwrap(),
            ),
            message_ids: vec!["0b0f6a8e-35f5-4a8e-9f5a-0a8f3c2d1e4b".into()],
        },
    )
    .unwrap();
    assert!(matches!(
        block_on(engine.send(id, "bob", &delete, &mut rng)),
        Err(ChatError::Invalid(_))
    ));
}

#[test]
fn local_timeline_notices_are_never_sent() {
    let mut rng = test_rng();
    let alice = device("alice", 1, &mut rng);
    let server = Rc::new(MockServer::default());
    let mut engine = Engine::new_for_development(alice, server);
    let id = "6c1d7e2f-9a3b-4c5d-8e7f-1a2b3c4d5e6f";
    let notice = ChatContent::group_update_with_id(
        id,
        "t",
        &kutup_chat_proto::GroupUpdateBody {
            actor: "alice@example.test".into(),
            changes: vec![kutup_chat_proto::GroupUpdateChange::Closed],
        },
    )
    .unwrap();
    for peer in ["bob", "alice"] {
        assert!(matches!(
            block_on(engine.send(id, peer, &notice, &mut rng)),
            Err(ChatError::Invalid(message)) if message.contains("never sent")
        ));
    }
}
