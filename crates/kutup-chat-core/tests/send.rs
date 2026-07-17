//! The send-orchestration proof: multi-device fan-out, `409 DeviceListMismatch`
//! recovery (missing / extra / stale-reinstall), the safety-number-change signal,
//! and the durable `sendId` outbox (crash-then-resend), all driven through a mock
//! transport. The mock's futures are immediately ready, so `futures_executor`
//! polls the engine's async methods to completion with no real runtime.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};
use std::rc::Rc;

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use futures_executor::block_on;
use kutup_chat_core::{
    AccountAuthority, ChatAddress, ChatContent, ChatDb, ChatError, ChatTransport, ContactState,
    Engine, Result, SendOutcome, Session, SqliteChatDb,
};
use kutup_chat_proto::{
    hash_transparency_map_checkpoint, hash_transparency_map_leaf, hash_transparency_node,
    map_key_bit, transparency_map_empty_hashes, transparency_map_key, DeliveredEnvelope,
    DeviceListMismatch, DeviceManifest, DevicePreKeyBundle, MailboxPage, ManifestDevice,
    ManifestTransparencyLeaf, ManifestTransparencyMapProof, ManifestTransparencyProof,
    OwnChatProfileResponse, PublishManifestResponse, PutChatProfileRequest,
    RegisterChatDeviceRequest, SendMessagesRequest, TransparencyCheckpoint, TransparencyHash,
    TransparencyMapSibling, UserPreKeyBundlesResponse,
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
    sync_fetch_script: RefCell<Vec<Vec<DevicePreKeyBundle>>>,
    sync_manifest_script: RefCell<Vec<Option<DeviceManifest>>>,
    own_manifest: RefCell<Option<DeviceManifest>>,
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
    transparency_events: RefCell<Vec<(ManifestTransparencyLeaf, usize)>>,
    transparency_hashes: RefCell<Vec<TransparencyHash>>,
    transparency_map: RefCell<BTreeMap<String, ManifestTransparencyLeaf>>,
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
    fn script_manifests(&self, manifests: Vec<Option<DeviceManifest>>) {
        *self.manifest_script.borrow_mut() = manifests;
    }
    fn script_sync_manifests(&self, manifests: Vec<Option<DeviceManifest>>) {
        *self.sync_manifest_script.borrow_mut() = manifests;
    }
    /// The envelopes of the most recent accepted send.
    fn last_delivered(&self) -> Vec<kutup_chat_proto::OutgoingEnvelope> {
        self.delivered.borrow().last().unwrap().1.clone()
    }
    fn last_synced(&self) -> Vec<kutup_chat_proto::OutgoingEnvelope> {
        self.synced.borrow().last().unwrap().1.clone()
    }

    fn transparency_proof(
        &self,
        username: &str,
        manifest: &DeviceManifest,
        consistency_from: u64,
    ) -> ManifestTransparencyProof {
        let leaf = ManifestTransparencyLeaf::from_manifest(username, manifest).unwrap();
        let mut events = self.transparency_events.borrow_mut();
        let mut hashes = self.transparency_hashes.borrow_mut();
        let mut current_map = self.transparency_map.borrow_mut();
        let leaf_index = events
            .iter()
            .find_map(|(existing, position)| (existing == &leaf).then_some(*position))
            .unwrap_or_else(|| {
                let position = hashes.len();
                hashes.push(leaf.hash().unwrap());
                current_map.insert(username.to_string(), leaf.clone());
                let (map_root, _) = test_map_proof(&current_map, &leaf);
                hashes.push(hash_transparency_map_checkpoint(map_root));
                events.push((leaf.clone(), position));
                position
            });
        let (map_root, siblings) = test_map_proof(&current_map, &leaf);
        let map_checkpoint_index = hashes.len() - 1;
        assert!(consistency_from <= hashes.len() as u64);
        let consistency = if consistency_from == 0 || consistency_from == hashes.len() as u64 {
            Vec::new()
        } else {
            test_consistency(consistency_from as usize, &hashes)
        };
        let checkpoint = TransparencyCheckpoint {
            log_id: "01".repeat(32),
            tree_size: hashes.len() as u64,
            root_hash: hex::encode(test_merkle_root(&hashes)),
        };
        let map_root = hex::encode(map_root);
        let authentication = kutup_chat_proto::TransparencyCheckpointAuthentication::sign(
            &checkpoint,
            &map_root,
            1_752_688_000 + hashes.len() as i64,
            &SigningKey::from_bytes(&[91; 32]),
        )
        .unwrap();
        ManifestTransparencyProof {
            leaf_index: leaf_index as u64,
            leaf,
            checkpoint,
            inclusion: test_inclusion(leaf_index, &hashes)
                .into_iter()
                .map(hex::encode)
                .collect(),
            consistency_from,
            consistency: consistency.into_iter().map(hex::encode).collect(),
            map: ManifestTransparencyMapProof {
                root_hash: map_root,
                checkpoint_leaf_index: map_checkpoint_index as u64,
                checkpoint_inclusion: test_inclusion(map_checkpoint_index, &hashes)
                    .into_iter()
                    .map(hex::encode)
                    .collect(),
                siblings,
            },
            authentication,
        }
    }
}

fn test_map_proof(
    values: &BTreeMap<String, ManifestTransparencyLeaf>,
    target: &ManifestTransparencyLeaf,
) -> (TransparencyHash, Vec<TransparencyMapSibling>) {
    let defaults = transparency_map_empty_hashes();
    let mut nodes = BTreeMap::<(usize, TransparencyHash), TransparencyHash>::new();
    for leaf in values.values() {
        let key = transparency_map_key(&leaf.username).unwrap();
        let mut node = hash_transparency_map_leaf(leaf).unwrap();
        nodes.insert((256, key), node);
        for depth in (0..256).rev() {
            let sibling = nodes
                .get(&(depth + 1, test_map_sibling_prefix(&key, depth)))
                .copied()
                .unwrap_or(defaults[depth + 1]);
            node = if map_key_bit(&key, depth) == 0 {
                hash_transparency_node(node, sibling)
            } else {
                hash_transparency_node(sibling, node)
            };
            nodes.insert((depth, test_map_prefix(&key, depth)), node);
        }
    }
    let root = nodes[&(0, [0; 32])];
    let target_key = transparency_map_key(&target.username).unwrap();
    let siblings = (0..256)
        .filter_map(|depth| {
            nodes
                .get(&(depth + 1, test_map_sibling_prefix(&target_key, depth)))
                .copied()
                .filter(|hash| *hash != defaults[depth + 1])
                .map(|hash| TransparencyMapSibling {
                    depth: depth as u16,
                    hash: hex::encode(hash),
                })
        })
        .collect();
    (root, siblings)
}

fn test_map_prefix(key: &TransparencyHash, depth: usize) -> TransparencyHash {
    let mut path = *key;
    let full_bytes = depth / 8;
    let remaining_bits = depth % 8;
    if remaining_bits == 0 {
        path[full_bytes..].fill(0);
    } else {
        path[full_bytes] &= 0xff << (8 - remaining_bits);
        path[full_bytes + 1..].fill(0);
    }
    path
}

fn test_map_sibling_prefix(key: &TransparencyHash, depth: usize) -> TransparencyHash {
    let mut path = test_map_prefix(key, depth + 1);
    path[depth / 8] ^= 1 << (7 - (depth % 8));
    path
}

fn test_merkle_root(leaves: &[TransparencyHash]) -> TransparencyHash {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let split = 1usize << ((leaves.len() - 1).ilog2());
    hash_transparency_node(
        test_merkle_root(&leaves[..split]),
        test_merkle_root(&leaves[split..]),
    )
}

fn test_inclusion(index: usize, leaves: &[TransparencyHash]) -> Vec<TransparencyHash> {
    if leaves.len() == 1 {
        return Vec::new();
    }
    let split = 1usize << ((leaves.len() - 1).ilog2());
    if index < split {
        let mut proof = test_inclusion(index, &leaves[..split]);
        proof.push(test_merkle_root(&leaves[split..]));
        proof
    } else {
        let mut proof = test_inclusion(index - split, &leaves[split..]);
        proof.push(test_merkle_root(&leaves[..split]));
        proof
    }
}

fn test_consistency(old_size: usize, leaves: &[TransparencyHash]) -> Vec<TransparencyHash> {
    fn subproof(
        old_size: usize,
        leaves: &[TransparencyHash],
        complete: bool,
        out: &mut Vec<TransparencyHash>,
    ) {
        if old_size == leaves.len() {
            if !complete {
                out.push(test_merkle_root(leaves));
            }
            return;
        }
        let split = 1usize << ((leaves.len() - 1).ilog2());
        if old_size <= split {
            subproof(old_size, &leaves[..split], complete, out);
            out.push(test_merkle_root(&leaves[split..]));
        } else {
            subproof(old_size - split, &leaves[split..], false, out);
            out.push(test_merkle_root(&leaves[..split]));
        }
    }
    let mut proof = Vec::new();
    subproof(old_size, leaves, true, &mut proof);
    proof
}

#[async_trait(?Send)]
impl ChatTransport for MockServer {
    async fn register_device(&self, _req: &RegisterChatDeviceRequest) -> Result<u32> {
        Ok(1)
    }

    async fn fetch_bundles(
        &self,
        username: &str,
        transparency_tree_size: u64,
    ) -> Result<UserPreKeyBundlesResponse> {
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
        let transparency = manifest
            .as_ref()
            .map(|manifest| self.transparency_proof(username, manifest, transparency_tree_size));
        Ok(UserPreKeyBundlesResponse {
            username: username.to_string(),
            devices,
            manifest,
            transparency,
        })
    }

    async fn fetch_sync_bundles(
        &self,
        username: &str,
        _current_device_id: u32,
        transparency_tree_size: u64,
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
        let transparency = manifest
            .as_ref()
            .map(|manifest| self.transparency_proof(username, manifest, transparency_tree_size));
        Ok(UserPreKeyBundlesResponse {
            username: username.to_string(),
            devices,
            manifest,
            transparency,
        })
    }

    async fn fetch_manifest(&self, _username: &str) -> Result<Option<DeviceManifest>> {
        Ok(self.own_manifest.borrow().clone())
    }

    async fn publish_manifest(
        &self,
        manifest: &DeviceManifest,
        transparency_tree_size: u64,
    ) -> Result<PublishManifestResponse> {
        *self.own_manifest.borrow_mut() = Some(manifest.clone());
        Ok(PublishManifestResponse {
            manifest: manifest.clone(),
            transparency: self.transparency_proof("alice", manifest, transparency_tree_size),
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
                    sender_device_id: req.sender_device_id,
                    envelope_type: envelope.envelope_type,
                    suite: envelope.suite,
                    content: envelope.content.clone(),
                    server_timestamp: "2026-07-16T10:00:00Z".into(),
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
    let alice_bundle = bundle_of(&alice_session, 1);
    server.script_sync(vec![vec![alice_bundle.clone()]]);
    server.script_sync_manifests(vec![Some(signed_manifest(&alice_bundle))]);
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
    assert_eq!(pin.highest_version, 1);
    assert_eq!(pin.authority_key_id, manifest.authority_key_id);
    assert_eq!(pin.transparency_position, Some(0));
    let checkpoint = block_on(alice_db.load_transparency_trust("local"))
        .unwrap()
        .unwrap();
    assert!(checkpoint.tree_size >= 1);
    assert_eq!(checkpoint.log_id, "01".repeat(32));
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
fn explicit_contact_state_converges_over_authenticated_linked_device_sync() {
    let mut rng = test_rng();
    let alice1 = device("alice", 1, &mut rng);
    let alice2 = device("alice", 2, &mut rng);
    let bundles = vec![bundle_of(&alice1, 1), bundle_of(&alice2, 2)];
    let server = Rc::new(MockServer::default());
    server.script_sync(vec![bundles]);
    server.set_sync_active(vec![(1, reg_id(&alice1)), (2, reg_id(&alice2))]);

    let mut first = Engine::new_for_development(alice1, server.clone());
    let local = block_on(first.block_contact("bob", "2026-07-16T10:05:00Z", &mut rng)).unwrap();
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
