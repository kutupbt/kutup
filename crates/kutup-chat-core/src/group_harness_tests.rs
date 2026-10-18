//! Groups end to end through real engines (docs/plans/pairwise-groups.md):
//! one server, `example.test`, that is every account's chat server and the
//! groups' home. It keeps what the real one keeps (registrations, signed
//! manifests, profiles, mailboxes, the sealed-sender policy, the groups'
//! states and logs) and checks what it checks (device sets, delivery
//! capabilities, who may read or change a group), crypto-blind otherwise.
//! Its futures are always ready, so `block_on` drives every engine call.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashSet};
use std::rc::Rc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use futures_executor::block_on;
use kutup_chat_proto::group::{
    check_change, check_genesis, decode_exact, GroupActionV1, GroupChangeError, GroupChangeV1,
    GroupLimits, GroupStateV1,
};
use kutup_chat_proto::group_route::{
    GroupGatewayKeyConfigV1, GroupHomePinV1, GroupJoinInfoV1, GroupLogEntryV1, GroupLogPageV1,
    GroupLogQueryV1, GroupNotaryV1, GroupOperationV1, GroupRequestAuthV1, GroupRequestV1,
    GroupResponseStatusV1, GroupResponseV1, GroupStateAnswerV1,
};
use kutup_chat_proto::{
    AccountManifestHistoryPageV1, AccountManifestPublicationV1, AccountManifestV1,
    DeliveredEnvelope, DeviceListMismatch, DevicePreKeyBundle, DirectChatSuiteId, EnvelopeType,
    MailboxPage, OwnChatProfileResponse, PutChatProfileRequest, RegisterChatDeviceRequest,
    SealedMessageSubmissionV1, SealedSenderRootV1, SealedSenderServerCertificateV1,
    SealedSenderServicePolicyV1, SealedSenderSuiteId, SendMessagesRequest,
    SenderCertificateResponseV1, UserPreKeyBundlesResponse,
};
use kutup_crypto::oblivious::GatewayKey;
use kutup_federation_proto::{
    FederatedFeaturePolicyEnvelopeV1, FederatedFeaturePolicyHistoryV1,
    FederatedFeaturePolicyTypeV1, FederationIdentityDocumentV1,
};
use libsignal_protocol::{KeyPair, PublicKey, SenderCertificate, ServerCertificate, Timestamp};
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng, TryRngCore as _};
use sha2::{Digest as _, Sha256};

use crate::engine::{Engine, ReceiveReport};
use crate::error::{ChatError, Result};
use crate::group::GroupStatus;
use crate::group_engine::GroupSync;
use crate::transport::{ChatTransport, GroupGatewayAnswer, GroupRelayOutcome, SendOutcome};
use crate::{AccountAuthority, ChatContent, SqliteChatDb};

pub(crate) const SERVER: &str = "example.test";
const ISSUED_AT: &str = "2026-10-18T00:00:00Z";

pub(crate) fn rng() -> impl Rng + CryptoRng {
    OsRng.unwrap_err()
}

fn now() -> i64 {
    crate::clock::unix_millis() / 1000
}

/// One device's published keys; one-time prekeys are handed out once each.
struct HostedDevice {
    registration: RegisterChatDeviceRequest,
    next_ec: usize,
    next_kyber: usize,
}

impl HostedDevice {
    /// A bundle as a fetch serves it: one one-time prekey of each kind used up
    /// (`consume`), or none for a device that never encrypts to itself.
    fn bundle(&mut self, device_id: u32, consume: bool) -> DevicePreKeyBundle {
        let registration = &self.registration;
        let kyber = registration
            .one_time_kyber_pre_keys
            .get(self.next_kyber)
            .cloned()
            .unwrap_or_else(|| registration.last_resort_kyber_pre_key.clone());
        let one_time = registration.one_time_pre_keys.get(self.next_ec).cloned();
        if consume {
            self.next_kyber += 1;
            self.next_ec += 1;
        }
        DevicePreKeyBundle {
            device_id,
            registration_id: registration.registration_id,
            suite: registration.suite,
            identity_key: registration.identity_key.clone(),
            signed_pre_key: registration.signed_pre_key.clone(),
            kyber_pre_key: kyber,
            one_time_pre_key: one_time,
        }
    }
}

#[derive(Default)]
struct HostedAccount {
    devices: BTreeMap<u32, HostedDevice>,
    manifests: Vec<AccountManifestV1>,
    profile: Option<PutChatProfileRequest>,
}

/// A group as its home holds it: the state, its head, and the log.
struct HostedGroup {
    state: GroupStateV1,
    head: [u8; 32],
    log: Vec<(GroupChangeV1, GroupNotaryV1)>,
}

/// The one server of these tests.
pub(crate) struct World {
    identity: FederationIdentityDocumentV1,
    key: SigningKey,
    gateway: GatewayKey,
    config: GroupGatewayKeyConfigV1,
    groups: RefCell<BTreeMap<[u8; 32], HostedGroup>>,
    nonces: RefCell<HashSet<String>>,
    server_key: KeyPair,
    server_certificate: ServerCertificate,
    policy: FederatedFeaturePolicyHistoryV1,
    accounts: RefCell<BTreeMap<String, HostedAccount>>,
    mailboxes: RefCell<BTreeMap<(String, u32), Vec<DeliveredEnvelope>>>,
    cursor: Cell<u64>,
    /// Every sealed submission that was stored: `(recipient, submission)`.
    pub(crate) sealed_sent: RefCell<Vec<(String, SealedMessageSubmissionV1)>>,
}

impl World {
    pub(crate) fn new() -> Rc<Self> {
        let mut rng = rng();
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let identity = FederationIdentityDocumentV1::genesis(SERVER, now() - 3600, &key).unwrap();
        let gateway = GatewayKey::generate(1).unwrap();
        let config = GroupGatewayKeyConfigV1::sign(
            &identity,
            &key,
            gateway.key_id(),
            &gateway.public_key(),
            now() - 100,
            now() - 100 + 7 * 24 * 60 * 60,
        )
        .unwrap();
        let trust_root = KeyPair::generate(&mut rng);
        let server_key = KeyPair::generate(&mut rng);
        let server_certificate =
            ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)
                .unwrap();
        let root_key = trust_root.public_key.serialize();
        let root_id = hex::encode(Sha256::digest(&root_key));
        let payload = SealedSenderServicePolicyV1 {
            policy_version: 1,
            canonical_domain: SERVER.into(),
            suite: SealedSenderSuiteId::LibsignalV2DeliveryCapabilityV1,
            roots: vec![SealedSenderRootV1 {
                root_id: root_id.clone(),
                public_key: STANDARD.encode(&root_key),
                activates_at: now() - 3600,
                revokes_at: None,
            }],
            server_certificates: vec![SealedSenderServerCertificateV1 {
                certificate_id: 1,
                root_id,
                certificate: STANDARD.encode(server_certificate.serialized().unwrap()),
                activates_at: now() - 3600,
                expires_at: now() + 30 * 24 * 60 * 60,
            }],
            sender_certificate_lifetime_seconds: 24 * 60 * 60,
            maximum_clock_skew_seconds: 300,
            direct_chat_suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
        }
        .canonical_bytes()
        .unwrap();
        let envelope = FederatedFeaturePolicyEnvelopeV1::sign(
            SERVER,
            FederatedFeaturePolicyTypeV1::SealedSenderService,
            1,
            None,
            &identity,
            &payload,
            now() - 3600,
            &key,
        )
        .unwrap();
        let policy = FederatedFeaturePolicyHistoryV1 {
            domain: SERVER.into(),
            feature_type: FederatedFeaturePolicyTypeV1::SealedSenderService,
            identities: vec![identity.clone()],
            policies: vec![envelope],
        };
        Rc::new(Self {
            identity,
            key,
            gateway,
            config,
            groups: RefCell::new(BTreeMap::new()),
            nonces: RefCell::new(HashSet::new()),
            server_key,
            server_certificate,
            policy,
            accounts: RefCell::new(BTreeMap::new()),
            mailboxes: RefCell::new(BTreeMap::new()),
            cursor: Cell::new(0),
            sealed_sent: RefCell::new(Vec::new()),
        })
    }

    /// A new account with its first device, its manifest and its profile
    /// published, sealed sender on. `n` makes its id.
    pub(crate) fn person(self: &Rc<Self>, n: u8) -> Person {
        let account = format!("aci:00000000-0000-4000-8000-0000000000{n:02x}@{SERVER}");
        let authority = AccountAuthority::derive(&[n; 32]).unwrap();
        let wrapping_key = [n.wrapping_add(100); 32];
        self.device_of(&account, authority, wrapping_key)
    }

    /// Another device of `person`'s account, linked as a new install is.
    #[allow(dead_code)] // for the linked-device tests
    pub(crate) fn link_device(self: &Rc<Self>, person: &Person) -> Person {
        let seed = person.authority_seed;
        self.device_of(
            &person.account,
            AccountAuthority::derive(&[seed; 32]).unwrap(),
            person.wrapping_key,
        )
    }

    fn device_of(
        self: &Rc<Self>,
        account: &str,
        authority: AccountAuthority,
        wrapping_key: [u8; 32],
    ) -> Person {
        let mut rng = rng();
        let client = Rc::new(Client {
            world: Rc::clone(self),
            account: account.to_string(),
            device: Cell::new(0),
        });
        let db = Rc::new(SqliteChatDb::open_in_memory().unwrap());
        let mut engine = block_on(Engine::register(
            db,
            client.clone(),
            account.to_string(),
            32,
            &mut rng,
        ))
        .unwrap();
        engine.set_sealed_sender_enabled(true);
        block_on(engine.sync_own_manifest(&authority, ISSUED_AT)).unwrap();
        block_on(engine.initialize_profile(&wrapping_key, "Someone", &mut rng)).unwrap();
        let authority_seed = account
            .strip_suffix(&format!("@{SERVER}"))
            .and_then(|id| u8::from_str_radix(&id[id.len() - 2..], 16).ok())
            .unwrap();
        Person {
            engine,
            client,
            account: account.to_string(),
            authority_seed,
            wrapping_key,
        }
    }

    /// The envelopes waiting for one device.
    pub(crate) fn mailbox(&self, account: &str, device: u32) -> Vec<DeliveredEnvelope> {
        self.mailboxes
            .borrow()
            .get(&(account.to_string(), device))
            .cloned()
            .unwrap_or_default()
    }

    /// Keeps only the envelopes `keep` says to (the rest are lost on the way).
    pub(crate) fn retain_mailbox(
        &self,
        account: &str,
        device: u32,
        keep: impl Fn(&DeliveredEnvelope) -> bool,
    ) {
        if let Some(mailbox) = self
            .mailboxes
            .borrow_mut()
            .get_mut(&(account.to_string(), device))
        {
            mailbox.retain(|envelope| keep(envelope));
        }
    }

    /// The group as its home holds it now.
    pub(crate) fn group_state(&self, group_id: &str) -> GroupStateV1 {
        let id = kutup_chat_proto::group::decode_group_id(group_id).unwrap();
        self.groups.borrow()[&id].state.clone()
    }

    fn deposit(&self, account: &str, device: u32, mut envelope: DeliveredEnvelope) {
        let cursor = self.cursor.get() + 1;
        self.cursor.set(cursor);
        envelope.cursor = cursor;
        envelope.id = uuid::Uuid::new_v4().to_string();
        self.mailboxes
            .borrow_mut()
            .entry((account.to_string(), device))
            .or_default()
            .push(envelope);
    }

    /// The server's 409: the request's devices against the account's.
    fn device_check(
        &self,
        account: &str,
        sent: &[(u32, u32)],
        except: Option<u32>,
    ) -> Option<DeviceListMismatch> {
        let accounts = self.accounts.borrow();
        let active: Vec<(u32, u32)> = accounts
            .get(account)
            .map(|hosted| {
                hosted
                    .devices
                    .iter()
                    .filter(|(id, _)| Some(**id) != except)
                    .map(|(id, device)| (*id, device.registration.registration_id))
                    .collect()
            })
            .unwrap_or_default();
        let missing_devices: Vec<u32> = active
            .iter()
            .map(|(id, _)| *id)
            .filter(|id| !sent.iter().any(|(sent, _)| sent == id))
            .collect();
        let extra_devices: Vec<u32> = sent
            .iter()
            .map(|(id, _)| *id)
            .filter(|id| !active.iter().any(|(active, _)| active == id))
            .collect();
        let stale_devices: Vec<u32> = sent
            .iter()
            .filter(|(id, registration)| {
                active
                    .iter()
                    .any(|(active, current)| active == id && current != registration)
            })
            .map(|(id, _)| *id)
            .collect();
        if missing_devices.is_empty() && extra_devices.is_empty() && stale_devices.is_empty() {
            None
        } else {
            Some(DeviceListMismatch {
                missing_devices,
                stale_devices,
                extra_devices,
            })
        }
    }

    /// Whether `capability` is the one `account`'s current profile key gives.
    fn capability_holds(&self, account: &str, capability: &[u8; 16]) -> bool {
        self.accounts
            .borrow()
            .get(account)
            .and_then(|hosted| hosted.profile.as_ref())
            .is_some_and(|profile| {
                profile.delivery_capability_verifier
                    == hex::encode(kutup_chat_proto::capability_hash(capability))
            })
    }

    fn bundles(&self, account: &str, keep: Option<u32>) -> Result<UserPreKeyBundlesResponse> {
        let mut accounts = self.accounts.borrow_mut();
        let hosted = accounts
            .get_mut(account)
            .ok_or_else(|| ChatError::Transport("no such account".into()))?;
        let devices = hosted
            .devices
            .iter_mut()
            // Every device is served (the manifest names them all); the
            // asking device's own one-time prekeys aren't used up.
            .map(|(id, device)| device.bundle(*id, Some(*id) != keep))
            .collect();
        Ok(UserPreKeyBundlesResponse {
            account: account.parse().unwrap(),
            devices,
            manifest: hosted.manifests.last().cloned(),
        })
    }

    // ----- the group home -----

    fn status(status: GroupResponseStatusV1) -> GroupResponseV1 {
        GroupResponseV1::new(status, now(), b"")
    }

    fn ok(body: Vec<u8>) -> GroupResponseV1 {
        GroupResponseV1::new(GroupResponseStatusV1::Ok, now(), &body)
    }

    fn refused(error: &GroupChangeError) -> GroupResponseV1 {
        match error {
            GroupChangeError::WrongRevision | GroupChangeError::WrongPrevious => {
                Self::status(GroupResponseStatusV1::Conflict)
            }
            other => GroupResponseV1::refused(other.code(), now()),
        }
    }

    fn notarise(
        &self,
        group_id: &[u8; 32],
        change: &GroupChangeV1,
        next: &GroupStateV1,
    ) -> GroupNotaryV1 {
        GroupNotaryV1::sign(
            &self.identity,
            &self.key,
            &self.config,
            group_id,
            next.revision,
            &change.hash().unwrap(),
            &next.hash().unwrap(),
        )
        .unwrap()
    }

    /// What the home answers, as `chat_groups/gateway.rs` does.
    fn answer(&self, request: &GroupRequestV1) -> GroupResponseV1 {
        if request.home != SERVER {
            return Self::status(GroupResponseStatusV1::NotFound);
        }
        if !request.is_timely(now()) {
            return Self::status(GroupResponseStatusV1::ClockSkew);
        }
        let Ok(group_id) = request.group_id() else {
            return GroupResponseV1::refused("malformed", now());
        };
        let GroupRequestAuthV1::Pseudonym { pseudonym, .. } = &request.auth else {
            // Links come with a later slice of these tests.
            return Self::status(GroupResponseStatusV1::NotFound);
        };
        if request.verify_pseudonym().is_err() {
            return Self::status(GroupResponseStatusV1::NotFound);
        }
        if !self.nonces.borrow_mut().insert(request.nonce.clone()) {
            return Self::status(GroupResponseStatusV1::Replayed);
        }
        let change = || {
            request
                .body()
                .ok()
                .and_then(|body| GroupChangeV1::from_canonical_bytes(&body).ok())
        };
        let mut groups = self.groups.borrow_mut();
        match request.operation {
            GroupOperationV1::Create => {
                let Some(change) = change() else {
                    return GroupResponseV1::refused("malformed", now());
                };
                if change.actor != *pseudonym || change.group_id != request.group_id {
                    return GroupResponseV1::refused("wrongGroup", now());
                }
                let pin = GroupHomePinV1::of(&self.identity).unwrap();
                let genesis = match check_genesis(&change, &pin, &GroupLimits::MAX) {
                    Ok(genesis) => genesis,
                    Err(error) => return Self::refused(&error),
                };
                if groups.contains_key(&group_id) {
                    return Self::status(GroupResponseStatusV1::Conflict);
                }
                let notary = self.notarise(&group_id, &change, &genesis);
                groups.insert(
                    group_id,
                    HostedGroup {
                        state: genesis.clone(),
                        head: change.hash().unwrap(),
                        log: vec![(change.clone(), notary.clone())],
                    },
                );
                Self::ok(
                    GroupStateAnswerV1 {
                        state: STANDARD.encode(genesis.canonical_bytes().unwrap()),
                        change: STANDARD.encode(change.canonical_bytes().unwrap()),
                        notary,
                    }
                    .canonical_bytes()
                    .unwrap(),
                )
            }
            GroupOperationV1::GetState => {
                let Some(group) = groups.get(&group_id) else {
                    return Self::status(GroupResponseStatusV1::NotFound);
                };
                if group.state.member(pseudonym).is_none() {
                    return Self::status(GroupResponseStatusV1::NotFound);
                }
                let (change, notary) = group.log.last().unwrap();
                Self::ok(
                    GroupStateAnswerV1 {
                        state: STANDARD.encode(group.state.canonical_bytes().unwrap()),
                        change: STANDARD.encode(change.canonical_bytes().unwrap()),
                        notary: notary.clone(),
                    }
                    .canonical_bytes()
                    .unwrap(),
                )
            }
            GroupOperationV1::GetLogs => {
                let Some(query) = request
                    .body()
                    .ok()
                    .and_then(|body| serde_json::from_slice::<GroupLogQueryV1>(&body).ok())
                else {
                    return GroupResponseV1::refused("malformed", now());
                };
                let Some(group) = groups.get(&group_id) else {
                    return Self::status(GroupResponseStatusV1::NotFound);
                };
                let Some(member) = group.state.member(pseudonym) else {
                    return Self::status(GroupResponseStatusV1::NotFound);
                };
                let from = query.from_revision.max(member.joined_at_revision);
                let limit = usize::from(query.limit.max(1));
                let rest: Vec<_> = group
                    .log
                    .iter()
                    .filter(|(change, _)| change.revision >= from)
                    .collect();
                let page = GroupLogPageV1 {
                    entries: rest
                        .iter()
                        .take(limit)
                        .map(|(change, notary)| GroupLogEntryV1 {
                            change: STANDARD.encode(change.canonical_bytes().unwrap()),
                            notary: notary.clone(),
                        })
                        .collect(),
                    more: rest.len() > limit,
                };
                Self::ok(page.canonical_bytes().unwrap())
            }
            GroupOperationV1::SubmitChange => {
                let Some(change) = change() else {
                    return GroupResponseV1::refused("malformed", now());
                };
                if change.actor != *pseudonym {
                    return GroupResponseV1::refused("wrongActor", now());
                }
                let Some(group) = groups.get_mut(&group_id) else {
                    return Self::status(GroupResponseStatusV1::NotFound);
                };
                if !admitted(&group.state, &group_id, &change) {
                    return Self::status(GroupResponseStatusV1::NotFound);
                }
                let next = match check_change(&group.state, &group.head, &change, &GroupLimits::MAX)
                {
                    Ok(next) => next,
                    Err(error) => return Self::refused(&error),
                };
                let notary = self.notarise(&group_id, &change, &next);
                group.state = next;
                group.head = change.hash().unwrap();
                group.log.push((change.clone(), notary.clone()));
                Self::ok(
                    serde_json::to_vec(&GroupLogEntryV1 {
                        change: STANDARD.encode(change.canonical_bytes().unwrap()),
                        notary,
                    })
                    .unwrap(),
                )
            }
            GroupOperationV1::GetJoinInfo => {
                let Some(group) = groups.get(&group_id) else {
                    return Self::status(GroupResponseStatusV1::NotFound);
                };
                if !group
                    .state
                    .slots
                    .iter()
                    .any(|slot| slot.claim_key == *pseudonym)
                {
                    return Self::status(GroupResponseStatusV1::NotFound);
                }
                Self::ok(
                    GroupJoinInfoV1 {
                        revision: group.state.revision,
                        head: STANDARD.encode(group.head),
                        member_count: group.state.members.len() as u16,
                        title: None,
                        description: None,
                        avatar: None,
                        requires_approval: None,
                    }
                    .canonical_bytes()
                    .unwrap(),
                )
            }
            _ => Self::status(GroupResponseStatusV1::Unavailable),
        }
    }
}

/// Whether the change's actor may act: a member, or a newcomer whose own
/// action holds (as the server's `admitted`).
fn admitted(state: &GroupStateV1, group_id: &[u8; 32], change: &GroupChangeV1) -> bool {
    let actor = change.actor.as_str();
    if !change.is_newcomers_change() {
        return state.member(actor).is_some();
    }
    match change.actions.as_slice() {
        [GroupActionV1::Claim {
            slot_id,
            claim_signature,
            ..
        }] => {
            let Some(slot) = state.slots.iter().find(|slot| slot.slot_id == *slot_id) else {
                return false;
            };
            let (Ok(claim_key), Ok(slot_bytes), Ok(actor_key), Ok(signature)) = (
                decode_exact::<32>("claimKey", &slot.claim_key),
                decode_exact::<16>("slotId", slot_id),
                decode_exact::<32>("actor", actor),
                decode_exact::<64>("signature", claim_signature),
            ) else {
                return false;
            };
            kutup_crypto::chat_group::verify_claim_signature(
                &claim_key,
                group_id,
                &slot_bytes,
                slot.created_at_revision,
                &actor_key,
                &signature,
            )
            .is_ok()
        }
        [GroupActionV1::CancelRequest] => state.requesting.iter().any(|r| r.pseudonym == actor),
        _ => false,
    }
}

/// One device's connection to the server: it acts as `account`.
pub(crate) struct Client {
    world: Rc<World>,
    account: String,
    device: Cell<u32>,
}

#[async_trait(?Send)]
impl ChatTransport for Client {
    async fn register_device(&self, request: &RegisterChatDeviceRequest) -> Result<u32> {
        let mut accounts = self.world.accounts.borrow_mut();
        let hosted = accounts.entry(self.account.clone()).or_default();
        let device_id = hosted.devices.keys().max().map_or(1, |last| last + 1);
        hosted.devices.insert(
            device_id,
            HostedDevice {
                registration: request.clone(),
                next_ec: 0,
                next_kyber: 0,
            },
        );
        self.device.set(device_id);
        Ok(device_id)
    }

    async fn fetch_bundles(&self, account: &str) -> Result<UserPreKeyBundlesResponse> {
        self.world.bundles(account, None)
    }

    async fn fetch_sync_bundles(
        &self,
        account: &str,
        current_device_id: u32,
    ) -> Result<UserPreKeyBundlesResponse> {
        self.world.bundles(account, Some(current_device_id))
    }

    async fn fetch_manifest(&self, account: &str) -> Result<Option<AccountManifestV1>> {
        Ok(self
            .world
            .accounts
            .borrow()
            .get(account)
            .and_then(|hosted| hosted.manifests.last().cloned()))
    }

    async fn fetch_manifest_history(
        &self,
        account: &str,
        _from_sequence: u64,
        to_sequence: u64,
        page_from_sequence: u64,
    ) -> Result<AccountManifestHistoryPageV1> {
        let manifests = self
            .world
            .accounts
            .borrow()
            .get(account)
            .map(|hosted| {
                hosted
                    .manifests
                    .iter()
                    .filter(|m| m.sequence >= page_from_sequence && m.sequence <= to_sequence)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        Ok(AccountManifestHistoryPageV1 {
            account: account.parse().unwrap(),
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
        let mut accounts = self.world.accounts.borrow_mut();
        let hosted = accounts.entry(self.account.clone()).or_default();
        if hosted
            .manifests
            .last()
            .is_none_or(|prior| prior.sequence < manifest.sequence)
        {
            hosted.manifests.push(manifest.clone());
        }
        Ok(AccountManifestPublicationV1 {
            manifest: hosted.manifests.last().cloned().unwrap(),
        })
    }

    async fn fetch_own_profile(&self) -> Result<Option<OwnChatProfileResponse>> {
        Ok(self
            .world
            .accounts
            .borrow()
            .get(&self.account)
            .and_then(|hosted| hosted.profile.clone()))
    }

    async fn publish_profile(
        &self,
        profile: &PutChatProfileRequest,
    ) -> Result<OwnChatProfileResponse> {
        let mut accounts = self.world.accounts.borrow_mut();
        let hosted = accounts.entry(self.account.clone()).or_default();
        if hosted.profile.as_ref().is_some_and(|current| {
            (current.revision, current.source_device_id)
                >= (profile.revision, profile.source_device_id)
                && current != profile
        }) {
            return Err(ChatError::Transport("profile conflict".into()));
        }
        hosted.profile = Some(profile.clone());
        Ok(profile.clone())
    }

    async fn fetch_profile(
        &self,
        _account: &str,
        _version: &str,
        _access_key: &[u8],
    ) -> Result<Option<kutup_chat_proto::ChatProfileResponse>> {
        Ok(None)
    }

    async fn fetch_sealed_sender_policy(
        &self,
        domain: &str,
    ) -> Result<FederatedFeaturePolicyHistoryV1> {
        if domain != SERVER {
            return Err(ChatError::Transport("unknown server".into()));
        }
        Ok(self.world.policy.clone())
    }

    async fn fetch_sender_certificate(
        &self,
        device_id: u32,
    ) -> Result<SenderCertificateResponseV1> {
        let identity = {
            let accounts = self.world.accounts.borrow();
            let device = accounts
                .get(&self.account)
                .and_then(|hosted| hosted.devices.get(&device_id))
                .ok_or_else(|| ChatError::Transport("no such device".into()))?;
            PublicKey::deserialize(&STANDARD.decode(&device.registration.identity_key).unwrap())
                .unwrap()
        };
        let expires_at = now() + 60 * 60;
        let certificate = SenderCertificate::new(
            self.account.clone(),
            None,
            identity,
            crate::address::device_id_u8(device_id).unwrap(),
            Timestamp::from_epoch_millis(expires_at as u64 * 1000),
            self.world.server_certificate.clone(),
            &self.world.server_key.private_key,
            &mut rng(),
        )
        .unwrap();
        Ok(SenderCertificateResponseV1 {
            suite: SealedSenderSuiteId::LibsignalV2DeliveryCapabilityV1,
            certificate: STANDARD.encode(certificate.serialized().unwrap()),
            expires_at,
            service_policy_sequence: 1,
        })
    }

    async fn fetch_sealed_bundles(
        &self,
        account: &str,
        capability: &[u8; 16],
    ) -> Result<UserPreKeyBundlesResponse> {
        if !self.world.capability_holds(account, capability) {
            return Err(ChatError::Transport("sealed delivery unavailable".into()));
        }
        self.world.bundles(account, None)
    }

    async fn send_sealed(
        &self,
        account: &str,
        request: &SealedMessageSubmissionV1,
    ) -> Result<SendOutcome> {
        let capability: [u8; 16] = STANDARD
            .decode(&request.capability)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| ChatError::Transport("malformed capability".into()))?;
        if !self.world.capability_holds(account, &capability) {
            return Ok(SendOutcome::Refused);
        }
        let sent: Vec<(u32, u32)> = request
            .envelopes
            .iter()
            .map(|e| (e.device_id, e.registration_id))
            .collect();
        if let Some(mismatch) = self.world.device_check(account, &sent, None) {
            return Ok(SendOutcome::Mismatch(mismatch));
        }
        for envelope in &request.envelopes {
            self.world.deposit(
                account,
                envelope.device_id,
                DeliveredEnvelope {
                    id: String::new(),
                    cursor: 0,
                    sender: None,
                    sealed_sender: true,
                    sender_device_id: 0,
                    envelope_type: EnvelopeType::Message,
                    suite: envelope.suite,
                    content: envelope.content.clone(),
                    server_timestamp: crate::clock::rfc3339(crate::clock::unix_millis()),
                    send_id: Some(request.send_id.clone()),
                },
            );
        }
        self.world
            .sealed_sent
            .borrow_mut()
            .push((account.to_string(), request.clone()));
        Ok(SendOutcome::Delivered {
            deduplicated: false,
        })
    }

    async fn send(&self, account: &str, request: &SendMessagesRequest) -> Result<SendOutcome> {
        let sent: Vec<(u32, u32)> = request
            .envelopes
            .iter()
            .map(|e| (e.device_id, e.registration_id))
            .collect();
        if let Some(mismatch) = self.world.device_check(account, &sent, None) {
            return Ok(SendOutcome::Mismatch(mismatch));
        }
        self.store_identified(account, request);
        Ok(SendOutcome::Delivered {
            deduplicated: false,
        })
    }

    async fn send_sync(&self, request: &SendMessagesRequest) -> Result<SendOutcome> {
        let sent: Vec<(u32, u32)> = request
            .envelopes
            .iter()
            .map(|e| (e.device_id, e.registration_id))
            .collect();
        if let Some(mismatch) =
            self.world
                .device_check(&self.account, &sent, Some(request.sender_device_id))
        {
            return Ok(SendOutcome::Mismatch(mismatch));
        }
        let account = self.account.clone();
        self.store_identified(&account, request);
        Ok(SendOutcome::Delivered {
            deduplicated: false,
        })
    }

    async fn drain(&self, device_id: u32, after: Option<u64>, limit: u32) -> Result<MailboxPage> {
        let mailbox = self.world.mailbox(&self.account, device_id);
        let pending: Vec<_> = mailbox
            .into_iter()
            .filter(|envelope| after.is_none_or(|cursor| envelope.cursor > cursor))
            .collect();
        let more = pending.len() > limit as usize;
        Ok(MailboxPage {
            envelopes: pending.into_iter().take(limit as usize).collect(),
            more,
        })
    }

    async fn ack(&self, device_id: u32, ids: &[String]) -> Result<()> {
        self.world
            .retain_mailbox(&self.account, device_id, |envelope| {
                !ids.contains(&envelope.id)
            });
        Ok(())
    }

    async fn fetch_group_gateway(&self, home: &str, _from: u64) -> Result<GroupGatewayAnswer> {
        if home != SERVER {
            return Err(ChatError::Transport("unknown home".into()));
        }
        Ok(GroupGatewayAnswer {
            config: self.world.config.clone(),
            identity_history: vec![self.world.identity.clone()],
        })
    }

    async fn relay_group_request(&self, home: &str, sealed: &[u8]) -> Result<GroupRelayOutcome> {
        if home != SERVER {
            return Ok(GroupRelayOutcome::Unreachable);
        }
        let Ok((body, context)) = self.world.gateway.open_request(sealed) else {
            return Ok(GroupRelayOutcome::Unopenable);
        };
        let answer = match GroupRequestV1::from_canonical_bytes(&body) {
            Ok(request) => self.world.answer(&request),
            Err(_) => GroupResponseV1::refused("malformed", now()),
        };
        Ok(GroupRelayOutcome::Answered(
            context
                .seal_response(&answer.canonical_bytes().unwrap())
                .unwrap(),
        ))
    }
}

impl Client {
    fn store_identified(&self, account: &str, request: &SendMessagesRequest) {
        for envelope in &request.envelopes {
            self.world.deposit(
                account,
                envelope.device_id,
                DeliveredEnvelope {
                    id: String::new(),
                    cursor: 0,
                    sender: Some(self.account.parse().unwrap()),
                    sealed_sender: false,
                    sender_device_id: request.sender_device_id,
                    envelope_type: envelope.envelope_type,
                    suite: envelope.suite,
                    content: envelope.content.clone(),
                    server_timestamp: crate::clock::rfc3339(crate::clock::unix_millis()),
                    send_id: Some(request.send_id.clone()),
                },
            );
        }
    }
}

/// One device of an account, with what its app keeps.
pub(crate) struct Person {
    pub(crate) engine: Engine,
    #[allow(dead_code)]
    pub(crate) client: Rc<Client>,
    pub(crate) account: String,
    #[allow(dead_code)] // what linking another device needs
    authority_seed: u8,
    #[allow(dead_code)]
    wrapping_key: [u8; 32],
}

impl Person {
    pub(crate) fn device(&self) -> u32 {
        self.engine.session().device_id()
    }

    /// Takes everything waiting for this device.
    pub(crate) fn receive(&mut self) -> ReceiveReport {
        block_on(self.engine.receive(&mut rng())).unwrap()
    }

    pub(crate) fn sync(&mut self, group_id: &str) -> GroupSync {
        block_on(self.engine.sync_group(group_id)).unwrap()
    }

    /// Sends a text to the group: its send id.
    pub(crate) fn send_text(&mut self, group_id: &str, text: &str) -> String {
        let send_id = uuid::Uuid::new_v4().to_string();
        let seq = block_on(self.engine.session().next_sent_seq()).unwrap();
        let content = ChatContent::text_with_id(
            &send_id,
            crate::clock::rfc3339(crate::clock::unix_millis()),
            seq,
            text,
        );
        let summary =
            block_on(
                self.engine
                    .send_group_message(group_id, &send_id, content, &mut rng()),
            )
            .unwrap();
        assert_eq!(summary.pending, 0, "every leg went out");
        send_id
    }

    pub(crate) fn status(&self, group_id: &str) -> GroupStatus {
        block_on(self.engine.load_group_record(group_id))
            .unwrap()
            .status
    }

    /// The group texts this device has, in its history, oldest first.
    pub(crate) fn group_texts(&self, group_id: &str) -> Vec<String> {
        let received = block_on(self.engine.session().history()).unwrap();
        let sent = block_on(self.engine.session().sent_history()).unwrap();
        received
            .iter()
            .map(|message| &message.content)
            .chain(sent.iter().map(|message| &message.content))
            .filter_map(|bytes| {
                let content = serde_json::from_slice::<ChatContent>(bytes).ok()?;
                (content.group_context()?.group_id == group_id)
                    .then(|| content.as_text().map(|text| text.text))
                    .flatten()
            })
            .collect()
    }

    /// The placeholders of group messages this device couldn't read yet.
    pub(crate) fn group_placeholders(&self, group_id: &str) -> usize {
        block_on(self.engine.session().history())
            .unwrap()
            .iter()
            .filter(|message| {
                serde_json::from_slice::<ChatContent>(&message.content)
                    .ok()
                    .is_some_and(|content| {
                        content.as_undecryptable().is_some()
                            && content
                                .group_context()
                                .is_some_and(|context| context.group_id == group_id)
                    })
            })
            .count()
    }
}

/// Every device takes what waits for it, again until nothing is left
/// (answers to what came in go out meanwhile).
pub(crate) fn deliver_all(people: &mut [&mut Person]) {
    for _ in 0..8 {
        let mut any = false;
        for person in people.iter_mut() {
            let world = &person.client.world;
            if !world.mailbox(&person.account, person.device()).is_empty() {
                any = true;
                person.receive();
            }
        }
        if !any {
            return;
        }
    }
    panic!("the mailboxes never emptied");
}

/// `a` writes to `b`, who accepts the request: accepted contacts both ways,
/// each holding the other's profile key (what inviting needs).
pub(crate) fn befriend(a: &mut Person, b: &mut Person) {
    let mut rng = rng();
    let send_id = uuid::Uuid::new_v4().to_string();
    let seq = block_on(a.engine.session().next_sent_seq()).unwrap();
    let content = ChatContent::text_with_id(&send_id, ISSUED_AT, seq, "hello");
    block_on(a.engine.send(&send_id, &b.account, &content, &mut rng)).unwrap();
    b.receive();
    block_on(b.engine.accept_contact(&a.account, ISSUED_AT, &mut rng)).unwrap();
    // A reply is what accepts the conversation on `a`'s side.
    let send_id = uuid::Uuid::new_v4().to_string();
    let seq = block_on(b.engine.session().next_sent_seq()).unwrap();
    let content = ChatContent::text_with_id(&send_id, ISSUED_AT, seq, "hi");
    block_on(b.engine.send(&send_id, &a.account, &content, &mut rng)).unwrap();
    a.receive();
    b.receive();
    for (me, peer) in [(&*a, &*b), (&*b, &*a)] {
        let contact = block_on(me.engine.session().contact(&peer.account))
            .unwrap()
            .expect("a contact");
        assert_eq!(contact.state, crate::ContactState::Accepted);
        assert!(
            block_on(me.engine.session().peer_profile(&peer.account))
                .unwrap()
                .is_some(),
            "the peer's profile key is held"
        );
    }
}

/// `alice` makes a group; each of `invitees` (made her contacts first) takes
/// the invitation and joins; everyone is caught up. The group's id.
pub(crate) fn group_of(alice: &mut Person, invitees: &mut [&mut Person]) -> String {
    for invitee in invitees.iter_mut() {
        befriend(alice, invitee);
    }
    let created = block_on(alice.engine.create_group("Team")).unwrap();
    assert!(created.title_set);
    let group_id = created.group_id;
    let accounts: Vec<String> = invitees.iter().map(|p| p.account.clone()).collect();
    let sent = block_on(
        alice
            .engine
            .invite_to_group(&group_id, &accounts, &mut rng()),
    )
    .unwrap();
    assert_eq!(sent, accounts.len());
    for invitee in invitees.iter_mut() {
        let report = invitee.receive();
        let invites: Vec<_> = report
            .group_invites
            .iter()
            .map(|notice| (notice.group_id.clone(), notice.from.clone(), notice.request))
            .collect();
        assert_eq!(
            invites,
            vec![(group_id.clone(), alice.account.clone(), false)]
        );
        assert!(matches!(
            invitee.status(&group_id),
            GroupStatus::Invited { .. }
        ));
        let joined = block_on(invitee.engine.accept_group_invite(&group_id, &mut rng())).unwrap();
        assert!(matches!(
            joined,
            GroupSync::Current {
                key_confirmed: true,
                ..
            }
        ));
        assert_eq!(invitee.status(&group_id), GroupStatus::Member);
    }
    let revision = alice.sync(&group_id);
    for invitee in invitees.iter_mut() {
        assert_eq!(invitee.sync(&group_id), revision);
    }
    group_id
}

#[test]
fn group_harness_members_message_each_other_under_sender_keys() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let mut carol = world.person(0xc3);
    let group_id = group_of(&mut alice, &mut [&mut bob, &mut carol]);
    assert_eq!(world.group_state(&group_id).members.len(), 3);

    let first = alice.send_text(&group_id, "hello group");
    for person in [&mut bob, &mut carol] {
        let report = person.receive();
        let texts: Vec<_> = report
            .messages
            .iter()
            .filter_map(|m| Some((m.content.as_text()?.text, m.content.message_id.clone())))
            .collect();
        assert_eq!(texts, vec![("hello group".to_string(), first.clone())]);
        let message = report
            .messages
            .iter()
            .find(|m| m.content.as_text().is_some())
            .unwrap();
        assert_eq!(message.from.name(), alice.account);
        let context = message.content.group_context().unwrap();
        assert_eq!(context.group_id, group_id);
        assert_eq!(context.revision, world.group_state(&group_id).revision);
        assert!(report.errors.is_empty());
    }

    bob.send_text(&group_id, "hi from bob");
    for person in [&mut alice, &mut carol] {
        let report = person.receive();
        let texts: Vec<_> = report
            .messages
            .iter()
            .filter_map(|m| m.content.as_text().map(|t| t.text))
            .collect();
        assert_eq!(texts, vec!["hi from bob".to_string()]);
    }
    deliver_all(&mut [&mut alice, &mut bob, &mut carol]);
    assert_eq!(
        carol.group_texts(&group_id),
        vec!["hello group".to_string(), "hi from bob".to_string()]
    );
    // One encryption per message: each member account got one envelope of
    // the group message, not one per pairwise session.
    let legs = world
        .sealed_sent
        .borrow()
        .iter()
        .filter(|(_, submission)| submission.send_id == first)
        .count();
    assert_eq!(legs, 2);
}

#[test]
fn group_harness_a_device_without_the_key_heals_through_a_refresh() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let mut carol = world.person(0xc3);
    let group_id = group_of(&mut alice, &mut [&mut bob, &mut carol]);

    let lost = alice.send_text(&group_id, "you missed the key");
    // Carol's copy of Alice's key is lost on the way; the message isn't.
    world.retain_mailbox(&carol.account, carol.device(), |envelope| {
        envelope.send_id.as_deref() == Some(lost.as_str())
    });
    let report = carol.receive();
    assert_eq!(report.repaired.len(), 1, "a placeholder, not an error");
    assert_eq!(carol.group_placeholders(&group_id), 1);
    assert!(carol.group_texts(&group_id).is_empty());

    // Alice answers the refresh with her key and the message again.
    deliver_all(&mut [&mut alice, &mut bob, &mut carol]);
    assert_eq!(
        carol.group_texts(&group_id),
        vec!["you missed the key".to_string()]
    );
    assert_eq!(carol.group_placeholders(&group_id), 0);

    // And the key holds for the next one.
    alice.send_text(&group_id, "and again");
    carol.receive();
    assert_eq!(
        carol.group_texts(&group_id),
        vec!["you missed the key".to_string(), "and again".to_string()]
    );
}

// ----- the #242 review: removal, invitations, the send log, refresh limits -----

/// The pseudonym `person`'s account has in the group, as `viewer` reads it.
fn pseudonym_of(viewer: &mut Person, group_id: &str, person: &Person) -> String {
    block_on(viewer.engine.group_members(group_id))
        .unwrap()
        .into_iter()
        .find(|member| {
            member
                .verified
                .as_ref()
                .is_some_and(|verified| verified.account.to_string() == person.account)
        })
        .expect("a verified member")
        .pseudonym
}

fn distribution_id(person: &Person, group_id: &str) -> String {
    block_on(person.engine.load_group_record(group_id))
        .unwrap()
        .sender_book
        .expect("a sender key")
        .distribution_id
}

/// The accounts a group message went to (one sealed submission each).
fn reached(world: &World, send_id: &str) -> Vec<String> {
    let mut accounts: Vec<String> = world
        .sealed_sent
        .borrow()
        .iter()
        .filter(|(_, submission)| submission.send_id == send_id)
        .map(|(account, _)| account.clone())
        .collect();
    accounts.sort();
    accounts
}

/// A group of three where Bob is an administrator too, everyone caught up and
/// holding Alice's sender key.
fn group_with_two_admins(world: &Rc<World>) -> (Person, Person, Person, String) {
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let mut carol = world.person(0xc3);
    let group_id = group_of(&mut alice, &mut [&mut bob, &mut carol]);
    let bobs = pseudonym_of(&mut alice, &group_id, &bob);
    block_on(
        alice
            .engine
            .set_group_member_admin(&group_id, &bobs, true, &mut rng()),
    )
    .unwrap();
    deliver_all(&mut [&mut alice, &mut bob, &mut carol]);
    alice.send_text(&group_id, "before");
    deliver_all(&mut [&mut alice, &mut bob, &mut carol]);
    assert_eq!(carol.group_texts(&group_id), vec!["before".to_string()]);
    (alice, bob, carol, group_id)
}

#[test]
fn group_review_another_admins_removal_reaches_a_member_through_the_change_notice() {
    let world = World::new();
    let (mut alice, mut bob, carol, group_id) = group_with_two_admins(&world);
    let before = distribution_id(&alice, &group_id);

    let carols = pseudonym_of(&mut bob, &group_id, &carol);
    block_on(
        bob.engine
            .remove_group_member(&group_id, &carols, &mut rng()),
    )
    .unwrap();
    // Bob's notice makes Alice catch up when it arrives.
    let report = alice.receive();
    assert!(report.errors.is_empty());
    let revision = world.group_state(&group_id).revision;
    let record = block_on(alice.engine.load_group_record(&group_id)).unwrap();
    assert_eq!(record.verified().unwrap().unwrap().0.revision, revision);

    // Her next message goes to Bob alone, under a new key.
    let after = alice.send_text(&group_id, "after");
    assert_eq!(reached(&world, &after), vec![bob.account.clone()]);
    assert_ne!(distribution_id(&alice, &group_id), before);
    assert!(world
        .mailbox(&carol.account, carol.device())
        .iter()
        .all(|envelope| envelope.send_id.as_deref() != Some(after.as_str())));
    bob.receive();
    assert_eq!(
        bob.group_texts(&group_id),
        vec!["before".to_string(), "after".to_string()]
    );
}

#[test]
fn group_review_an_unsynced_member_catches_up_before_sending_and_refuses_the_removed() {
    let world = World::new();
    let (mut alice, mut bob, mut carol, group_id) = group_with_two_admins(&world);
    let before = distribution_id(&alice, &group_id);

    let carols = pseudonym_of(&mut bob, &group_id, &carol);
    block_on(
        bob.engine
            .remove_group_member(&group_id, &carols, &mut rng()),
    )
    .unwrap();
    // Alice never gets Bob's notice, and her last catch-up is a while ago.
    world.retain_mailbox(&alice.account, alice.device(), |_| false);
    let mut record = block_on(alice.engine.load_group_record(&group_id)).unwrap();
    record.synced_at_ms =
        Some(crate::clock::unix_millis() - crate::group_send::SEND_CATCH_UP_AFTER_MS - 1);
    block_on(alice.engine.save_group(&record)).unwrap();

    let after = alice.send_text(&group_id, "after");
    assert_eq!(reached(&world, &after), vec![bob.account.clone()]);
    assert_ne!(
        distribution_id(&alice, &group_id),
        before,
        "the removed member's devices held the old key"
    );

    // Carol hasn't caught up and still sends under her old state: refused.
    let hers = carol.send_text(&group_id, "still here?");
    assert!(reached(&world, &hers).contains(&alice.account));
    let report = alice.receive();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert!(report
        .messages
        .iter()
        .all(|message| message.content.as_text().is_none()));
    assert!(!alice
        .group_texts(&group_id)
        .contains(&"still here?".to_string()));
    let report = bob.receive();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert!(!bob
        .group_texts(&group_id)
        .contains(&"still here?".to_string()));

    // Carol learns of it from the home, as a possible removal.
    assert!(matches!(
        carol.sync(&group_id),
        GroupSync::MaybeRemoved { .. }
    ));
}

/// Whether any row `person` keeps holds `needle`.
fn stored_anywhere(person: &Person, needle: &str) -> bool {
    let db = person.engine.session().db();
    let mut rows: Vec<Vec<u8>> = Vec::new();
    rows.extend(
        block_on(person.engine.session().history())
            .unwrap()
            .into_iter()
            .map(|m| m.content),
    );
    rows.extend(
        block_on(person.engine.session().sent_history())
            .unwrap()
            .into_iter()
            .map(|m| m.content),
    );
    for entry in block_on(db.list_outbox()).unwrap() {
        rows.push(entry.content);
        rows.push(entry.envelopes);
        if let Some(sync) = entry.sync {
            rows.push(sync.content);
        }
    }
    for entry in block_on(db.list_group_outbox()).unwrap() {
        rows.push(entry.content);
    }
    rows.iter()
        .any(|row| String::from_utf8_lossy(row).contains(needle))
}

#[test]
fn group_review_the_claim_key_is_never_kept_by_the_inviter() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    befriend(&mut alice, &mut bob);
    let group_id = block_on(alice.engine.create_group("Team"))
        .unwrap()
        .group_id;
    let to_alice = |world: &World| {
        world
            .sealed_sent
            .borrow()
            .iter()
            .filter(|(account, _)| *account == alice.account)
            .count()
    };
    let before = to_alice(&world);
    let sent = block_on(alice.engine.invite_to_group(
        &group_id,
        &[bob.account.clone()],
        &mut rng(),
    ))
    .unwrap();
    assert_eq!(sent, 1);
    bob.receive();
    let GroupStatus::Invited { claim_key_seed, .. } = bob.status(&group_id) else {
        panic!("invited")
    };
    assert!(!stored_anywhere(&alice, &claim_key_seed.0));
    // No copy for Alice's own account.
    assert_eq!(to_alice(&world), before);
}

fn set_contact_state(person: &mut Person, peer: &str, state: crate::ContactState) {
    let mut contact = block_on(person.engine.session().contact(peer))
        .unwrap()
        .expect("a contact");
    contact.state = state;
    let mut pending = crate::db::Pending::default();
    pending.contacts.insert(peer.to_string(), contact);
    block_on(person.engine.session().db().apply(&pending)).unwrap();
}

#[test]
fn group_review_invitations_follow_the_block_and_request_rules() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let mut carol = world.person(0xc3);
    befriend(&mut alice, &mut bob);
    befriend(&mut alice, &mut carol);
    let group_id = block_on(alice.engine.create_group("Team"))
        .unwrap()
        .group_id;

    // Bob blocked Alice here (his server still takes her capability): the
    // invitation is dropped, nothing waits for his choice.
    set_contact_state(&mut bob, &alice.account, crate::ContactState::Blocked);
    // Carol never accepted Alice: a message request.
    set_contact_state(
        &mut carol,
        &alice.account,
        crate::ContactState::PendingIncoming,
    );
    block_on(alice.engine.invite_to_group(
        &group_id,
        &[bob.account.clone(), carol.account.clone()],
        &mut rng(),
    ))
    .unwrap();
    let report = bob.receive();
    assert!(report.group_invites.is_empty());
    assert!(block_on(bob.engine.session().db().load_group(&group_id))
        .unwrap()
        .is_none());
    let report = carol.receive();
    assert_eq!(report.group_invites.len(), 1);
    assert!(report.group_invites[0].request);

    // Declined, then invited again: the new invitation stands.
    block_on(carol.engine.decline_group_invite(&group_id)).unwrap();
    assert_eq!(carol.status(&group_id), GroupStatus::Gone);
    set_contact_state(&mut carol, &alice.account, crate::ContactState::Accepted);
    block_on(
        alice
            .engine
            .invite_to_group(&group_id, &[carol.account.clone()], &mut rng()),
    )
    .unwrap();
    let report = carol.receive();
    assert_eq!(report.group_invites.len(), 1);
    assert!(!report.group_invites[0].request);
    assert!(matches!(
        block_on(carol.engine.accept_group_invite(&group_id, &mut rng())).unwrap(),
        GroupSync::Current { .. }
    ));
    assert_eq!(carol.status(&group_id), GroupStatus::Member);
}

#[test]
fn group_review_the_send_log_forgets_after_a_week_and_at_a_delete() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    let kept = alice.send_text(&group_id, "kept a week");
    let deleted = alice.send_text(&group_id, "deleted");
    let log = |person: &Person| -> Vec<String> {
        block_on(person.engine.session().db().list_group_outbox())
            .unwrap()
            .into_iter()
            .map(|entry| entry.send_id)
            .collect()
    };
    assert!(log(&alice).contains(&kept) && log(&alice).contains(&deleted));

    // Deleted for everyone: out of the log at once.
    let send_id = uuid::Uuid::new_v4().to_string();
    let seq = block_on(alice.engine.session().next_sent_seq()).unwrap();
    let delete = ChatContent::message_mutation_with_id(
        &send_id,
        ISSUED_AT,
        seq,
        &deleted,
        kutup_chat_proto::content::MessageMutationOperation::Delete,
        None,
    )
    .unwrap();
    block_on(
        alice
            .engine
            .send_group_message(&group_id, &send_id, delete, &mut rng()),
    )
    .unwrap();
    assert!(!log(&alice).contains(&deleted));
    assert!(log(&alice).contains(&kept));

    // A week on, nothing delivered stays.
    let later = crate::clock::unix_millis() + crate::session::GROUP_SEND_LOG_MS + 1;
    block_on(alice.engine.session.purge_expired_history(later)).unwrap();
    assert!(log(&alice).is_empty());
}

#[test]
fn group_review_a_refresh_is_answered_once_an_hour_per_device() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    let sent = alice.send_text(&group_id, "once");
    deliver_all(&mut [&mut alice, &mut bob]);
    let to_bob = |world: &World| {
        world
            .sealed_sent
            .borrow()
            .iter()
            .filter(|(account, _)| *account == bob.account)
            .count()
    };
    let from = crate::address::ChatAddress::from_sender(&alice.account, alice.device()).unwrap();
    // Asked for the same message three times: answered once (key and message).
    for _ in 0..3 {
        block_on(
            bob.engine
                .request_group_resend(&group_id, &from, vec![sent.clone()], &mut rng()),
        )
        .unwrap();
    }
    let before = to_bob(&world);
    alice.receive();
    let answered = to_bob(&world) - before;
    assert_eq!(answered, 2, "the key and the message, once");
}

#[test]
fn group_review_the_same_send_id_sends_once() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    let send_id = alice.send_text(&group_id, "once");
    let count = world.sealed_sent.borrow().len();
    let seq = block_on(alice.engine.session().next_sent_seq()).unwrap();
    let again = ChatContent::text_with_id(&send_id, ISSUED_AT, seq, "once");
    let summary = block_on(
        alice
            .engine
            .send_group_message(&group_id, &send_id, again, &mut rng()),
    )
    .unwrap();
    assert_eq!(summary.pending, 0);
    assert_eq!(world.sealed_sent.borrow().len(), count);
    bob.receive();
    assert_eq!(bob.group_texts(&group_id), vec!["once".to_string()]);
}

#[test]
fn group_review_the_gate_catches_up_once_then_decides() {
    use crate::group::ContextCheck::*;
    use crate::group_engine::gate_for;
    use crate::session::GroupGate::*;
    // A context ahead or on another head: catch up first, whoever sent it.
    assert_eq!(gate_for(Behind, true, true, false), CatchUp);
    assert_eq!(gate_for(Fork, false, true, false), CatchUp);
    // Then decided by membership.
    assert_eq!(gate_for(Behind, true, false, true), Accept);
    assert_eq!(gate_for(Fork, false, false, true), Refuse);
    // A stranger: one catch-up, when the last isn't too recent.
    assert_eq!(gate_for(Current, false, true, true), CatchUp);
    assert_eq!(gate_for(SenderBehind, false, true, false), Refuse);
    assert_eq!(gate_for(SenderBehind, true, true, true), Accept);
}
