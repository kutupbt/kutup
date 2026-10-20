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
    GroupContextV1, GroupLimits, GroupStateV1,
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
pub(crate) const ISSUED_AT: &str = "2026-10-18T00:00:00Z";

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
    /// Every pseudonym that was ever a member or a requester (the server
    /// keeps hashes).
    seen: HashSet<String>,
}

/// The one server of these tests.
/// One account's group list as its server keeps it: entry id → (revision,
/// envelope).
pub(crate) type GroupList = BTreeMap<String, (u64, String)>;

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
    /// Each account's group list: entry id → (revision, envelope).
    pub(crate) group_lists: RefCell<BTreeMap<String, GroupList>>,
    /// Each account's Chat contact list: entry id → (revision, envelope).
    pub(crate) contact_lists: RefCell<BTreeMap<String, GroupList>>,
    /// The most entries a contact list holds (the server's is 10,000).
    pub(crate) contact_list_cap: Cell<usize>,
    /// The contact list can't be read (its server is down).
    pub(crate) contact_list_down: Cell<bool>,
    /// Each account's identity pin list: (revision, envelope).
    pub(crate) identity_pins: RefCell<BTreeMap<String, (u64, String)>>,
    /// How many pin lists were written.
    pub(crate) pin_writes: Cell<usize>,
    /// How many sealed batches were sent.
    pub(crate) batches: Cell<usize>,
    /// How many whole states the group home was asked for.
    pub(crate) state_requests: Cell<usize>,
    /// How many changes the group home took.
    pub(crate) group_changes: Cell<usize>,
    /// The group list can't be read (its server is down).
    pub(crate) group_list_down: Cell<bool>,
    /// The home calls every newcomer's pseudonym used.
    pub(crate) every_pseudonym_used: Cell<bool>,
    /// How many claims the home refused as a used pseudonym.
    pub(crate) pseudonyms_used: Cell<usize>,
    /// How many times a group list was read.
    pub(crate) list_reads: Cell<usize>,
    /// One-shot answers the batch route gives an account instead of taking
    /// its send.
    pub(crate) batch_answers: RefCell<Vec<(String, kutup_chat_proto::SealedBatchOutcomeV1)>>,
    /// How many batch requests fail outright (no answer) before they go.
    pub(crate) batch_failures: Cell<u32>,
    /// Accounts whose manifest can't be fetched now.
    pub(crate) manifests_down: RefCell<HashSet<String>>,
    /// The home can't be reached now.
    pub(crate) home_down: Cell<bool>,
    /// How many requests reached the home.
    pub(crate) home_requests: Cell<usize>,
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
            batches: Cell::new(0),
            state_requests: Cell::new(0),
            group_changes: Cell::new(0),
            group_list_down: Cell::new(false),
            every_pseudonym_used: Cell::new(false),
            pseudonyms_used: Cell::new(0),
            list_reads: Cell::new(0),
            batch_answers: RefCell::new(Vec::new()),
            batch_failures: Cell::new(0),
            manifests_down: RefCell::new(HashSet::new()),
            group_lists: RefCell::new(BTreeMap::new()),
            contact_lists: RefCell::new(BTreeMap::new()),
            contact_list_cap: Cell::new(10_000),
            contact_list_down: Cell::new(false),
            identity_pins: RefCell::new(BTreeMap::new()),
            pin_writes: Cell::new(0),
            home_down: Cell::new(false),
            home_requests: Cell::new(0),
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
        // The account's master key (its authority's, as above) and key
        // binding, as the app hands them over.
        let binding = format!("{authority_seed:08x}-0000-4000-8000-{authority_seed:012x}");
        engine
            .enable_group_list(&[authority_seed; 32], &binding)
            .unwrap();
        // Timed as the web is: a block is written at once.
        engine
            .enable_contact_list(
                &[authority_seed; 32],
                &binding,
                crate::contact_list::ContactListTiming {
                    block: crate::contact_list::BlockTiming::Immediate,
                },
            )
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
    /// A home that makes things up: it serves the group's state with
    /// `pseudonym` added as a member under `entry`, notarised as if a change
    /// had put it there (no member signed one).
    pub(crate) fn serve_made_up_member(&self, group_id: &str, pseudonym: &str, entry: &str) {
        let id = kutup_chat_proto::group::decode_group_id(group_id).unwrap();
        let mut groups = self.groups.borrow_mut();
        let group = groups.get_mut(&id).unwrap();
        let mut next = group.state.clone();
        next.revision += 1;
        next.members.push(kutup_chat_proto::group::GroupMemberV1 {
            pseudonym: pseudonym.to_string(),
            role: kutup_chat_proto::group::GroupRole::Member,
            joined_at_revision: next.revision,
            entry: entry.to_string(),
        });
        // In key order, as a state lists its members.
        next.members
            .sort_by_key(|member| decode_exact::<32>("pseudonym", &member.pseudonym).unwrap());
        let (last, _) = group.log.last().unwrap().clone();
        let change = GroupChangeV1 {
            revision: next.revision,
            previous_hash: kutup_chat_proto::group::encode(&group.head),
            ..last
        };
        let notary = self.notarise(&id, &change, &next);
        group.state = next;
        group.head = change.hash().unwrap();
        group.log.push((change, notary));
    }

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
                        seen: genesis
                            .members
                            .iter()
                            .map(|member| member.pseudonym.clone())
                            .collect(),
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
                self.state_requests.set(self.state_requests.get() + 1);
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
                // As the server: valid in every way, but this pseudonym was
                // a member before.
                if change.is_newcomers_change()
                    && (self.every_pseudonym_used.get() || group.seen.contains(&change.actor))
                {
                    self.pseudonyms_used.set(self.pseudonyms_used.get() + 1);
                    return GroupResponseV1::refused(
                        kutup_chat_proto::group_route::PSEUDONYM_USED,
                        now(),
                    );
                }
                let notary = self.notarise(&group_id, &change, &next);
                // Ever a member, or a requester (as the server).
                group
                    .seen
                    .extend(next.members.iter().map(|member| member.pseudonym.clone()));
                group.seen.extend(
                    next.requesting
                        .iter()
                        .map(|request| request.pseudonym.clone()),
                );
                group.state = next;
                group.head = change.hash().unwrap();
                group.log.push((change.clone(), notary.clone()));
                self.group_changes.set(self.group_changes.get() + 1);
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
        if self.world.manifests_down.borrow().contains(account) {
            return Err(ChatError::Transport(
                "the manifest can't be fetched now".into(),
            ));
        }
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
            // A device the account no longer lists is revoked: the server
            // stops serving it, as the real one does.
            let listed: HashSet<u32> = manifest
                .devices
                .iter()
                .map(|device| device.device_id)
                .collect();
            hosted.devices.retain(|id, _| listed.contains(id));
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

    async fn fetch_group_list(&self) -> Result<Vec<crate::GroupListItem>> {
        self.world.list_reads.set(self.world.list_reads.get() + 1);
        if self.world.group_list_down.get() {
            return Err(ChatError::Transport("the group list is down".into()));
        }
        Ok(self
            .world
            .group_lists
            .borrow()
            .get(&self.account)
            .map(|entries| {
                entries
                    .iter()
                    .map(|(id, (revision, envelope))| crate::GroupListItem {
                        id: id.clone(),
                        revision: *revision,
                        envelope: envelope.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn store_group_entry(
        &self,
        id: &str,
        base_revision: u64,
        revision: u64,
        envelope: &str,
    ) -> Result<bool> {
        // As the server: the revision from the sealed header, one size only.
        let sealed = STANDARD
            .decode(envelope)
            .map_err(|_| ChatError::Transport("malformed envelope".into()))?;
        let header = kutup_crypto::chat_group_list::inspect(&sealed)
            .map_err(|error| ChatError::Transport(error.to_string()))?;
        assert_eq!(header, revision, "the head lists the sealed revision");
        let mut lists = self.world.group_lists.borrow_mut();
        let entries = lists.entry(self.account.clone()).or_default();
        let listed = entries.get(id).map_or(0, |(revision, _)| *revision);
        if listed != base_revision || revision <= listed {
            return Ok(false);
        }
        entries.insert(id.to_string(), (revision, envelope.to_string()));
        Ok(true)
    }

    async fn fetch_identity_pins(&self) -> Result<Option<crate::IdentityPinsRecord>> {
        Ok(self
            .world
            .identity_pins
            .borrow()
            .get(&self.account)
            .map(|(revision, envelope)| crate::IdentityPinsRecord {
                revision: *revision,
                envelope: envelope.clone(),
            }))
    }

    async fn store_identity_pins(&self, write: &crate::IdentityPinsWrite) -> Result<bool> {
        let mut pins = self.world.identity_pins.borrow_mut();
        let listed = pins.get(&self.account).map_or(0, |(revision, _)| *revision);
        if listed != write.base_revision {
            return Ok(false);
        }
        pins.insert(
            self.account.clone(),
            (write.revision, write.envelope.clone()),
        );
        self.world.pin_writes.set(self.world.pin_writes.get() + 1);
        Ok(true)
    }

    async fn fetch_contact_list(&self) -> Result<Vec<crate::transport::ContactListItem>> {
        if self.world.contact_list_down.get() {
            return Err(ChatError::Transport("the contact list is down".into()));
        }
        Ok(self
            .world
            .contact_lists
            .borrow()
            .get(&self.account)
            .map(|entries| {
                entries
                    .iter()
                    .map(|(id, (revision, envelope))| crate::GroupListItem {
                        id: id.clone(),
                        revision: *revision,
                        envelope: envelope.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn store_contact_entry(
        &self,
        id: &str,
        base_revision: u64,
        revision: u64,
        envelope: &str,
    ) -> Result<crate::transport::ContactListWrite> {
        use crate::transport::ContactListWrite;
        if self.world.contact_list_down.get() {
            return Err(ChatError::Transport("the contact list is down".into()));
        }
        // As the server: the revision from the sealed header, one size only.
        let sealed = STANDARD
            .decode(envelope)
            .map_err(|_| ChatError::Transport("malformed envelope".into()))?;
        let header = kutup_crypto::chat_contact_list::inspect(&sealed)
            .map_err(|error| ChatError::Transport(error.to_string()))?;
        assert_eq!(header, revision, "the head lists the sealed revision");
        let mut lists = self.world.contact_lists.borrow_mut();
        let entries = lists.entry(self.account.clone()).or_default();
        let listed = entries.get(id).map_or(0, |(revision, _)| *revision);
        if listed != base_revision || revision <= listed {
            return Ok(ContactListWrite::Conflict);
        }
        if base_revision == 0 && entries.len() >= self.world.contact_list_cap.get() {
            return Ok(ContactListWrite::Full);
        }
        entries.insert(id.to_string(), (revision, envelope.to_string()));
        Ok(ContactListWrite::Stored)
    }

    async fn delete_contact_entry(&self, id: &str, revision: u64) -> Result<bool> {
        let mut lists = self.world.contact_lists.borrow_mut();
        let entries = lists.entry(self.account.clone()).or_default();
        if entries.get(id).map(|(listed, _)| *listed) != Some(revision) {
            return Ok(false);
        }
        entries.remove(id);
        Ok(true)
    }

    /// The batch route, recipient by recipient as the server applies it.
    async fn send_sealed_batch(
        &self,
        server: &str,
        batch: &kutup_chat_proto::SealedBatchSubmissionV1,
    ) -> Result<kutup_chat_proto::SealedBatchResponseV1> {
        use kutup_chat_proto::{SealedBatchOutcomeV1 as Outcome, SealedBatchResultV1};
        batch.validate().map_err(ChatError::Invalid)?;
        if self.world.batch_failures.get() > 0 {
            self.world
                .batch_failures
                .set(self.world.batch_failures.get() - 1);
            return Err(ChatError::Transport("the batch request failed".into()));
        }
        self.world.batches.set(self.world.batches.get() + 1);
        let mut results = Vec::new();
        for recipient in &batch.recipients {
            let account = format!("aci:{}@{server}", recipient.account_id);
            let scripted = {
                let mut answers = self.world.batch_answers.borrow_mut();
                answers
                    .iter()
                    .position(|(to, _)| *to == account)
                    .map(|place| answers.remove(place).1)
            };
            let outcome = match scripted {
                Some(outcome) => outcome,
                None => match self.send_sealed(&account, &recipient.submission).await? {
                    SendOutcome::Delivered { deduplicated } => Outcome::Delivered {
                        stored: recipient.submission.envelopes.len(),
                        deduplicated,
                    },
                    SendOutcome::Mismatch(mismatch) => Outcome::DeviceMismatch { mismatch },
                    SendOutcome::Refused => Outcome::Unavailable,
                },
            };
            results.push(SealedBatchResultV1 {
                account_id: recipient.account_id.clone(),
                send_id: recipient.submission.send_id.clone(),
                outcome,
            });
        }
        Ok(kutup_chat_proto::SealedBatchResponseV1 { results })
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
        if home != SERVER || self.world.home_down.get() {
            return Ok(GroupRelayOutcome::Unreachable);
        }
        self.world
            .home_requests
            .set(self.world.home_requests.get() + 1);
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
    pub(crate) authority_seed: u8,
    #[allow(dead_code)]
    pub(crate) wrapping_key: [u8; 32],
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

    /// Writes this device's due group list entries now (as before signing
    /// out); how many were written.
    pub(crate) fn flush_list(&mut self) -> usize {
        block_on(self.engine.flush_group_list(true)).unwrap()
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
    use crate::group_gate::Standing::*;
    use crate::group_gate::{gate_for, Reading};
    use crate::session::GroupGate::*;
    let read = |first, caught_up, may_catch_up, readable| Reading {
        first,
        caught_up,
        may_catch_up,
        readable,
    };
    // A context ahead or on another head: catch up first when allowed,
    // otherwise wait.
    assert_eq!(
        gate_for(Some(Behind), Member, read(true, false, true, true)),
        CatchUp
    );
    assert_eq!(
        gate_for(Some(Fork), Stranger, read(true, false, true, true)),
        CatchUp
    );
    assert_eq!(
        gate_for(Some(Behind), Member, read(true, false, false, true)),
        Hold
    );
    // Then decided by membership.
    assert_eq!(
        gate_for(Some(Behind), Member, read(false, true, true, true)),
        Accept
    );
    assert_eq!(
        gate_for(Some(Current), Unconfirmed, read(true, false, true, true)),
        Hold
    );
    // A stranger: refused once this device is at the home's latest, or when
    // their context isn't ahead; held only while no catch-up worked.
    assert_eq!(
        gate_for(Some(Behind), Stranger, read(false, true, true, true)),
        Refuse
    );
    assert_eq!(
        gate_for(Some(Behind), Stranger, read(false, false, true, true)),
        Hold
    );
    assert_eq!(
        gate_for(Some(SenderBehind), Stranger, read(true, false, true, true)),
        Refuse
    );
    assert_eq!(
        gate_for(Some(Current), Stranger, read(true, false, true, true)),
        Refuse
    );
    // Readable content without a context from a stranger: refused at once.
    assert_eq!(
        gate_for(None, Stranger, read(true, false, true, true)),
        Refuse
    );
    // An unreadable message: one bounded catch-up, then decided.
    assert_eq!(
        gate_for(None, Stranger, read(true, false, true, false)),
        CatchUp
    );
    assert_eq!(
        gate_for(None, Stranger, read(true, false, false, false)),
        Hold
    );
    assert_eq!(
        gate_for(None, Stranger, read(false, true, true, false)),
        Refuse
    );
    assert_eq!(
        gate_for(None, Member, read(true, false, true, false)),
        Accept
    );
}

#[test]
fn group_review_catch_ups_are_bounded_per_group() {
    use crate::group_gate::CatchUps;
    let now = 1_000_000;
    let fresh = CatchUps {
        last_ms: now,
        failures: 0,
        asked_up_to: 5,
        current_at_ms: now,
    };
    // News (a small step past this device's revision 5, not asked for yet)
    // goes after a short gap; the same revision, or a far one, waits.
    assert!(!fresh.allows(now + 1_000, Some(6), 5));
    assert!(fresh.allows(now + 2_000, Some(6), 5));
    assert!(!fresh.allows(now + 2_000, Some(5), 5));
    assert!(!fresh.allows(now + 2_000, Some(u64::MAX), 5));
    assert!(!fresh.allows(now + 9_000, None, 5));
    assert!(fresh.allows(now + 10_000, None, 5));
    // After failures, even news waits a growing back-off, at most 15 minutes.
    let failing = CatchUps {
        failures: 3,
        ..fresh
    };
    assert!(!failing.allows(now + 79_000, Some(6), 5));
    assert!(failing.allows(now + 80_000, Some(6), 5));
    let failing = CatchUps {
        failures: 30,
        ..fresh
    };
    assert!(failing.allows(now + 15 * 60 * 1000, None, 5));
}

#[test]
fn group_review_held_envelopes_are_capped_and_given_up() {
    use crate::group_gate::{
        HeldEnvelopes, HoldDecision, GROUP_HOLD_MS, MAX_HELD_PER_GROUP, MAX_HELD_PER_SENDER,
        MAX_HELD_PER_STRANGER,
    };
    let envelope = |id: &str| DeliveredEnvelope {
        id: id.into(),
        cursor: 1,
        sender: None,
        sealed_sender: true,
        sender_device_id: 0,
        envelope_type: kutup_chat_proto::EnvelopeType::Message,
        suite: kutup_chat_proto::DirectChatSuiteId::PqxdhTripleRatchetV1,
        content: "AA==".into(),
        server_timestamp: ISSUED_AT.into(),
        send_id: None,
    };
    let now = 10 * GROUP_HOLD_MS;
    let mut held = HeldEnvelopes::default();
    let keep = |held: &mut HeldEnvelopes, group: &str, sender: &str, member: bool, n: usize| {
        let id = format!("{sender}-{n}");
        held.keep(group, sender, member, &id, &envelope(&id), now, now)
    };
    // A stranger keeps at most 8, a member 32.
    let kept = (0..20)
        .filter(|n| {
            matches!(
                keep(&mut held, "g", "stranger", false, *n),
                HoldDecision::Keep
            )
        })
        .count();
    assert_eq!(kept, MAX_HELD_PER_STRANGER);
    let kept = (0..40)
        .filter(|n| matches!(keep(&mut held, "g", "member", true, *n), HoldDecision::Keep))
        .count();
    assert_eq!(kept, MAX_HELD_PER_SENDER);
    // Strangers fill the rest of the group.
    let mut n = 0;
    while (MAX_HELD_PER_STRANGER + MAX_HELD_PER_SENDER) + n < MAX_HELD_PER_GROUP {
        let sender = format!("stranger-{}", n / MAX_HELD_PER_STRANGER);
        assert!(matches!(
            keep(&mut held, "g", &sender, false, n),
            HoldDecision::Keep
        ));
        n += 1;
    }
    // Full: a new stranger takes room only from the biggest stranger, a
    // member from a stranger, and a stranger never from a member.
    match keep(&mut held, "g", "late-stranger", false, 0) {
        HoldDecision::KeepEvicting(evicted, _) => assert!(evicted.starts_with("stranger")),
        other => panic!("the biggest stranger gives one up: {other:?}"),
    }
    match keep(&mut held, "g", "another-member", true, 0) {
        HoldDecision::KeepEvicting(evicted, _) => assert!(evicted.starts_with("stranger")),
        other => panic!("a member's envelope takes a stranger's room: {other:?}"),
    }
    // Another group has its own room; a week-old envelope is given up.
    assert!(matches!(
        keep(&mut held, "h", "stranger", false, 0),
        HoldDecision::Keep
    ));
    let old = envelope("old");
    assert!(matches!(
        held.keep("h", "late", true, "old", &old, now - GROUP_HOLD_MS, now),
        HoldDecision::Drop
    ));
}

// ----- the #242 re-review: nothing real is lost -----

/// Forgets what `person` holds about members and catch-ups, as a reload does.
fn forget_member_caches(person: &mut Person) {
    person.engine.group_members_seen.clear();
    person.engine.manifest_keys_seen.clear();
    person.engine.group_catch_ups.clear();
}

#[test]
fn group_rereview_a_new_members_first_messages_arrive_without_a_sync() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let mut carol = world.person(0xc3);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    alice.send_text(&group_id, "before carol");
    deliver_all(&mut [&mut alice, &mut bob]);

    befriend(&mut alice, &mut carol);
    block_on(
        alice
            .engine
            .invite_to_group(&group_id, &[carol.account.clone()], &mut rng()),
    )
    .unwrap();
    // Bob catches up from Alice's notice, and nobody syncs again.
    bob.receive();
    carol.receive();
    block_on(carol.engine.accept_group_invite(&group_id, &mut rng())).unwrap();
    carol.send_text(&group_id, "hi all");
    carol.send_text(&group_id, "second");
    for person in [&mut alice, &mut bob] {
        let report = person.receive();
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        // Carol's change came right after the last catch-up: it may wait the
        // short gap between catch-ups, and is read on the next pass.
        if !report.held.is_empty() {
            person.engine.advance_clock_for_testing(2_000);
            let report = person.receive();
            assert!(report.held.is_empty(), "nothing waits: {:?}", report.held);
        }
        let texts = person.group_texts(&group_id);
        assert!(
            texts.contains(&"hi all".to_string()) && texts.contains(&"second".to_string()),
            "{texts:?}"
        );
        assert_eq!(person.group_placeholders(&group_id), 0);
    }
}

#[test]
fn group_rereview_a_member_whose_manifest_cant_be_fetched_is_held_not_dropped() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    bob.send_text(&group_id, "with the key");
    deliver_all(&mut [&mut alice, &mut bob]);

    world
        .manifests_down
        .borrow_mut()
        .insert(bob.account.clone());
    forget_member_caches(&mut alice);
    bob.send_text(&group_id, "while down");
    let report = alice.receive();
    assert_eq!(report.held.len(), 1, "{report:?}");
    assert!(!alice
        .group_texts(&group_id)
        .contains(&"while down".to_string()));
    // Read again on a later pass, once the manifest is back and the
    // back-off for it passed.
    world.manifests_down.borrow_mut().clear();
    let report = alice.receive();
    assert_eq!(report.held.len(), 1, "not looked up again at once");
    alice.engine.advance_clock_for_testing(11_000);
    let report = alice.receive();
    assert!(report.held.is_empty());
    assert!(alice
        .group_texts(&group_id)
        .contains(&"while down".to_string()));
}

#[test]
fn group_rereview_an_unreachable_home_holds_a_new_member_then_delivers() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let mut carol = world.person(0xc3);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    befriend(&mut alice, &mut carol);
    block_on(
        alice
            .engine
            .invite_to_group(&group_id, &[carol.account.clone()], &mut rng()),
    )
    .unwrap();
    carol.receive();
    block_on(carol.engine.accept_group_invite(&group_id, &mut rng())).unwrap();
    // Bob's home goes away before he hears of Carol.
    world.home_down.set(true);
    carol.send_text(&group_id, "hello bob");
    let report = bob.receive();
    assert!(!report.held.is_empty(), "{report:?}");
    assert!(!bob
        .group_texts(&group_id)
        .contains(&"hello bob".to_string()));
    // Back, but within the back-off: no catch-up, still waiting.
    world.home_down.set(false);
    let requests = world.home_requests.get();
    let report = bob.receive();
    assert!(!report.held.is_empty());
    assert_eq!(world.home_requests.get(), requests);
    // Past it: caught up, and delivered.
    bob.engine.advance_clock_for_testing(21_000);
    bob.receive();
    assert!(bob
        .group_texts(&group_id)
        .contains(&"hello bob".to_string()));
}

#[test]
fn group_rereview_a_removed_member_costs_no_catch_up() {
    let world = World::new();
    let (mut alice, mut bob, mut carol, group_id) = group_with_two_admins(&world);
    let carols = pseudonym_of(&mut bob, &group_id, &carol);
    block_on(
        bob.engine
            .remove_group_member(&group_id, &carols, &mut rng()),
    )
    .unwrap();
    alice.receive();
    let before = world.home_requests.get();
    // Carol, behind, keeps sending: refused at once, no catch-up for any.
    for n in 0..3 {
        carol.send_text(&group_id, &format!("still here {n}"));
    }
    let report = alice.receive();
    assert!(
        report.errors.is_empty() && report.held.is_empty(),
        "{report:?}"
    );
    assert_eq!(world.home_requests.get(), before);
    assert!(alice
        .group_texts(&group_id)
        .iter()
        .all(|text| !text.starts_with("still here")));
}

#[test]
fn group_rereview_a_fork_is_flagged_and_cleared_only_by_its_member() {
    use crate::session::GroupGate;
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let mut carol = world.person(0xc3);
    let group_id = group_of(&mut alice, &mut [&mut bob, &mut carol]);
    deliver_all(&mut [&mut alice, &mut bob, &mut carol]);
    let record = block_on(alice.engine.load_group_record(&group_id)).unwrap();
    let current = Engine::group_context(&record).unwrap();
    // Carol's context names another head at Alice's revision, still so after
    // Alice catches up: taken (she is a member), and the group flagged.
    let mut forked = current.clone();
    forked.chain_hash = kutup_chat_proto::group::encode(&[9u8; 32]);
    let before = world.home_requests.get();
    let gate = block_on(alice.engine.decide_group_content(
        &group_id,
        &carol.account,
        Some(&forked),
        true,
        alice.engine.now_ms(),
    ))
    .unwrap();
    assert_eq!(gate, GroupGate::Accept);
    assert!(world.home_requests.get() > before, "caught up first");
    let flagged = block_on(alice.engine.load_group_record(&group_id)).unwrap();
    assert_eq!(flagged.fork_at_revision, Some(current.revision));
    assert_eq!(flagged.fork_sender.as_deref(), Some(carol.account.as_str()));
    assert!(alice
        .engine
        .events
        .iter()
        .any(|event| matches!(event, crate::ChatEvent::GroupForkSuspected { .. })));
    // Bob matching doesn't clear it; Carol matching does.
    block_on(alice.engine.decide_group_content(
        &group_id,
        &bob.account,
        Some(&current),
        true,
        i64::MAX,
    ))
    .unwrap();
    assert!(block_on(alice.engine.load_group_record(&group_id))
        .unwrap()
        .fork_at_revision
        .is_some());
    block_on(alice.engine.decide_group_content(
        &group_id,
        &carol.account,
        Some(&current),
        true,
        i64::MAX,
    ))
    .unwrap();
    assert!(block_on(alice.engine.load_group_record(&group_id))
        .unwrap()
        .fork_at_revision
        .is_none());
}

#[test]
fn group_rereview_the_refresh_limit_survives_a_reload() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    let sent = alice.send_text(&group_id, "once");
    deliver_all(&mut [&mut alice, &mut bob]);
    let bobs = bob.account.clone();
    let to_bob = |world: &World| {
        world
            .sealed_sent
            .borrow()
            .iter()
            .filter(|(account, _)| *account == bobs)
            .count()
    };
    let from = crate::address::ChatAddress::from_sender(&alice.account, alice.device()).unwrap();
    let ask = |bob: &mut Person| {
        block_on(bob.engine.request_group_resend(
            &group_id,
            &from,
            vec![sent.clone(), "never-sent".into()],
            &mut rng(),
        ))
        .unwrap();
    };
    ask(&mut bob);
    let before = to_bob(&world);
    alice.receive();
    // The key, the message, and "unavailable" for the unknown one.
    assert_eq!(to_bob(&world) - before, 3);

    // A reload of Alice's engine: the same requests aren't answered again.
    let db = Rc::clone(alice.engine.session().db());
    let device = alice.device();
    let transport: Rc<dyn ChatTransport> = alice.client.clone();
    let mut engine = block_on(Engine::open(db, transport, alice.account.clone(), device)).unwrap();
    engine.set_sealed_sender_enabled(true);
    alice.engine = engine;
    ask(&mut bob);
    let before = to_bob(&world);
    alice.receive();
    assert_eq!(to_bob(&world), before);
}

// ----- the #242 third review: strangers can't make members wait -----

#[test]
fn group_third_a_removed_member_with_an_ahead_context_is_refused_after_one_catch_up() {
    use crate::session::GroupGate;
    let world = World::new();
    let (mut alice, mut bob, carol, group_id) = group_with_two_admins(&world);
    let carols = pseudonym_of(&mut bob, &group_id, &carol);
    block_on(
        bob.engine
            .remove_group_member(&group_id, &carols, &mut rng()),
    )
    .unwrap();
    alice.receive();
    alice.engine.advance_clock_for_testing(60_000);
    let record = block_on(alice.engine.load_group_record(&group_id)).unwrap();
    let mut ahead = Engine::group_context(&record).unwrap();
    // Her envelopes all arrived now, before any catch-up for them.
    let arrived = alice.engine.now_ms();
    let before = world.home_requests.get();
    // A forged revision far ahead: one catch-up, then refused.
    ahead.revision += 1000;
    let decide = |alice: &mut Person,
                  context: Option<&kutup_chat_proto::group::GroupContextV1>,
                  readable| {
        block_on(alice.engine.decide_group_content(
            &group_id,
            &carol.account,
            context,
            readable,
            arrived,
        ))
        .unwrap()
    };
    assert_eq!(decide(&mut alice, Some(&ahead), true), GroupGate::Refuse);
    let after_first = world.home_requests.get();
    assert!(after_first > before);
    // Every other envelope of hers that came before that catch-up: refused,
    // without another, ahead or not, readable or not.
    for step in 2..40u64 {
        ahead.revision += step;
        assert_eq!(decide(&mut alice, Some(&ahead), true), GroupGate::Refuse);
    }
    assert_eq!(decide(&mut alice, None, false), GroupGate::Refuse);
    assert_eq!(decide(&mut alice, None, true), GroupGate::Refuse);
    assert_eq!(
        world.home_requests.get(),
        after_first,
        "one catch-up for them all"
    );
    // The forged context counted as a failure: the next one waits longer.
    let state = alice.engine.group_catch_ups[&group_id];
    assert!(state.failures > 0);
}

#[test]
fn group_third_many_queued_envelopes_from_a_removed_member_are_refused_not_held() {
    let world = World::new();
    let (mut alice, mut bob, mut carol, group_id) = group_with_two_admins(&world);
    let carols = pseudonym_of(&mut bob, &group_id, &carol);
    block_on(
        bob.engine
            .remove_group_member(&group_id, &carols, &mut rng()),
    )
    .unwrap();
    alice.receive();
    // Carol, unaware, starts a new key Alice never gets (path (c): her
    // messages can't be read and carry no context Alice can see) and sends
    // a lot.
    let mut record = block_on(carol.engine.load_group_record(&group_id)).unwrap();
    record.sender_book = None;
    block_on(carol.engine.save_group(&record)).unwrap();
    world.retain_mailbox(&alice.account, alice.device(), |_| true);
    for n in 0..20 {
        carol.send_text(&group_id, &format!("still here {n}"));
    }
    let before = world.home_requests.get();
    // Inside the back-off after Alice's last catch-up a few may wait (at most
    // a stranger's share); the next catch-up refuses them all.
    let report = alice.receive();
    assert!(
        report.held.len() <= crate::group_gate::MAX_HELD_PER_STRANGER,
        "{:?}",
        report.held
    );
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    alice.engine.advance_clock_for_testing(11_000);
    let report = alice.receive();
    assert!(report.held.is_empty(), "nothing waits: {:?}", report.held);
    assert_eq!(alice.group_placeholders(&group_id), 0);
    assert!(alice
        .group_texts(&group_id)
        .iter()
        .all(|text| !text.starts_with("still here")));
    assert!(
        world.home_requests.get() - before <= 1,
        "at most one catch-up"
    );
    assert!(world.mailbox(&alice.account, alice.device()).is_empty());
}

#[test]
fn group_third_an_undelivered_group_message_fails_after_a_week() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    let send_id = alice.send_text(&group_id, "kept a while");
    // Make the entry undelivered, as a leg to a server gone would stay.
    let mut entry = block_on(alice.engine.session().db().list_group_outbox())
        .unwrap()
        .into_iter()
        .find(|entry| entry.send_id == send_id)
        .unwrap();
    for leg in &mut entry.legs {
        leg.delivered = false;
    }
    let mut pending = crate::db::Pending::default();
    pending.group_outbox.insert(send_id.clone(), Some(entry));
    block_on(alice.engine.session().db().apply(&pending)).unwrap();
    let in_log = |person: &Person| {
        block_on(person.engine.session().db().list_group_outbox())
            .unwrap()
            .iter()
            .any(|entry| entry.send_id == send_id)
    };
    // A day on: still tried.
    let day = crate::clock::unix_millis() + crate::session::GROUP_SEND_LOG_MS + 1;
    block_on(alice.engine.session.purge_expired_history(day)).unwrap();
    assert!(in_log(&alice));
    // A week on: failed, its plaintext gone.
    let week = crate::clock::unix_millis() + crate::session::GROUP_UNDELIVERED_MS + 1;
    block_on(alice.engine.session.purge_expired_history(week)).unwrap();
    assert!(!in_log(&alice));
}

#[test]
fn group_third_a_disappearing_group_message_leaves_the_send_log() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    let send_id = uuid::Uuid::new_v4().to_string();
    let seq = block_on(alice.engine.session().next_sent_seq()).unwrap();
    let content = ChatContent::text_with_id(&send_id, ISSUED_AT, seq, "gone in a minute")
        .with_disappearing_after(60)
        .unwrap();
    block_on(
        alice
            .engine
            .send_group_message(&group_id, &send_id, content, &mut rng()),
    )
    .unwrap();
    let in_log = |person: &Person| {
        block_on(person.engine.session().db().list_group_outbox())
            .unwrap()
            .iter()
            .any(|entry| entry.send_id == send_id)
    };
    assert!(in_log(&alice));
    let later = crate::clock::unix_millis() + 61_000;
    block_on(alice.engine.session.purge_expired_history(later)).unwrap();
    assert!(!in_log(&alice));
}

// ----- sealed batches (#244) -----

#[test]
fn group_batches_a_message_goes_to_all_member_accounts_in_one_request() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let mut carol = world.person(0xc3);
    let mut dave = world.person(0xd4);
    let group_id = group_of(&mut alice, &mut [&mut bob, &mut carol, &mut dave]);
    deliver_all(&mut [&mut alice, &mut bob, &mut carol, &mut dave]);
    // The first message: one request for the key's distribution, one for it.
    let before = world.batches.get();
    alice.send_text(&group_id, "with the key");
    assert_eq!(world.batches.get() - before, 2);
    // Then one request a message.
    let before = world.batches.get();
    let send_id = alice.send_text(&group_id, "one request");
    assert_eq!(world.batches.get() - before, 1);
    assert_eq!(reached(&world, &send_id).len(), 3);
    for person in [&mut bob, &mut carol, &mut dave] {
        person.receive();
        let texts = person.group_texts(&group_id);
        assert!(
            texts.contains(&"with the key".to_string())
                && texts.contains(&"one request".to_string())
        );
    }
}

#[test]
fn group_batches_a_limited_leg_waits_and_a_refused_one_fails() {
    use kutup_chat_proto::SealedBatchOutcomeV1 as Outcome;
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let mut carol = world.person(0xc3);
    let group_id = group_of(&mut alice, &mut [&mut bob, &mut carol]);
    alice.send_text(&group_id, "with the key");
    deliver_all(&mut [&mut alice, &mut bob, &mut carol]);
    world.batch_answers.borrow_mut().extend([
        (bob.account.clone(), Outcome::RateLimited),
        (carol.account.clone(), Outcome::Refused),
    ]);
    let send_id = uuid::Uuid::new_v4().to_string();
    let seq = block_on(alice.engine.session().next_sent_seq()).unwrap();
    let content = ChatContent::text_with_id(&send_id, ISSUED_AT, seq, "limited");
    let summary = block_on(alice.engine.send_group_message(
        &group_id,
        &send_id,
        content,
        &mut rng(),
    ))
    .unwrap();
    // Bob's leg waits, Carol's failed for good.
    assert_eq!((summary.pending, summary.failed), (1, 1));
    // Not before its wait has passed; then the next flush takes Bob's, with
    // the same send id; Carol's isn't tried.
    let waiting = block_on(alice.engine.flush_group_outbox(&mut rng())).unwrap();
    assert_eq!((waiting[0].pending, waiting[0].failed), (1, 1));
    block_on(alice.engine.group_legs_due_now_for_testing()).unwrap();
    let flushed = block_on(alice.engine.flush_group_outbox(&mut rng())).unwrap();
    assert_eq!(flushed.len(), 1);
    assert_eq!((flushed[0].pending, flushed[0].failed), (0, 1));
    bob.receive();
    assert!(bob.group_texts(&group_id).contains(&"limited".to_string()));
    carol.receive();
    assert!(!carol
        .group_texts(&group_id)
        .contains(&"limited".to_string()));
}

// ----- the #242 review follow-ups -----

#[test]
fn group_followup_a_member_who_joins_after_a_catch_up_is_taken() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let mut carol = world.person(0xc3);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    deliver_all(&mut [&mut alice, &mut bob]);
    // Bob is at the home's latest, a while ago.
    assert!(matches!(bob.sync(&group_id), GroupSync::Current { .. }));
    bob.engine.advance_clock_for_testing(3_000);
    // Then Carol joins and writes: her key and message come after that
    // catch-up, so they make Bob catch up again, and are taken.
    befriend(&mut alice, &mut carol);
    block_on(
        alice
            .engine
            .invite_to_group(&group_id, &[carol.account.clone()], &mut rng()),
    )
    .unwrap();
    carol.receive();
    block_on(carol.engine.accept_group_invite(&group_id, &mut rng())).unwrap();
    carol.send_text(&group_id, "hello after your catch-up");
    let report = bob.receive();
    assert!(
        report.held.is_empty() && report.errors.is_empty(),
        "{report:?}"
    );
    assert!(bob
        .group_texts(&group_id)
        .contains(&"hello after your catch-up".to_string()));
}

#[test]
fn group_followup_a_long_log_is_read_in_parts() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    // More changes than one catch-up reads (test-sized pages).
    for n in 0..20 {
        block_on(
            alice
                .engine
                .set_group_title(&group_id, &format!("Team {n}"), &mut rng()),
        )
        .unwrap();
    }
    world.retain_mailbox(&bob.account, bob.device(), |_| false);
    let first = bob.sync(&group_id);
    assert!(matches!(first, GroupSync::Partial { .. }), "{first:?}");
    let mut last = first;
    for _ in 0..4 {
        last = bob.sync(&group_id);
        if matches!(last, GroupSync::Current { .. }) {
            break;
        }
    }
    let GroupSync::Current { revision, .. } = last else {
        panic!("caught up at last: {last:?}")
    };
    assert_eq!(revision, world.group_state(&group_id).revision);
}

#[test]
fn group_followup_a_pool_full_of_members_takes_no_stranger() {
    use crate::group_gate::{HeldEnvelopes, HoldDecision, MAX_HELD_PER_GROUP, MAX_HELD_PER_SENDER};
    let envelope = |id: &str| DeliveredEnvelope {
        id: id.into(),
        cursor: 1,
        sender: None,
        sealed_sender: true,
        sender_device_id: 0,
        envelope_type: kutup_chat_proto::EnvelopeType::Message,
        suite: kutup_chat_proto::DirectChatSuiteId::PqxdhTripleRatchetV1,
        content: "AA==".into(),
        server_timestamp: ISSUED_AT.into(),
        send_id: None,
    };
    let mut held = HeldEnvelopes::default();
    for n in 0..MAX_HELD_PER_GROUP {
        let sender = format!("member-{}", n / MAX_HELD_PER_SENDER);
        let id = format!("{sender}-{n}");
        assert!(matches!(
            held.keep("g", &sender, true, &id, &envelope(&id), 0, 0),
            HoldDecision::Keep
        ));
    }
    assert!(matches!(
        held.keep("g", "stranger", false, "s", &envelope("s"), 0, 0),
        HoldDecision::Drop
    ));
}

#[test]
fn group_followup_an_evicted_envelope_is_acknowledged_and_reported() {
    use crate::group_gate::{HeldEnvelopes, MAX_HELD_PER_GROUP, MAX_HELD_PER_STRANGER};
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    let envelope = |id: &str| DeliveredEnvelope {
        id: id.into(),
        cursor: 1,
        sender: None,
        sealed_sender: true,
        sender_device_id: 0,
        envelope_type: kutup_chat_proto::EnvelopeType::Message,
        suite: kutup_chat_proto::DirectChatSuiteId::PqxdhTripleRatchetV1,
        content: "AA==".into(),
        server_timestamp: ISSUED_AT.into(),
        send_id: None,
    };
    let inbound = |id: &str, received_at: i64| crate::db::InboundEnvelope {
        id: id.into(),
        cursor: 1,
        envelope: serde_json::to_vec(&envelope(id)).unwrap(),
        state: crate::db::InboundState::PendingDecrypt,
        attempts: 0,
        failure_kind: None,
        last_error: None,
        received_at,
    };
    let now = alice.engine.now_ms();
    let mut held = HeldEnvelopes::default();
    let mut report = ReceiveReport::default();
    let mut acks = Vec::new();
    // Strangers fill Alice's room for the group.
    for n in 0..MAX_HELD_PER_GROUP {
        let sender = format!(
            "aci:00000000-0000-4000-8000-{:012x}@{SERVER}",
            n / MAX_HELD_PER_STRANGER
        );
        let id = format!("stranger-{n}");
        block_on(alice.engine.hold_group_envelope(
            &mut held,
            &group_id,
            &sender,
            &inbound(&id, now),
            &envelope(&id),
            &mut report,
            &mut acks,
        ))
        .unwrap();
    }
    assert_eq!(report.held.len(), MAX_HELD_PER_GROUP);
    // Bob, a member, needs room: a stranger's newest gives it up.
    block_on(alice.engine.hold_group_envelope(
        &mut held,
        &group_id,
        &bob.account,
        &inbound("bobs", now),
        &envelope("bobs"),
        &mut report,
        &mut acks,
    ))
    .unwrap();
    assert!(report.held.contains(&"bobs".to_string()));
    assert_eq!(report.held.len(), MAX_HELD_PER_GROUP);
    assert_eq!(acks.len(), 1);
    assert!(acks[0].starts_with("stranger"));
    assert_eq!(report.suppressed, acks);
    assert!(!report.held.contains(&acks[0]));
}

#[test]
fn group_batches_a_conflicting_leg_waits_for_its_queued_copy() {
    use kutup_chat_proto::SealedBatchOutcomeV1 as Outcome;
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    alice.send_text(&group_id, "with the key");
    deliver_all(&mut [&mut alice, &mut bob]);
    // Our own earlier copy is still queued under the send id: it goes out,
    // so a conflict waits, however often, and never fails the leg.
    world.batch_answers.borrow_mut().extend([
        (bob.account.clone(), Outcome::Conflict),
        (bob.account.clone(), Outcome::Conflict),
    ]);
    let send_id = alice_sends(&mut alice, &group_id, "conflicted");
    for _ in 0..2 {
        let summary = block_on(alice.engine.deliver_group_entry(&send_id, &mut rng())).unwrap();
        assert_eq!((summary.pending, summary.failed), (1, 0));
        block_on(alice.engine.group_legs_due_now_for_testing()).unwrap();
    }
    let flushed = block_on(alice.engine.flush_group_outbox(&mut rng())).unwrap();
    assert_eq!(
        (flushed[0].pending, flushed[0].failed, flushed[0].delivered),
        (0, 0, 1)
    );
    bob.receive();
    assert!(bob
        .group_texts(&group_id)
        .contains(&"conflicted".to_string()));
}

#[test]
fn group_batches_a_queued_leg_waits_and_reaches_a_device_linked_meanwhile() {
    use kutup_chat_proto::SealedBatchOutcomeV1 as Outcome;
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    alice.send_text(&group_id, "with the key");
    deliver_all(&mut [&mut alice, &mut bob]);
    // Queued for Bob's server, which can't be reached: not delivered yet.
    world
        .batch_answers
        .borrow_mut()
        .push((bob.account.clone(), Outcome::Pending));
    let send_id = alice_sends(&mut alice, &group_id, "queued");
    let sent = block_on(alice.engine.session().db().load_sent_message(&send_id))
        .unwrap()
        .unwrap();
    assert!(!sent.delivered, "a queued leg is not delivered");
    // Meanwhile Bob links a device; the next try meets the new device set,
    // and both his devices get it.
    let bob2 = world.link_device(&bob);
    block_on(alice.engine.group_legs_due_now_for_testing()).unwrap();
    let flushed = block_on(alice.engine.flush_group_outbox(&mut rng())).unwrap();
    assert_eq!((flushed[0].pending, flushed[0].failed), (0, 0));
    // The amended leg covers both his devices (the new one takes the group
    // up from the account's group list, which is the continuity slice), and
    // the first reads it.
    let entry = block_on(alice.engine.session().db().list_group_outbox())
        .unwrap()
        .into_iter()
        .find(|entry| entry.send_id == send_id)
        .unwrap();
    let leg = entry
        .legs
        .iter()
        .find(|leg| leg.account == bob.account)
        .unwrap();
    assert!(leg.delivered && !leg.failed);
    assert!(
        leg.devices.contains(&bob.device()) && leg.devices.contains(&bob2.device()),
        "{:?}",
        leg.devices
    );
    bob.receive();
    assert!(bob.group_texts(&group_id).contains(&"queued".to_string()));
}

#[test]
fn group_batches_a_failed_batch_goes_again_with_the_same_send_ids() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    alice.send_text(&group_id, "with the key");
    deliver_all(&mut [&mut alice, &mut bob]);
    world.batch_failures.set(1);
    let send_id = alice_sends(&mut alice, &group_id, "after a failure");
    block_on(alice.engine.group_legs_due_now_for_testing()).unwrap();
    let flushed = block_on(alice.engine.flush_group_outbox(&mut rng())).unwrap();
    assert_eq!(
        (flushed[0].send_id.as_str(), flushed[0].pending),
        (send_id.as_str(), 0)
    );
    bob.receive();
    let texts = bob.group_texts(&group_id);
    assert_eq!(
        texts
            .iter()
            .filter(|text| *text == "after a failure")
            .count(),
        1
    );
}

#[test]
fn group_batches_a_leg_not_taken_in_a_week_fails_and_says_so() {
    use kutup_chat_proto::SealedBatchOutcomeV1 as Outcome;
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    alice.send_text(&group_id, "with the key");
    deliver_all(&mut [&mut alice, &mut bob]);
    world
        .batch_answers
        .borrow_mut()
        .push((bob.account.clone(), Outcome::RateLimited));
    let send_id = alice_sends(&mut alice, &group_id, "too late");
    block_on(
        alice
            .engine
            .age_group_entry_for_testing(&send_id, crate::session::GROUP_UNDELIVERED_MS),
    )
    .unwrap();
    let flushed = block_on(alice.engine.flush_group_outbox(&mut rng())).unwrap();
    assert_eq!((flushed[0].pending, flushed[0].failed), (0, 1));
    let sent = block_on(alice.engine.session().db().load_sent_message(&send_id))
        .unwrap()
        .unwrap();
    assert!(sent.delivered);
    assert_eq!(sent.failed_recipients, 1);
}

#[test]
fn group_batches_a_queued_sender_key_is_not_in_the_book_nor_queued_again_within_the_hour() {
    use kutup_chat_proto::SealedBatchOutcomeV1 as Outcome;
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    // The first send hands out the key: queued for Bob's server, not stored,
    // and the message behind it waits there too.
    world.batch_answers.borrow_mut().extend([
        (bob.account.clone(), Outcome::Pending),
        (bob.account.clone(), Outcome::Pending),
    ]);
    alice_sends(&mut alice, &group_id, "first");
    let record = block_on(alice.engine.load_group_record(&group_id)).unwrap();
    let book = record.sender_book.expect("a key");
    assert!(
        !book
            .devices
            .iter()
            .any(|device| device.account == bob.account),
        "a key only queued is handed out again"
    );
    assert!(book
        .queued
        .iter()
        .any(|queued| queued.device.account == bob.account));
    // A send within the hour doesn't queue it again for a server that is down.
    let batches = world.batches.get();
    world
        .batch_answers
        .borrow_mut()
        .push((bob.account.clone(), Outcome::Pending));
    alice_sends(&mut alice, &group_id, "second");
    assert_eq!(world.batches.get(), batches + 1, "only the message, no key");
    // An hour on, the key is handed out again, and Bob reads what follows.
    let mut record = block_on(alice.engine.load_group_record(&group_id)).unwrap();
    for queued in &mut record.sender_book.as_mut().unwrap().queued {
        queued.at_ms -= crate::group::QUEUED_KEY_WAIT_MS;
    }
    block_on(alice.engine.save_group(&record)).unwrap();
    alice_sends(&mut alice, &group_id, "third");
    block_on(alice.engine.group_legs_due_now_for_testing()).unwrap();
    block_on(alice.engine.flush_group_outbox(&mut rng())).unwrap();
    bob.receive();
    assert!(bob.group_texts(&group_id).contains(&"third".to_string()));
}

#[test]
fn group_batches_a_message_is_sent_once_its_server_has_every_leg() {
    use kutup_chat_proto::SealedBatchOutcomeV1 as Outcome;
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let mut carol = world.person(0xc3);
    let mut dave = world.person(0xd4);
    let group_id = group_of(&mut alice, &mut [&mut bob, &mut carol, &mut dave]);
    alice.send_text(&group_id, "with the key");
    deliver_all(&mut [&mut alice, &mut bob, &mut carol, &mut dave]);
    let sent = |alice: &Person, send_id: &str| {
        block_on(alice.engine.session().db().load_sent_message(send_id))
            .unwrap()
            .unwrap()
    };
    // Bob's server is down (queued at ours), Carol's is over a limit, Dave
    // takes no sealed mail.
    world.batch_answers.borrow_mut().extend([
        (bob.account.clone(), Outcome::Pending),
        (carol.account.clone(), Outcome::RateLimited),
        (dave.account.clone(), Outcome::PeerUnsupported),
    ]);
    let send_id = alice_sends(&mut alice, &group_id, "slow");
    // Still sending to Carol; Bob's is with our server.
    let first = sent(&alice, &send_id);
    assert_eq!(
        (first.delivered, first.waiting_recipients),
        (false, Some(1))
    );
    // Dave's is known not to arrive while the others still wait.
    assert_eq!(first.failed_recipients, 1);
    // Carol's goes; Bob's server is still down: sent, not yet delivered.
    world
        .batch_answers
        .borrow_mut()
        .push((bob.account.clone(), Outcome::Pending));
    block_on(alice.engine.group_legs_due_now_for_testing()).unwrap();
    block_on(alice.engine.flush_group_outbox(&mut rng())).unwrap();
    let second = sent(&alice, &send_id);
    assert_eq!(
        (second.delivered, second.waiting_recipients),
        (false, Some(0))
    );
    // Bob's server comes back: done, and Dave's server never took it.
    block_on(alice.engine.group_legs_due_now_for_testing()).unwrap();
    block_on(alice.engine.flush_group_outbox(&mut rng())).unwrap();
    let done = sent(&alice, &send_id);
    assert_eq!(
        (
            done.delivered,
            done.waiting_recipients,
            done.failed_recipients
        ),
        (true, Some(0), 1)
    );
    // A direct message carries no such count.
    let direct_id = uuid::Uuid::new_v4().to_string();
    let seq = block_on(alice.engine.session().next_sent_seq()).unwrap();
    let content = ChatContent::text_with_id(&direct_id, ISSUED_AT, seq, "direct");
    block_on(
        alice
            .engine
            .send(&direct_id, &bob.account, &content, &mut rng()),
    )
    .unwrap();
    assert_eq!(sent(&alice, &direct_id).waiting_recipients, None);
}

#[test]
fn group_batches_a_leg_whose_devices_changed_after_queueing_is_sending_again() {
    use kutup_chat_proto::{DeviceListMismatch, SealedBatchOutcomeV1 as Outcome};
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    alice.send_text(&group_id, "with the key");
    deliver_all(&mut [&mut alice, &mut bob]);
    world
        .batch_answers
        .borrow_mut()
        .push((bob.account.clone(), Outcome::Pending));
    let send_id = alice_sends(&mut alice, &group_id, "queued then refused");
    let waiting = |alice: &Person| {
        block_on(alice.engine.session().db().load_sent_message(&send_id))
            .unwrap()
            .unwrap()
            .waiting_recipients
    };
    assert_eq!(waiting(&alice), Some(0), "with our server: sent");
    // Bob's server answers that his devices changed; the amended copy is
    // then limited: our server doesn't hold it, so it is sending again.
    world.batch_answers.borrow_mut().extend([
        (
            bob.account.clone(),
            Outcome::DeviceMismatch {
                mismatch: DeviceListMismatch {
                    missing_devices: Vec::new(),
                    stale_devices: Vec::new(),
                    extra_devices: Vec::new(),
                },
            },
        ),
        (bob.account.clone(), Outcome::RateLimited),
    ]);
    block_on(alice.engine.group_legs_due_now_for_testing()).unwrap();
    block_on(alice.engine.flush_group_outbox(&mut rng())).unwrap();
    assert_eq!(waiting(&alice), Some(1));
}

#[test]
fn group_batches_a_queued_key_is_held_once_a_message_after_it_arrives() {
    use kutup_chat_proto::{DeviceListMismatch, SealedBatchOutcomeV1 as Outcome};
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let mut carol = world.person(0xc3);
    let group_id = group_of(&mut alice, &mut [&mut bob, &mut carol]);
    // Both keys and the messages behind them wait at the members' servers.
    world.batch_answers.borrow_mut().extend([
        (bob.account.clone(), Outcome::Pending),
        (carol.account.clone(), Outcome::Pending),
        (bob.account.clone(), Outcome::Pending),
        (carol.account.clone(), Outcome::Pending),
    ]);
    alice_sends(&mut alice, &group_id, "first");
    let book = |alice: &Person| {
        block_on(alice.engine.load_group_record(&group_id))
            .unwrap()
            .sender_book
            .unwrap()
    };
    let holds = |book: &crate::group::SenderBook, account: &str| {
        book.devices.iter().any(|device| device.account == account)
    };
    let queued = book(&alice);
    assert!(!holds(&queued, &bob.account) && !holds(&queued, &carol.account));
    assert_eq!(queued.queued.len(), 2);
    // Bob's message is then stored: the key ahead of it went first, so his
    // device holds it. Carol's devices changed: her queued key is dropped
    // and a fresh one goes to her current devices.
    world.batch_answers.borrow_mut().push((
        carol.account.clone(),
        Outcome::DeviceMismatch {
            mismatch: DeviceListMismatch {
                missing_devices: Vec::new(),
                stale_devices: Vec::new(),
                extra_devices: Vec::new(),
            },
        },
    ));
    block_on(alice.engine.group_legs_due_now_for_testing()).unwrap();
    block_on(alice.engine.flush_group_outbox(&mut rng())).unwrap();
    let settled = book(&alice);
    assert!(holds(&settled, &bob.account), "{settled:?}");
    assert!(
        settled
            .queued
            .iter()
            .all(|queued| queued.device.account != carol.account),
        "{settled:?}"
    );
}

/// Alice sends `text` to the group; its send id.
fn alice_sends(alice: &mut Person, group_id: &str, text: &str) -> String {
    let send_id = uuid::Uuid::new_v4().to_string();
    let seq = block_on(alice.engine.session().next_sent_seq()).unwrap();
    let content = ChatContent::text_with_id(&send_id, ISSUED_AT, seq, text);
    block_on(
        alice
            .engine
            .send_group_message(group_id, &send_id, content, &mut rng()),
    )
    .unwrap();
    send_id
}

#[test]
fn group_invite_reaches_a_device_linked_just_before() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    befriend(&mut alice, &mut bob);
    // Alice knows Bob's one device; then Bob links another (or signs in on a
    // clean browser): the invitation's first send meets a device mismatch,
    // and goes again to the devices he has now.
    let mut bob2 = world.link_device(&bob);
    let group_id = block_on(alice.engine.create_group("Team"))
        .unwrap()
        .group_id;
    let sent = block_on(alice.engine.invite_to_group(
        &group_id,
        &[bob.account.clone()],
        &mut rng(),
    ))
    .unwrap();
    assert_eq!(sent, 1);
    bob2.receive();
    assert!(
        matches!(bob2.status(&group_id), GroupStatus::Invited { .. }),
        "{:?}",
        bob2.status(&group_id)
    );
}

#[test]
fn group_invite_after_a_declined_one_from_the_same_person_is_taken() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    befriend(&mut alice, &mut bob);
    let bob_account = bob.account.clone();
    let invite = |alice: &mut Person, title: &str| {
        let group_id = block_on(alice.engine.create_group(title)).unwrap().group_id;
        let sent = block_on(alice.engine.invite_to_group(
            &group_id,
            std::slice::from_ref(&bob_account),
            &mut rng(),
        ))
        .unwrap();
        assert_eq!(sent, 1);
        group_id
    };
    let first = invite(&mut alice, "First");
    bob.receive();
    assert!(matches!(bob.status(&first), GroupStatus::Invited { .. }));
    block_on(bob.engine.decline_group_invite(&first)).unwrap();
    let second = invite(&mut alice, "Second");
    bob.receive();
    assert!(
        matches!(bob.status(&second), GroupStatus::Invited { .. }),
        "{:?}",
        block_on(bob.engine.session().db().load_group(&second))
            .unwrap()
            .map(|r| r.status)
    );
}

#[test]
fn group_invite_from_a_stranger_after_a_declined_one_is_taken() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    befriend(&mut alice, &mut bob);
    // A device of Bob's that knows no contacts (a clean browser).
    let mut bob2 = world.link_device(&bob);
    assert!(block_on(bob2.engine.session().contact(&alice.account))
        .unwrap()
        .is_none());
    let bob_account = bob.account.clone();
    let invite = |alice: &mut Person, title: &str| {
        let group_id = block_on(alice.engine.create_group(title)).unwrap().group_id;
        let sent = block_on(alice.engine.invite_to_group(
            &group_id,
            std::slice::from_ref(&bob_account),
            &mut rng(),
        ))
        .unwrap();
        assert_eq!(sent, 1);
        group_id
    };
    let first = invite(&mut alice, "First");
    bob2.receive();
    assert!(matches!(bob2.status(&first), GroupStatus::Invited { .. }));
    block_on(bob2.engine.decline_group_invite(&first)).unwrap();
    let second = invite(&mut alice, "Second");
    bob2.receive();
    assert!(
        matches!(bob2.status(&second), GroupStatus::Invited { .. }),
        "{:?}",
        block_on(bob2.engine.session().db().load_group(&second))
            .unwrap()
            .map(|r| r.status)
    );
}

#[test]
fn group_ui_an_invitation_names_the_group_before_joining() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    befriend(&mut alice, &mut bob);
    let group_id = block_on(alice.engine.create_group("Team"))
        .unwrap()
        .group_id;
    block_on(
        alice
            .engine
            .invite_to_group(&group_id, &[bob.account.clone()], &mut rng()),
    )
    .unwrap();
    bob.receive();
    let listed = block_on(bob.engine.list_groups()).unwrap();
    let invited = listed
        .iter()
        .find(|group| group.group_id == group_id)
        .unwrap();
    assert_eq!(invited.title.as_deref(), Some("Team"));
}

// ----- new devices keep their groups (pairwise-groups.md §5) -----

#[test]
fn group_list_a_member_who_replaces_their_only_device_keeps_the_group() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    alice.send_text(&group_id, "before");
    deliver_all(&mut [&mut alice, &mut bob]);
    // Bob's entry is in his list (once his delayed write went).
    bob.flush_list();
    assert_eq!(
        world
            .group_lists
            .borrow()
            .get(&bob.account)
            .map(BTreeMap::len),
        Some(1)
    );

    // Bob's only device is gone; a new one is set up and the old one revoked.
    let mut bob2 = world.link_device(&bob);
    let authority = AccountAuthority::derive(&[0xb2; 32]).unwrap();
    block_on(
        bob2.engine
            .revoke_manifest_device(&authority, bob.device(), ISSUED_AT),
    )
    .unwrap();
    drop(bob);
    // Bob's binding is his account authority's, not the old device's: Alice
    // still sees him verified.
    forget_member_caches(&mut alice);
    let members = block_on(alice.engine.group_members(&group_id)).unwrap();
    assert!(
        members.iter().all(|member| member.verified.is_some()),
        "{members:?}"
    );

    // It learns the group from the list and takes its state.
    let taken = block_on(bob2.engine.sync_group_list(&mut rng())).unwrap();
    assert_eq!(taken, vec![group_id.clone()]);
    assert_eq!(bob2.status(&group_id), GroupStatus::Member);
    let entry =
        crate::group::own_entry(&block_on(bob2.engine.load_group_record(&group_id)).unwrap())
            .unwrap()
            .expect("a member");
    assert_eq!(entry.account.to_string(), bob2.account);

    // Alice sees him verified again, and they write to each other.
    alice.receive();
    let members = block_on(alice.engine.group_members(&group_id)).unwrap();
    assert!(
        members.iter().all(|member| member.verified.is_some()),
        "{members:?}"
    );
    alice.send_text(&group_id, "after the new device");
    deliver_all(&mut [&mut alice, &mut bob2]);
    assert!(bob2
        .group_texts(&group_id)
        .contains(&"after the new device".to_string()));
    bob2.send_text(&group_id, "from the new device");
    deliver_all(&mut [&mut alice, &mut bob2]);
    assert!(alice
        .group_texts(&group_id)
        .contains(&"from the new device".to_string()));
}

/// Bob's only device goes before its list write did; a new one is set up
/// and the old one revoked. Nothing in his list.
fn bob_replaced_before_his_list_write(world: &Rc<World>, bob: Person) -> Person {
    let mut bob2 = world.link_device(&bob);
    let authority = AccountAuthority::derive(&[bob.authority_seed; 32]).unwrap();
    block_on(
        bob2.engine
            .revoke_manifest_device(&authority, bob.device(), ISSUED_AT),
    )
    .unwrap();
    drop(bob);
    bob2
}

#[test]
fn group_recover_a_device_whose_list_write_was_lost_gets_the_group_from_the_next_send() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    alice.send_text(&group_id, "before");
    deliver_all(&mut [&mut alice, &mut bob]);
    // His entry was due a few minutes on; the device went first.
    assert!(world.group_lists.borrow().get(&bob.account).is_none());
    let mut bob2 = bob_replaced_before_his_list_write(&world, bob);
    assert!(block_on(bob2.engine.sync_group_list(&mut rng()))
        .unwrap()
        .is_empty());
    assert!(block_on(bob2.engine.list_groups()).unwrap().is_empty());

    // Alice's next message reaches the new device pairwise, with the group's
    // key in its context naming Bob's pseudonym: it finds Bob's place again
    // and reads it, signing nothing anew.
    let changes = world.group_changes.get();
    alice.send_text(&group_id, "after the loss");
    deliver_all(&mut [&mut alice, &mut bob2]);
    assert_eq!(world.group_changes.get(), changes);
    assert_eq!(bob2.status(&group_id), GroupStatus::Member);
    assert!(bob2
        .group_texts(&group_id)
        .contains(&"after the loss".to_string()));
    let record = block_on(bob2.engine.load_group_record(&group_id)).unwrap();
    assert_eq!(record.join_epoch, 0);
    assert!(record.list_due_at_ms.is_some(), "the entry is written back");
    bob2.flush_list();
    assert_eq!(
        world
            .group_lists
            .borrow()
            .get(&bob2.account)
            .map(BTreeMap::len),
        Some(1)
    );
    // And he writes to the group again.
    bob2.send_text(&group_id, "back");
    deliver_all(&mut [&mut alice, &mut bob2]);
    assert!(alice.group_texts(&group_id).contains(&"back".to_string()));
}

/// The context a message of `person`'s group carries.
fn context_of(person: &Person, group_id: &str) -> GroupContextV1 {
    Engine::group_context(&block_on(person.engine.load_group_record(group_id)).unwrap()).unwrap()
}

/// `person`'s account's pseudonym in `group_id` at `epoch`, as its key gives it.
fn derived_pseudonym(person: &Person, group_id: &str, epoch: u32) -> String {
    let keys = crate::group::GroupAccountKeys::derive(&[person.authority_seed; 32]).unwrap();
    let group = kutup_chat_proto::group::decode_group_id(group_id).unwrap();
    kutup_chat_proto::group::encode(&keys.pseudonyms.pseudonym(&group, epoch).public_key())
}

fn recover(person: &mut Person, context: &GroupContextV1, sender: &Person, named: &str) -> bool {
    block_on(
        person
            .engine
            .recover_group(context, &sender.account, named, &mut rng()),
    )
    .unwrap()
}

#[test]
fn group_recover_a_removed_member_gets_nothing_back() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    let context = context_of(&alice, &group_id);
    let bobs = pseudonym_of(&mut alice, &group_id, &bob);
    block_on(
        alice
            .engine
            .remove_group_member(&group_id, &bobs, &mut rng()),
    )
    .unwrap();
    let mut bob2 = bob_replaced_before_his_list_write(&world, bob);
    // Even holding the group's key and his own pseudonym (from an older
    // message), he gets the answer an unknown group gets: one question.
    let probes = world.state_requests.get();
    assert!(!recover(&mut bob2, &context, &alice, &bobs));
    assert_eq!(world.state_requests.get() - probes, 1);
    assert!(block_on(bob2.engine.list_groups()).unwrap().is_empty());
    // Not asked again within the hour.
    assert!(!recover(&mut bob2, &context, &alice, &bobs));
    assert_eq!(world.state_requests.get() - probes, 1);
}

#[test]
fn group_recover_asks_nothing_for_a_pseudonym_that_isnt_this_accounts() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let carol = world.person(0xc3);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    let context = context_of(&alice, &group_id);
    let mut bob2 = bob_replaced_before_his_list_write(&world, bob);
    // A stranger naming someone else's pseudonym, or none of his, makes the
    // device ask the home nothing at all.
    let probes = world.state_requests.get();
    let carols = derived_pseudonym(&carol, &group_id, 0);
    assert!(!recover(&mut bob2, &context, &carol, &carols));
    let alices = derived_pseudonym(&alice, &group_id, 0);
    assert!(!recover(&mut bob2, &context, &alice, &alices));
    assert_eq!(world.state_requests.get(), probes);
    assert!(block_on(bob2.engine.list_groups()).unwrap().is_empty());
}

#[test]
fn group_recover_takes_nothing_from_a_sender_who_isnt_a_member() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let carol = world.person(0xc3);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    let context = context_of(&alice, &group_id);
    let bobs = derived_pseudonym(&bob, &group_id, 0);
    let mut bob2 = bob_replaced_before_his_list_write(&world, bob);
    // Carol learnt the group's key and Bob's pseudonym somehow; she isn't a
    // member, so nothing is kept (and the group can still come back from a
    // member, after the hour).
    assert!(!recover(&mut bob2, &context, &carol, &bobs));
    assert!(block_on(bob2.engine.list_groups()).unwrap().is_empty());
}

#[test]
fn group_recover_a_group_the_list_says_he_left_stays_left() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    let context = context_of(&alice, &group_id);
    let bobs = derived_pseudonym(&bob, &group_id, 0);
    bob.flush_list();
    block_on(bob.engine.leave_group(&group_id, &mut rng())).unwrap();
    bob.flush_list();
    let mut bob2 = bob_replaced_before_his_list_write(&world, bob);
    let probes = world.state_requests.get();
    assert!(!recover(&mut bob2, &context, &alice, &bobs));
    assert_eq!(world.state_requests.get(), probes, "the list says gone");
    assert!(!matches!(
        block_on(bob2.engine.session().db().load_group(&group_id)).unwrap(),
        Some(record) if record.status == GroupStatus::Member
    ));
}

#[test]
fn group_recover_a_made_up_state_without_his_binding_is_not_joined() {
    let world = World::new();
    let mut mallory = world.person(0xd4);
    let mut bob = world.person(0xb2);
    befriend(&mut mallory, &mut bob);
    // Mallory's own group; her home (here, the one test home) serves a state
    // listing Bob's pseudonym for it with an entry naming Bob, bound by
    // Mallory's authority, not his.
    let group_id = block_on(mallory.engine.create_group("Trap"))
        .unwrap()
        .group_id;
    let record = block_on(mallory.engine.load_group_record(&group_id)).unwrap();
    let bobs = derived_pseudonym(&bob, &group_id, 0);
    let group = kutup_chat_proto::group::decode_group_id(&group_id).unwrap();
    let mallory_keys =
        crate::group::GroupAccountKeys::derive(&[mallory.authority_seed; 32]).unwrap();
    let entry = crate::group::seal_member_entry(
        &record.master().unwrap().state_key(),
        &group,
        &kutup_chat_proto::group::decode_exact::<32>("p", &bobs).unwrap(),
        &bob.account.parse().unwrap(),
        &[7u8; 32],
        &mallory_keys.authority,
    )
    .unwrap();
    world.serve_made_up_member(&group_id, &bobs, &entry);
    let context = context_of(&mallory, &group_id);
    let submitted = world.group_changes.get();

    assert!(!recover(&mut bob, &context, &mallory, &bobs));
    assert!(block_on(bob.engine.session().db().load_group(&group_id))
        .unwrap()
        .is_none());
    // Nothing was signed into her group.
    assert_eq!(world.group_changes.get(), submitted);
    assert_eq!(
        world
            .group_lists
            .borrow()
            .get(&bob.account)
            .map_or(0, BTreeMap::len),
        0
    );
}

#[test]
fn group_recover_a_home_of_a_former_members_is_another_group() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    let bobs = derived_pseudonym(&bob, &group_id, 0);
    let mut bob2 = bob_replaced_before_his_list_write(&world, bob);
    // Mallory, removed long ago, kept the key and saw Bob's binding; she
    // names a home of her own for the real group id. The id binds the home,
    // so that is another group: refused before anything is asked.
    let mut context = context_of(&alice, &group_id);
    context.home.server = "mallory.test".into();
    let probes = world.state_requests.get();
    assert!(!recover(&mut bob2, &context, &alice, &bobs));
    let mut context = context_of(&alice, &group_id);
    context.home.identity_sequence += 1;
    assert!(!recover(&mut bob2, &context, &alice, &bobs));
    assert_eq!(world.state_requests.get(), probes);
    assert!(block_on(bob2.engine.list_groups()).unwrap().is_empty());
    // The honest recovery isn't locked out by it.
    assert!(recover(
        &mut bob2,
        &context_of(&alice, &group_id),
        &alice,
        &bobs
    ));
}

#[test]
fn group_recover_fails_closed_when_the_list_cant_be_read() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    let bobs = derived_pseudonym(&bob, &group_id, 0);
    // A fresh device that hasn't read the list this run, which is down.
    let mut bob2 = world.link_device(&bob);
    drop(bob);
    world.group_list_down.set(true);
    let probes = world.state_requests.get();
    assert!(!recover(
        &mut bob2,
        &context_of(&alice, &group_id),
        &alice,
        &bobs
    ));
    assert_eq!(world.state_requests.get(), probes);
    assert!(block_on(bob2.engine.list_groups()).unwrap().is_empty());
    // The attempt counted before the list was asked for: more contexts
    // within the hour ask nothing more, of the list or the home.
    let reads = world.list_reads.get();
    for _ in 0..5 {
        assert!(!recover(
            &mut bob2,
            &context_of(&alice, &group_id),
            &alice,
            &bobs
        ));
    }
    assert_eq!(world.list_reads.get(), reads);
    assert_eq!(world.state_requests.get(), probes);
}

#[test]
fn group_recover_takes_up_at_most_ten_groups_an_hour() {
    let world = World::new();
    let alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let home = context_of_new_group(&world);
    let probes = world.state_requests.get();
    // Eleven groups he isn't in (unknown at the home): ten are asked about.
    for _ in 0..11 {
        let (context, group_id) = home();
        let named = derived_pseudonym(&bob, &group_id, 0);
        assert!(!recover(&mut bob, &context, &alice, &named));
    }
    assert_eq!(
        world.state_requests.get() - probes,
        crate::group_recover::MAX_RECOVERIES_PER_HOUR
    );
}

/// Contexts of groups that don't exist at the test home, each with a fresh
/// key bound to it (as a real one would be).
fn context_of_new_group(world: &Rc<World>) -> impl Fn() -> (GroupContextV1, String) {
    let template = {
        let mut someone = world.person(0xe5);
        let group_id = block_on(someone.engine.create_group("Template"))
            .unwrap()
            .group_id;
        context_of(&someone, &group_id)
    };
    move || {
        let key = kutup_crypto::chat_group::GroupMasterKey::generate(crate::group::home_of(
            &template.home,
        ))
        .unwrap();
        let group_id = kutup_chat_proto::group::encode_group_id(&key.group_id());
        let mut context = template.clone();
        context.group_id = group_id.clone();
        context.master_key = kutup_chat_proto::group::encode(key.as_bytes());
        (context, group_id)
    }
}

#[test]
fn group_claim_goes_past_an_epoch_the_list_learnt_after_the_invitation() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    // Bob's second device reads his (empty) list early in its run.
    let mut bob2 = world.link_device(&bob);
    block_on(bob2.engine.sync_group_list(&mut rng())).unwrap();
    // The invitation reaches both devices; the first joins (epoch 0) and
    // leaves again, and the list says so.
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    bob.flush_list();
    block_on(bob.engine.leave_group(&group_id, &mut rng())).unwrap();
    bob.flush_list();
    deliver_all(&mut [&mut alice, &mut bob, &mut bob2]);
    // Alice invites him back; the second device, still on its early read
    // and its first invitation's epoch, accepts: the claim reads the list
    // again and goes past epoch 0, which he left.
    block_on(
        alice
            .engine
            .invite_to_group(&group_id, &[bob2.account.clone()], &mut rng()),
    )
    .unwrap();
    bob2.receive();
    let invited = block_on(bob2.engine.load_group_record(&group_id)).unwrap();
    assert!(matches!(invited.status, GroupStatus::Invited { .. }));
    assert_eq!(
        invited.join_epoch, 0,
        "the invitation came on the early read"
    );
    block_on(bob2.engine.accept_group_invite(&group_id, &mut rng())).unwrap();
    assert_eq!(bob2.status(&group_id), GroupStatus::Member);
    assert_eq!(
        block_on(bob2.engine.load_group_record(&group_id))
            .unwrap()
            .join_epoch,
        1
    );
}

#[test]
fn group_rejoin_after_a_reload_goes_past_the_epoch_the_list_holds() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    let first = pseudonym_of(&mut alice, &group_id, &bob);
    bob.flush_list();
    block_on(bob.engine.leave_group(&group_id, &mut rng())).unwrap();
    bob.flush_list();
    deliver_all(&mut [&mut alice, &mut bob]);
    // A fresh device of Bob's, which hasn't read the list this run, is
    // invited back and accepts: epoch 1, a new pseudonym.
    let mut bob2 = world.link_device(&bob);
    drop(bob);
    block_on(
        alice
            .engine
            .invite_to_group(&group_id, &[bob2.account.clone()], &mut rng()),
    )
    .unwrap();
    bob2.receive();
    block_on(bob2.engine.accept_group_invite(&group_id, &mut rng())).unwrap();
    let record = block_on(bob2.engine.load_group_record(&group_id)).unwrap();
    assert_eq!(record.join_epoch, 1);
    assert_eq!(bob2.status(&group_id), GroupStatus::Member);
    alice.sync(&group_id);
    deliver_all(&mut [&mut alice, &mut bob2]);
    assert_ne!(pseudonym_of(&mut alice, &group_id, &bob2), first);
}

#[test]
fn group_recover_a_rejoin_is_a_new_pseudonym_found_again() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    let first = pseudonym_of(&mut alice, &group_id, &bob);
    block_on(bob.engine.leave_group(&group_id, &mut rng())).unwrap();
    deliver_all(&mut [&mut alice, &mut bob]);
    block_on(
        alice
            .engine
            .invite_to_group(&group_id, &[bob.account.clone()], &mut rng()),
    )
    .unwrap();
    bob.receive();
    block_on(bob.engine.accept_group_invite(&group_id, &mut rng())).unwrap();
    assert_eq!(bob.status(&group_id), GroupStatus::Member);
    let record = block_on(bob.engine.load_group_record(&group_id)).unwrap();
    assert_eq!(record.join_epoch, 1);
    // Alice learns of the rejoin at her next catch-up, then reads what he
    // sent meanwhile.
    alice.sync(&group_id);
    deliver_all(&mut [&mut alice, &mut bob]);
    let second = pseudonym_of(&mut alice, &group_id, &bob);
    assert_ne!(first, second);

    // His only device goes before the rejoin's list write: the new one
    // passes epoch 0 (removed) and finds him at 1.
    let mut bob2 = bob_replaced_before_his_list_write(&world, bob);
    alice.send_text(&group_id, "welcome back");
    deliver_all(&mut [&mut alice, &mut bob2]);
    assert_eq!(bob2.status(&group_id), GroupStatus::Member);
    assert_eq!(
        block_on(bob2.engine.load_group_record(&group_id))
            .unwrap()
            .join_epoch,
        1
    );
    assert!(bob2
        .group_texts(&group_id)
        .contains(&"welcome back".to_string()));
}

#[test]
fn group_claim_after_a_total_loss_goes_past_a_pseudonym_the_home_has_seen() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    let first = pseudonym_of(&mut alice, &group_id, &bob);
    // He leaves, and his only device goes before either list write.
    block_on(bob.engine.leave_group(&group_id, &mut rng())).unwrap();
    deliver_all(&mut [&mut alice, &mut bob]);
    assert!(world.group_lists.borrow().get(&bob.account).is_none());
    let mut bob2 = bob_replaced_before_his_list_write(&world, bob);
    // Invited back, the new device knows of no earlier join: epoch 0, which
    // the home has seen. It refuses that alone, and the claim is made again
    // at epoch 1.
    block_on(
        alice
            .engine
            .invite_to_group(&group_id, &[bob2.account.clone()], &mut rng()),
    )
    .unwrap();
    bob2.receive();
    assert_eq!(
        block_on(bob2.engine.load_group_record(&group_id))
            .unwrap()
            .join_epoch,
        0
    );
    let joined = block_on(bob2.engine.accept_group_invite(&group_id, &mut rng())).unwrap();
    assert!(matches!(joined, GroupSync::Current { .. }), "{joined:?}");
    assert_eq!(world.pseudonyms_used.get(), 1);
    assert_eq!(bob2.status(&group_id), GroupStatus::Member);
    assert_eq!(
        block_on(bob2.engine.load_group_record(&group_id))
            .unwrap()
            .join_epoch,
        1
    );
    alice.sync(&group_id);
    deliver_all(&mut [&mut alice, &mut bob2]);
    assert_ne!(pseudonym_of(&mut alice, &group_id, &bob2), first);
    // The list now holds epoch 1, for his next devices.
    bob2.flush_list();
    let mut bob3 = world.link_device(&bob2);
    block_on(bob3.engine.sync_group_list(&mut rng())).unwrap();
    assert_eq!(bob3.status(&group_id), GroupStatus::Member);
    assert_eq!(
        block_on(bob3.engine.load_group_record(&group_id))
            .unwrap()
            .join_epoch,
        1
    );
}

#[test]
fn group_claim_stops_after_the_last_join_epoch() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    befriend(&mut alice, &mut bob);
    let group_id = block_on(alice.engine.create_group("Team"))
        .unwrap()
        .group_id;
    block_on(
        alice
            .engine
            .invite_to_group(&group_id, &[bob.account.clone()], &mut rng()),
    )
    .unwrap();
    bob.receive();
    world.every_pseudonym_used.set(true);
    let changes = world.group_changes.get();
    assert!(block_on(bob.engine.accept_group_invite(&group_id, &mut rng())).is_err());
    assert_eq!(
        world.pseudonyms_used.get(),
        crate::group::MAX_JOIN_EPOCHS as usize
    );
    assert_eq!(world.group_changes.get(), changes);
    let record = block_on(bob.engine.load_group_record(&group_id)).unwrap();
    assert!(matches!(record.status, GroupStatus::Invited { .. }));
    assert_eq!(record.join_epoch, crate::group::MAX_JOIN_EPOCHS - 1);
}

#[test]
fn group_claim_from_a_later_epoch_still_stops_at_the_last_one() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    befriend(&mut alice, &mut bob);
    let group_id = block_on(alice.engine.create_group("Team"))
        .unwrap()
        .group_id;
    block_on(
        alice
            .engine
            .invite_to_group(&group_id, &[bob.account.clone()], &mut rng()),
    )
    .unwrap();
    bob.receive();
    // The invitation came at epoch 10 (the account's eleventh join).
    let mut record = block_on(bob.engine.load_group_record(&group_id)).unwrap();
    let keys = crate::group::GroupAccountKeys::derive(&[bob.authority_seed; 32]).unwrap();
    let group = kutup_chat_proto::group::decode_group_id(&group_id).unwrap();
    record.join_epoch = 10;
    record.pseudonym_seed = crate::group::SecretText(kutup_chat_proto::group::encode(
        keys.pseudonyms.pseudonym(&group, 10).seed(),
    ));
    block_on(bob.engine.save_group(&record)).unwrap();
    world.every_pseudonym_used.set(true);
    assert!(block_on(bob.engine.accept_group_invite(&group_id, &mut rng())).is_err());
    // Epochs 10 to 63, no further: recovery's window still covers it.
    assert_eq!(
        world.pseudonyms_used.get(),
        (crate::group::MAX_JOIN_EPOCHS - 10) as usize
    );
    let record = block_on(bob.engine.load_group_record(&group_id)).unwrap();
    assert_eq!(record.join_epoch, crate::group::MAX_JOIN_EPOCHS - 1);
}

#[test]
fn group_claim_after_another_device_joined_and_listed_it_is_a_member_too() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let mut bob2 = world.link_device(&bob);
    befriend(&mut alice, &mut bob);
    let group_id = block_on(alice.engine.create_group("Team"))
        .unwrap()
        .group_id;
    block_on(
        alice
            .engine
            .invite_to_group(&group_id, &[bob.account.clone()], &mut rng()),
    )
    .unwrap();
    bob.receive();
    bob2.receive();
    // The first device joins and its list entry (a member at epoch 0) is
    // written before the second accepts: the second's claim re-reads the
    // list and stays at epoch 0, where the account is in.
    block_on(bob.engine.accept_group_invite(&group_id, &mut rng())).unwrap();
    bob.flush_list();
    let joined = block_on(bob2.engine.accept_group_invite(&group_id, &mut rng())).unwrap();
    assert!(matches!(joined, GroupSync::Current { .. }), "{joined:?}");
    for device in [&bob, &bob2] {
        assert_eq!(device.status(&group_id), GroupStatus::Member);
        assert_eq!(
            block_on(device.engine.load_group_record(&group_id))
                .unwrap()
                .join_epoch,
            0
        );
    }
    // Neither device wrote the account out of the group.
    bob2.flush_list();
    let mut bob3 = world.link_device(&bob);
    block_on(bob3.engine.sync_group_list(&mut rng())).unwrap();
    assert_eq!(bob3.status(&group_id), GroupStatus::Member);
    assert_eq!(world.group_state(&group_id).members.len(), 2);
}

#[test]
fn group_claim_two_devices_accepting_at_once_are_both_members() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let mut bob2 = world.link_device(&bob);
    befriend(&mut alice, &mut bob);
    let group_id = block_on(alice.engine.create_group("Team"))
        .unwrap()
        .group_id;
    block_on(
        alice
            .engine
            .invite_to_group(&group_id, &[bob.account.clone()], &mut rng()),
    )
    .unwrap();
    bob.receive();
    bob2.receive();
    // Both devices have the invitation; the first claims the slot, the
    // second finds the account in the group under the same pseudonym.
    for device in [&mut bob, &mut bob2] {
        let joined = block_on(device.engine.accept_group_invite(&group_id, &mut rng())).unwrap();
        assert!(matches!(joined, GroupSync::Current { .. }), "{joined:?}");
        assert_eq!(device.status(&group_id), GroupStatus::Member);
    }
    let pseudonym = |person: &Person| {
        block_on(person.engine.load_group_record(&group_id))
            .unwrap()
            .pseudonym_text()
            .unwrap()
    };
    assert_eq!(pseudonym(&bob), pseudonym(&bob2));
    assert_eq!(world.group_state(&group_id).members.len(), 2);
}

#[test]
fn group_list_a_group_left_on_one_device_is_left_on_the_other() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let mut carol = world.person(0xc3);
    let group_id = group_of(&mut alice, &mut [&mut bob, &mut carol]);
    bob.flush_list();
    let mut bob2 = world.link_device(&bob);
    block_on(bob2.engine.sync_group_list(&mut rng())).unwrap();
    assert_eq!(bob2.status(&group_id), GroupStatus::Member);
    block_on(bob.engine.leave_group(&group_id, &mut rng())).unwrap();
    bob.flush_list();
    block_on(bob2.engine.sync_group_list(&mut rng())).unwrap();
    assert_eq!(bob2.status(&group_id), GroupStatus::Gone);
}

#[test]
fn group_list_entries_are_per_account_and_sealed() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    alice.flush_list();
    bob.flush_list();
    let lists = world.group_lists.borrow();
    let ids = |account: &str| lists[account].keys().cloned().collect::<Vec<_>>();
    // The same group under unrelated ids, and no group id in the clear.
    assert_ne!(ids(&alice.account), ids(&bob.account));
    for entries in lists.values() {
        for (id, (_, envelope)) in entries {
            assert_ne!(*id, group_id);
            assert!(!envelope.contains(&group_id));
            // One size for every entry.
            assert_eq!(
                STANDARD.decode(envelope).unwrap().len(),
                kutup_crypto::chat_group_list::SEALED_LEN
            );
        }
    }
}

#[test]
fn group_list_writes_wait_and_only_joins_and_leaves_write() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    let written = |account: &str| {
        world
            .group_lists
            .borrow()
            .get(account)
            .map_or(0, BTreeMap::len)
    };
    // Joined: due at a random moment in the next ten minutes, not at once.
    assert_eq!(written(&bob.account), 0);
    let due = block_on(bob.engine.load_group_record(&group_id))
        .unwrap()
        .list_due_at_ms
        .expect("a write is due");
    let now = crate::clock::unix_millis();
    assert!(
        due >= now - 60_000 && due <= now + 10 * 60 * 1000,
        "{due} vs {now}"
    );
    assert_eq!(bob.flush_list(), 1);
    assert_eq!(written(&bob.account), 1);

    // Messages and other changes write nothing; a second device that reads
    // the list writes nothing either.
    alice.send_text(&group_id, "hello");
    deliver_all(&mut [&mut alice, &mut bob]);
    assert_eq!(bob.flush_list(), 0);
    let mut bob2 = world.link_device(&bob);
    block_on(bob2.engine.sync_group_list(&mut rng())).unwrap();
    assert_eq!(bob2.flush_list(), 0);

    // Leaving writes, once.
    block_on(bob.engine.leave_group(&group_id, &mut rng())).unwrap();
    assert_eq!(bob.flush_list(), 1);
    assert_eq!(bob.flush_list(), 0);
}

#[test]
fn group_list_a_rotated_profile_key_reaches_the_group() {
    let world = World::new();
    let mut alice = world.person(0xa1);
    let mut bob = world.person(0xb2);
    let group_id = group_of(&mut alice, &mut [&mut bob]);
    alice.send_text(&group_id, "before");
    deliver_all(&mut [&mut alice, &mut bob]);
    // Bob's profile key changes (as blocking someone rotates it): his entry
    // in the group gets the new one, so the group still reaches him.
    let wrapping_key = bob.wrapping_key;
    block_on(
        bob.engine
            .rotate_profile_key(&wrapping_key, ISSUED_AT, &mut rng()),
    )
    .unwrap();
    let entry =
        crate::group::own_entry(&block_on(bob.engine.load_group_record(&group_id)).unwrap())
            .unwrap()
            .unwrap();
    let profile = block_on(bob.engine.local_profile()).unwrap().unwrap();
    assert_eq!(entry.profile_key, STANDARD.encode(&profile.key));
    deliver_all(&mut [&mut alice, &mut bob]);
    alice.send_text(&group_id, "after the rotation");
    deliver_all(&mut [&mut alice, &mut bob]);
    assert!(bob
        .group_texts(&group_id)
        .contains(&"after the rotation".to_string()));
}
