//! Following username renames through the engine (docs/plans/username-renames.md):
//! a send to a name its peer left (`409 renamed`) is followed and sent again;
//! a peer met first at its new address takes its old thread along; another
//! authority at a pinned address first checks whether the pinned account
//! moved away; and this account follows its own rename. A mock server answers
//! per address.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use futures_executor::block_on;
use kutup_chat_core::{
    AccountAuthority, ChatContent, ChatDb, ChatError, ChatTransport, Engine, RenameChainEntryV1,
    RenameChainsV1, Result, SendOutcome, Session, SqliteChatDb,
};
use kutup_chat_proto::{
    AccountManifestDeviceV1, AccountManifestHistoryPageV1, AccountManifestPublicationV1,
    AccountManifestV1, DevicePreKeyBundle, DirectChatSuiteId, MailboxPage,
    RegisterChatDeviceRequest, SendMessagesRequest, UserPreKeyBundlesResponse,
};
use kutup_crypto::account_rename;
use kutup_crypto::identity::AccountIdentityKeysV1;
use rand::rngs::OsRng;
use rand::TryRngCore as _;

const T: i64 = 1_790_000_000_000;

fn device(user: &str) -> Session {
    block_on(Session::generate(
        Rc::new(SqliteChatDb::open_in_memory().unwrap()),
        user,
        1,
        10,
        &mut OsRng.unwrap_err(),
    ))
    .unwrap()
}

fn bundle_of(session: &Session) -> DevicePreKeyBundle {
    let reg = session.registration().unwrap();
    DevicePreKeyBundle {
        device_id: 1,
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

fn manifest(
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
                device_id: 1,
                direct_chat_suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
                identity_key: bundle.identity_key.clone(),
                registration_id: bundle.registration_id,
                mls: None,
            }],
            "2026-10-15T10:00:00Z",
        )
        .unwrap()
}

/// The chain of the account derived from `seed` through `addresses`.
fn chains(seed: u8, addresses: &[&str]) -> RenameChainsV1 {
    let identity = AccountIdentityKeysV1::derive(&[seed; 32]).unwrap();
    let chain = addresses
        .windows(2)
        .enumerate()
        .map(|(i, pair)| {
            account_rename::sign(&identity, i as u64 + 1, pair[0], pair[1], T + i as i64).unwrap()
        })
        .collect();
    RenameChainsV1 {
        version: 1,
        chains: vec![RenameChainEntryV1 {
            incarnation_id: identity.incarnation_id(),
            authority_public_key: STANDARD.encode(identity.authority_public_key()),
            current: addresses.last().unwrap().to_string(),
            state: "current".into(),
            chain,
        }],
        unavailable: false,
    }
}

/// A server answering per address: the manifest and keys published at
/// each, the names their accounts left (`409 renamed`), and their chains.
#[derive(Default)]
struct Server {
    published: RefCell<HashMap<String, (AccountManifestV1, DevicePreKeyBundle)>>,
    left: RefCell<HashMap<String, RenameChainsV1>>,
    renames: RefCell<HashMap<String, RenameChainsV1>>,
    own: RefCell<Option<AccountManifestV1>>,
    own_bundle: RefCell<Option<DevicePreKeyBundle>>,
    delivered: RefCell<Vec<String>>,
}

impl Server {
    fn publish(&self, address: &str, manifest: AccountManifestV1, bundle: DevicePreKeyBundle) {
        self.published
            .borrow_mut()
            .insert(address.to_string(), (manifest, bundle));
    }

    /// `from` is a name its account left for `to`: lookups there answer
    /// `409 renamed`, and the chain is served at both.
    fn rename(&self, from: &str, to: &str, chains: RenameChainsV1) {
        let moved = self.published.borrow_mut().remove(from);
        if let Some(published) = moved {
            self.published
                .borrow_mut()
                .insert(to.to_string(), published);
        }
        self.left
            .borrow_mut()
            .insert(from.to_string(), chains.clone());
        self.renames
            .borrow_mut()
            .insert(from.to_string(), chains.clone());
        self.renames.borrow_mut().insert(to.to_string(), chains);
    }
}

#[async_trait(?Send)]
impl ChatTransport for Server {
    async fn register_device(&self, _req: &RegisterChatDeviceRequest) -> Result<u32> {
        Ok(1)
    }

    async fn fetch_bundles(&self, username: &str) -> Result<UserPreKeyBundlesResponse> {
        if let Some(chains) = self.left.borrow().get(username) {
            return Err(ChatError::Renamed(Box::new(chains.clone())));
        }
        let published = self.published.borrow().get(username).cloned();
        let (manifest, bundle) = published.expect("someone published at the address");
        Ok(UserPreKeyBundlesResponse {
            username: manifest.account.clone(),
            devices: vec![bundle],
            manifest: Some(manifest),
        })
    }

    async fn fetch_sync_bundles(
        &self,
        username: &str,
        _device: u32,
    ) -> Result<UserPreKeyBundlesResponse> {
        Ok(UserPreKeyBundlesResponse {
            username: username.to_string(),
            devices: self.own_bundle.borrow().iter().cloned().collect(),
            manifest: self.own.borrow().clone(),
        })
    }

    async fn fetch_manifest(&self, _username: &str) -> Result<Option<AccountManifestV1>> {
        Ok(self.own.borrow().clone())
    }

    async fn fetch_manifest_history(
        &self,
        _username: &str,
        _from: u64,
        to: u64,
        page_from: u64,
    ) -> Result<AccountManifestHistoryPageV1> {
        let manifests: Vec<_> = self.own.borrow().iter().cloned().collect();
        Ok(AccountManifestHistoryPageV1 {
            account: manifests
                .first()
                .map(|m| m.account.clone())
                .unwrap_or_default(),
            from_sequence: page_from,
            to_sequence: to,
            manifests,
            next_sequence: None,
        })
    }

    async fn publish_manifest(
        &self,
        manifest: &AccountManifestV1,
    ) -> Result<AccountManifestPublicationV1> {
        *self.own.borrow_mut() = Some(manifest.clone());
        Ok(AccountManifestPublicationV1 {
            manifest: manifest.clone(),
        })
    }

    async fn fetch_renames(
        &self,
        address: &str,
        _incarnation: Option<&str>,
    ) -> Result<RenameChainsV1> {
        Ok(self
            .renames
            .borrow()
            .get(address)
            .cloned()
            .unwrap_or(RenameChainsV1 {
                version: 1,
                chains: Vec::new(),
                unavailable: false,
            }))
    }

    async fn send(&self, username: &str, _req: &SendMessagesRequest) -> Result<SendOutcome> {
        self.delivered.borrow_mut().push(username.to_string());
        Ok(SendOutcome::Delivered {
            deduplicated: false,
        })
    }

    async fn drain(&self, _device: u32, _after: Option<u64>, _limit: u32) -> Result<MailboxPage> {
        Ok(MailboxPage {
            envelopes: Vec::new(),
            more: false,
        })
    }

    async fn ack(&self, _device: u32, _ids: &[String]) -> Result<()> {
        Ok(())
    }
}

const ALICE: &str = "alice@kutup.test";
const ADA_OLD: &str = "ada_l@kutup.test";
const ADA_NEW: &str = "ada_lovelace@kutup.test";

/// Alice, who has written to Ada at her old name, and the server.
fn alice_knows_ada() -> (Engine, Rc<Server>, Rc<dyn ChatDb>, AccountAuthority) {
    let server = Rc::new(Server::default());
    let ada = device(ADA_OLD);
    let ada_authority = AccountAuthority::derive(&[1; 32]).unwrap();
    let ada_bundle = bundle_of(&ada);
    server.publish(
        ADA_OLD,
        manifest(ADA_OLD, &ada_bundle, &ada_authority),
        ada_bundle,
    );
    let alice_authority = AccountAuthority::derive(&[9; 32]).unwrap();
    let db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open_in_memory().unwrap());
    let mut session = block_on(Session::generate(
        Rc::clone(&db),
        ALICE,
        1,
        10,
        &mut OsRng.unwrap_err(),
    ))
    .unwrap();
    *server.own_bundle.borrow_mut() = Some(bundle_of(&session));
    block_on(session.complete_registration(1)).unwrap();
    let mut alice = Engine::new(session, server.clone());
    block_on(alice.sync_own_manifest(&alice_authority, "2026-10-15T09:00:00Z")).unwrap();
    send(&mut alice, "m1", ADA_OLD).unwrap();
    (alice, server, db, alice_authority)
}

fn send(engine: &mut Engine, id: &str, to: &str) -> Result<kutup_chat_core::SendSummary> {
    block_on(engine.send(
        id,
        to,
        &ChatContent::text_with_id(id, "2026-10-15T10:00:00Z", 1, id),
        &mut OsRng.unwrap_err(),
    ))
}

fn pinned(engine: &Engine, address: &str) -> Option<kutup_chat_core::ManifestTrust> {
    block_on(engine.session().manifest_trust(address)).unwrap()
}

#[test]
fn a_send_to_a_name_its_peer_left_follows_and_goes_to_the_new_one() {
    let (mut alice, server, _, _) = alice_knows_ada();
    server.rename(ADA_OLD, ADA_NEW, chains(1, &[ADA_OLD, ADA_NEW]));
    // The device list Alice holds runs out (or a send meets a mismatch).
    alice.forget_known_devices();

    let summary = send(&mut alice, "m2", ADA_OLD).unwrap();
    assert_eq!(summary.moved_to.as_deref(), Some(ADA_NEW));
    assert_eq!(
        server.delivered.borrow().last().map(String::as_str),
        Some(ADA_NEW)
    );
    assert!(pinned(&alice, ADA_OLD).is_none());
    assert_eq!(
        pinned(&alice, ADA_NEW).unwrap().renames.unwrap().sequence,
        1
    );
    // Later sends to the old name go to the new one straight away.
    let again = send(&mut alice, "m3", ADA_OLD).unwrap();
    assert_eq!(again.moved_to.as_deref(), Some(ADA_NEW));
    assert_eq!(alice.session().current_peer(ADA_OLD), ADA_NEW);
}

#[test]
fn a_peer_met_at_its_new_address_brings_its_old_thread() {
    let (mut alice, server, _, _) = alice_knows_ada();
    server.rename(ADA_OLD, ADA_NEW, chains(1, &[ADA_OLD, ADA_NEW]));

    let summary = send(&mut alice, "m2", ADA_NEW).unwrap();
    assert_eq!(summary.moved_to, None);
    assert!(pinned(&alice, ADA_OLD).is_none());
    // The same pin, moved: not a new person at the new address.
    let moved = pinned(&alice, ADA_NEW).unwrap();
    assert_eq!(moved.renames.unwrap().addresses, [ADA_OLD, ADA_NEW]);
}

#[test]
fn someone_else_at_a_pinned_name_is_new_after_the_pinned_account_moved_away() {
    let (mut alice, server, _, _) = alice_knows_ada();
    // Ada renamed (Alice missed it); later someone else took her old name.
    server.rename(ADA_OLD, ADA_NEW, chains(1, &[ADA_OLD, ADA_NEW]));
    server.left.borrow_mut().remove(ADA_OLD);
    let mallory = device(ADA_OLD);
    let mallory_bundle = bundle_of(&mallory);
    let mallory_authority = AccountAuthority::derive(&[2; 32]).unwrap();
    server.publish(
        ADA_OLD,
        manifest(ADA_OLD, &mallory_bundle, &mallory_authority),
        mallory_bundle,
    );
    alice.forget_known_devices();

    send(&mut alice, "m2", ADA_OLD).unwrap();
    // Ada's thread went with her; whoever is at the old name is someone new.
    let ada = pinned(&alice, ADA_NEW).unwrap();
    assert_eq!(
        ada.self_authority_key,
        AccountAuthority::derive(&[1; 32])
            .unwrap()
            .public_key_base64()
    );
    let newcomer = pinned(&alice, ADA_OLD).unwrap();
    assert_eq!(
        newcomer.self_authority_key,
        mallory_authority.public_key_base64()
    );
    assert!(newcomer.renames.is_none());
}

#[test]
fn another_authority_without_a_chain_is_still_a_changed_identity() {
    let (mut alice, server, _, _) = alice_knows_ada();
    let mallory = device(ADA_OLD);
    let mallory_bundle = bundle_of(&mallory);
    let mallory_authority = AccountAuthority::derive(&[2; 32]).unwrap();
    server.publish(
        ADA_OLD,
        manifest(ADA_OLD, &mallory_bundle, &mallory_authority),
        mallory_bundle,
    );
    // Mallory's own chain naming the address is no chain of Ada's.
    server
        .renames
        .borrow_mut()
        .insert(ADA_OLD.into(), chains(2, &[ADA_OLD, "mallory@kutup.test"]));
    alice.forget_known_devices();

    assert!(send(&mut alice, "m2", ADA_OLD).is_err());
    let kept = pinned(&alice, ADA_OLD).unwrap();
    assert_eq!(
        kept.self_authority_key,
        AccountAuthority::derive(&[1; 32])
            .unwrap()
            .public_key_base64()
    );
    assert_eq!(kept.trust, kutup_chat_core::AuthorityTrust::Quarantined);
    assert!(pinned(&alice, "mallory@kutup.test").is_none());
}

#[test]
fn this_account_follows_its_own_rename_and_publishes_under_it() {
    let (mut alice, server, _, authority) = alice_knows_ada();
    let new = "alice_new@kutup.test";
    server
        .renames
        .borrow_mut()
        .insert(new.into(), chains(9, &[ALICE, new]));

    assert!(block_on(alice.adopt_own_rename(&authority, new)).unwrap());
    assert_eq!(alice.session().user(), new);
    assert!(pinned(&alice, ALICE).is_none());
    let published = block_on(alice.sync_own_manifest(&authority, "2026-10-15T11:00:00Z")).unwrap();
    assert_eq!(published.account, new);
    assert_eq!(published.sequence, 2);
    // Done once: a restart does nothing more.
    assert!(!block_on(alice.adopt_own_rename(&authority, new)).unwrap());
    // Ada is still where she was, and still reachable.
    send(&mut alice, "m2", ADA_OLD).unwrap();
}

#[test]
fn a_chain_of_another_authority_never_moves_this_account() {
    let (mut alice, server, _, authority) = alice_knows_ada();
    let new = "alice_new@kutup.test";
    server
        .renames
        .borrow_mut()
        .insert(new.into(), chains(3, &[ALICE, new]));
    assert!(block_on(alice.adopt_own_rename(&authority, new)).is_err());
    assert_eq!(alice.session().user(), ALICE);
    assert!(pinned(&alice, ALICE).is_some());
}
