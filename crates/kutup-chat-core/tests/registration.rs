//! Registration is a two-system transaction: private material lands locally,
//! then the server assigns a device id. These tests prove an ambiguous first
//! response is finished with the exact request (`resume_registration`), that
//! a confirmed id survives reopen, and that `installation` reports each step.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use async_trait::async_trait;
use futures_executor::block_on;
use kutup_chat_core::{
    AccountAuthority, ChatDb, ChatError, ChatTransport, Engine, Installation, Result, SendOutcome,
    SqliteChatDb,
};
use kutup_chat_proto::{
    AccountPreKeyBundlesResponse, MailboxPage, RegisterChatDeviceRequestV2, SendMessagesRequest,
};
use rand::rngs::OsRng;
use rand::TryRngCore as _;

/// The `session` hash test servers give every device.
const DEVICE_SESSION: &str = "5151515151515151515151515151515151515151515151515151515151515151";

struct RegistrationServer {
    requests: RefCell<Vec<Vec<u8>>>,
    fail_next: Cell<bool>,
    assigned: u32,
    /// The account's manifest, once a re-registration published it.
    manifest: RefCell<Option<kutup_chat_proto::AccountManifestV3>>,
    /// Every manifest the account has had, oldest first.
    history: RefCell<Vec<kutup_chat_proto::AccountManifestV3>>,
}

#[async_trait(?Send)]
impl ChatTransport for RegistrationServer {
    async fn register_device(&self, req: &RegisterChatDeviceRequestV2) -> Result<u32> {
        self.requests
            .borrow_mut()
            .push(serde_json::to_vec(req).unwrap());
        // The server stored it either way; only the answer may be lost.
        if let kutup_chat_proto::DeviceRegistrationV1::Reregistration { manifest } =
            &req.registration
        {
            *self.manifest.borrow_mut() = Some((**manifest).clone());
            self.history.borrow_mut().push((**manifest).clone());
        }
        if self.fail_next.replace(false) {
            return Err(ChatError::Transport("ambiguous response".into()));
        }
        Ok(self.assigned)
    }

    async fn fetch_device_session(&self) -> Result<String> {
        Ok(DEVICE_SESSION.into())
    }

    async fn fetch_manifest(
        &self,
        _account: &str,
    ) -> Result<Option<kutup_chat_proto::AccountManifestV3>> {
        Ok(self.manifest.borrow().clone())
    }

    async fn fetch_manifest_history(
        &self,
        account: &str,
        _from_sequence: u64,
        to_sequence: u64,
        page_from_sequence: u64,
    ) -> Result<kutup_chat_proto::AccountManifestHistoryPageV3> {
        let manifests: Vec<_> = self
            .history
            .borrow()
            .iter()
            .filter(|manifest| {
                manifest.sequence >= page_from_sequence && manifest.sequence <= to_sequence
            })
            .cloned()
            .collect();
        Ok(kutup_chat_proto::AccountManifestHistoryPageV3 {
            account: account.parse().unwrap(),
            from_sequence: page_from_sequence,
            to_sequence,
            manifests,
            next_sequence: None,
        })
    }

    async fn fetch_bundles(&self, _username: &str) -> Result<AccountPreKeyBundlesResponse> {
        unreachable!()
    }

    async fn send(&self, _username: &str, _req: &SendMessagesRequest) -> Result<SendOutcome> {
        unreachable!()
    }

    async fn drain(
        &self,
        _device_id: u32,
        _after: Option<u64>,
        _limit: u32,
    ) -> Result<MailboxPage> {
        unreachable!()
    }

    async fn ack(&self, _device_id: u32, _ids: &[String]) -> Result<()> {
        unreachable!()
    }
}

const ACCOUNT: &str = "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test";

#[test]
fn ambiguous_registration_retries_exactly_and_persists_device_id() {
    let path = std::env::temp_dir().join(format!(
        "kutup-chat-register-{}.db",
        OsRng.unwrap_err().try_next_u64().unwrap()
    ));
    let server = Rc::new(RegistrationServer {
        requests: RefCell::new(Vec::new()),
        fail_next: Cell::new(true),
        assigned: 1,
        manifest: RefCell::new(None),
        history: RefCell::new(Vec::new()),
    });
    let authority = AccountAuthority::derive(&[9u8; 32]).unwrap();

    let first_db = Rc::new(SqliteChatDb::open(&path).unwrap());
    // The account's first Chat device: it re-registers.
    assert_eq!(
        block_on(Engine::installation(
            first_db.as_ref(),
            server.as_ref(),
            ACCOUNT
        ))
        .unwrap(),
        Installation::Unregistered {
            account_has_identity: false
        }
    );
    let first = block_on(Engine::reregister(
        first_db,
        server.clone(),
        ACCOUNT,
        &authority,
        "2026-10-22T00:00:00Z",
        10,
        &mut OsRng.unwrap_err(),
    ));
    assert!(matches!(first, Err(ChatError::Transport(_))));

    let second_db = Rc::new(SqliteChatDb::open(&path).unwrap());
    assert_eq!(
        block_on(Engine::installation(
            second_db.as_ref(),
            server.as_ref(),
            ACCOUNT
        ))
        .unwrap(),
        Installation::Registering
    );
    let second = block_on(Engine::resume_registration(
        second_db.clone(),
        server.clone(),
        ACCOUNT,
    ))
    .unwrap();
    assert_eq!(second.session().device_id(), 1);
    assert_eq!(server.requests.borrow().len(), 2);
    assert_eq!(server.requests.borrow()[0], server.requests.borrow()[1]);
    let local = block_on(second_db.load_local_identity()).unwrap().unwrap();
    assert_eq!(local.device_id, Some(1));
    assert!(local.credential.is_some());
    assert_eq!(
        block_on(second_db.load_pending_registration()).unwrap(),
        None
    );

    // An already-confirmed database is opened without touching the
    // registration endpoint.
    let third_db = Rc::new(SqliteChatDb::open(&path).unwrap());
    assert_eq!(
        block_on(Engine::installation(
            third_db.as_ref(),
            server.as_ref(),
            ACCOUNT
        ))
        .unwrap(),
        Installation::Registered { device_id: 1 }
    );
    let third = block_on(Engine::open(third_db.clone(), server.clone(), ACCOUNT, 1)).unwrap();
    assert_eq!(third.session().device_id(), 1);
    assert_eq!(server.requests.borrow().len(), 2);

    // A caller cannot accidentally bind the durable ratchet state to a
    // different server device id.
    let wrong_device = block_on(Engine::open(third_db, server.clone(), ACCOUNT, 8));
    assert!(matches!(
        wrong_device,
        Err(ChatError::Invalid(message)) if message.contains("belongs to device 1")
    ));

    // Another browser of the account now finds an identity to link to.
    let other = SqliteChatDb::open_in_memory().unwrap();
    assert_eq!(
        block_on(Engine::installation(&other, server.as_ref(), ACCOUNT)).unwrap(),
        Installation::Unregistered {
            account_has_identity: true
        }
    );

    drop(second);
    drop(third);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

/// One device list per account (docs/plans/one-device-list.md): a Chat
/// re-registration leaves the account's other devices listed as they were,
/// and takes the lowest id they leave free, under its sign-in's session.
#[test]
fn a_reregistration_keeps_the_accounts_other_devices() {
    use kutup_chat_proto::{AccountManifestDeviceV3, DeviceKind};
    let authority = AccountAuthority::derive(&[9u8; 32]).unwrap();
    let editor = AccountManifestDeviceV3 {
        device_id: 1,
        kind: DeviceKind::Editor,
        chat: None,
        frame_key: Some(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            ed25519_dalek::SigningKey::from_bytes(&[4; 32])
                .verifying_key()
                .to_bytes(),
        )),
        session: "52".repeat(32),
    };
    // The account's manifest from before it had Chat: an Office instance.
    let identity = libsignal_protocol::IdentityKeyPair::generate(&mut OsRng.unwrap_err());
    let head = authority
        .sign_manifest(
            ACCOUNT.parse().unwrap(),
            1,
            None,
            &identity,
            vec![editor.clone()],
            "2026-10-24T00:00:00Z",
        )
        .unwrap();
    let server = Rc::new(RegistrationServer {
        requests: RefCell::new(Vec::new()),
        fail_next: Cell::new(false),
        assigned: 2,
        manifest: RefCell::new(Some(head.clone())),
        history: RefCell::new(vec![head.clone()]),
    });
    let db = Rc::new(SqliteChatDb::open_in_memory().unwrap());
    let engine = block_on(Engine::reregister(
        db,
        server.clone(),
        ACCOUNT,
        &authority,
        "2026-10-25T00:00:00Z",
        10,
        &mut OsRng.unwrap_err(),
    ))
    .unwrap();
    assert_eq!(engine.session().device_id(), 2);
    let manifest = server.manifest.borrow().clone().unwrap();
    assert_eq!(manifest.sequence, 2);
    assert_eq!(manifest.devices.len(), 2);
    assert_eq!(manifest.devices[0], editor);
    let chat = &manifest.devices[1];
    assert_eq!(
        (chat.device_id, chat.kind, chat.session.as_str()),
        (2, DeviceKind::Chat, DEVICE_SESSION)
    );
    manifest.verify_successor(Some(&head)).unwrap();
}
