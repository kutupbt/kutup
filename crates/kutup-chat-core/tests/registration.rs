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
