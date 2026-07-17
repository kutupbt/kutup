//! Registration is a two-system transaction: private material lands locally,
//! then the server assigns a device id. These tests prove an ambiguous first
//! response retries the exact request and that a confirmed id survives reopen.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use async_trait::async_trait;
use futures_executor::block_on;
use kutup_chat_core::{
    ChatDb, ChatError, ChatTransport, Engine, Result, SendOutcome, SqliteChatDb,
};
use kutup_chat_proto::{
    MailboxPage, RegisterChatDeviceRequest, SendMessagesRequest, UserPreKeyBundlesResponse,
};
use rand::rngs::OsRng;
use rand::TryRngCore as _;

struct RegistrationServer {
    requests: RefCell<Vec<Vec<u8>>>,
    fail_next: Cell<bool>,
    assigned: u32,
}

#[async_trait(?Send)]
impl ChatTransport for RegistrationServer {
    async fn register_device(&self, req: &RegisterChatDeviceRequest) -> Result<u32> {
        self.requests
            .borrow_mut()
            .push(serde_json::to_vec(req).unwrap());
        if self.fail_next.replace(false) {
            return Err(ChatError::Transport("ambiguous response".into()));
        }
        Ok(self.assigned)
    }

    async fn fetch_bundles(
        &self,
        _username: &str,
        _transparency_tree_size: u64,
    ) -> Result<UserPreKeyBundlesResponse> {
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

#[test]
fn ambiguous_registration_retries_exactly_and_persists_device_id() {
    let path = std::env::temp_dir().join(format!(
        "kutup-chat-register-{}.db",
        OsRng.unwrap_err().try_next_u64().unwrap()
    ));
    let server = Rc::new(RegistrationServer {
        requests: RefCell::new(Vec::new()),
        fail_next: Cell::new(true),
        assigned: 7,
    });

    let first_db = Rc::new(SqliteChatDb::open(&path).unwrap());
    let first = block_on(Engine::register(
        first_db,
        server.clone(),
        "alice",
        10,
        &mut OsRng.unwrap_err(),
    ));
    assert!(matches!(first, Err(ChatError::Transport(_))));

    let second_db = Rc::new(SqliteChatDb::open(&path).unwrap());
    let second = block_on(Engine::register(
        second_db.clone(),
        server.clone(),
        "alice",
        10,
        &mut OsRng.unwrap_err(),
    ))
    .unwrap();
    assert_eq!(second.session().device_id(), 7);
    assert_eq!(server.requests.borrow().len(), 2);
    assert_eq!(server.requests.borrow()[0], server.requests.borrow()[1]);
    assert_eq!(
        block_on(second_db.load_local_identity())
            .unwrap()
            .unwrap()
            .device_id,
        Some(7)
    );
    assert_eq!(
        block_on(second_db.load_pending_registration()).unwrap(),
        None
    );

    // Initialization against an already-confirmed database reopens without
    // touching the registration endpoint.
    let third_db = Rc::new(SqliteChatDb::open(&path).unwrap());
    let third = block_on(Engine::register(
        third_db.clone(),
        server.clone(),
        "alice",
        10,
        &mut OsRng.unwrap_err(),
    ))
    .unwrap();
    assert_eq!(third.session().device_id(), 7);
    assert_eq!(server.requests.borrow().len(), 2);

    // A caller cannot accidentally bind the durable ratchet state to a
    // different server device id.
    let wrong_device = block_on(Engine::open(third_db, server.clone(), "alice", 8));
    assert!(matches!(
        wrong_device,
        Err(ChatError::Invalid(message)) if message.contains("belongs to device 7")
    ));

    drop(second);
    drop(third);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}
