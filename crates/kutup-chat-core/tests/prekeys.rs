//! Low-watermark prekey maintenance: private keys + the exact upload request
//! become durable before publication, and a crash/network failure retries that
//! same idempotent request after reopen.

use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::rc::Rc;

use async_trait::async_trait;
use futures_executor::block_on;
use kutup_chat_core::{
    ChatDb, ChatError, ChatTransport, Engine, Result, SendOutcome, Session, SqliteChatDb,
};
use kutup_chat_proto::{
    MailboxPage, PreKeyCountResponse, RegisterChatDeviceRequest, ReplenishKeysRequest,
    SendMessagesRequest, UserPreKeyBundlesResponse,
};
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng, TryRngCore as _};

fn test_rng() -> impl Rng + CryptoRng {
    OsRng.unwrap_err()
}

struct TempDb(std::path::PathBuf);

impl TempDb {
    fn new() -> Self {
        let n: u64 = test_rng().random();
        Self(std::env::temp_dir().join(format!("kutup-chat-prekeys-{n}.db")))
    }

    fn open(&self) -> Rc<SqliteChatDb> {
        Rc::new(SqliteChatDb::open(&self.0).unwrap())
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.0.display()));
        }
    }
}

#[derive(Default)]
struct KeyServer {
    ec: RefCell<HashSet<u32>>,
    kyber: RefCell<HashSet<u32>>,
    fail_next_upload: Cell<bool>,
    attempted_requests: RefCell<Vec<Vec<u8>>>,
}

#[async_trait(?Send)]
impl ChatTransport for KeyServer {
    async fn register_device(&self, _req: &RegisterChatDeviceRequest) -> Result<u32> {
        unreachable!()
    }

    async fn fetch_bundles(&self, _username: &str) -> Result<UserPreKeyBundlesResponse> {
        unreachable!()
    }

    async fn prekey_count(&self, _device_id: u32) -> Result<PreKeyCountResponse> {
        Ok(PreKeyCountResponse {
            one_time_pre_keys: self.ec.borrow().len() as u64,
            one_time_kyber_pre_keys: self.kyber.borrow().len() as u64,
        })
    }

    async fn replenish_prekeys(
        &self,
        _device_id: u32,
        request: &ReplenishKeysRequest,
    ) -> Result<()> {
        self.attempted_requests
            .borrow_mut()
            .push(serde_json::to_vec(request).unwrap());
        if self.fail_next_upload.replace(false) {
            return Err(ChatError::Transport("simulated upload loss".into()));
        }
        self.ec
            .borrow_mut()
            .extend(request.one_time_pre_keys.iter().map(|key| key.key_id));
        self.kyber
            .borrow_mut()
            .extend(request.one_time_kyber_pre_keys.iter().map(|key| key.key_id));
        Ok(())
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
fn failed_upload_retries_the_exact_durable_keys_after_reopen() {
    let db_file = TempDb::new();
    let db = db_file.open();
    let mut rng = test_rng();
    let mut session = block_on(Session::generate(db.clone(), "alice", 1, 2, &mut rng)).unwrap();
    block_on(session.complete_registration(1)).unwrap();
    let server = Rc::new(KeyServer::default());
    server.fail_next_upload.set(true);
    let mut engine = Engine::new(session, server.clone());

    let failed = block_on(engine.maintain_prekeys(2, 5, &mut rng));
    assert!(matches!(failed, Err(ChatError::Transport(_))));
    let durable = block_on(db.load_pending_prekey_upload()).unwrap().unwrap();
    assert_eq!(durable, server.attempted_requests.borrow()[0]);
    drop(engine);
    drop(db);

    let reopened_db = db_file.open();
    let reopened = block_on(Session::open(reopened_db.clone(), "alice", 1)).unwrap();
    let mut engine = Engine::new(reopened, server.clone());
    let report = block_on(engine.maintain_prekeys(2, 5, &mut rng)).unwrap();

    assert_eq!(report.uploaded_ec, 5);
    assert_eq!(report.uploaded_kyber, 5);
    assert_eq!(report.after.one_time_pre_keys, 5);
    assert_eq!(report.after.one_time_kyber_pre_keys, 5);
    assert_eq!(
        server.attempted_requests.borrow()[0],
        server.attempted_requests.borrow()[1]
    );
    assert!(block_on(reopened_db.load_pending_prekey_upload())
        .unwrap()
        .is_none());
}
