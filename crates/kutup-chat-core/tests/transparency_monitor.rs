use std::cell::Cell;
use std::rc::Rc;

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use futures_executor::block_on;
use kutup_chat_core::{
    ChatContent, ChatDb, ChatError, ChatTransport, Engine, Result, SendOutcome, SqliteChatDb,
    TransparencyMonitorState, TransparencyPolicy, TransparencyScopePolicy, TransparencyVerifierKey,
};
use kutup_chat_proto::{
    MailboxPage, RegisterChatDeviceRequest, SendMessagesRequest, TransparencyCheckpoint,
    TransparencyCheckpointAuthentication, TransparencyCheckpointResponse,
    UserPreKeyBundlesResponse,
};
use rand::rngs::OsRng;
use rand::TryRngCore as _;

#[derive(Clone, Copy)]
enum MonitorMode {
    Valid,
    Unavailable,
    MissingWitness,
    Tampered,
}

struct MonitorServer {
    mode: Cell<MonitorMode>,
    signing_key: SigningKey,
    witness_key: SigningKey,
}

impl MonitorServer {
    fn response(&self, from_tree_size: u64) -> TransparencyCheckpointResponse {
        let checkpoint = TransparencyCheckpoint {
            log_id: "11".repeat(32),
            tree_size: 1,
            root_hash: "22".repeat(32),
        };
        let map_root = "33".repeat(32);
        let mut authentication = TransparencyCheckpointAuthentication::sign(
            &checkpoint,
            &map_root,
            1_752_688_000,
            &self.signing_key,
        )
        .unwrap();
        if !matches!(self.mode.get(), MonitorMode::MissingWitness) {
            authentication
                .add_witness(
                    &checkpoint,
                    &map_root,
                    "audit.example",
                    1_752_688_001,
                    &self.witness_key,
                )
                .unwrap();
        }
        if matches!(self.mode.get(), MonitorMode::Tampered) {
            authentication.operator_signature = "AA==".into();
        }
        TransparencyCheckpointResponse {
            checkpoint,
            map_root,
            authentication,
            consistency_from: from_tree_size,
            consistency: Vec::new(),
        }
    }
}

#[async_trait(?Send)]
impl ChatTransport for MonitorServer {
    async fn register_device(&self, _request: &RegisterChatDeviceRequest) -> Result<u32> {
        Ok(7)
    }

    async fn fetch_transparency_checkpoint(
        &self,
        _scope: &str,
        from_tree_size: u64,
    ) -> Result<TransparencyCheckpointResponse> {
        match self.mode.get() {
            MonitorMode::Unavailable => Err(ChatError::Transport("offline".into())),
            MonitorMode::Valid | MonitorMode::MissingWitness | MonitorMode::Tampered => {
                Ok(self.response(from_tree_size))
            }
        }
    }

    async fn fetch_bundles(
        &self,
        _username: &str,
        _transparency_tree_size: u64,
    ) -> Result<UserPreKeyBundlesResponse> {
        panic!("a failed monitor must block before fetching bundles")
    }

    async fn send(&self, _username: &str, _request: &SendMessagesRequest) -> Result<SendOutcome> {
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
fn scheduled_monitor_persists_status_and_blocks_after_verification_failure() {
    let path = std::env::temp_dir().join(format!(
        "kutup-chat-monitor-{}.db",
        OsRng.unwrap_err().try_next_u64().unwrap()
    ));
    let server = Rc::new(MonitorServer {
        mode: Cell::new(MonitorMode::Valid),
        signing_key: SigningKey::from_bytes(&[42; 32]),
        witness_key: SigningKey::from_bytes(&[43; 32]),
    });
    let public = server.signing_key.verifying_key();
    let witness_public = server.witness_key.verifying_key();
    let policy = TransparencyPolicy {
        scopes: vec![TransparencyScopePolicy {
            scope: "local".into(),
            operator_key_id: kutup_chat_proto::transparency_signing_key_id(&public),
            operator_public_key: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                public.as_bytes(),
            ),
            witnesses: vec![TransparencyVerifierKey {
                witness_id: "audit.example".into(),
                key_id: kutup_chat_proto::transparency_signing_key_id(&witness_public),
                public_key: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    witness_public.as_bytes(),
                ),
            }],
            witness_quorum: 1,
        }],
    };

    let db = Rc::new(SqliteChatDb::open(&path).unwrap());
    let mut engine = block_on(Engine::register(
        db.clone(),
        server.clone(),
        "alice",
        2,
        &mut OsRng.unwrap_err(),
    ))
    .unwrap();
    engine.set_transparency_policy(policy.clone()).unwrap();

    let healthy = block_on(engine.monitor_transparency("local")).unwrap();
    assert_eq!(healthy.state, TransparencyMonitorState::Healthy);
    assert_eq!(healthy.tree_size, Some(1));
    assert_eq!(
        block_on(db.load_transparency_trust("local"))
            .unwrap()
            .unwrap()
            .tree_size,
        1
    );

    server.mode.set(MonitorMode::Unavailable);
    let unavailable = block_on(engine.monitor_transparency("local")).unwrap();
    assert_eq!(unavailable.state, TransparencyMonitorState::Unavailable);
    assert_eq!(unavailable.last_success_at_ms, healthy.last_success_at_ms);

    server.mode.set(MonitorMode::MissingWitness);
    let failed = block_on(engine.monitor_transparency("local")).unwrap();
    assert_eq!(failed.state, TransparencyMonitorState::VerificationFailed);
    assert!(failed.detail.unwrap().contains("trusted witnesses"));
    server.mode.set(MonitorMode::Tampered);
    let tampered = block_on(engine.monitor_transparency("local")).unwrap();
    assert_eq!(tampered.state, TransparencyMonitorState::VerificationFailed);
    assert!(tampered.detail.unwrap().contains("operatorSignature"));
    assert!(matches!(
        block_on(engine.send(
            "blocked-send",
            "bob",
            &ChatContent::text_with_id(
                "blocked-send",
                "2026-07-17T10:00:00Z",
                1,
                "hello"
            ),
            &mut OsRng.unwrap_err(),
        )),
        Err(ChatError::Trust(message)) if message.contains("monitor verification failed")
    ));

    drop(engine);
    drop(db);
    let reopened_db = Rc::new(SqliteChatDb::open(&path).unwrap());
    assert_eq!(
        block_on(reopened_db.load_transparency_monitor_status("local"))
            .unwrap()
            .unwrap()
            .state,
        TransparencyMonitorState::VerificationFailed
    );
    let mut reopened = block_on(Engine::open(
        reopened_db.clone(),
        server.clone(),
        "alice",
        7,
    ))
    .unwrap();
    reopened.set_transparency_policy(policy).unwrap();
    server.mode.set(MonitorMode::Valid);
    let recovered = block_on(reopened.monitor_transparency("local")).unwrap();
    assert_eq!(recovered.state, TransparencyMonitorState::Healthy);

    drop(reopened);
    drop(reopened_db);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}
