//! UniFFI boundary shared by the native Kutup clients.
//!
//! Swift/Kotlin supply one authenticated HTTP adapter plus account-scoped
//! database paths and keys. Rust owns libsignal, protocol DTOs, signed device
//! manifests, SQLCipher, retry/reconciliation, and history mapping.

mod http;
mod types;

use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};

use futures_channel::oneshot;
use kutup_chat_core::{
    AccountAuthority, ChatContent, ChatError, ChatTransport, Engine, SqliteChatDb,
};
use rand::rngs::OsRng;
use rand::TryRngCore as _;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use zeroize::Zeroize;

pub use http::ChatHttpClient;
pub use types::*;

const INITIAL_PREKEYS: usize = 50;
const PREKEY_LOW_WATERMARK: usize = 20;
const PREKEY_TARGET: usize = 50;

/// Native handle for one account-scoped chat installation.
///
/// libsignal's store futures are deliberately `!Send` so the same core can run
/// in a browser. Native clients therefore use one dedicated worker thread that
/// exclusively owns the engine and SQLCipher connection. UniFFI async methods
/// exchange typed commands with it, making overlap safe without moving ratchet
/// state between Swift/Kotlin executor threads.
#[derive(uniffi::Object)]
pub struct NativeChatClient {
    user: String,
    device_id: u32,
    commands: mpsc::Sender<Command>,
    worker: Mutex<Option<JoinHandle<()>>>,
    closed: AtomicBool,
}

#[uniffi::export]
impl NativeChatClient {
    pub fn device_id(&self) -> u32 {
        self.device_id
    }

    pub fn user(&self) -> String {
        self.user.clone()
    }

    /// Deterministically stop the engine worker and drop its SQLCipher,
    /// libsignal, and authority-key state. Call this on logout/account lock.
    pub async fn shutdown(&self) -> Result<()> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::Shutdown(reply))
            .map_err(|_| worker_stopped())?;
        response.await.map_err(|_| worker_stopped())??;
        self.join_worker();
        Ok(())
    }

    pub async fn sync_manifest(&self) -> Result<()> {
        self.dispatch(Command::SyncManifest).await
    }

    pub async fn send_text(
        &self,
        send_id: String,
        peer: String,
        sent_at: String,
        text: String,
    ) -> Result<ChatSendSummary> {
        self.dispatch(|reply| Command::SendText {
            send_id,
            peer,
            sent_at,
            text,
            reply,
        })
        .await
    }

    /// Flush crash-surviving sends, then journal/decrypt/ack the mailbox.
    /// WebSocket and lifecycle events are hints that call this same method.
    pub async fn reconcile(&self) -> Result<ChatReceiveReport> {
        self.dispatch(Command::Reconcile).await
    }

    pub async fn maintain_prekeys(&self) -> Result<ChatPreKeyMaintenance> {
        self.dispatch(Command::MaintainPrekeys).await
    }

    pub async fn history(&self) -> Result<Vec<ChatHistoryEntry>> {
        self.dispatch(Command::History).await
    }

    pub async fn pending_send_count(&self) -> Result<u64> {
        self.dispatch(Command::PendingSendCount).await
    }

    pub async fn inbound_attention(&self) -> Result<Vec<ChatInboundAttention>> {
        self.dispatch(Command::InboundAttention).await
    }

    pub async fn quarantine_inbound(&self, id: String) -> Result<()> {
        self.dispatch(|reply| Command::QuarantineInbound { id, reply })
            .await
    }

    pub async fn resolve_dead_letter(&self, id: String) -> Result<()> {
        self.dispatch(|reply| Command::ResolveDeadLetter { id, reply })
            .await
    }

    pub async fn verify_authority(&self, peer: String) -> Result<ChatManifestTrust> {
        self.dispatch(|reply| Command::VerifyAuthority { peer, reply })
            .await
    }
}

impl NativeChatClient {
    async fn dispatch<T: Send + 'static>(
        &self,
        build: impl FnOnce(oneshot::Sender<Result<T>>) -> Command,
    ) -> Result<T> {
        if self.closed.load(Ordering::Acquire) {
            return Err(KutupChatError::Closed);
        }
        let (reply, response) = oneshot::channel();
        self.commands
            .send(build(reply))
            .map_err(|_| worker_stopped())?;
        response.await.map_err(|_| worker_stopped())?
    }

    fn join_worker(&self) {
        if let Some(worker) = self.worker.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = worker.join();
        }
    }
}

impl Drop for NativeChatClient {
    fn drop(&mut self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            let (reply, _response) = oneshot::channel();
            let _ = self.commands.send(Command::Shutdown(reply));
        }
        self.join_worker();
    }
}

/// Open or restart-safely register an account's native chat device. Key bytes
/// are moved to the engine worker, used to unlock/derive state, and zeroized
/// before the first result crosses back to Swift/Kotlin.
#[uniffi::export]
pub async fn open_native_chat_client(
    database_path: String,
    database_key: Vec<u8>,
    user: String,
    master_key: Vec<u8>,
    transparency_policy: ChatTransparencyPolicy,
    http: Arc<dyn ChatHttpClient>,
) -> Result<Arc<NativeChatClient>> {
    if database_path.trim().is_empty() {
        return Err(KutupChatError::InvalidInput {
            message: "database path is empty".into(),
        });
    }
    if user.trim().is_empty() {
        return Err(KutupChatError::InvalidInput {
            message: "chat username is empty".into(),
        });
    }
    let database_key = take_key(database_key, "database key")?;
    let master_key = take_key(master_key, "account master key")?;
    let (commands, receiver) = mpsc::channel();
    let (ready, initialized) = oneshot::channel();
    let worker_user = user.clone();
    let worker = thread::Builder::new()
        .name(format!("kutup-chat-{user}"))
        .spawn(move || {
            worker_main(
                WorkerConfig {
                    database_path,
                    database_key,
                    master_key,
                    user: worker_user,
                    transparency_policy: transparency_policy.into(),
                    http,
                },
                receiver,
                ready,
            )
        })
        .map_err(|error| KutupChatError::Storage {
            message: format!("start chat worker: {error}"),
        })?;

    let device_id = match initialized.await {
        Ok(Ok(device_id)) => device_id,
        Ok(Err(error)) => {
            let _ = worker.join();
            return Err(error);
        }
        Err(_) => {
            let _ = worker.join();
            return Err(worker_stopped());
        }
    };
    Ok(Arc::new(NativeChatClient {
        user,
        device_id,
        commands,
        worker: Mutex::new(Some(worker)),
        closed: AtomicBool::new(false),
    }))
}

struct WorkerConfig {
    database_path: String,
    database_key: [u8; 32],
    master_key: [u8; 32],
    user: String,
    transparency_policy: kutup_chat_core::TransparencyPolicy,
    http: Arc<dyn ChatHttpClient>,
}

enum Command {
    SyncManifest(oneshot::Sender<Result<()>>),
    SendText {
        send_id: String,
        peer: String,
        sent_at: String,
        text: String,
        reply: oneshot::Sender<Result<ChatSendSummary>>,
    },
    Reconcile(oneshot::Sender<Result<ChatReceiveReport>>),
    MaintainPrekeys(oneshot::Sender<Result<ChatPreKeyMaintenance>>),
    History(oneshot::Sender<Result<Vec<ChatHistoryEntry>>>),
    PendingSendCount(oneshot::Sender<Result<u64>>),
    InboundAttention(oneshot::Sender<Result<Vec<ChatInboundAttention>>>),
    QuarantineInbound {
        id: String,
        reply: oneshot::Sender<Result<()>>,
    },
    ResolveDeadLetter {
        id: String,
        reply: oneshot::Sender<Result<()>>,
    },
    VerifyAuthority {
        peer: String,
        reply: oneshot::Sender<Result<ChatManifestTrust>>,
    },
    Shutdown(oneshot::Sender<Result<()>>),
}

fn worker_main(
    mut config: WorkerConfig,
    commands: mpsc::Receiver<Command>,
    ready: oneshot::Sender<Result<u32>>,
) {
    let initialized = futures_executor::block_on(async {
        let database = SqliteChatDb::open_encrypted(&config.database_path, &config.database_key);
        config.database_key.zeroize();
        let database = Rc::new(database?);

        let authority = AccountAuthority::derive(&config.master_key);
        config.master_key.zeroize();
        let authority = authority?;
        let transport: Rc<dyn ChatTransport> = Rc::new(http::NativeTransport { http: config.http });
        let mut rng = OsRng.unwrap_err();
        let mut engine =
            Engine::register(database, transport, config.user, INITIAL_PREKEYS, &mut rng).await?;
        engine.set_transparency_policy(config.transparency_policy)?;
        engine.sync_own_manifest(&authority, now_rfc3339()?).await?;
        Result::<_>::Ok((engine, authority))
    });

    let (mut engine, authority) = match initialized {
        Ok(value) => value,
        Err(error) => {
            config.database_key.zeroize();
            config.master_key.zeroize();
            let _ = ready.send(Err(error));
            return;
        }
    };
    if ready.send(Ok(engine.session().device_id())).is_err() {
        return;
    }

    while let Ok(command) = commands.recv() {
        match command {
            Command::SyncManifest(reply) => {
                let result = futures_executor::block_on(async {
                    engine.sync_own_manifest(&authority, now_rfc3339()?).await?;
                    Ok(())
                });
                let _ = reply.send(result);
            }
            Command::SendText {
                send_id,
                peer,
                sent_at,
                text,
                reply,
            } => {
                let result = futures_executor::block_on(async {
                    let sequence = engine.session().next_sent_seq().await?;
                    let mut rng = OsRng.unwrap_err();
                    let summary = engine
                        .send(
                            &send_id,
                            &peer,
                            &ChatContent::text_with_id(&send_id, sent_at, sequence, text),
                            &mut rng,
                        )
                        .await?;
                    Ok(summary.into())
                });
                let _ = reply.send(result);
            }
            Command::Reconcile(reply) => {
                let result = futures_executor::block_on(async {
                    let mut rng = OsRng.unwrap_err();
                    engine.flush_outbox(&mut rng).await?;
                    Ok(engine.receive(&mut rng).await?.into())
                });
                let _ = reply.send(result);
            }
            Command::MaintainPrekeys(reply) => {
                let result = futures_executor::block_on(async {
                    let mut rng = OsRng.unwrap_err();
                    Ok(engine
                        .maintain_prekeys(PREKEY_LOW_WATERMARK, PREKEY_TARGET, &mut rng)
                        .await?
                        .into())
                });
                let _ = reply.send(result);
            }
            Command::History(reply) => {
                let _ = reply.send(futures_executor::block_on(history(&engine)));
            }
            Command::PendingSendCount(reply) => {
                let result = futures_executor::block_on(async {
                    Ok(engine.pending_send_count().await? as u64)
                });
                let _ = reply.send(result);
            }
            Command::InboundAttention(reply) => {
                let result = futures_executor::block_on(async {
                    Ok(engine
                        .inbound_attention()
                        .await?
                        .into_iter()
                        .map(Into::into)
                        .collect())
                });
                let _ = reply.send(result);
            }
            Command::QuarantineInbound { id, reply } => {
                let result = futures_executor::block_on(async {
                    engine.quarantine_inbound(&id).await?;
                    Ok(())
                });
                let _ = reply.send(result);
            }
            Command::ResolveDeadLetter { id, reply } => {
                let result = futures_executor::block_on(async {
                    engine.resolve_dead_letter(&id).await?;
                    Ok(())
                });
                let _ = reply.send(result);
            }
            Command::VerifyAuthority { peer, reply } => {
                let result = futures_executor::block_on(async {
                    Ok(engine.mark_authority_verified(&peer).await?.into())
                });
                let _ = reply.send(result);
            }
            Command::Shutdown(reply) => {
                let _ = reply.send(Ok(()));
                break;
            }
        }
    }
}

async fn history(engine: &Engine) -> Result<Vec<ChatHistoryEntry>> {
    let incoming = engine.session().history().await?;
    let outgoing = engine.session().sent_history().await?;
    let mut history = Vec::with_capacity(incoming.len() + outgoing.len());
    for message in incoming {
        let content = serde_json::from_slice::<ChatContent>(&message.content)
            .map_err(|error| ChatError::Content(error.to_string()))?;
        history.push(ChatHistoryEntry {
            id: message.id,
            peer: message.peer,
            direction: ChatDirection::Incoming,
            sender_device_id: Some(message.sender_device_id),
            cursor: Some(message.cursor),
            timestamp_ms: message.received_at,
            delivered: true,
            deduplicated: false,
            content: content.into(),
        });
    }
    for message in outgoing {
        let content = serde_json::from_slice::<ChatContent>(&message.content)
            .map_err(|error| ChatError::Content(error.to_string()))?;
        history.push(ChatHistoryEntry {
            id: message.send_id,
            peer: message.peer,
            direction: ChatDirection::Outgoing,
            sender_device_id: None,
            cursor: None,
            timestamp_ms: message.created_at,
            delivered: message.delivered,
            deduplicated: message.deduplicated,
            content: content.into(),
        });
    }
    history.sort_by(|left, right| {
        left.timestamp_ms
            .cmp(&right.timestamp_ms)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(history)
}

fn take_key(mut bytes: Vec<u8>, name: &str) -> Result<[u8; 32]> {
    let key = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| KutupChatError::InvalidInput {
        message: format!("{name} must contain exactly 32 bytes"),
    });
    bytes.zeroize();
    key
}

fn now_rfc3339() -> Result<String> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|error| KutupChatError::InvalidInput {
            message: format!("format current timestamp: {error}"),
        })
}

fn worker_stopped() -> KutupChatError {
    KutupChatError::Storage {
        message: "chat worker stopped unexpectedly".into(),
    }
}

uniffi::setup_scaffolding!();
