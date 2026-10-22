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
    AccountAuthority, ChatContent, ChatError, ChatTransport, Engine, Installation, SqliteChatDb,
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

    /// The account this client runs as: `aci:<uuid>@<server>`.
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

    /// The server's `mailboxRetentionDays` (from chat capabilities; 0 keeps
    /// mail for ever): how long replaced prekeys are kept before deletion.
    pub async fn set_mailbox_retention_days(&self, days: u32) -> Result<()> {
        self.dispatch(|reply| Command::SetMailboxRetentionDays { days, reply })
            .await
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

    pub async fn safety_number(&self, peer: String) -> Result<ChatSafetyNumber> {
        self.dispatch(|reply| Command::SafetyNumber { peer, reply })
            .await
    }

    pub async fn verify_safety_number(
        &self,
        peer: String,
        scanned_payload: String,
    ) -> Result<ChatSafetyNumber> {
        self.dispatch(|reply| Command::VerifySafetyNumber {
            peer,
            scanned_payload,
            reply,
        })
        .await
    }

    /// Mark the contact's identity verified (or clear it) by hand, after
    /// comparing the numbers; `identity_key` is the compared number's.
    pub async fn set_identity_verified(
        &self,
        peer: String,
        identity_key: String,
        verified: bool,
    ) -> Result<ChatSafetyNumber> {
        self.dispatch(|reply| Command::SetIdentityVerified {
            peer,
            identity_key,
            verified,
            reply,
        })
        .await
    }

    /// Link a new device of this account: `code` is the `kutup://link?…`
    /// code it shows. `false`: the code expired.
    pub async fn link_device(
        &self,
        code: String,
        settings: ChatProvisionedSettings,
    ) -> Result<bool> {
        self.dispatch(|reply| Command::LinkDevice {
            code,
            settings,
            reply,
        })
        .await
    }

    /// Reset the account's identity, keeping its devices but `remove` (a
    /// lost or stolen one). Returns the devices kept.
    pub async fn reset_identity(&self, remove: Vec<u32>) -> Result<Vec<u32>> {
        self.dispatch(|reply| Command::ResetIdentity { remove, reply })
            .await
    }
}

/// The new device's side of linking (docs/plans/account-identity-key.md):
/// show `link_code` once the provisioning socket gave its address, and hand
/// the envelope the socket delivers to [`open_linked_native_chat_client`].
#[derive(uniffi::Object)]
pub struct NativeLinkingDevice {
    inner: kutup_chat_core::LinkingDevice,
}

#[uniffi::export]
impl NativeLinkingDevice {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: kutup_chat_core::LinkingDevice::new(),
        })
    }

    pub fn link_code(&self, address: String) -> Result<String> {
        Ok(self.inner.link_code(&address)?)
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

/// Open an account's native chat device: the one this database holds, a
/// registration it started, or — for the account's first Chat device — a
/// re-registration. Another device of the account holding the identity is
/// [`KutupChatError::LinkRequired`]. Key bytes are moved to the engine
/// worker, used to unlock/derive state, and zeroized before the first result
/// crosses back to Swift/Kotlin. `binding` is the account's key binding (the
/// session's `envelopeBinding`), which the account's own seals bind.
#[uniffi::export]
pub async fn open_native_chat_client(
    database_path: String,
    database_key: Vec<u8>,
    account: String,
    master_key: Vec<u8>,
    binding: String,
    http: Arc<dyn ChatHttpClient>,
) -> Result<Arc<NativeChatClient>> {
    start_client(
        database_path,
        database_key,
        account,
        master_key,
        binding,
        http,
        Install::Open,
    )
    .await
}

/// Re-register: a new account identity, this device alone in the account's
/// manifest, the account's other devices dropped ("I don't have my other
/// devices"). Contacts see the safety number change once.
#[uniffi::export]
pub async fn reregister_native_chat_client(
    database_path: String,
    database_key: Vec<u8>,
    account: String,
    master_key: Vec<u8>,
    binding: String,
    http: Arc<dyn ChatHttpClient>,
) -> Result<Arc<NativeChatClient>> {
    start_client(
        database_path,
        database_key,
        account,
        master_key,
        binding,
        http,
        Install::Reregister,
    )
    .await
}

/// Register this device with the identity a linking device sent: `envelope`
/// is the provisioning envelope (JSON) the socket delivered.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub async fn open_linked_native_chat_client(
    linking: Arc<NativeLinkingDevice>,
    envelope: String,
    database_path: String,
    database_key: Vec<u8>,
    account: String,
    master_key: Vec<u8>,
    binding: String,
    http: Arc<dyn ChatHttpClient>,
) -> Result<Arc<NativeChatClient>> {
    let envelope =
        serde_json::from_str(&envelope).map_err(|error| KutupChatError::InvalidInput {
            message: format!("provisioning envelope: {error}"),
        })?;
    start_client(
        database_path,
        database_key,
        account,
        master_key,
        binding,
        http,
        Install::Linked { linking, envelope },
    )
    .await
}

/// How the worker gets its device.
enum Install {
    Open,
    Reregister,
    Linked {
        linking: Arc<NativeLinkingDevice>,
        envelope: kutup_chat_proto::ProvisionEnvelopeV1,
    },
}

async fn start_client(
    database_path: String,
    database_key: Vec<u8>,
    account: String,
    master_key: Vec<u8>,
    binding: String,
    http: Arc<dyn ChatHttpClient>,
    install: Install,
) -> Result<Arc<NativeChatClient>> {
    if database_path.trim().is_empty() {
        return Err(KutupChatError::InvalidInput {
            message: "database path is empty".into(),
        });
    }
    // The device's account, for good: its string form `aci:<uuid>@<server>`.
    let user = kutup_chat_core::parse_account(&account)
        .map_err(|error| KutupChatError::InvalidInput {
            message: error.to_string(),
        })?
        .to_string();
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
                    binding,
                    user: worker_user,
                    http,
                    install,
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
    binding: String,
    /// The account: `aci:<uuid>@<server>`.
    user: String,
    http: Arc<dyn ChatHttpClient>,
    install: Install,
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
    SetMailboxRetentionDays {
        days: u32,
        reply: oneshot::Sender<Result<()>>,
    },
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
    SafetyNumber {
        peer: String,
        reply: oneshot::Sender<Result<ChatSafetyNumber>>,
    },
    VerifySafetyNumber {
        peer: String,
        scanned_payload: String,
        reply: oneshot::Sender<Result<ChatSafetyNumber>>,
    },
    SetIdentityVerified {
        peer: String,
        identity_key: String,
        verified: bool,
        reply: oneshot::Sender<Result<ChatSafetyNumber>>,
    },
    LinkDevice {
        code: String,
        settings: ChatProvisionedSettings,
        reply: oneshot::Sender<Result<bool>>,
    },
    ResetIdentity {
        remove: Vec<u32>,
        reply: oneshot::Sender<Result<Vec<u32>>>,
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

        let authority = AccountAuthority::derive(&config.master_key)?;
        let transport: Rc<dyn ChatTransport> =
            Rc::new(http::NativeTransport::new(config.http.clone()));
        let mut rng = OsRng.unwrap_err();
        let user = config.user.clone();
        let mut engine = match std::mem::replace(&mut config.install, Install::Open) {
            Install::Open => {
                match Engine::installation(database.as_ref(), transport.as_ref(), &user).await? {
                    Installation::Registered { device_id } => {
                        Engine::open(database, transport, user, device_id).await?
                    }
                    Installation::Registering => {
                        Engine::resume_registration(database, transport, user).await?
                    }
                    Installation::Unregistered {
                        account_has_identity: false,
                    } => {
                        Engine::reregister(
                            database,
                            transport,
                            user,
                            &authority,
                            now_rfc3339()?,
                            INITIAL_PREKEYS,
                            &mut rng,
                        )
                        .await?
                    }
                    Installation::Unregistered {
                        account_has_identity: true,
                    } => return Err(KutupChatError::LinkRequired),
                }
            }
            Install::Reregister => {
                Engine::reregister(
                    database,
                    transport,
                    user,
                    &authority,
                    now_rfc3339()?,
                    INITIAL_PREKEYS,
                    &mut rng,
                )
                .await?
            }
            Install::Linked { linking, envelope } => {
                let provision = linking
                    .inner
                    .verify(transport.as_ref(), &user, &authority, &envelope)
                    .await?;
                Engine::register_linked(
                    database,
                    transport,
                    user,
                    provision,
                    INITIAL_PREKEYS,
                    &mut rng,
                )
                .await?
            }
        };
        // One identity for every app of the account (docs/plans/drive-identity-pins.md).
        engine.enable_identity_pins(&config.master_key, &config.binding)?;
        engine.enable_group_list(&config.master_key, &config.binding)?;
        config.master_key.zeroize();
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
            Command::SetMailboxRetentionDays { days, reply } => {
                engine.set_mailbox_retention_days(days);
                let _ = reply.send(Ok(()));
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
            Command::SafetyNumber { peer, reply } => {
                let result = futures_executor::block_on(async {
                    Ok(engine.safety_number(&peer).await?.into())
                });
                let _ = reply.send(result);
            }
            Command::VerifySafetyNumber {
                peer,
                scanned_payload,
                reply,
            } => {
                let result = futures_executor::block_on(async {
                    Ok(engine
                        .verify_safety_number(&peer, &scanned_payload)
                        .await?
                        .into())
                });
                let _ = reply.send(result);
            }
            Command::SetIdentityVerified {
                peer,
                identity_key,
                verified,
                reply,
            } => {
                let result = futures_executor::block_on(async {
                    Ok(engine
                        .set_identity_verified(&peer, &identity_key, verified)
                        .await?
                        .into())
                });
                let _ = reply.send(result);
            }
            Command::LinkDevice {
                code,
                settings,
                reply,
            } => {
                let result = futures_executor::block_on(async {
                    Ok(engine
                        .link_device(
                            &code,
                            kutup_chat_core::ProvisionedSettings {
                                read_receipts: settings.read_receipts,
                                typing_indicators: settings.typing_indicators,
                            },
                            &authority,
                        )
                        .await?)
                });
                let _ = reply.send(result);
            }
            Command::ResetIdentity { remove, reply } => {
                let result = futures_executor::block_on(async {
                    let mut rng = OsRng.unwrap_err();
                    Ok(engine
                        .reset_identity(&remove, now_rfc3339()?, &mut rng)
                        .await?)
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
    let me = engine.session().user().to_owned();
    let incoming = engine.session().history().await?;
    let outgoing = engine.session().sent_history().await?;
    let mut history = Vec::with_capacity(incoming.len() + outgoing.len());
    for message in incoming {
        history.push(incoming_entry(message)?);
    }
    for message in outgoing {
        history.push(outgoing_entry(message, &me)?);
    }
    history.sort_by(|left, right| {
        left.timestamp_ms
            .cmp(&right.timestamp_ms)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(history)
}

/// A received message: written by the other account, in its chat.
fn incoming_entry(message: kutup_chat_core::InboxMessage) -> Result<ChatHistoryEntry> {
    let content = serde_json::from_slice::<ChatContent>(&message.content)
        .map_err(|error| ChatError::Content(error.to_string()))?;
    Ok(ChatHistoryEntry {
        id: message.id,
        conversation: message.peer.clone(),
        sender: message.peer,
        direction: ChatDirection::Incoming,
        sender_device_id: Some(message.sender_device_id),
        cursor: Some(message.cursor),
        timestamp_ms: message.received_at,
        delivered: true,
        deduplicated: false,
        content: content.into(),
    })
}

/// A sent message: written by this account (`me`), in the other's chat.
fn outgoing_entry(message: kutup_chat_core::SentMessage, me: &str) -> Result<ChatHistoryEntry> {
    let content = serde_json::from_slice::<ChatContent>(&message.content)
        .map_err(|error| ChatError::Content(error.to_string()))?;
    Ok(ChatHistoryEntry {
        id: message.send_id,
        conversation: message.peer,
        sender: me.to_owned(),
        direction: ChatDirection::Outgoing,
        sender_device_id: None,
        cursor: None,
        timestamp_ms: message.created_at,
        delivered: message.delivered,
        deduplicated: message.deduplicated,
        content: content.into(),
    })
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

#[cfg(test)]
mod history_tests {
    use super::*;

    fn content() -> Vec<u8> {
        serde_json::to_vec(&ChatContent::text_with_id(
            "m1",
            "2026-07-16T12:00:00Z",
            1,
            "hi",
        ))
        .unwrap()
    }

    #[test]
    fn an_outgoing_entry_is_written_by_this_account_in_the_others_chat() {
        let entry = outgoing_entry(
            kutup_chat_core::SentMessage {
                send_id: "s1".into(),
                peer: "bob@chat.test".into(),
                sender_device_id: 7,
                content: content(),
                created_at: 1,
                delivered_at: None,
                delivered: false,
                deduplicated: false,
                failed_recipients: 0,
                waiting_recipients: None,
            },
            "alice@chat.test",
        )
        .unwrap();
        assert_eq!(entry.conversation, "bob@chat.test");
        assert_eq!(entry.sender, "alice@chat.test");
    }

    #[test]
    fn an_incoming_entry_is_written_by_the_other_account() {
        let entry = incoming_entry(kutup_chat_core::InboxMessage {
            id: "m1".into(),
            peer: "bob@chat.test".into(),
            sender_device_id: 3,
            cursor: 9,
            content: content(),
            received_at: 1,
        })
        .unwrap();
        assert_eq!(entry.conversation, "bob@chat.test");
        assert_eq!(entry.sender, "bob@chat.test");
    }
}
