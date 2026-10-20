//! A user's Chat as the web runs it (`WasmChatClient::open` and
//! `reconcile`): Chat core's engine on an in-memory SQLite store, the same
//! startup (register the device, identity pins, sealed sending as the server
//! advertises it, the signed manifest, the profile), and the WebSocket that
//! says when to read the mailbox.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use futures_util::{SinkExt as _, StreamExt as _};
use kutup_chat_core::{AccountAuthority, ChatContent, Engine, ReceivedMessage, SqliteChatDb};
use kutup_chat_proto::{ChatWsServerMessage, ReceiptState};
use rand::rngs::OsRng;
use rand::TryRngCore as _;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::Notify;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::Message;

use crate::account::User;
use crate::api::Api;
use crate::metrics::Metrics;
use crate::transport::Transport;

/// One-time prekeys a new device publishes, as the web's.
const INITIAL_PREKEYS: usize = 50;
/// The web pings this often so a dead connection is noticed.
const PING_EVERY: Duration = Duration::from_secs(25);

pub struct Chat {
    pub engine: Engine,
    profile_wrapping_key: [u8; 32],
    pub token: Rc<RefCell<String>>,
}

pub fn now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

fn rng() -> impl rand::CryptoRng {
    OsRng.unwrap_err()
}

impl Chat {
    /// Registers this user's device and publishes what the web publishes on
    /// first opening Chat.
    pub async fn open(api: &Api, user: &User, sealed_sender: bool) -> Result<Chat> {
        let token = Rc::new(RefCell::new(user.token.clone()));
        let transport = Rc::new(Transport {
            api: api.clone(),
            token: token.clone(),
        });
        let db = Rc::new(SqliteChatDb::open_in_memory()?);
        let authority = AccountAuthority::derive(&user.master_key)?;
        let profile_wrapping_key =
            kutup_chat_core::derive_wrapping_key(&user.master_key, &user.binding)?;
        let mut rng = rng();
        let mut engine = Engine::register(
            db,
            transport,
            user.chat_account(),
            INITIAL_PREKEYS,
            &mut rng,
        )
        .await?;
        engine.enable_identity_pins(&user.master_key, &user.binding)?;
        engine.set_sealed_sender_enabled(sealed_sender);
        engine.sync_own_manifest(&authority, now()).await?;
        engine
            .initialize_profile(&profile_wrapping_key, &user.username, &mut rng)
            .await?;
        Ok(Chat {
            engine,
            profile_wrapping_key,
            token,
        })
    }

    pub fn device_id(&self) -> u32 {
        self.engine.session().device_id()
    }

    /// Accepts `peer` as a contact, as answering their first message does.
    pub async fn accept(&mut self, peer: &str) -> Result<()> {
        self.engine.accept_contact(peer, &now(), &mut rng()).await?;
        Ok(())
    }

    async fn send(
        &mut self,
        peer: &str,
        content: impl FnOnce(&str, u64) -> Result<ChatContent>,
    ) -> Result<()> {
        let send_id = uuid::Uuid::new_v4().to_string();
        let seq = self.engine.session().next_sent_seq().await?;
        let content = content(&send_id, seq)?;
        self.engine
            .send(&send_id, peer, &content, &mut rng())
            .await?;
        Ok(())
    }

    /// A text that carries when it was sent, so its reader can time the
    /// delivery end to end.
    pub async fn send_text(&mut self, peer: &str) -> Result<()> {
        let sent_ms = unix_ms();
        self.send(peer, |id, seq| {
            Ok(ChatContent::text_with_id(
                id,
                now(),
                seq,
                format!("load {sent_ms} {}", "x".repeat(80)),
            ))
        })
        .await
    }

    pub async fn send_typing(&mut self, peer: &str) -> Result<()> {
        self.send(peer, |id, seq| {
            Ok(ChatContent::typing_with_id(id, now(), seq, true))
        })
        .await
    }

    pub async fn send_receipt(
        &mut self,
        peer: &str,
        ids: Vec<String>,
        state: ReceiptState,
    ) -> Result<()> {
        self.send(peer, |id, seq| {
            ChatContent::receipt_with_id(id, now(), seq, ids, state).map_err(|e| anyhow!(e))
        })
        .await
    }

    /// The web's reconcile pass: the outbox, contact syncs, the profile, then
    /// the mailbox. The messages that arrived.
    pub async fn reconcile(&mut self) -> Result<Vec<ReceivedMessage>> {
        let mut rng = rng();
        self.engine
            .flush_outbox_collecting_failures(&mut rng)
            .await?;
        let _ = self.engine.flush_contact_syncs(&now(), &mut rng).await;
        let _ = self
            .engine
            .flush_profile(&self.profile_wrapping_key, &now(), &mut rng)
            .await;
        let report = self.engine.receive(&mut rng).await?;
        let _ = self.engine.flush_contact_syncs(&now(), &mut rng).await;
        let _ = self.engine.refresh_profiles().await;
        Ok(report.messages)
    }
}

pub fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

/// The milliseconds since a load-test text was sent, from its body.
pub fn delivery_ms(message: &ReceivedMessage) -> Option<u64> {
    if message.content.kind != kutup_chat_proto::content::kind::TEXT {
        return None;
    }
    let text = message.content.body.get("text")?.as_str()?;
    let sent: u64 = text
        .strip_prefix("load ")?
        .split(' ')
        .next()?
        .parse()
        .ok()?;
    Some(unix_ms().saturating_sub(sent))
}

/// Holds the user's Chat WebSocket open: pings as the web does, and wakes
/// `arrived` when the server pushes an envelope or asks for a drain. Ends
/// when the server closes it or `stop` is notified.
pub async fn hold_socket(
    api: Api,
    token: String,
    device_id: u32,
    arrived: Rc<Notify>,
    stop: Rc<Notify>,
    metrics: Metrics,
) -> Result<()> {
    let url = format!(
        "{}/api/chat/ws?deviceId={device_id}",
        api.base.replacen("http", "ws", 1)
    );
    let mut request = url.into_client_request()?;
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {token}").parse()?);
    let started = std::time::Instant::now();
    let (socket, _) = match tokio_tungstenite::connect_async(request).await {
        Ok(connected) => connected,
        Err(error) => {
            metrics.error("ws.connect", error.to_string());
            return Err(error.into());
        }
    };
    metrics.ok("ws.connect", started.elapsed());
    let _open = metrics.socket_opened();
    let (mut write, mut read) = socket.split();
    let mut ping = tokio::time::interval(PING_EVERY);
    ping.tick().await;
    loop {
        tokio::select! {
            _ = stop.notified() => {
                let _ = write.close().await;
                return Ok(());
            }
            _ = ping.tick() => {
                if let Err(error) = write.send(Message::text(r#"{"type":"ping"}"#)).await {
                    metrics.error("ws.dropped", error.to_string());
                    return Err(error.into());
                }
            }
            frame = read.next() => match frame {
                Some(Ok(Message::Text(text))) => {
                    if let Ok(ChatWsServerMessage::Envelope { .. } | ChatWsServerMessage::DrainMailbox) =
                        serde_json::from_str::<ChatWsServerMessage>(&text)
                    {
                        arrived.notify_one();
                    }
                }
                Some(Ok(_)) => {}
                Some(Err(error)) => {
                    metrics.error("ws.dropped", error.to_string());
                    return Err(error.into());
                }
                None => {
                    metrics.error("ws.dropped", "closed by the server");
                    return Ok(());
                }
            }
        }
    }
}
