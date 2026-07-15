//! The engine — the async orchestration over a [`Session`] and a
//! [`ChatTransport`]. This is the surface the client apps drive: register a
//! device, send a message (with `409` device-list recovery, backed by the durable
//! `sendId` outbox), and flush the outbox after a restart.
//!
//! It interleaves the two worlds cleanly: `await` the async transport for network
//! I/O, call the synchronous [`Session`] methods (each one atomic transaction) for
//! crypto + store. The `Rc<dyn ChatTransport>` is cloned per call so a network
//! `await` never holds a borrow of `self` across the subsequent store write.

use std::rc::Rc;

use rand::{CryptoRng, Rng};

use crate::db::ChatDb;
use crate::error::{ChatError, Result};
use crate::session::{ReceiveOutcome, ReceivedMessage, SendSummary, Session};
use crate::transport::{ChatTransport, SendOutcome};
use kutup_chat_proto::{ChatContent, OutgoingEnvelope, SendMessagesRequest};

/// How many send/recovery rounds a single message gets before giving up. Each 409
/// consumes one; a well-behaved server converges in 1–2.
const MAX_SEND_ATTEMPTS: u32 = 5;
/// Drain page size (the contract caps it at 500).
const DRAIN_LIMIT: u32 = 500;

/// The outcome of a drain: the messages received, plus the envelopes that were
/// acked-and-dropped (decrypted-but-unparseable, or undecryptable) so the caller
/// can log/telemeter them without them wedging the mailbox.
#[derive(Debug, Default)]
pub struct ReceiveReport {
    pub messages: Vec<ReceivedMessage>,
    /// Ids that decrypted but whose plaintext wasn't a valid content document.
    pub undecodable: Vec<String>,
    /// `(id, error)` for envelopes that failed to decrypt and were skipped.
    pub errors: Vec<(String, String)>,
}

/// A registered chat client: one device plus its transport.
pub struct Engine {
    session: Session,
    transport: Rc<dyn ChatTransport>,
}

impl Engine {
    /// Wrap an already-registered [`Session`] with a transport.
    pub fn new(session: Session, transport: Rc<dyn ChatTransport>) -> Self {
        Engine { session, transport }
    }

    /// Register a brand-new device end-to-end: generate keys, `POST` the
    /// registration, and adopt the server-assigned device id.
    pub async fn register<R: Rng + CryptoRng>(
        db: Rc<dyn ChatDb>,
        transport: Rc<dyn ChatTransport>,
        user: impl Into<String>,
        num_one_time: usize,
        rng: &mut R,
    ) -> Result<Self> {
        // Provisional device id 1; the server assigns the real one below (no crypto
        // op runs before that, so the provisional value is never used on the wire).
        let mut session = Session::generate(db, user, 1, num_one_time, rng)?;
        let request = session
            .registration()
            .expect("a freshly generated session carries its registration")
            .clone();
        let device_id = transport.register_device(&request).await?;
        session.set_device_id(device_id);
        Ok(Engine::new(session, transport))
    }

    /// Reopen an installed device.
    pub fn open(
        db: Rc<dyn ChatDb>,
        transport: Rc<dyn ChatTransport>,
        user: impl Into<String>,
        device_id: u32,
    ) -> Result<Self> {
        Ok(Engine::new(Session::open(db, user, device_id)?, transport))
    }

    /// The underlying device session (for the crypto/store primitives + the
    /// registration payload before it's published).
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// How many sends are still pending in the durable outbox (undelivered) — for a
    /// "N unsent" indicator, or to decide whether to [`flush_outbox`](Self::flush_outbox).
    pub fn pending_send_count(&self) -> Result<usize> {
        Ok(self.session.pending_outbox()?.len())
    }

    /// Send `content` to every active device of `peer_user`. Persists the ciphertext
    /// in a durable `sendId`-keyed outbox before hitting the network, recovers from
    /// `409 DeviceListMismatch`, and drops the outbox entry once delivered.
    pub async fn send<R: Rng + CryptoRng>(
        &mut self,
        send_id: &str,
        peer_user: &str,
        content: &ChatContent,
        rng: &mut R,
    ) -> Result<SendSummary> {
        let transport = Rc::clone(&self.transport);
        let bundles = transport.fetch_bundles(peer_user).await?.devices;
        let mut summary = SendSummary::default();
        let envelopes =
            self.session
                .enqueue_send(send_id, peer_user, &bundles, content, &mut summary, rng)?;
        self.deliver(send_id, peer_user, envelopes, &mut summary, rng)
            .await?;
        Ok(summary)
    }

    /// Resend every outbox entry left over from a previous run (e.g. a crash after
    /// the ratchet advanced but before the server confirmed). Idempotent on the
    /// server via `sendId`.
    pub async fn flush_outbox<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<SendSummary>> {
        let mut summaries = Vec::new();
        for entry in self.session.pending_outbox()? {
            let envelopes: Vec<OutgoingEnvelope> = serde_json::from_slice(&entry.envelopes)
                .map_err(|e| ChatError::Content(e.to_string()))?;
            let mut summary = SendSummary::default();
            self.deliver(&entry.send_id, &entry.peer, envelopes, &mut summary, rng)
                .await?;
            summaries.push(summary);
        }
        Ok(summaries)
    }

    /// Drain the mailbox and decrypt everything new, oldest-first, resuming from the
    /// durable cursor. For each envelope the ratchet advance, the plaintext, and the
    /// cursor are persisted in one transaction **before** the batch is acked — so a
    /// crash between persist and ack simply re-drains from a cursor past the message
    /// (never re-decrypting it). Already-processed cursors (a WebSocket twin, say)
    /// are acked but not re-decrypted; an undecryptable envelope is skipped (the
    /// ratchet tolerates the gap) and reported rather than wedging the mailbox.
    pub async fn receive<R: Rng + CryptoRng>(&mut self, rng: &mut R) -> Result<ReceiveReport> {
        let transport = Rc::clone(&self.transport);
        let device_id = self.session.device_id();
        let mut after = self.session.last_cursor()?;
        let mut report = ReceiveReport::default();

        loop {
            let page = transport.drain(device_id, after, DRAIN_LIMIT).await?;
            let mut ack_ids = Vec::new();
            for envelope in &page.envelopes {
                // A cursor at or below the resume point was already processed: ack it
                // (tolerating a WS/REST twin) but never re-decrypt it.
                if after.is_some_and(|c| envelope.cursor <= c) {
                    ack_ids.push(envelope.id.clone());
                    continue;
                }
                match self.session.receive_envelope(envelope, rng) {
                    Ok(ReceiveOutcome::Message(message)) => {
                        after = Some(message.cursor);
                        ack_ids.push(message.id.clone());
                        report.messages.push(*message);
                    }
                    Ok(ReceiveOutcome::Undecodable { id, cursor }) => {
                        after = Some(cursor);
                        ack_ids.push(id.clone());
                        report.undecodable.push(id);
                    }
                    Err(e) => {
                        // Undecryptable: advance past it (libsignal tolerates the
                        // ratchet gap), ack it, and report — one bad message must not
                        // stall the whole inbox. Proper session-reset recovery is a
                        // follow-up (sessionControl).
                        self.session.skip_cursor(envelope.cursor)?;
                        after = Some(envelope.cursor);
                        ack_ids.push(envelope.id.clone());
                        report.errors.push((envelope.id.clone(), e.to_string()));
                    }
                }
            }
            if !ack_ids.is_empty() {
                transport.ack(&ack_ids).await?;
            }
            if !page.more {
                break;
            }
        }
        Ok(report)
    }

    /// The send/recover loop shared by [`send`](Self::send) and
    /// [`flush_outbox`](Self::flush_outbox): POST the current envelope set; on a
    /// mismatch, re-fetch bundles, amend the durable send, and retry.
    async fn deliver<R: Rng + CryptoRng>(
        &mut self,
        send_id: &str,
        peer_user: &str,
        mut envelopes: Vec<OutgoingEnvelope>,
        summary: &mut SendSummary,
        rng: &mut R,
    ) -> Result<()> {
        let transport = Rc::clone(&self.transport);
        for attempt in 1..=MAX_SEND_ATTEMPTS {
            summary.attempts = attempt;
            let request = SendMessagesRequest {
                sender_device_id: self.session.device_id(),
                send_id: send_id.to_string(),
                envelopes: envelopes.clone(),
                access_token: None,
            };
            match transport.send(peer_user, &request).await? {
                SendOutcome::Delivered { deduplicated } => {
                    self.session.complete_send(send_id)?;
                    summary.delivered = true;
                    summary.deduplicated = deduplicated;
                    return Ok(());
                }
                SendOutcome::Mismatch(mismatch) => {
                    let bundles = transport.fetch_bundles(peer_user).await?.devices;
                    envelopes = self
                        .session
                        .amend_send(send_id, peer_user, &mismatch, &bundles, summary, rng)?;
                }
            }
        }
        Err(ChatError::SendNotConverged(MAX_SEND_ATTEMPTS))
    }
}
