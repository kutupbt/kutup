//! Attachment messages waiting for the recipient's server to store its copy
//! (docs/plans/federation-outbox.md, "Media sends", Signal's model).
//!
//! An attachment message to another account is written to history at once
//! (it shows as sending), but it is encrypted and sent only once the
//! recipient's server holds the attachment: never before, so the recipient
//! never gets a message whose attachment its server can't give it. The
//! client asks its own server for the copy (`POST /api/chat/media/deliveries`)
//! with the wait's operation; `queued` asks again later, with backoff, until
//! the wait's lifetime ends. Storage full, a refusal or the end of the
//! lifetime shows the message as not delivered, with a retry.
//!
//! The wait is the message's own history record (`SentMessage::media_wait`)
//! plus a short list of the send ids waiting, so finding what is due never
//! reads the whole history.

use kutup_chat_proto::{ChatAttachmentDescriptorV1, ChatContent};
use rand::{CryptoRng, Rng};

use crate::clock::unix_millis;
use crate::db::{MediaWait, MediaWaitFailure, SentMessage};
use crate::engine::Engine;
use crate::error::{ChatError, Result};
use crate::session::SendSummary;

/// The first wait after a try left the send waiting, doubling up to
/// [`RETRY_MAX_MS`]: a few minutes at most, so a peer coming back is seen
/// soon (the app also asks again when it is online or reopened).
const RETRY_FIRST_MS: i64 = 5_000;
const RETRY_MAX_MS: i64 = 300_000;

/// An attachment send due to ask for its copy now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaSendDue {
    pub send_id: String,
    pub peer: String,
    pub operation_id: String,
    pub descriptor: ChatAttachmentDescriptorV1,
}

/// The waiting attachment sends: those due now, and when the next is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MediaSends {
    pub due: Vec<MediaSendDue>,
    /// When the soonest one not yet due is (milliseconds).
    pub next_retry_ms: Option<i64>,
    /// Those whose lifetime just ended: now not delivered.
    pub expired: Vec<String>,
}

impl Engine {
    /// Writes an attachment message to `peer_user` to history, waiting for
    /// the recipient's server to store its copy under `operation_id`, for
    /// at most `lifetime_ms`. Asked again for the same send, it changes
    /// nothing.
    pub async fn stage_media_send(
        &mut self,
        send_id: &str,
        peer_user: &str,
        content: &ChatContent,
        operation_id: &str,
        lifetime_ms: i64,
    ) -> Result<()> {
        if content.message_id != send_id || content.as_attachment().is_none() {
            return Err(ChatError::Invalid(
                "a media send is an attachment message under its own sendId".into(),
            ));
        }
        if peer_user == self.session().user() {
            return Err(ChatError::Invalid(
                "Note to Self keeps its attachments on this account's server".into(),
            ));
        }
        if uuid::Uuid::parse_str(operation_id)
            .map(|parsed| parsed.hyphenated().to_string() != operation_id)
            .unwrap_or(true)
        {
            return Err(ChatError::Invalid(
                "a media send's operation is a canonical UUID".into(),
            ));
        }
        if let Some(sent) = self.session().sent_message(send_id).await? {
            if sent.peer == peer_user && sent.media_wait.is_some() {
                return Ok(());
            }
            return Err(ChatError::Invalid(format!(
                "sendId {send_id} is already used"
            )));
        }
        if self.media_delivery_capability(peer_user).await?.is_none() {
            return Err(ChatError::Invalid(
                "the recipient's server takes attachments only from an accepted contact".into(),
            ));
        }
        let now = unix_millis();
        let message = SentMessage {
            send_id: send_id.to_owned(),
            peer: peer_user.to_owned(),
            sender_device_id: self.session().device_id(),
            content: serde_json::to_vec(content).map_err(|e| ChatError::Content(e.to_string()))?,
            created_at: now,
            delivered_at: None,
            delivered: false,
            deduplicated: false,
            failed_recipients: 0,
            waiting_recipients: None,
            media_wait: Some(MediaWait {
                operation_id: operation_id.to_owned(),
                attempts: 0,
                retry_at_ms: now,
                deadline_ms: now.saturating_add(lifetime_ms.max(0)),
                failed: None,
            }),
        };
        let mut waiting = self.session().media_waits().await?;
        waiting.push(send_id.to_owned());
        self.session_mut()
            .save_media_waits(vec![message], Some(content.seq), &waiting)
            .await
    }

    /// The waiting attachment sends due at `now_ms`. Those past their
    /// lifetime become not delivered here.
    pub async fn media_sends(&mut self, now_ms: i64) -> Result<MediaSends> {
        let waiting = self.session().media_waits().await?;
        let mut sends = MediaSends::default();
        let mut kept = Vec::new();
        let mut changed = Vec::new();
        for send_id in &waiting {
            let Some(mut sent) = self.session().sent_message(send_id).await? else {
                continue;
            };
            let Some(wait) = sent
                .media_wait
                .as_mut()
                .filter(|wait| wait.failed.is_none())
            else {
                continue;
            };
            if now_ms > wait.deadline_ms {
                wait.failed = Some(MediaWaitFailure::Expired);
                sends.expired.push(send_id.clone());
                changed.push(sent);
                continue;
            }
            kept.push(send_id.clone());
            if wait.retry_at_ms > now_ms {
                sends.next_retry_ms = Some(
                    sends
                        .next_retry_ms
                        .map_or(wait.retry_at_ms, |next| next.min(wait.retry_at_ms)),
                );
                continue;
            }
            let content: ChatContent = serde_json::from_slice(&sent.content)
                .map_err(|e| ChatError::Content(e.to_string()))?;
            let descriptor = content.as_attachment().ok_or_else(|| {
                ChatError::Db(format!("media send {send_id} lost its attachment"))
            })?;
            sends.due.push(MediaSendDue {
                send_id: send_id.clone(),
                peer: sent.peer.clone(),
                operation_id: wait.operation_id.clone(),
                descriptor,
            });
        }
        if kept != waiting {
            self.session_mut()
                .save_media_waits(changed, None, &kept)
                .await?;
        }
        Ok(sends)
    }

    /// The recipient's server doesn't have the copy yet (`queued`, or this
    /// server couldn't be reached): asked again after a growing wait. When.
    pub async fn defer_media_send(&mut self, send_id: &str, now_ms: i64) -> Result<i64> {
        let mut sent = self.waiting_media_send(send_id).await?;
        let wait = sent.media_wait.as_mut().expect("a waiting media send");
        let delay = RETRY_FIRST_MS
            .saturating_mul(1_i64 << wait.attempts.min(16))
            .min(RETRY_MAX_MS);
        wait.attempts = wait.attempts.saturating_add(1);
        wait.retry_at_ms = now_ms.saturating_add(delay);
        let retry_at = wait.retry_at_ms;
        let waiting = self.session().media_waits().await?;
        self.session_mut()
            .save_media_waits(vec![sent], None, &waiting)
            .await?;
        Ok(retry_at)
    }

    /// The send was not delivered (storage full, or refused for good).
    pub async fn fail_media_send(
        &mut self,
        send_id: &str,
        failure: MediaWaitFailure,
    ) -> Result<()> {
        let mut sent = self.waiting_media_send(send_id).await?;
        sent.media_wait
            .as_mut()
            .expect("a waiting media send")
            .failed = Some(failure);
        let mut waiting = self.session().media_waits().await?;
        waiting.retain(|id| id != send_id);
        self.session_mut()
            .save_media_waits(vec![sent], None, &waiting)
            .await
    }

    /// The recipient's server stored the copy: the message is encrypted and
    /// sent now, keeping its place in the conversation.
    pub async fn release_media_send<R: Rng + CryptoRng>(
        &mut self,
        send_id: &str,
        rng: &mut R,
    ) -> Result<SendSummary> {
        let sent = self.waiting_media_send(send_id).await?;
        let content: ChatContent =
            serde_json::from_slice(&sent.content).map_err(|e| ChatError::Content(e.to_string()))?;
        let summary = self
            .send_at(send_id, &sent.peer, &content, Some(sent.created_at), rng)
            .await?;
        let mut waiting = self.session().media_waits().await?;
        waiting.retain(|id| id != send_id);
        self.session_mut()
            .save_media_waits(Vec::new(), None, &waiting)
            .await?;
        Ok(summary)
    }

    /// The person retries a send that was not delivered: it waits again for
    /// `lifetime_ms`. After a refusal or a full storage it asks under a new
    /// operation (the server keeps the old one's answer); after its lifetime
    /// ran out, under the same one, which may still be on its way.
    pub async fn restart_media_send(&mut self, send_id: &str, lifetime_ms: i64) -> Result<()> {
        let Some(mut sent) = self.session().sent_message(send_id).await? else {
            return Err(ChatError::Invalid(format!("no send {send_id}")));
        };
        let Some(wait) = sent.media_wait.as_mut() else {
            return Err(ChatError::Invalid(format!(
                "send {send_id} is not an attachment wait"
            )));
        };
        let Some(failure) = wait.failed.take() else {
            return Ok(());
        };
        if failure != MediaWaitFailure::Expired {
            wait.operation_id = uuid::Uuid::new_v4().hyphenated().to_string();
        }
        let now = unix_millis();
        wait.attempts = 0;
        wait.retry_at_ms = now;
        wait.deadline_ms = now.saturating_add(lifetime_ms.max(0));
        let mut waiting = self.session().media_waits().await?;
        waiting.push(send_id.to_owned());
        self.session_mut()
            .save_media_waits(vec![sent], None, &waiting)
            .await
    }

    async fn waiting_media_send(&self, send_id: &str) -> Result<SentMessage> {
        self.session()
            .sent_message(send_id)
            .await?
            .filter(|sent| {
                sent.media_wait
                    .as_ref()
                    .is_some_and(|wait| wait.failed.is_none())
            })
            .ok_or_else(|| ChatError::Invalid(format!("send {send_id} is not waiting for media")))
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use futures_executor::block_on;
    use kutup_crypto::chat_media::{object_ciphertext_size, ChatMediaSuiteId};

    use super::*;
    use crate::group_harness_tests::{befriend, rng, World};

    const OPERATION: &str = "66666666-6666-4666-8666-666666666666";

    fn attachment(send_id: &str, seq: u64) -> ChatContent {
        let descriptor = ChatAttachmentDescriptorV1 {
            version: 1,
            suite: ChatMediaSuiteId::XChaCha20Poly1305SecretStreamV1,
            attachment_id: "55555555-5555-4555-8555-555555555555".into(),
            origin_domain: "a.test".into(),
            retrieval_token: base64::engine::general_purpose::STANDARD.encode([1; 32]),
            ciphertext_bytes: object_ciphertext_size(7).unwrap(),
            ciphertext_sha256: "22".repeat(32),
            attachment_key: base64::engine::general_purpose::STANDARD.encode([3; 32]),
            plaintext_bytes: 7,
            filename: "a.pdf".into(),
            mime_type: "application/pdf".into(),
            media_class: kutup_chat_proto::ChatMediaClassV1::File,
            caption: None,
            width: None,
            height: None,
            duration_ms: None,
            preview: None,
            backup_media_id: None,
        };
        ChatContent::attachment_with_id(send_id, "2026-10-27T10:00:00Z", seq, descriptor).unwrap()
    }

    fn received_ids(report: &crate::engine::ReceiveReport) -> Vec<String> {
        report
            .messages
            .iter()
            .filter(|message| message.content.as_attachment().is_some())
            .map(|message| message.content.message_id.clone())
            .collect()
    }

    #[test]
    fn an_attachment_message_waits_for_the_copy_then_goes_in_its_place() {
        let world = World::new();
        let (mut alice, mut bob) = (world.person(1), world.person(2));
        befriend(&mut alice, &mut bob);
        let send_id = uuid::Uuid::new_v4().to_string();
        let seq = block_on(alice.engine.session().next_sent_seq()).unwrap();
        let content = attachment(&send_id, seq);
        block_on(alice.engine.stage_media_send(
            &send_id,
            &bob.account,
            &content,
            OPERATION,
            60_000,
        ))
        .unwrap();
        // Asked again: nothing changes.
        block_on(alice.engine.stage_media_send(
            &send_id,
            &bob.account,
            &content,
            OPERATION,
            60_000,
        ))
        .unwrap();
        // The sequence is taken: the next message gets the one after.
        assert_eq!(
            block_on(alice.engine.session().next_sent_seq()).unwrap(),
            seq + 1
        );
        let written = block_on(alice.engine.session().sent_message(&send_id))
            .unwrap()
            .unwrap();
        assert!(!written.delivered);
        // Nothing reaches Bob while it waits, and a plain send of it is refused.
        assert!(received_ids(&bob.receive()).is_empty());
        assert!(block_on(
            alice
                .engine
                .send(&send_id, &bob.account, &content, &mut rng())
        )
        .is_err());

        let now = unix_millis();
        let sends = block_on(alice.engine.media_sends(now)).unwrap();
        assert_eq!(sends.due.len(), 1);
        assert_eq!(sends.due[0].operation_id, OPERATION);
        assert_eq!(sends.due[0].peer, bob.account);
        // `queued`: not due again until its wait is over.
        let retry_at = block_on(alice.engine.defer_media_send(&send_id, now)).unwrap();
        assert_eq!(retry_at, now + RETRY_FIRST_MS);
        let sends = block_on(alice.engine.media_sends(now)).unwrap();
        assert!(sends.due.is_empty());
        assert_eq!(sends.next_retry_ms, Some(retry_at));
        let sends = block_on(alice.engine.media_sends(retry_at)).unwrap();
        assert_eq!(sends.due.len(), 1);

        // Stored: sent now, keeping when it was written.
        let summary = block_on(alice.engine.release_media_send(&send_id, &mut rng())).unwrap();
        assert!(summary.delivered);
        let sent = block_on(alice.engine.session().sent_message(&send_id))
            .unwrap()
            .unwrap();
        assert_eq!(sent.created_at, written.created_at);
        assert!(sent.media_wait.is_none());
        assert!(block_on(alice.engine.media_sends(retry_at))
            .unwrap()
            .due
            .is_empty());
        assert_eq!(received_ids(&bob.receive()), vec![send_id]);
    }

    #[test]
    fn a_refused_or_late_attachment_is_not_delivered_until_retried() {
        let world = World::new();
        let (mut alice, mut bob) = (world.person(1), world.person(2));
        befriend(&mut alice, &mut bob);
        let refused = uuid::Uuid::new_v4().to_string();
        let seq = block_on(alice.engine.session().next_sent_seq()).unwrap();
        block_on(alice.engine.stage_media_send(
            &refused,
            &bob.account,
            &attachment(&refused, seq),
            OPERATION,
            60_000,
        ))
        .unwrap();
        let late = uuid::Uuid::new_v4().to_string();
        block_on(alice.engine.stage_media_send(
            &late,
            &bob.account,
            &attachment(&late, seq + 1),
            "77777777-7777-4777-8777-777777777777",
            1_000,
        ))
        .unwrap();
        block_on(
            alice
                .engine
                .fail_media_send(&refused, MediaWaitFailure::StorageFull),
        )
        .unwrap();
        let sends = block_on(alice.engine.media_sends(unix_millis() + 5_000)).unwrap();
        assert!(sends.due.is_empty());
        assert_eq!(sends.expired, vec![late.clone()]);
        let failure = |id: &str| {
            block_on(alice.engine.session().sent_message(id))
                .unwrap()
                .unwrap()
                .media_wait
                .unwrap()
        };
        assert_eq!(
            failure(&refused).failed,
            Some(MediaWaitFailure::StorageFull)
        );
        assert_eq!(failure(&late).failed, Some(MediaWaitFailure::Expired));
        // A failed send isn't released.
        assert!(block_on(alice.engine.release_media_send(&refused, &mut rng())).is_err());

        // Retried: a refusal asks under a new operation, a late one the same.
        block_on(alice.engine.restart_media_send(&refused, 60_000)).unwrap();
        block_on(alice.engine.restart_media_send(&late, 60_000)).unwrap();
        let sends = block_on(alice.engine.media_sends(unix_millis())).unwrap();
        let operations: std::collections::HashMap<_, _> = sends
            .due
            .iter()
            .map(|due| (due.send_id.clone(), due.operation_id.clone()))
            .collect();
        assert_eq!(operations.len(), 2);
        assert_ne!(operations[&refused], OPERATION);
        assert_eq!(operations[&late], "77777777-7777-4777-8777-777777777777");
        assert!(received_ids(&bob.receive()).is_empty());
    }
}
