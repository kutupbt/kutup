//! Delivery capabilities for the multi-recipient group route
//! (docs/plans/pairwise-groups.md, "Slice 2").
//!
//! Each account draws a random 16-byte capability per group, publishes its
//! hash to its own server (with every other group's, padded with dummies to a
//! multiple of 8 so the count doesn't tell how many groups it is in), and
//! hands it to the other members pairwise in a hidden `groupDelivery`. A
//! member sends group messages to the account on the multi-recipient route
//! with it; one who doesn't hold it sends pairwise. The capability is drawn
//! again whenever a member who holds it is no longer one, so a removed
//! member's copy stops working at once. This account's other devices learn
//! it from the account's group list.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha256};

use kutup_chat_proto::content::GroupDeliveryBody;
use kutup_chat_proto::{ChatContent, SealedBatchOutcomeV1, SealedMessageSubmissionV1};

use crate::clock::unix_millis;
use crate::engine::Engine;
use crate::error::Result;
use crate::group::{DeliveryBook, GroupRecordV1, GroupStatus, HeldCapability, SecretText};
use crate::group_send::Recipient;
use crate::transport::GroupCapabilitiesOutcome;

/// Published capability hashes are padded to a multiple of this.
pub(crate) const CAPABILITY_BUCKET: usize = 8;

/// `count` hashes rounded up to the next bucket (at least one bucket, so no
/// groups and a few look the same).
pub(crate) fn padded_len(count: usize) -> usize {
    count.max(1).div_ceil(CAPABILITY_BUCKET) * CAPABILITY_BUCKET
}

impl Engine {
    /// Gives this account's capability for the group to every member who
    /// doesn't hold it, drawing a new one first when there is none or a
    /// holder left. Best effort: a member not reached now is tried with the
    /// next message, and sends to this account pairwise meanwhile.
    pub(crate) async fn hand_out_delivery<R: Rng + CryptoRng>(
        &mut self,
        record: &mut GroupRecordV1,
        recipients: &[Recipient],
        certificate: &libsignal_protocol::SenderCertificate,
        rng: &mut R,
    ) -> Result<()> {
        if record.status != GroupStatus::Member {
            return Ok(());
        }
        let me = self.session.account_ref().to_string();
        let members: Vec<String> = recipients
            .iter()
            .map(|recipient| recipient.account.clone())
            .filter(|account| account != &me)
            .collect();
        if record
            .delivery
            .as_ref()
            .is_none_or(|book| book.must_rotate(&members))
        {
            record.delivery = Some(DeliveryBook::draw(unix_millis(), rng));
            self.group_capabilities_due = true;
            // This account's other devices take it from the group list.
            self.schedule_group_entry(&record.group_id).await?;
        }
        let book = record.delivery.clone().expect("drawn above");
        let missing: Vec<String> = book.missing(&members).into_iter().cloned().collect();
        if missing.is_empty() {
            return Ok(());
        }
        let body = GroupDeliveryBody {
            group_id: record.group_id.clone(),
            capability: Some(book.capability.0.clone()),
            drawn_at_ms: book.drawn_at_ms,
        };
        let mut sends = Vec::new();
        for recipient in recipients
            .iter()
            .filter(|recipient| missing.contains(&recipient.account))
        {
            if recipient.bundles.is_empty() {
                continue;
            }
            let send_id = uuid::Uuid::new_v4().to_string();
            let content = ChatContent::group_delivery_with_id(
                send_id.clone(),
                crate::clock::rfc3339(unix_millis()),
                0,
                &body,
            );
            let sealed = self
                .session
                .seal_pairwise(
                    &recipient.account,
                    &recipient.bundles,
                    certificate,
                    &content,
                    rng,
                )
                .await?;
            let envelopes = self.sealed_envelopes(sealed);
            sends.push((
                recipient.account.clone(),
                SealedMessageSubmissionV1 {
                    send_id,
                    capability: STANDARD.encode(recipient.capability),
                    envelopes,
                },
            ));
        }
        let outcomes = self.send_sealed_batches(&sends).await;
        let book = record.delivery.as_mut().expect("drawn above");
        for ((account, _), outcome) in sends.iter().zip(outcomes) {
            // Stored there, or queued for its server: it holds it, or will.
            if matches!(
                outcome,
                Some(SealedBatchOutcomeV1::Delivered { .. } | SealedBatchOutcomeV1::Pending)
            ) && !book.holders.contains(account)
            {
                book.holders.push(account.clone());
            }
        }
        book.holders.sort();
        self.save_group(record).await
    }

    /// A member's `groupDelivery`, from `sender`: its capability kept (the
    /// newest), or, asked for this account's, handed out again with the next
    /// message. Taken only from a verified member of the group.
    pub(crate) async fn take_group_delivery(
        &mut self,
        sender: &str,
        body: GroupDeliveryBody,
    ) -> Result<()> {
        let Some(mut record) = self.session.db().load_group(&body.group_id).await? else {
            return Ok(());
        };
        let members = self.group_members(&body.group_id).await?;
        let verified = members.iter().any(|member| {
            member
                .verified
                .as_ref()
                .is_some_and(|verified| verified.account.to_string() == sender)
        });
        if !verified || sender == self.session.account_ref().to_string() {
            return Ok(());
        }
        match body.capability.clone() {
            Some(capability) => {
                let newer = record
                    .member_capabilities
                    .get(sender)
                    .is_none_or(|held| held.drawn_at_ms < body.drawn_at_ms);
                if !newer {
                    return Ok(());
                }
                record.member_capabilities.insert(
                    sender.to_string(),
                    HeldCapability {
                        capability: SecretText(capability),
                        drawn_at_ms: body.drawn_at_ms,
                    },
                );
            }
            None => {
                let Some(book) = record.delivery.as_mut() else {
                    return Ok(());
                };
                book.holders.retain(|holder| holder != sender);
            }
        }
        self.save_group(&record).await
    }

    /// The capability this device holds for `account` in the group, if any.
    pub(crate) fn held_capability(record: &GroupRecordV1, account: &str) -> Option<[u8; 16]> {
        record.member_capabilities.get(account)?.bytes()
    }

    /// Sets this account's published group capabilities to every group it
    /// is in, padded: when one was drawn or a group left. Best effort; a
    /// limit the server refuses leaves groups on the pairwise route.
    pub async fn publish_group_capabilities(&mut self) -> Result<()> {
        if !self.group_capabilities_due {
            return Ok(());
        }
        let Some(keys) = self.group_keys.as_ref() else {
            return Ok(());
        };
        let mut hashes = Vec::new();
        let mut epoch = 0i64;
        for record in self.session.db().list_groups().await? {
            if record.status != GroupStatus::Member {
                continue;
            }
            let Some(book) = record.delivery.as_ref() else {
                continue;
            };
            let Some(capability) = book.bytes() else {
                continue;
            };
            epoch = epoch.max(book.drawn_at_ms);
            hashes.push(STANDARD.encode(Sha256::digest(capability)));
        }
        let epoch = u64::try_from(epoch).unwrap_or(0);
        let mut slot = 0u32;
        while hashes.len() < padded_len(hashes.len()) {
            hashes.push(STANDARD.encode(keys.delivery_padding.dummy(epoch, slot)));
            slot += 1;
        }
        hashes.sort();
        match self.transport.set_group_capabilities(&hashes).await? {
            GroupCapabilitiesOutcome::Set { .. } => {
                self.group_capabilities_due = false;
                self.group_capability_limit = false;
            }
            GroupCapabilitiesOutcome::LimitReached => {
                self.group_capabilities_due = false;
                self.group_capability_limit = true;
            }
        }
        Ok(())
    }

    /// Whether the server refused this account's group capabilities as too
    /// many (its groups then stay on the pairwise route).
    pub fn group_capability_limit_reached(&self) -> bool {
        self.group_capability_limit
    }

    /// Asks `account` for its capability in the group (the one this device
    /// held was refused): dropped here, and its next message brings a new one.
    pub(crate) fn forget_member_capability(record: &mut GroupRecordV1, account: &str) {
        record.member_capabilities.remove(account);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_capabilities_pad_to_a_multiple_of_eight() {
        assert_eq!(padded_len(0), 8);
        assert_eq!(padded_len(1), 8);
        assert_eq!(padded_len(8), 8);
        assert_eq!(padded_len(9), 16);
        assert_eq!(padded_len(120), 120);
    }
}
