//! Delivery capabilities for the multi-recipient group route
//! (docs/plans/pairwise-groups.md, "Slice 2").
//!
//! Each account draws a random 16-byte capability per group, publishes its
//! hash to its own server (with every other group's, padded with dummies to a
//! multiple of 8 so the count doesn't tell how many groups it is in), and
//! hands it to the other members pairwise in a hidden `groupDelivery`. A
//! member sends group messages to the account on the multi-recipient route
//! with it; one who doesn't hold it sends pairwise. This account's other
//! devices learn it from the account's group list.
//!
//! A capability is retired as soon as an account that may hold it is no
//! longer a member (`group::settle_delivery`, run as each change is
//! accepted, on every device of the account), and the next send draws
//! another. What the server keeps changes only by deltas (`PUT { add, remove
//! }`), kept in a durable ledger until the server takes them: a device that
//! is behind never sets the whole set back to what it last saw. Only the
//! device that drew a capability adds it; any device retires one. The
//! dummies are one per slot, the same for as long as the account keeps
//! them, so two published sets differ only where a real capability changed.

use std::collections::{BTreeSet, VecDeque};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use kutup_chat_proto::content::GroupDeliveryBody;
use kutup_chat_proto::{ChatContent, SealedBatchOutcomeV1, SealedMessageSubmissionV1};

use crate::clock::unix_millis;
use crate::db::Pending;
use crate::engine::Engine;
use crate::error::{ChatError, Result};
use crate::group::{DeliveryBook, GroupRecordV1, GroupStatus, HeldCapability, SecretText};
use crate::group_send::Recipient;
use crate::transport::GroupCapabilitiesOutcome;

/// Published capability hashes are padded to a multiple of this.
pub(crate) const CAPABILITY_BUCKET: usize = 8;

/// How many retired capabilities a device remembers, so a stale copy of a
/// record can't bring one back.
const RETIRED_KEPT: usize = 256;

/// While the server holds the account at its limit, new capabilities are
/// offered again at most this often (removals go at once).
pub(crate) const LIMIT_RETRY_MS: i64 = 60 * 60 * 1000;

/// `count` hashes rounded up to the next bucket (at least one bucket, so no
/// groups and a few look the same).
pub(crate) fn padded_len(count: usize) -> usize {
    count.max(1).div_ceil(CAPABILITY_BUCKET) * CAPABILITY_BUCKET
}

/// The dummies `count` real capabilities are padded with.
fn dummies_for(count: usize) -> usize {
    padded_len(count) - count
}

/// A capability's published form: its SHA-256, canonical base64.
pub(crate) fn capability_hash(capability: &[u8; 16]) -> String {
    STANDARD.encode(Sha256::digest(capability))
}

/// The hash this account publishes for `record`'s group: its capability
/// while it is a member.
pub(crate) fn published_hash(record: &GroupRecordV1) -> Option<String> {
    if record.status != GroupStatus::Member {
        return None;
    }
    record
        .delivery
        .as_ref()
        .and_then(DeliveryBook::bytes)
        .map(|capability| capability_hash(&capability))
}

/// The account's group capability changes this device owes its server, and
/// the capabilities it retired (`Pending::group_capabilities`).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CapabilityLedger {
    #[serde(default)]
    pub add: BTreeSet<String>,
    #[serde(default)]
    pub remove: BTreeSet<String>,
    /// Retired here, newest last: never kept in a record again.
    #[serde(default)]
    pub retired: VecDeque<String>,
    /// The server refused the adds as more than it takes for one account:
    /// those groups stay on the pairwise route.
    #[serde(default)]
    pub limit: bool,
    /// The count of real capabilities the published dummies pad (`None`
    /// before this device padded any).
    #[serde(default)]
    pub padded_for: Option<usize>,
}

impl CapabilityLedger {
    fn added(&mut self, hash: String) {
        self.remove.remove(&hash);
        self.add.insert(hash);
    }

    fn removed(&mut self, hash: String) {
        self.add.remove(&hash);
        self.remove.insert(hash);
    }

    fn retire(&mut self, hash: String) {
        if !self.retired.contains(&hash) {
            self.retired.push_back(hash.clone());
            while self.retired.len() > RETIRED_KEPT {
                self.retired.pop_front();
            }
        }
        self.removed(hash);
    }

    pub(crate) fn is_retired(&self, hash: &str) -> bool {
        self.retired.iter().any(|retired| retired == hash)
    }

    fn is_empty(&self) -> bool {
        self.add.is_empty() && self.remove.is_empty()
    }

    fn bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|error| ChatError::Db(format!("encode group capabilities: {error}")))
    }
}

/// The dummy in `slot`, as published.
fn dummy_hash(keys: &crate::group::GroupAccountKeys, slot: usize) -> String {
    let slot = u32::try_from(slot).unwrap_or(u32::MAX);
    STANDARD.encode(keys.delivery_padding.dummy(slot))
}

impl Engine {
    /// The ledger as stored (a fresh read: another tab's engine may have
    /// written it).
    pub(crate) async fn capability_ledger(&self) -> Result<CapabilityLedger> {
        match self.session.db().load_group_capabilities().await? {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| ChatError::Db(format!("decode group capabilities: {error}"))),
            None => Ok(CapabilityLedger::default()),
        }
    }

    /// What saving `record` changes in the account's published capabilities,
    /// staged in `pending` with the record (one write): the capability it
    /// replaces or ends is retired, one this device drew is added, and the
    /// padding follows the count. `record`'s capability is dropped when this
    /// device retired it already. True when the ledger changed.
    pub(crate) async fn stage_capability_change(
        &mut self,
        stored: Option<&GroupRecordV1>,
        record: &mut GroupRecordV1,
        pending: &mut Pending,
    ) -> Result<bool> {
        let old = stored.and_then(published_hash);
        let mut ledger = self.capability_ledger().await?;
        if published_hash(record).is_some_and(|hash| ledger.is_retired(&hash)) {
            record.delivery = None;
        }
        let new = published_hash(record);
        if old == new {
            return Ok(false);
        }
        let before = self
            .session
            .db()
            .list_groups()
            .await?
            .iter()
            .filter(|group| published_hash(group).is_some())
            .count();
        let after = before - usize::from(old.is_some()) + usize::from(new.is_some());
        if let Some(old) = old {
            ledger.retire(old);
        }
        if let (Some(new), Some(book)) = (new, record.delivery.as_ref()) {
            if book.drawn_here {
                ledger.added(new);
            }
        }
        if let Some(keys) = self.group_keys.as_ref() {
            // Only the slots whose dummy comes or goes: a dummy sent again
            // would tell the server it is one.
            let from = ledger.padded_for.map_or(0, dummies_for);
            let to = dummies_for(after);
            for slot in to..from {
                ledger.removed(dummy_hash(keys, slot));
            }
            for slot in from..to {
                ledger.added(dummy_hash(keys, slot));
            }
            ledger.padded_for = Some(after);
        }
        pending.group_capabilities = Some(ledger.bytes()?);
        Ok(true)
    }

    /// Sends the server what the ledger owes it, best effort: what it
    /// doesn't take now waits for the next change, send or list read. Over
    /// the account's limit, the removals still go (alone), and new
    /// capabilities are offered again at most hourly.
    pub async fn flush_group_capabilities(&mut self) -> Result<()> {
        let mut ledger = self.capability_ledger().await?;
        if ledger.is_empty() {
            return Ok(());
        }
        let now = self.now_ms();
        if ledger.remove.is_empty() && ledger.limit && now < self.capability_retry_at_ms {
            return Ok(());
        }
        let add: Vec<String> = ledger.add.iter().cloned().collect();
        let remove: Vec<String> = ledger.remove.iter().cloned().collect();
        match self
            .transport
            .change_group_capabilities(&add, &remove)
            .await?
        {
            GroupCapabilitiesOutcome::Changed { .. } => {
                ledger.add.clear();
                ledger.remove.clear();
                ledger.limit = false;
            }
            GroupCapabilitiesOutcome::LimitReached => {
                // A retired capability never waits on room for new ones.
                if !remove.is_empty()
                    && matches!(
                        self.transport
                            .change_group_capabilities(&[], &remove)
                            .await?,
                        GroupCapabilitiesOutcome::Changed { .. }
                    )
                {
                    ledger.remove.clear();
                }
                ledger.limit = true;
                self.capability_retry_at_ms = now.saturating_add(LIMIT_RETRY_MS);
            }
        }
        let pending = Pending {
            group_capabilities: Some(ledger.bytes()?),
            ..Pending::default()
        };
        self.session.db().apply(&pending).await
    }

    /// Gives this account's capability for the group to every member who
    /// doesn't hold it, drawing a new one first when there is none (never
    /// drawn, or retired). Handed out only once the server took it. Best
    /// effort: a member not reached now is tried with the next message, and
    /// sends to this account pairwise meanwhile.
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
        let retired = match published_hash(record) {
            Some(hash) => self.capability_ledger().await?.is_retired(&hash),
            None => false,
        };
        if record.delivery.is_none() || retired {
            let after = record.listed_delivery_ms.unwrap_or(0);
            record.delivery = Some(DeliveryBook::draw(
                unix_millis(),
                after,
                members.clone(),
                rng,
            ));
            // Its add goes to the server here, with the record.
            self.save_group(record).await?;
            // This account's other devices take it from the group list.
            self.schedule_group_entry(&record.group_id).await?;
        } else {
            self.flush_group_capabilities().await?;
        }
        let Some(hash) = published_hash(record) else {
            return Ok(());
        };
        let ledger = self.capability_ledger().await?;
        if ledger.add.contains(&hash) {
            // Not on the server yet (unreachable, or the account is at its
            // limit): members would only be refused.
            return Ok(());
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
            ) {
                book.handed_to(account);
            }
        }
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

    /// Whether the server refused this account's new group capabilities as
    /// too many (those groups then stay on the pairwise route).
    pub async fn group_capability_limit_reached(&self) -> Result<bool> {
        Ok(self.capability_ledger().await?.limit)
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
