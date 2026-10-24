//! Group send endorsements, this device's side
//! (docs/plans/group-send-endorsements.md).
//!
//! The account's own server endorses it once a day (§3.2); this device checks
//! the endorsement and shares it, sealed, with the home of each group the
//! account is in (§3.3). It reads the other members' blobs from each home,
//! checks every one against the member's server key, and keeps the
//! endorsements (§3.4). A message to the members of one server goes on the
//! multi-recipient route with one token combined from their endorsements
//! ([`Engine::group_send_token`]); a member without a usable one gets
//! pairwise copies.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::group_route::GroupOperationV1;
use kutup_chat_proto::group_send::{
    GroupEndorsementPageV1, GroupEndorsementQueryV1, GroupEndorsementUploadV1, GroupSendParamsV1,
};
use kutup_crypto::chat_group::SealedField;
use kutup_group_send::{Endorsement, EndorsementBlob, EndorsementKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::Pending;
use crate::engine::Engine;
use crate::error::{ChatError, Result};
use crate::group::{GroupRecordV1, GroupStatus};
use crate::group_engine::{accepted_body, group_error};

/// A member's endorsement is used only while it has at least this long left,
/// so a send never races its expiry at the destination.
const USABLE_MARGIN_SECS: u64 = 10 * 60;

/// How long a server's endorsement keys are kept before they are asked again
/// (a key that rotated meanwhile fails a check, and the copies go pairwise).
const KEYS_KEPT_MS: i64 = 60 * 60 * 1000;

/// After a failed fetch of this account's endorsement, or a failed upload to
/// a group, it is tried again at most this often.
const RETRY_MS: i64 = 10 * 60 * 1000;

/// A group's endorsements are read again at most this often, unless a
/// member lacks a usable one.
const READ_EVERY_MS: i64 = 30 * 60 * 1000;

/// …and, when one does, at most this often.
const READ_AGAIN_MS: i64 = 60 * 1000;

/// What one read asks of the home; the home may answer fewer.
const PAGE_LIMIT: u16 = 100;

/// How many pages one read takes at most (the rest wait for the next).
const PAGES_PER_READ: usize = 20;

/// Each member keeps at most this many endorsements (the current one and
/// the next).
const KEPT_PER_MEMBER: usize = 2;

/// This account's endorsement as its server issued it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OwnEndorsement {
    pub key_id: u32,
    pub expiration: u64,
    /// The serialized response, with its proof, canonical base64: what the
    /// blob carries.
    pub response: String,
}

/// What a group's record keeps of its endorsements.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupEndorsements {
    /// This account's endorsement as last uploaded to the group: its
    /// expiration, under the join epoch it was uploaded as (a rejoin is a
    /// new pseudonym, which uploads again).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uploaded: Option<Uploaded>,
    /// The home's upload order this device has read up to.
    #[serde(default)]
    pub after: u64,
    /// Each member account's checked endorsements, oldest first.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub members: BTreeMap<String, Vec<HeldEndorsement>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Uploaded {
    pub join_epoch: u32,
    pub expiration: u64,
}

/// One checked endorsement of a member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HeldEndorsement {
    pub expiration: u64,
    /// `kutup_group_send::Endorsement::to_bytes`, canonical base64.
    pub endorsement: String,
}

impl GroupEndorsements {
    pub fn is_empty(&self) -> bool {
        self.uploaded.is_none() && self.after == 0 && self.members.is_empty()
    }

    /// `account`'s newest endorsement usable at `now`.
    pub(crate) fn usable(&self, account: &str, now: u64) -> Option<Endorsement> {
        self.members
            .get(account)?
            .iter()
            .rev()
            .filter(|held| held.expiration > now.saturating_add(USABLE_MARGIN_SECS))
            .find_map(|held| {
                let bytes = STANDARD.decode(&held.endorsement).ok()?;
                Endorsement::from_bytes(&bytes).ok()
            })
    }

    /// Keeps `endorsement` for `account`: one per expiration, the newest
    /// [`KEPT_PER_MEMBER`].
    fn keep(&mut self, account: &str, endorsement: &Endorsement) {
        let held = self.members.entry(account.to_string()).or_default();
        held.retain(|kept| kept.expiration != endorsement.expiration);
        held.push(HeldEndorsement {
            expiration: endorsement.expiration,
            endorsement: STANDARD.encode(endorsement.to_bytes()),
        });
        held.sort_by_key(|kept| kept.expiration);
        let extra = held.len().saturating_sub(KEPT_PER_MEMBER);
        held.drain(..extra);
    }

    /// Drops what expired and the accounts that aren't members now.
    fn prune(&mut self, members: &[String], now: u64) {
        self.members.retain(|account, held| {
            held.retain(|kept| kept.expiration > now);
            !held.is_empty() && members.contains(account)
        });
    }

    /// Drops `account`'s endorsement of `expiration` (its token was refused).
    pub(crate) fn forget(&mut self, account: &str, expiration: u64) {
        if let Some(held) = self.members.get_mut(account) {
            held.retain(|kept| kept.expiration != expiration);
            if held.is_empty() {
                self.members.remove(account);
            }
        }
    }
}

/// The in-memory side: server keys and when things were last tried.
#[derive(Default)]
pub(crate) struct EndorsementCache {
    /// Each server's keys (`None`: it publishes none), and when they were
    /// fetched.
    keys: BTreeMap<String, (i64, Option<GroupSendParamsV1>)>,
    /// When this account's endorsement may be fetched again after a failure.
    own_retry_at_ms: i64,
    /// Per group: when an upload may be tried again after a failure.
    upload_retry_at_ms: BTreeMap<String, i64>,
    /// Per group: when its endorsements were last read.
    read_at_ms: BTreeMap<String, i64>,
}

fn now_seconds(now_ms: i64) -> u64 {
    u64::try_from(now_ms / 1000).unwrap_or(0)
}

fn account_uuid(account: &str) -> Result<Uuid> {
    let parsed = crate::address::parse_account(account)?;
    Uuid::parse_str(&parsed.account_id)
        .map_err(|_| ChatError::Invalid("an account id is not a UUID".into()))
}

fn zk_error(error: kutup_group_send::Error) -> ChatError {
    ChatError::Trust(format!("group send endorsement: {error}"))
}

impl Engine {
    /// The endorsement keys of `server` (this account's own for its own
    /// server), as fetched within the last hour.
    async fn group_send_keys(&mut self, server: &str) -> Result<Option<GroupSendParamsV1>> {
        let now = self.now_ms();
        if let Some((at, keys)) = self.endorsement_cache.keys.get(server) {
            if now.saturating_sub(*at) < KEYS_KEPT_MS {
                return Ok(keys.clone());
            }
        }
        let own = server == self.session.server();
        let keys = self
            .transport
            .fetch_group_send_params(if own { None } else { Some(server) })
            .await?;
        if let Some(keys) = &keys {
            keys.validate().map_err(ChatError::Invalid)?;
        }
        self.endorsement_cache
            .keys
            .insert(server.to_string(), (now, keys.clone()));
        Ok(keys)
    }

    /// `server`'s key `key_id`, if it publishes it.
    async fn group_send_key(&mut self, server: &str, key_id: u32) -> Result<EndorsementKey> {
        let keys = self
            .group_send_keys(server)
            .await?
            .ok_or_else(|| ChatError::Trust(format!("{server} publishes no endorsement keys")))?;
        let key = keys
            .key(key_id)
            .ok_or_else(|| ChatError::Trust(format!("{server} has no endorsement key {key_id}")))?;
        EndorsementKey::from_bytes(&key.public_key_bytes().map_err(ChatError::Invalid)?)
            .map_err(zk_error)
    }

    /// Forgets `server`'s keys (a token under them was refused), so the next
    /// check asks again.
    pub(crate) fn forget_group_send_keys(&mut self, server: &str) {
        self.endorsement_cache.keys.remove(server);
    }

    async fn stored_own_endorsement(&self) -> Result<Option<OwnEndorsement>> {
        match self.session.db().load_group_send_endorsement().await? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
            None => Ok(None),
        }
    }

    /// This account's endorsement: the stored one while it has more than
    /// [`kutup_group_send::REFRESH_BEFORE_SECS`] left, otherwise a new one
    /// from its server, checked before it is kept. `None` while there is no
    /// usable one (the server doesn't issue them, or can't be reached).
    pub(crate) async fn own_group_send_endorsement(&mut self) -> Result<Option<OwnEndorsement>> {
        let now_ms = self.now_ms();
        let now = now_seconds(now_ms);
        let stored = self
            .stored_own_endorsement()
            .await?
            .filter(|own| own.expiration > now.saturating_add(USABLE_MARGIN_SECS));
        let fresh = stored.as_ref().is_some_and(|own| {
            own.expiration.saturating_sub(now) >= kutup_group_send::REFRESH_BEFORE_SECS
        });
        if fresh || now_ms < self.endorsement_cache.own_retry_at_ms {
            return Ok(stored);
        }
        match self.fetch_own_group_send_endorsement(now).await {
            Ok(own) => {
                let pending = Pending {
                    group_send_endorsement: Some(serde_json::to_vec(&own).map_err(|error| {
                        ChatError::Db(format!("encode group send endorsement: {error}"))
                    })?),
                    ..Pending::default()
                };
                self.session.db().apply(&pending).await?;
                Ok(Some(own))
            }
            Err(_) => {
                self.endorsement_cache.own_retry_at_ms = now_ms.saturating_add(RETRY_MS);
                Ok(stored)
            }
        }
    }

    /// Asks this account's server for today's endorsement and checks it
    /// against the server's published key.
    async fn fetch_own_group_send_endorsement(&mut self, now: u64) -> Result<OwnEndorsement> {
        let issued = self.transport.fetch_group_send_endorsement().await?;
        issued.validate().map_err(ChatError::Invalid)?;
        let server = self.session.server().to_string();
        let key = self.group_send_key(&server, issued.key_id).await?;
        let account = account_uuid(&self.session.account_ref().to_string())?;
        let response = issued.response_bytes().map_err(ChatError::Invalid)?;
        let endorsement =
            kutup_group_send::receive(&response, account, now, &key).map_err(zk_error)?;
        if endorsement.expiration != issued.expiration {
            return Err(ChatError::Trust(
                "the endorsement's expiration isn't the one its server named".into(),
            ));
        }
        Ok(OwnEndorsement {
            key_id: issued.key_id,
            expiration: issued.expiration,
            response: issued.response,
        })
    }

    /// Shares this account's endorsement with `record`'s home when the home
    /// doesn't hold the current one from this pseudonym (§3.3). Best effort:
    /// true when the record changed (save it).
    pub(crate) async fn share_group_send_endorsement(
        &mut self,
        record: &mut GroupRecordV1,
    ) -> Result<bool> {
        if record.status != GroupStatus::Member || record.state.is_none() {
            return Ok(false);
        }
        let Some(own) = self.own_group_send_endorsement().await? else {
            return Ok(false);
        };
        let current = Uploaded {
            join_epoch: record.join_epoch,
            expiration: own.expiration,
        };
        if record.endorsements.uploaded == Some(current) {
            return Ok(false);
        }
        let now_ms = self.now_ms();
        if self
            .endorsement_cache
            .upload_retry_at_ms
            .get(&record.group_id)
            .is_some_and(|at| now_ms < *at)
        {
            return Ok(false);
        }
        let blob = EndorsementBlob {
            server: self.session.server().to_string(),
            key_id: own.key_id,
            response: STANDARD
                .decode(&own.response)
                .map_err(|_| ChatError::Invalid("stored endorsement is not base64".into()))?,
        }
        .encode()
        .map_err(zk_error)?;
        let pseudonym = record.pseudonym().map_err(group_error)?.public_key();
        let sealed = record
            .master()
            .map_err(group_error)?
            .state_key()
            .seal(SealedField::Endorsement, &pseudonym, &blob)
            .map_err(|error| ChatError::Invalid(format!("seal endorsement: {error}")))?;
        let body = GroupEndorsementUploadV1 {
            expiration: own.expiration,
            sealed: STANDARD.encode(&sealed),
        }
        .canonical_bytes()
        .map_err(ChatError::Invalid)?;
        let accepted = match self
            .group_request(record, GroupOperationV1::PutEndorsement, &body)
            .await
        {
            Ok(Ok(response)) => accepted_body(response).is_ok(),
            _ => false,
        };
        if accepted {
            record.endorsements.uploaded = Some(current);
            self.endorsement_cache
                .upload_retry_at_ms
                .remove(&record.group_id);
        } else {
            self.endorsement_cache
                .upload_retry_at_ms
                .insert(record.group_id.clone(), now_ms.saturating_add(RETRY_MS));
        }
        // The gateway cache may have moved either way.
        Ok(true)
    }

    /// Reads the members' blobs uploaded since this device's cursor and keeps
    /// what checks out (§3.4): a blob that doesn't open, names another
    /// server, or holds a response that isn't for that member from that
    /// server's key is dropped. `eager` when a member lacks a usable
    /// endorsement (read at most once a minute; otherwise every half hour).
    /// Best effort: true when the record changed (save it).
    pub(crate) async fn read_group_send_endorsements(
        &mut self,
        record: &mut GroupRecordV1,
        eager: bool,
    ) -> Result<bool> {
        if record.status != GroupStatus::Member || record.state.is_none() {
            return Ok(false);
        }
        let now_ms = self.now_ms();
        let every = if eager { READ_AGAIN_MS } else { READ_EVERY_MS };
        if self
            .endorsement_cache
            .read_at_ms
            .get(&record.group_id)
            .is_some_and(|at| now_ms.saturating_sub(*at) < every)
        {
            return Ok(false);
        }
        self.endorsement_cache
            .read_at_ms
            .insert(record.group_id.clone(), now_ms);
        let now = now_seconds(now_ms);
        // The verified members, by pseudonym.
        let members = self.group_members(&record.group_id).await?;
        let by_pseudonym: BTreeMap<Vec<u8>, String> = members
            .iter()
            .filter_map(|member| {
                let account = member.verified.as_ref()?.account.to_string();
                Some((STANDARD.decode(&member.pseudonym).ok()?, account))
            })
            .collect();
        let me = self.session.account_ref().to_string();
        let state_key = record.master().map_err(group_error)?.state_key();
        let before = record.endorsements.clone();
        for _ in 0..PAGES_PER_READ {
            let query = GroupEndorsementQueryV1 {
                after: record.endorsements.after,
                limit: PAGE_LIMIT,
            }
            .canonical_bytes()
            .map_err(ChatError::Invalid)?;
            let page = match self
                .group_request(record, GroupOperationV1::GetEndorsements, &query)
                .await?
            {
                Ok(response) => match accepted_body(response) {
                    Ok(body) => GroupEndorsementPageV1::from_canonical_bytes(&body)
                        .map_err(ChatError::Invalid)?,
                    Err(_) => break,
                },
                Err(_) => break,
            };
            for item in &page.endorsements {
                let Ok(pseudonym) = STANDARD.decode(&item.pseudonym) else {
                    continue;
                };
                let Some(account) = by_pseudonym.get(&pseudonym) else {
                    continue;
                };
                if account == &me {
                    continue;
                }
                if let Ok(endorsement) = self
                    .check_member_blob(&state_key, &pseudonym, account, item.expiration, &item.sealed, now)
                    .await
                {
                    record.endorsements.keep(account, &endorsement);
                }
            }
            record.endorsements.after = record.endorsements.after.max(page.next_after);
            if !page.more {
                break;
            }
        }
        let accounts: Vec<String> = by_pseudonym.into_values().collect();
        record.endorsements.prune(&accounts, now);
        Ok(record.endorsements != before)
    }

    /// One member's blob, opened and checked: its endorsement.
    async fn check_member_blob(
        &mut self,
        state_key: &kutup_crypto::chat_group::GroupStateKey,
        pseudonym: &[u8],
        account: &str,
        expiration: u64,
        sealed: &str,
        now: u64,
    ) -> Result<Endorsement> {
        kutup_group_send::check_expiration(expiration, now).map_err(zk_error)?;
        let sealed = STANDARD
            .decode(sealed)
            .map_err(|_| ChatError::Invalid("endorsement blob is not base64".into()))?;
        let blob = state_key
            .open(SealedField::Endorsement, pseudonym, &sealed)
            .map_err(|_| ChatError::Trust("an endorsement blob doesn't open".into()))?;
        let blob = EndorsementBlob::decode(&blob).map_err(zk_error)?;
        let parsed = crate::address::parse_account(account)?;
        if blob.server != parsed.server {
            return Err(ChatError::Trust(
                "an endorsement blob names another server than its member's".into(),
            ));
        }
        let key = self.group_send_key(&blob.server, blob.key_id).await?;
        let endorsement = kutup_group_send::receive(&blob.response, account_uuid(account)?, now, &key)
            .map_err(zk_error)?;
        if endorsement.expiration != expiration {
            return Err(ChatError::Trust(
                "an endorsement blob's expiration isn't its response's".into(),
            ));
        }
        Ok(endorsement)
    }

    /// Keeps `group_id`'s endorsements current: this account's shared, the
    /// members' read (`eager` when one lacks a usable endorsement). Best
    /// effort; saves the record when it changed.
    pub(crate) async fn refresh_group_send_endorsements(
        &mut self,
        group_id: &str,
        eager: bool,
    ) -> Result<()> {
        let mut record = self.load_group_record(group_id).await?;
        let shared = self.share_group_send_endorsement(&mut record).await?;
        let read = self.read_group_send_endorsements(&mut record, eager).await?;
        if shared || read {
            self.save_group(&record).await?;
        }
        Ok(())
    }

    /// Every group's endorsements kept current (the periodic look). Best
    /// effort, group by group.
    pub(crate) async fn refresh_all_group_send_endorsements(&mut self) -> Result<()> {
        let groups = self.session.db().list_groups().await?;
        for group in groups {
            if group.status == GroupStatus::Member {
                let _ = self
                    .refresh_group_send_endorsements(&group.group_id, false)
                    .await;
            }
        }
        Ok(())
    }
}

/// The token for one multi-recipient request: `endorsements`, all of one
/// server and expiration, combined; canonical base64.
pub(crate) fn group_send_token(endorsements: &[Endorsement]) -> Result<String> {
    kutup_group_send::token(endorsements)
        .map(|token| STANDARD.encode(token))
        .map_err(zk_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(expiration: u64) -> Endorsement {
        let server = kutup_group_send::ServerKey::generate();
        let account = Uuid::from_u128(7);
        let now = expiration - 30 * 60 * 60;
        let issued = server.issue(account, now);
        assert_eq!(issued.expiration, expiration);
        kutup_group_send::receive(&issued.response, account, now, &server.public_key()).unwrap()
    }

    const DAY: u64 = 86_400;
    const MIDNIGHT: u64 = 20_000 * DAY;

    #[test]
    fn a_member_keeps_its_two_newest_and_the_usable_one_is_the_newest() {
        let mut endorsements = GroupEndorsements::default();
        let account = "aci:00000000-0000-4000-8000-000000000007@kutup.dev";
        let first = held(MIDNIGHT);
        let second = held(MIDNIGHT + DAY);
        let third = held(MIDNIGHT + 2 * DAY);
        endorsements.keep(account, &first);
        endorsements.keep(account, &second);
        endorsements.keep(account, &second);
        assert_eq!(endorsements.members[account].len(), 2);
        endorsements.keep(account, &third);
        let kept: Vec<u64> = endorsements.members[account]
            .iter()
            .map(|held| held.expiration)
            .collect();
        assert_eq!(kept, vec![MIDNIGHT + DAY, MIDNIGHT + 2 * DAY]);
        let now = MIDNIGHT + DAY / 2;
        assert_eq!(endorsements.usable(account, now), Some(third.clone()));
        // Within the margin of its expiry, one isn't used.
        endorsements.forget(account, third.expiration);
        assert_eq!(
            endorsements.usable(account, MIDNIGHT + DAY - 60),
            None
        );
        assert_eq!(endorsements.usable(account, now), Some(second));
    }

    #[test]
    fn pruning_drops_the_expired_and_those_no_longer_members() {
        let mut endorsements = GroupEndorsements::default();
        let ada = "aci:00000000-0000-4000-8000-000000000001@kutup.dev";
        let ben = "aci:00000000-0000-4000-8000-000000000002@kutup.dev";
        endorsements.keep(ada, &held(MIDNIGHT));
        endorsements.keep(ben, &held(MIDNIGHT + DAY));
        endorsements.prune(&[ada.to_string(), ben.to_string()], MIDNIGHT);
        assert!(!endorsements.members.contains_key(ada), "expired");
        endorsements.prune(&[ada.to_string()], MIDNIGHT);
        assert!(endorsements.members.is_empty(), "no longer a member");
        assert!(endorsements.is_empty());
    }
}
