//! The engine's groups (docs/plans/pairwise-groups.md): creating one on this
//! account's server, catching up through the home's log, and reading members
//! with their bindings checked against verified manifests. Everything goes
//! through the anonymous route ([`crate::group_client`]); the group logic is
//! [`crate::group`]'s.

use std::collections::BTreeMap;
use std::rc::Rc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::group::{
    decode_group_id, GroupActionV1, GroupAttribute, GroupChangeV1, GroupStateV1,
};
use kutup_chat_proto::group_route::{
    GroupHomePinV1, GroupLogEntryV1, GroupLogPageV1, GroupLogQueryV1, GroupOperationV1,
    GroupResponseStatusV1, GroupResponseV1, GroupStateAnswerV1,
};
use kutup_crypto::account_ref::AccountRef;
use libsignal_protocol::PublicKey;

use crate::db::Pending;
use crate::engine::Engine;
use crate::error::{ChatError, Result};
use crate::group::{self, GroupError, GroupMemberView, GroupRecordV1, GroupStatus, NewGroup};
use crate::group_client::{self, ConfigCheck, RequestSigner, RouteFailure};

/// How many changes one log request asks for.
const LOG_PAGE: u16 = 64;

/// What a group's view shows: its id, title and this device's standing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSummary {
    pub group_id: String,
    pub title: Option<String>,
    pub status: GroupStatus,
    pub revision: Option<u64>,
    pub member_count: usize,
}

/// What group content that came pairwise did.
#[derive(Debug, Clone, PartialEq)]
pub enum GroupContentOutcome {
    /// A member's sender key was taken.
    SenderKey,
    /// An invitation: an invited record now waits for this account's choice.
    Invited { group_id: String, from: String },
    /// A group message was kept.
    Message(Box<kutup_chat_proto::ChatContent>),
    /// Not from a member, or not for a group this account is in: dropped.
    Ignored,
}

/// A group just made: its id, and whether its title was set too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedGroup {
    pub group_id: String,
    pub title_set: bool,
}

/// How a catch-up ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupSync {
    /// At the home's latest revision. `key_confirmed` is false when the
    /// home's newest signature names a gateway key this device never held,
    /// even after fetching it again: a rotation it slept through, or a relay
    /// showing it another key. The group goes on; the view says so.
    Current { revision: u64, key_confirmed: bool },
    /// The home couldn't be asked now; the last verified state stands.
    Unreachable(RouteFailure),
    /// The home answers as if this account weren't in the group: it may have
    /// been removed, or the group ended. Not taken as final until it has
    /// lasted [`NOT_FOUND_CONFIRM_MS`] (the home's answer is the same for
    /// strangers, so it proves nothing on its own).
    MaybeRemoved { since_ms: i64 },
    /// This account is no longer in the group: a notarised change removed it,
    /// or the home has answered so for long enough.
    Gone,
}

/// How long the home must keep answering "not found" before a group is
/// taken as gone.
pub const NOT_FOUND_CONFIRM_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// The most log pages one catch-up reads.
const MAX_PAGES_PER_SYNC: usize = 256;

fn group_error(error: GroupError) -> ChatError {
    match error {
        GroupError::Notary => ChatError::Trust("the group home's signature doesn't verify".into()),
        GroupError::Change(change) => ChatError::Trust(format!("group change refused: {change}")),
        other => ChatError::Invalid(other.to_string()),
    }
}

fn decode_b64(value: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(value)
        .map_err(|_| ChatError::Invalid("group answer is not base64".into()))
}

fn now_seconds() -> i64 {
    crate::clock::unix_millis() / 1000
}

/// The answer's body, when the home said yes; its refusal, as an error.
fn accepted_body(response: GroupResponseV1) -> Result<Vec<u8>> {
    match response.status {
        GroupResponseStatusV1::Ok => response.body().map_err(ChatError::Invalid),
        GroupResponseStatusV1::Refused => Err(ChatError::Trust(format!(
            "the group home refused the change: {}",
            response.code.unwrap_or_default()
        ))),
        GroupResponseStatusV1::Conflict => Err(ChatError::Transport(
            "the group changed meanwhile; catch up and try again".into(),
        )),
        GroupResponseStatusV1::NotFound => Err(ChatError::Transport(
            "the group home doesn't know this group or member".into(),
        )),
        status => Err(ChatError::Transport(format!(
            "the group home answered {status:?}"
        ))),
    }
}

impl Engine {
    pub(crate) async fn save_group(&mut self, record: &GroupRecordV1) -> Result<()> {
        let mut pending = Pending::default();
        pending
            .groups
            .insert(record.group_id.clone(), record.clone());
        self.session.db().apply(&pending).await?;
        // The state may have changed: who is a member is checked again.
        self.group_members_seen.remove(&record.group_id);
        Ok(())
    }

    /// The group's verified member accounts (their bindings checked against
    /// their manifests), kept for an hour.
    pub(crate) async fn verified_member_accounts(&mut self, group_id: &str) -> Result<Vec<String>> {
        let now = crate::clock::unix_millis();
        if let Some((at, accounts)) = self.group_members_seen.get(group_id) {
            if now.saturating_sub(*at) < crate::engine::KNOWN_DEVICES_TTL_MS {
                return Ok(accounts.clone());
            }
        }
        let accounts: Vec<String> = self
            .group_members(group_id)
            .await?
            .into_iter()
            .filter_map(|member| member.verified.map(|verified| verified.account.to_string()))
            .collect();
        self.group_members_seen
            .insert(group_id.to_string(), (now, accounts.clone()));
        Ok(accounts)
    }

    /// Whether `account` is a verified member of a group this account is in.
    async fn is_group_member(&mut self, group_id: &str, account: &str) -> Result<bool> {
        let Some(record) = self.session.db().load_group(group_id).await? else {
            return Ok(false);
        };
        if record.status != GroupStatus::Member {
            return Ok(false);
        }
        Ok(self
            .verified_member_accounts(group_id)
            .await?
            .iter()
            .any(|member| member == account))
    }

    /// A sender-key message: only from a verified member of a group this
    /// account is in, then opened and kept in one commit.
    pub(crate) async fn receive_group_envelope(
        &mut self,
        envelope: &kutup_chat_proto::DeliveredEnvelope,
        inspection: &crate::session::SealedEnvelopeInspection,
        validating_root: &PublicKey,
    ) -> Result<crate::session::ReceiveOutcome> {
        let group_id = inspection
            .group_id
            .map(|id| kutup_chat_proto::group::encode_group_id(&id))
            .ok_or_else(|| ChatError::Trust("not a group message".into()))?;
        if !self.is_group_member(&group_id, &inspection.sender).await? {
            return Err(ChatError::Trust(
                "a group message from someone who isn't a verified member".into(),
            ));
        }
        self.session
            .receive_sealed_group_envelope(envelope, inspection, validating_root)
            .await
    }

    /// Group content that came pairwise. A sender key or a message is taken
    /// only from a verified member; an invitation starts an invited record
    /// that waits for this account's choice.
    pub(crate) async fn handle_group_content<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        id: &str,
        from: &crate::address::ChatAddress,
        cursor: u64,
        content: &kutup_chat_proto::ChatContent,
        rng: &mut R,
    ) -> Result<GroupContentOutcome> {
        let sender = from.name();
        if let Some(control) = content.as_session_control() {
            let Some(group) = control.group.as_ref() else {
                return Ok(GroupContentOutcome::Ignored);
            };
            if !self.is_group_member(&group.group_id, &sender).await? {
                return Ok(GroupContentOutcome::Ignored);
            }
            if control.action == kutup_chat_proto::SessionControlAction::Refresh {
                self.answer_group_refresh(from, &control, rng).await?;
            } else {
                self.session
                    .settle_waiting(&sender, control.action, &control.send_ids)
                    .await?;
            }
            return Ok(GroupContentOutcome::Ignored);
        }
        if let Some(body) = content.as_sender_key_distribution() {
            if !self.is_group_member(&body.group_id, &sender).await? {
                return Ok(GroupContentOutcome::Ignored);
            }
            let message = decode_b64(&body.message)?;
            self.session
                .process_sender_key_distribution(from, &message)
                .await?;
            return Ok(GroupContentOutcome::SenderKey);
        }
        if let Some(invite) = content.as_group_invite() {
            let group_id = invite.group_id.clone();
            if self.session.db().load_group(&group_id).await?.is_some() {
                return Ok(GroupContentOutcome::Ignored);
            }
            let record = group::record_from_invite(invite).map_err(group_error)?;
            self.save_group(&record).await?;
            return Ok(GroupContentOutcome::Invited {
                group_id,
                from: sender,
            });
        }
        let message = match content.as_resend() {
            Some(resend) => *resend.content,
            None => content.clone(),
        };
        if let Some(context) = message.group_context() {
            if !self.is_group_member(&context.group_id, &sender).await? {
                return Ok(GroupContentOutcome::Ignored);
            }
            self.session
                .store_group_message(id, from, cursor, &message)
                .await?;
            return Ok(GroupContentOutcome::Message(Box::new(message)));
        }
        Ok(GroupContentOutcome::Ignored)
    }

    pub(crate) async fn load_group_record(&self, group_id: &str) -> Result<GroupRecordV1> {
        self.session
            .db()
            .load_group(group_id)
            .await?
            .ok_or_else(|| ChatError::Invalid("no such group".into()))
    }

    /// One request to `record`'s home, signed by this account's pseudonym.
    async fn group_request(
        &mut self,
        record: &mut GroupRecordV1,
        operation: GroupOperationV1,
        body: &[u8],
    ) -> Result<std::result::Result<GroupResponseV1, RouteFailure>> {
        let group_id = decode_group_id(&record.group_id).map_err(ChatError::Invalid)?;
        let seed = zeroize::Zeroizing::new(*record.pseudonym().map_err(group_error)?.seed());
        let home = record.home.clone();
        let transport = Rc::clone(&self.transport);
        group_client::call(
            transport.as_ref(),
            &mut record.gateway,
            &home,
            &group_id,
            operation,
            body,
            &RequestSigner::Key(&seed),
            now_seconds(),
        )
        .await
    }

    /// This account's profile key, which its group entries carry.
    async fn own_profile_key(&self) -> Result<[u8; 32]> {
        let profile = self
            .session
            .db()
            .load_local_profile()
            .await?
            .ok_or_else(|| ChatError::Invalid("this account has no profile yet".into()))?;
        profile
            .key
            .as_slice()
            .try_into()
            .map_err(|_| ChatError::Invalid("the profile key is not 32 bytes".into()))
    }

    /// This account's server's identity, pinned by a new group: followed from
    /// the first document the server serves.
    async fn own_home_pin(&mut self) -> Result<(GroupHomePinV1, group_client::GatewayCache)> {
        let server = self.session.server().to_string();
        let answer = Rc::clone(&self.transport)
            .fetch_group_gateway(&server, 0)
            .await?;
        let first = answer
            .identity_history
            .first()
            .ok_or_else(|| ChatError::Trust("this server published no identity".into()))?;
        if first.server != server {
            return Err(ChatError::Trust(
                "this server's identity names another server".into(),
            ));
        }
        let root = GroupHomePinV1::of(first).map_err(ChatError::Trust)?;
        let current = root
            .follow(&answer.identity_history)
            .map_err(|error| ChatError::Trust(format!("this server's identity: {error}")))?;
        let pin = GroupHomePinV1::of(current).map_err(ChatError::Trust)?;
        // The cache keeps the history from the pinned document on.
        let from = answer
            .identity_history
            .iter()
            .position(|document| document.sequence == pin.identity_sequence)
            .unwrap_or(0);
        let mut cache = group_client::GatewayCache::default();
        answer
            .config
            .verify(&answer.identity_history[from..], now_seconds())
            .map_err(|error| ChatError::Trust(format!("this server's gateway key: {error}")))?;
        cache.config = Some(answer.config);
        cache.identity_history = answer.identity_history[from..].to_vec();
        Ok((pin, cache))
    }

    /// A new group on this account's server, with this account as its first
    /// administrator and `title` as its name.
    pub async fn create_group(&mut self, title: &str) -> Result<CreatedGroup> {
        let profile_key = self.own_profile_key().await?;
        let profile_key = &profile_key;
        let (pin, cache) = self.own_home_pin().await?;
        let me = self.session.account_ref().clone();
        let device_id = self.session.device_id();
        let session = &self.session;
        let sign = |bytes: &[u8]| session.sign_with_identity(bytes).map_err(|e| e.to_string());
        let (mut record, genesis) = group::create_group(NewGroup {
            home: pin,
            me: &me,
            device_id,
            profile_key,
            sign_binding: &sign,
        })
        .map_err(group_error)?;
        record.gateway = cache;
        let body = genesis.canonical_bytes().map_err(ChatError::Invalid)?;
        let response = match self
            .group_request(&mut record, GroupOperationV1::Create, &body)
            .await?
        {
            Ok(response) => response,
            Err(failure) => {
                return Err(ChatError::Transport(format!(
                    "this server can't take a new group now: {failure:?}"
                )))
            }
        };
        let answer: GroupStateAnswerV1 = serde_json::from_slice(&accepted_body(response)?)
            .map_err(|e| ChatError::Invalid(e.to_string()))?;
        group::accept_change(&mut record, &genesis, &answer.notary).map_err(group_error)?;
        self.save_group(&record).await?;
        // The group exists from here; a title that can't be set now is
        // reported, not an error, and can be set again.
        let mut title_set = true;
        if !title.trim().is_empty() {
            title_set = match group::seal_attribute(
                &record,
                GroupAttribute::Title,
                title.trim().as_bytes(),
            ) {
                Ok(value) => self
                    .submit_group_change(
                        &mut record,
                        vec![GroupActionV1::ModifyAttribute {
                            attribute: GroupAttribute::Title,
                            value: Some(value),
                        }],
                    )
                    .await
                    .is_ok(),
                Err(_) => false,
            };
        }
        Ok(CreatedGroup {
            group_id: record.group_id,
            title_set,
        })
    }

    /// Makes a change as this member and applies the home's notarised answer.
    async fn submit_group_change(
        &mut self,
        record: &mut GroupRecordV1,
        actions: Vec<GroupActionV1>,
    ) -> Result<GroupStateV1> {
        let change = group::author_change(record, actions).map_err(group_error)?;
        let body = change.canonical_bytes().map_err(ChatError::Invalid)?;
        let response = match self
            .group_request(record, GroupOperationV1::SubmitChange, &body)
            .await?
        {
            Ok(response) => response,
            Err(failure) => {
                return Err(ChatError::Transport(format!(
                    "the group's server can't be reached: {failure:?}"
                )))
            }
        };
        let entry: GroupLogEntryV1 = serde_json::from_slice(&accepted_body(response)?)
            .map_err(|e| ChatError::Invalid(e.to_string()))?;
        let returned = GroupChangeV1::from_canonical_bytes(&decode_b64(&entry.change)?)
            .map_err(ChatError::Invalid)?;
        if returned != change {
            return Err(ChatError::Trust(
                "the group home returned another change".into(),
            ));
        }
        let next = group::accept_change(record, &change, &entry.notary).map_err(group_error)?;
        self.save_group(record).await?;
        Ok(next)
    }

    /// Changes the group's title (who may: Signal's `attributes` access).
    pub async fn set_group_title(&mut self, group_id: &str, title: &str) -> Result<()> {
        let mut record = self.load_group_record(group_id).await?;
        let value = if title.trim().is_empty() {
            None
        } else {
            Some(
                group::seal_attribute(&record, GroupAttribute::Title, title.trim().as_bytes())
                    .map_err(group_error)?,
            )
        };
        self.submit_group_change(
            &mut record,
            vec![GroupActionV1::ModifyAttribute {
                attribute: GroupAttribute::Title,
                value,
            }],
        )
        .await
        .map(|_| ())
    }

    /// Catches up with the home: the log from the next revision on, every
    /// change checked and notarised; a whole state only for a device with
    /// none yet.
    pub async fn sync_group(&mut self, group_id: &str) -> Result<GroupSync> {
        let mut record = self.load_group_record(group_id).await?;
        if record.status == GroupStatus::Gone {
            return Ok(GroupSync::Gone);
        }
        let Some((state, _)) = record.verified().map_err(group_error)? else {
            return self.take_whole_state(&mut record).await;
        };
        let mut from = state.revision + 1;
        let mut newest = None;
        let mut history_refreshed = false;
        for page_number in 0.. {
            if page_number == MAX_PAGES_PER_SYNC {
                // Bounded: the rest is read on the next catch-up.
                break;
            }
            let query = serde_json::to_vec(&GroupLogQueryV1 {
                from_revision: from,
                limit: LOG_PAGE,
            })
            .map_err(|e| ChatError::Invalid(e.to_string()))?;
            let response = match self
                .group_request(&mut record, GroupOperationV1::GetLogs, &query)
                .await?
            {
                Ok(response) => response,
                Err(failure) => return Ok(GroupSync::Unreachable(failure)),
            };
            if response.status == GroupResponseStatusV1::NotFound {
                return self.not_found(&mut record).await;
            }
            let page: GroupLogPageV1 = serde_json::from_slice(&accepted_body(response)?)
                .map_err(|_| ChatError::Invalid("the group home's log page doesn't read".into()))?;
            if page.entries.is_empty() && page.more {
                return Err(ChatError::Trust(
                    "the group home answered an empty page with more to come".into(),
                ));
            }
            for entry in &page.entries {
                let change = GroupChangeV1::from_canonical_bytes(&decode_b64(&entry.change)?)
                    .map_err(ChatError::Invalid)?;
                match group::accept_change(&mut record, &change, &entry.notary) {
                    Ok(_) => {}
                    // A notary by an identity this device doesn't hold yet (the
                    // home rotated it): fetch the history again, once, and retry.
                    Err(GroupError::Notary) if !history_refreshed => {
                        history_refreshed = true;
                        self.refresh_gateway(&mut record).await?;
                        group::accept_change(&mut record, &change, &entry.notary)
                            .map_err(group_error)?;
                    }
                    Err(error) => return Err(group_error(error)),
                }
                from = change.revision + 1;
            }
            if let Some(last) = page.entries.last() {
                newest = Some(last.notary.clone());
            }
            record.not_found_since_ms = None;
            self.save_group(&record).await?;
            if !page.more || record.status == GroupStatus::Gone {
                break;
            }
        }
        // Only the newest notary must name the key this device is served (or
        // one it took before): an older change was notarised under the key of
        // its time.
        let mut key_confirmed = true;
        if let Some(notary) = newest {
            if record.gateway.check(&notary) == ConfigCheck::Unknown {
                self.refresh_gateway(&mut record).await?;
                key_confirmed = record.gateway.check(&notary) != ConfigCheck::Unknown;
                self.save_group(&record).await?;
            }
        }
        if record.status == GroupStatus::Gone {
            return Ok(GroupSync::Gone);
        }
        let revision = record
            .verified()
            .map_err(group_error)?
            .map(|(state, _)| state.revision)
            .unwrap_or_default();
        Ok(GroupSync::Current {
            revision,
            key_confirmed,
        })
    }

    async fn refresh_gateway(&mut self, record: &mut GroupRecordV1) -> Result<()> {
        let pin = record.home.clone();
        let transport = Rc::clone(&self.transport);
        record
            .gateway
            .refresh(transport.as_ref(), &pin, now_seconds())
            .await
    }

    /// The home answered "not found": kept as a possible removal until it
    /// has lasted long enough.
    async fn not_found(&mut self, record: &mut GroupRecordV1) -> Result<GroupSync> {
        let now = crate::clock::unix_millis();
        let since = *record.not_found_since_ms.get_or_insert(now);
        if now - since >= NOT_FOUND_CONFIRM_MS {
            record.status = GroupStatus::Gone;
        }
        self.save_group(record).await?;
        Ok(if record.status == GroupStatus::Gone {
            GroupSync::Gone
        } else {
            GroupSync::MaybeRemoved { since_ms: since }
        })
    }

    async fn take_whole_state(&mut self, record: &mut GroupRecordV1) -> Result<GroupSync> {
        let response = match self
            .group_request(record, GroupOperationV1::GetState, b"")
            .await?
        {
            Ok(response) => response,
            Err(failure) => return Ok(GroupSync::Unreachable(failure)),
        };
        if response.status == GroupResponseStatusV1::NotFound {
            return self.not_found(record).await;
        }
        let answer: GroupStateAnswerV1 = serde_json::from_slice(&accepted_body(response)?)
            .map_err(|_| ChatError::Invalid("the group home's state doesn't read".into()))?;
        let state = GroupStateV1::from_canonical_bytes(&decode_b64(&answer.state)?)
            .map_err(ChatError::Invalid)?;
        let change = GroupChangeV1::from_canonical_bytes(&decode_b64(&answer.change)?)
            .map_err(ChatError::Invalid)?;
        match group::accept_state(record, &state, &change, &answer.notary) {
            Ok(()) => {}
            // An identity this device doesn't hold yet: the history once more.
            Err(GroupError::Notary) => {
                self.refresh_gateway(record).await?;
                group::accept_state(record, &state, &change, &answer.notary)
                    .map_err(group_error)?;
            }
            Err(error) => return Err(group_error(error)),
        }
        record.not_found_since_ms = None;
        self.save_group(record).await?;
        let key_confirmed = record.gateway.check(&answer.notary) != ConfigCheck::Unknown;
        Ok(GroupSync::Current {
            revision: state.revision,
            key_confirmed,
        })
    }

    /// The group's members, each binding checked against its account's
    /// current verified manifest. A member whose device left the manifest
    /// shows unverified until they sign their binding again.
    pub async fn group_members(&mut self, group_id: &str) -> Result<Vec<GroupMemberView>> {
        let record = self.load_group_record(group_id).await?;
        let accounts = group::member_accounts(&record).map_err(group_error)?;
        let mut keys: BTreeMap<AccountRef, Vec<(u32, PublicKey)>> = BTreeMap::new();
        for account in accounts {
            let account_text = account.to_string();
            // A manifest that can't be fetched or verified now leaves that
            // member unverified; the list still shows.
            let Ok(Some(manifest)) = Rc::clone(&self.transport)
                .fetch_manifest(&account_text)
                .await
            else {
                continue;
            };
            let Ok(manifest) = self
                .accept_current_manifest_evidence(&account_text, &manifest)
                .await
            else {
                continue;
            };
            let devices = manifest
                .devices
                .iter()
                .filter_map(|device| {
                    let bytes = STANDARD.decode(&device.identity_key).ok()?;
                    Some((device.device_id, PublicKey::deserialize(&bytes).ok()?))
                })
                .collect();
            keys.insert(account, devices);
        }
        let verify = |account: &AccountRef, device_id: u32, bytes: &[u8], signature: &[u8]| {
            keys.get(account).is_some_and(|devices| {
                devices
                    .iter()
                    .any(|(id, key)| *id == device_id && key.verify_signature(bytes, signature))
            })
        };
        group::members(&record, &verify).map_err(group_error)
    }

    /// Every group this device knows, with its title.
    pub async fn list_groups(&self) -> Result<Vec<GroupSummary>> {
        let records = self.session.db().list_groups().await?;
        Ok(records
            .into_iter()
            .map(|record| {
                let title = group::attribute(&record, GroupAttribute::Title)
                    .ok()
                    .flatten()
                    .and_then(|bytes| String::from_utf8(bytes).ok());
                let verified = record.verified().ok().flatten();
                GroupSummary {
                    group_id: record.group_id.clone(),
                    title,
                    status: record.status.clone(),
                    revision: verified.as_ref().map(|(state, _)| state.revision),
                    member_count: verified.map_or(0, |(state, _)| state.members.len()),
                }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use async_trait::async_trait;
    use ed25519_dalek::{Signer as _, SigningKey};
    use futures_executor::block_on;
    use kutup_chat_proto::group::{check_change, check_genesis, decode_group_id, GroupLimits};
    use kutup_chat_proto::group_route::{GroupGatewayKeyConfigV1, GroupNotaryV1, GroupRequestV1};
    use kutup_chat_proto::{
        MailboxPage, RegisterChatDeviceRequest, SendMessagesRequest, UserPreKeyBundlesResponse,
    };
    use kutup_crypto::oblivious::GatewayKey;
    use kutup_federation_proto::FederationIdentityDocumentV1;
    use rand::rngs::OsRng;
    use rand::TryRngCore as _;

    use super::*;
    use crate::transport::{ChatTransport, GroupGatewayAnswer, GroupRelayOutcome, SendOutcome};
    use crate::SqliteChatDb;

    /// The home and this account's server in one: a gateway that opens what
    /// it gets, a log it pages, and notaries made under the config of their
    /// time.
    struct Home {
        identity: FederationIdentityDocumentV1,
        key: SigningKey,
        gateway: RefCell<GatewayKey>,
        config: RefCell<GroupGatewayKeyConfigV1>,
        /// What the gateway-key fetch serves (a home may serve one client
        /// another config).
        served: RefCell<Option<GroupGatewayKeyConfigV1>>,
        log: RefCell<Vec<(GroupChangeV1, GroupNotaryV1)>>,
        state: RefCell<Option<(GroupStateV1, [u8; 32])>>,
        empty_pages: Cell<bool>,
        not_found: Cell<bool>,
    }

    fn now() -> i64 {
        crate::clock::unix_millis() / 1000
    }

    impl Home {
        fn new() -> Self {
            let key = SigningKey::from_bytes(&[1u8; 32]);
            let identity = FederationIdentityDocumentV1::genesis("example.test", 10, &key).unwrap();
            let gateway = GatewayKey::generate(1).unwrap();
            let config = Self::sign_config(&identity, &key, &gateway, now() - 100);
            Self {
                identity,
                key,
                gateway: RefCell::new(gateway),
                config: RefCell::new(config),
                served: RefCell::new(None),
                log: RefCell::new(Vec::new()),
                state: RefCell::new(None),
                empty_pages: Cell::new(false),
                not_found: Cell::new(false),
            }
        }

        fn sign_config(
            identity: &FederationIdentityDocumentV1,
            key: &SigningKey,
            gateway: &GatewayKey,
            issued_at: i64,
        ) -> GroupGatewayKeyConfigV1 {
            GroupGatewayKeyConfigV1::sign(
                identity,
                key,
                gateway.key_id(),
                &gateway.public_key(),
                issued_at,
                issued_at + 7 * 24 * 60 * 60,
            )
            .unwrap()
        }

        fn rotate(&self, key_id: u8) {
            let gateway = GatewayKey::generate(key_id).unwrap();
            *self.config.borrow_mut() =
                Self::sign_config(&self.identity, &self.key, &gateway, now() - 50);
            *self.gateway.borrow_mut() = gateway;
        }

        fn accept(&self, change: &GroupChangeV1) -> GroupNotaryV1 {
            let next = match &*self.state.borrow() {
                None => check_genesis(
                    change,
                    &GroupHomePinV1::of(&self.identity).unwrap(),
                    &GroupLimits::MAX,
                )
                .unwrap(),
                Some((state, head)) => {
                    check_change(state, head, change, &GroupLimits::MAX).unwrap()
                }
            };
            let hash = change.hash().unwrap();
            let notary = GroupNotaryV1::sign(
                &self.identity,
                &self.key,
                &self.config.borrow(),
                &decode_group_id(&change.group_id).unwrap(),
                change.revision,
                &hash,
                &next.hash().unwrap(),
            )
            .unwrap();
            self.log.borrow_mut().push((change.clone(), notary.clone()));
            *self.state.borrow_mut() = Some((next, hash));
            notary
        }
    }

    #[async_trait(?Send)]
    impl ChatTransport for Home {
        async fn register_device(&self, _: &RegisterChatDeviceRequest) -> Result<u32> {
            Ok(1)
        }
        async fn fetch_bundles(&self, _: &str) -> Result<UserPreKeyBundlesResponse> {
            unreachable!()
        }
        async fn send(&self, _: &str, _: &SendMessagesRequest) -> Result<SendOutcome> {
            unreachable!()
        }
        async fn drain(&self, _: u32, _: Option<u64>, _: u32) -> Result<MailboxPage> {
            unreachable!()
        }
        async fn ack(&self, _: u32, _: &[String]) -> Result<()> {
            unreachable!()
        }

        async fn fetch_group_gateway(&self, _: &str, _: u64) -> Result<GroupGatewayAnswer> {
            Ok(GroupGatewayAnswer {
                config: self
                    .served
                    .borrow()
                    .clone()
                    .unwrap_or_else(|| self.config.borrow().clone()),
                identity_history: vec![self.identity.clone()],
            })
        }

        async fn relay_group_request(&self, _: &str, sealed: &[u8]) -> Result<GroupRelayOutcome> {
            let Ok((body, context)) = self.gateway.borrow().open_request(sealed) else {
                return Ok(GroupRelayOutcome::Unopenable);
            };
            let request = GroupRequestV1::from_canonical_bytes(&body).unwrap();
            let response = if self.not_found.get() {
                GroupResponseV1::new(GroupResponseStatusV1::NotFound, now(), b"")
            } else {
                assert_eq!(request.operation, GroupOperationV1::GetLogs);
                let query: GroupLogQueryV1 =
                    serde_json::from_slice(&request.body().unwrap()).unwrap();
                let entries = if self.empty_pages.get() {
                    Vec::new()
                } else {
                    self.log
                        .borrow()
                        .iter()
                        .filter(|(change, _)| change.revision >= query.from_revision)
                        .map(|(change, notary)| GroupLogEntryV1 {
                            change: STANDARD.encode(change.canonical_bytes().unwrap()),
                            notary: notary.clone(),
                        })
                        .collect()
                };
                let page = GroupLogPageV1 {
                    entries,
                    more: self.empty_pages.get(),
                };
                GroupResponseV1::new(
                    GroupResponseStatusV1::Ok,
                    now(),
                    &serde_json::to_vec(&page).unwrap(),
                )
            };
            Ok(GroupRelayOutcome::Answered(
                context
                    .seal_response(&response.canonical_bytes().unwrap())
                    .unwrap(),
            ))
        }
    }

    /// An engine, and a group it holds at revision 0 under the home's first
    /// key (its cache holding that key), with a title change at revision 1
    /// the home notarised under the same key.
    fn setup() -> (Engine, Rc<Home>, String) {
        let home = Rc::new(Home::new());
        let db = Rc::new(SqliteChatDb::open_in_memory().unwrap());
        let engine = block_on(Engine::register(
            db,
            home.clone(),
            "aci:00000000-0000-4000-8000-2bd806c97f0e@example.test",
            10,
            &mut OsRng.unwrap_err(),
        ))
        .unwrap();
        let account = engine.session.account_ref().clone();
        let device = SigningKey::from_bytes(&[3u8; 32]);
        let sign = |bytes: &[u8]| Ok(device.sign(bytes).to_bytes().to_vec());
        let (mut record, genesis) = group::create_group(NewGroup {
            home: GroupHomePinV1::of(&home.identity).unwrap(),
            me: &account,
            device_id: 1,
            profile_key: &[4u8; 32],
            sign_binding: &sign,
        })
        .unwrap();
        record.gateway.identity_history = vec![home.identity.clone()];
        record.gateway.config = Some(home.config.borrow().clone());
        let notary = home.accept(&genesis);
        group::accept_change(&mut record, &genesis, &notary).unwrap();
        let title = group::seal_attribute(&record, GroupAttribute::Title, b"T").unwrap();
        let change = group::author_change(
            &record,
            vec![GroupActionV1::ModifyAttribute {
                attribute: GroupAttribute::Title,
                value: Some(title),
            }],
        )
        .unwrap();
        home.accept(&change);
        block_on(engine.save_group(&record)).unwrap();
        (engine, home, record.group_id)
    }

    #[test]
    fn a_quiet_group_catches_up_across_a_key_rotation() {
        let (mut engine, home, group_id) = setup();
        // The change was notarised under key 1; the home has since moved to 2.
        home.rotate(2);
        let sync = block_on(engine.sync_group(&group_id)).unwrap();
        assert_eq!(
            sync,
            GroupSync::Current {
                revision: 1,
                key_confirmed: true
            }
        );
    }

    #[test]
    fn a_newest_signature_naming_a_key_never_held_is_flagged_not_fatal() {
        let (mut engine, home, group_id) = setup();
        // This client is served a config of its own (validly signed), while the
        // home's signatures name the one others get.
        let other = GatewayKey::generate(9).unwrap();
        *home.served.borrow_mut() = Some(Home::sign_config(
            &home.identity,
            &home.key,
            &other,
            now() - 10,
        ));
        // Its cache forgets the key it had, so it has never held the named one.
        let mut record = block_on(engine.load_group_record(&group_id)).unwrap();
        record.gateway.config = None;
        record.gateway.accepted.clear();
        block_on(engine.save_group(&record)).unwrap();
        *home.gateway.borrow_mut() = other;
        let sync = block_on(engine.sync_group(&group_id)).unwrap();
        assert_eq!(
            sync,
            GroupSync::Current {
                revision: 1,
                key_confirmed: false
            }
        );
    }

    #[test]
    fn an_empty_page_with_more_to_come_is_an_error() {
        let (mut engine, home, group_id) = setup();
        home.empty_pages.set(true);
        assert!(matches!(
            block_on(engine.sync_group(&group_id)),
            Err(ChatError::Trust(_))
        ));
    }

    #[test]
    fn not_found_is_a_possible_removal_until_it_lasts() {
        let (mut engine, home, group_id) = setup();
        home.not_found.set(true);
        let first = block_on(engine.sync_group(&group_id)).unwrap();
        assert!(matches!(first, GroupSync::MaybeRemoved { .. }));
        // Still answering so after the confirmation period: gone.
        let mut record = block_on(engine.load_group_record(&group_id)).unwrap();
        record.not_found_since_ms = Some(crate::clock::unix_millis() - NOT_FOUND_CONFIRM_MS - 1);
        block_on(engine.save_group(&record)).unwrap();
        assert_eq!(
            block_on(engine.sync_group(&group_id)).unwrap(),
            GroupSync::Gone
        );
        // And an answer that isn't "not found" resets the clock.
        let (mut engine, home, group_id) = setup();
        home.not_found.set(true);
        block_on(engine.sync_group(&group_id)).unwrap();
        home.not_found.set(false);
        block_on(engine.sync_group(&group_id)).unwrap();
        let record = block_on(engine.load_group_record(&group_id)).unwrap();
        assert_eq!(record.not_found_since_ms, None);
    }
}
