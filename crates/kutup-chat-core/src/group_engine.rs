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
use crate::group_client::{self, RequestSigner, RouteFailure};

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

/// How a catch-up ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupSync {
    /// At the home's latest revision.
    Current { revision: u64 },
    /// The home couldn't be asked now; the last verified state stands.
    Unreachable(RouteFailure),
    /// This account is no longer in the group.
    Gone,
}

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
    async fn save_group(&self, record: &GroupRecordV1) -> Result<()> {
        let mut pending = Pending::default();
        pending
            .groups
            .insert(record.group_id.clone(), record.clone());
        self.session.db().apply(&pending).await
    }

    async fn load_group_record(&self, group_id: &str) -> Result<GroupRecordV1> {
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
        let seed = *record.pseudonym().map_err(group_error)?.seed();
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
    pub async fn create_group(&mut self, title: &str, profile_key: &[u8; 32]) -> Result<String> {
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
        if !title.trim().is_empty() {
            let value =
                group::seal_attribute(&record, GroupAttribute::Title, title.trim().as_bytes())
                    .map_err(group_error)?;
            self.submit_group_change(
                &mut record,
                vec![GroupActionV1::ModifyAttribute {
                    attribute: GroupAttribute::Title,
                    value: Some(value),
                }],
            )
            .await?;
        }
        Ok(record.group_id)
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
        loop {
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
                // Removed: the home answers a former member as a stranger.
                record.status = GroupStatus::Gone;
                self.save_group(&record).await?;
                return Ok(GroupSync::Gone);
            }
            let page: GroupLogPageV1 = serde_json::from_slice(&accepted_body(response)?)
                .map_err(|e| ChatError::Invalid(e.to_string()))?;
            for entry in &page.entries {
                let change = GroupChangeV1::from_canonical_bytes(&decode_b64(&entry.change)?)
                    .map_err(ChatError::Invalid)?;
                group::accept_change(&mut record, &change, &entry.notary).map_err(group_error)?;
                from = change.revision + 1;
            }
            // A newest notary that names a config this device doesn't hold:
            // the relay may be hiding a newer one.
            if let Some(last) = page.entries.last() {
                if !record.gateway.named_by(&last.notary) {
                    let pin = record.home.clone();
                    let transport = Rc::clone(&self.transport);
                    record
                        .gateway
                        .refresh(transport.as_ref(), &pin, now_seconds())
                        .await?;
                    if !record.gateway.named_by(&last.notary) {
                        return Err(ChatError::Trust(
                            "the group home's key isn't the one its signatures name".into(),
                        ));
                    }
                }
            }
            self.save_group(&record).await?;
            if !page.more {
                break;
            }
        }
        let revision = record
            .verified()
            .map_err(group_error)?
            .map(|(state, _)| state.revision)
            .unwrap_or_default();
        Ok(if record.status == GroupStatus::Gone {
            GroupSync::Gone
        } else {
            GroupSync::Current { revision }
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
        let answer: GroupStateAnswerV1 = serde_json::from_slice(&accepted_body(response)?)
            .map_err(|e| ChatError::Invalid(e.to_string()))?;
        let state = GroupStateV1::from_canonical_bytes(&decode_b64(&answer.state)?)
            .map_err(ChatError::Invalid)?;
        let change = GroupChangeV1::from_canonical_bytes(&decode_b64(&answer.change)?)
            .map_err(ChatError::Invalid)?;
        group::accept_state(record, &state, &change, &answer.notary).map_err(group_error)?;
        self.save_group(record).await?;
        Ok(GroupSync::Current {
            revision: state.revision,
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
            let Some(manifest) = Rc::clone(&self.transport)
                .fetch_manifest(&account_text)
                .await?
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
