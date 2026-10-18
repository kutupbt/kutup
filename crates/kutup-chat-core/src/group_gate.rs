//! What a group's incoming content may do (docs/plans/pairwise-groups.md §2,
//! §3), decided before anything of it is kept, as Signal reads a group's
//! state before a message that names a newer one (`maybeUpdateGroup`):
//!
//! - A context ahead of this device's verified state, or on another head,
//!   makes it catch up from the home and read the content again.
//! - A sender who is a member at that state is taken; one whose membership
//!   can't be confirmed now (a stranger who may have joined since, a member
//!   whose manifest can't be fetched) is held: the envelope stays queued and
//!   is read again on a later pass, never dropped unconfirmed. A held
//!   envelope is given up after a week.
//! - A stranger whose own context isn't ahead of this state isn't a member
//!   (removed, or never one): dropped.
//! - Catch-ups are bounded per group: a context naming a revision not asked
//!   for yet goes at once, anything else waits a back-off that grows on
//!   failure, so neither a removed member nor an unreachable home makes a
//!   catch-up per message.

use std::collections::BTreeSet;

use kutup_chat_proto::group::GroupContextV1;
use libsignal_protocol::PublicKey;

use crate::engine::Engine;
use crate::error::{ChatError, Result};
use crate::group::{self, ContextCheck, GroupRecordV1, GroupStatus};
use crate::group_engine::{decode_b64, group_error, GroupContentOutcome, GroupSync};
use crate::session::{GroupGate, ReceiveOutcome};

/// How long a group's envelope may wait to be confirmed before it is given
/// up: as long as an unreadable message waits for its resend.
pub(crate) const GROUP_HOLD_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// The first wait between catch-ups of one group that bring nothing new; it
/// doubles on each failure, up to [`CATCH_UP_MAX_BACKOFF_MS`].
const CATCH_UP_BACKOFF_MS: i64 = 10 * 1000;
const CATCH_UP_MAX_BACKOFF_MS: i64 = 15 * 60 * 1000;

/// Whether a sender is a member, as this device can tell now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Standing {
    /// In the verified state, their binding checked against their manifest.
    Member,
    /// In the verified state, but their manifest can't be fetched or checked
    /// now.
    Unconfirmed,
    /// Not in the verified state.
    Stranger,
}

/// A group's members as last checked: verified, and in the state but not
/// confirmable now. Kept while the state's head is the same, for at most
/// the known-devices interval, and only when every member was confirmed.
#[derive(Debug, Clone, Default)]
pub(crate) struct GroupMembership {
    pub at_ms: i64,
    pub head: Option<String>,
    pub verified: Vec<String>,
    pub unconfirmed: Vec<String>,
}

impl GroupMembership {
    pub(crate) fn standing(&self, account: &str) -> Standing {
        if self.verified.iter().any(|member| member == account) {
            Standing::Member
        } else if self.unconfirmed.iter().any(|member| member == account) {
            Standing::Unconfirmed
        } else {
            Standing::Stranger
        }
    }
}

/// When a group was last caught up for incoming content, and how.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct CatchUps {
    pub last_ms: i64,
    pub failures: u32,
    /// The highest revision a context asked for: a higher one is new.
    pub asked_up_to: u64,
}

impl CatchUps {
    fn backoff_ms(&self) -> i64 {
        let doubled = CATCH_UP_BACKOFF_MS.saturating_mul(1i64 << self.failures.min(16));
        doubled.min(CATCH_UP_MAX_BACKOFF_MS)
    }

    /// Whether a catch-up for content naming `revision` (none for content
    /// without a context) may go now.
    pub(crate) fn allows(&self, now_ms: i64, revision: Option<u64>) -> bool {
        let news =
            self.failures == 0 && revision.is_some_and(|revision| revision > self.asked_up_to);
        news || now_ms.saturating_sub(self.last_ms) >= self.backoff_ms()
    }
}

/// What group content may do, from how its context compares with this
/// device's state (`None`: it carries none) and its sender's standing.
/// `first_read` is false once this device caught up for it.
pub(crate) fn gate_for(
    check: Option<ContextCheck>,
    standing: Standing,
    first_read: bool,
    may_catch_up: bool,
) -> GroupGate {
    let catch_up = || {
        if first_read && may_catch_up {
            GroupGate::CatchUp
        } else {
            GroupGate::Hold
        }
    };
    match (check, standing) {
        // The sender is further on, or on another head: who is in may have
        // changed, so catch up before deciding.
        (Some(ContextCheck::Behind | ContextCheck::Fork), _) if first_read => catch_up(),
        (_, Standing::Member) => GroupGate::Accept,
        (_, Standing::Unconfirmed) => GroupGate::Hold,
        // A stranger whose own context isn't ahead: not a member at a state
        // this device holds (removed, or never one).
        (Some(ContextCheck::Current | ContextCheck::SenderBehind), Standing::Stranger) => {
            GroupGate::Refuse
        }
        // Still ahead after a catch-up, or nothing to tell by: perhaps one
        // who joined since.
        (Some(ContextCheck::Behind | ContextCheck::Fork) | None, Standing::Stranger) => catch_up(),
    }
}

/// How a message's context compares with the record's verified state;
/// `None` for a context that doesn't read.
pub(crate) fn context_check(
    record: &GroupRecordV1,
    context: &GroupContextV1,
) -> Option<ContextCheck> {
    let head =
        kutup_chat_proto::group::decode_exact::<32>("chainHash", &context.chain_hash).ok()?;
    group::compare_context(record, context.revision, &head).ok()
}

impl Engine {
    /// The group's members as this device can tell now: each in the state,
    /// verified against their manifest, or not confirmable now.
    pub(crate) async fn group_membership(&mut self, group_id: &str) -> Result<GroupMembership> {
        let now = crate::clock::unix_millis();
        let record = self.load_group_record(group_id).await?;
        if let Some(seen) = self.group_members_seen.get(group_id) {
            if seen.head == record.head
                && now.saturating_sub(seen.at_ms) < crate::engine::KNOWN_DEVICES_TTL_MS
            {
                return Ok(seen.clone());
            }
        }
        let (members, unconfirmed) = self.group_members_checked(group_id).await?;
        let membership = GroupMembership {
            at_ms: now,
            head: record.head.clone(),
            verified: members
                .into_iter()
                .filter_map(|member| member.verified.map(|verified| verified.account.to_string()))
                .collect(),
            unconfirmed: unconfirmed.iter().map(ToString::to_string).collect(),
        };
        // A failure isn't kept: the next look tries again.
        if membership.unconfirmed.is_empty() {
            self.group_members_seen
                .insert(group_id.to_string(), membership.clone());
        }
        Ok(membership)
    }

    /// The group's verified member accounts.
    pub(crate) async fn verified_member_accounts(&mut self, group_id: &str) -> Result<Vec<String>> {
        Ok(self.group_membership(group_id).await?.verified)
    }

    /// Whether a catch-up of `group_id` for content naming `revision` may go
    /// now.
    fn may_catch_up(&self, group_id: &str, revision: Option<u64>) -> bool {
        self.group_catch_ups
            .get(group_id)
            .is_none_or(|state| state.allows(crate::clock::unix_millis(), revision))
    }

    /// Catches `group_id` up for incoming content: true when it is current
    /// with its home now.
    async fn catch_up_for_content(&mut self, group_id: &str, revision: Option<u64>) -> bool {
        let now = crate::clock::unix_millis();
        let current = matches!(
            self.sync_group(group_id).await,
            Ok(GroupSync::Current { .. })
        );
        let state = self
            .group_catch_ups
            .entry(group_id.to_string())
            .or_default();
        state.last_ms = now;
        state.failures = if current {
            0
        } else {
            state.failures.saturating_add(1)
        };
        if let Some(revision) = revision {
            state.asked_up_to = state.asked_up_to.max(revision);
        }
        current
    }

    /// Whether `account` is blocked by this account: nothing of theirs is
    /// taken in a group either, as in Signal.
    pub(crate) async fn is_blocked(&self, account: &str) -> Result<bool> {
        Ok(self
            .session
            .contact(account)
            .await?
            .is_some_and(|contact| contact.state == crate::ContactState::Blocked))
    }

    /// Notes what a member's accepted context said. Another head at this
    /// device's revision, or a context still ahead after a catch-up that
    /// reached the home's latest, flags the group: the home may be showing
    /// members different states. Only the member who showed it clears the
    /// flag, by matching again. Unauthenticated evidence, so the view says
    /// "may".
    async fn note_group_context(
        &mut self,
        group_id: &str,
        sender: &str,
        check: ContextCheck,
        caught_up: bool,
        revision: u64,
    ) -> Result<()> {
        let mut record = self.load_group_record(group_id).await?;
        let suspect = check == ContextCheck::Fork || (check == ContextCheck::Behind && caught_up);
        if suspect {
            if record.fork_at_revision != Some(revision)
                || record.fork_sender.as_deref() != Some(sender)
            {
                record.fork_at_revision = Some(revision);
                record.fork_sender = Some(sender.to_string());
                self.save_group(&record).await?;
                self.events.push_back(crate::ChatEvent::GroupForkSuspected {
                    group_id: group_id.to_string(),
                });
            }
        } else if check == ContextCheck::Current && record.fork_sender.as_deref() == Some(sender) {
            record.fork_at_revision = None;
            record.fork_sender = None;
            self.save_group(&record).await?;
        }
        Ok(())
    }

    /// What group content `sender` sent pairwise may do: the gate above,
    /// catching up at most once for it.
    pub(crate) async fn decide_group_content(
        &mut self,
        group_id: &str,
        sender: &str,
        context: Option<&GroupContextV1>,
    ) -> Result<GroupGate> {
        if self.is_blocked(sender).await? {
            return Ok(GroupGate::Refuse);
        }
        let mut caught_up = false;
        for first_read in [true, false] {
            let Some(record) = self.session.db().load_group(group_id).await? else {
                return Ok(GroupGate::Refuse);
            };
            if record.status != GroupStatus::Member {
                return Ok(GroupGate::Refuse);
            }
            let standing = self.group_membership(group_id).await?.standing(sender);
            let check = match context {
                Some(context) => match context_check(&record, context) {
                    Some(check) => Some(check),
                    None => return Ok(GroupGate::Refuse),
                },
                None => None,
            };
            let revision = context.map(|context| context.revision);
            let gate = gate_for(
                check,
                standing,
                first_read,
                self.may_catch_up(group_id, revision),
            );
            match gate {
                GroupGate::CatchUp => {
                    caught_up = self.catch_up_for_content(group_id, revision).await;
                }
                GroupGate::Accept => {
                    if let (Some(check), Some(revision)) = (check, revision) {
                        self.note_group_context(group_id, sender, check, caught_up, revision)
                            .await?;
                    }
                    return Ok(GroupGate::Accept);
                }
                other => return Ok(other),
            }
        }
        Ok(GroupGate::Hold)
    }

    /// A sender-key message: opened, then kept only as the gate says. Read
    /// again after a catch-up; held (left queued) when its sender can't be
    /// confirmed now.
    pub(crate) async fn receive_group_envelope(
        &mut self,
        envelope: &kutup_chat_proto::DeliveredEnvelope,
        inspection: &crate::session::SealedEnvelopeInspection,
        validating_root: &PublicKey,
    ) -> Result<ReceiveOutcome> {
        use std::cell::Cell;
        let group_id = inspection
            .group_id
            .map(|id| kutup_chat_proto::group::encode_group_id(&id))
            .ok_or_else(|| ChatError::Trust("not a group message".into()))?;
        let dropped = || ReceiveOutcome::Suppressed {
            id: envelope.id.clone(),
        };
        if self.is_blocked(&inspection.sender).await? {
            self.session.ack_dropped(envelope).await?;
            return Ok(dropped());
        }
        let mut caught_up = false;
        for first_read in [true, false] {
            let record = match self.session.db().load_group(&group_id).await? {
                Some(record) if record.status == GroupStatus::Member => record,
                // Not a group this account is in.
                _ => {
                    self.session.ack_dropped(envelope).await?;
                    return Ok(dropped());
                }
            };
            let standing = self
                .group_membership(&group_id)
                .await?
                .standing(&inspection.sender);
            let catch_ups = self
                .group_catch_ups
                .get(&group_id)
                .copied()
                .unwrap_or_default();
            let now = crate::clock::unix_millis();
            let seen = Cell::new(None);
            let gate = |context: &GroupContextV1| {
                let Some(check) = context_check(&record, context) else {
                    return GroupGate::Refuse;
                };
                let may_catch_up = catch_ups.allows(now, Some(context.revision));
                let gate = gate_for(Some(check), standing, first_read, may_catch_up);
                seen.set(Some((check, gate, context.revision)));
                gate
            };
            let outcome = self
                .session
                .receive_sealed_group_envelope(envelope, inspection, validating_root, &gate)
                .await?;
            if matches!(outcome, ReceiveOutcome::GroupCatchUp) {
                let revision = seen.get().map(|(_, _, revision)| revision);
                caught_up = self.catch_up_for_content(&group_id, revision).await;
                continue;
            }
            if let Some((check, GroupGate::Accept, revision)) = seen.get() {
                self.note_group_context(&group_id, &inspection.sender, check, caught_up, revision)
                    .await?;
            }
            return Ok(outcome);
        }
        Err(ChatError::Invalid(
            "a group message asked to catch up twice".into(),
        ))
    }

    /// Group content that came pairwise and that the gate let through: a
    /// sender key is taken, a refresh answered, a waiting record settled, a
    /// message kept; an invitation starts an invited record that waits for
    /// this account's choice.
    pub(crate) async fn handle_group_content<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        id: &str,
        from: &crate::address::ChatAddress,
        cursor: u64,
        content: &kutup_chat_proto::ChatContent,
        rng: &mut R,
    ) -> Result<GroupContentOutcome> {
        let sender = from.name();
        if let Some(invite) = content.as_group_invite() {
            return self.take_group_invite(invite, &sender).await;
        }
        if let Some(control) = content.as_session_control() {
            if control.group.is_none() {
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
            let message = decode_b64(&body.message)?;
            self.session
                .process_sender_key_distribution(from, &message)
                .await?;
            return Ok(GroupContentOutcome::SenderKey);
        }
        let message = match content.as_resend() {
            Some(resend) => *resend.content,
            None => content.clone(),
        };
        if message.group_context().is_some() {
            // A change notice says only that the group moved on.
            if message.kind == kutup_chat_proto::content::kind::GROUP_CHANGE {
                return Ok(GroupContentOutcome::Ignored);
            }
            self.session
                .store_group_message(id, from, cursor, &message)
                .await?;
            return Ok(GroupContentOutcome::Message(Box::new(message)));
        }
        Ok(GroupContentOutcome::Ignored)
    }

    /// An invitation from `sender`. Nothing from a blocked account is
    /// taken; a stranger's is a message request; a group this account is in
    /// is left as it is; a left or declined group, or an older invitation,
    /// takes a newer one. At most [`MAX_INVITATIONS_PER_SENDER`] wait from
    /// one sender.
    async fn take_group_invite(
        &mut self,
        invite: kutup_chat_proto::group::GroupInviteV1,
        sender: &str,
    ) -> Result<GroupContentOutcome> {
        if self.is_blocked(sender).await? {
            return Ok(GroupContentOutcome::Ignored);
        }
        let group_id = invite.group_id.clone();
        let previous = self.session.db().load_group(&group_id).await?;
        let replaceable = previous
            .as_ref()
            .is_none_or(|previous| match &previous.status {
                GroupStatus::Gone => true,
                GroupStatus::Invited { slot_revision, .. } => invite.slot_revision > *slot_revision,
                GroupStatus::Member | GroupStatus::Requesting => false,
            });
        if !replaceable {
            return Ok(GroupContentOutcome::Ignored);
        }
        let waiting: BTreeSet<String> = self
            .session
            .db()
            .list_groups()
            .await?
            .into_iter()
            .filter(|record| {
                record.group_id != group_id
                    && matches!(&record.status, GroupStatus::Invited { inviter, .. } if inviter == sender)
            })
            .map(|record| record.group_id)
            .collect();
        if waiting.len() >= MAX_INVITATIONS_PER_SENDER {
            return Ok(GroupContentOutcome::Ignored);
        }
        let record = match group::record_from_invite(invite, sender, previous.as_ref()) {
            Ok(record) => record,
            // A stale invitation for a membership that ended: dropped.
            Err(_) if previous.is_some() => return Ok(GroupContentOutcome::Ignored),
            Err(error) => return Err(group_error(error)),
        };
        self.save_group(&record).await?;
        let request = !self.session.contact(sender).await?.is_some_and(|contact| {
            matches!(
                contact.state,
                crate::ContactState::Accepted | crate::ContactState::PendingOutgoing
            )
        });
        Ok(GroupContentOutcome::Invited {
            group_id,
            from: sender.to_string(),
            request,
        })
    }
}

/// The most invitations one sender may have waiting for this account's
/// choice.
pub(crate) const MAX_INVITATIONS_PER_SENDER: usize = 20;
