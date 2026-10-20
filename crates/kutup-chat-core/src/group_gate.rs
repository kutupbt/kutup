//! What a group's incoming content may do (docs/plans/pairwise-groups.md §2,
//! §3), decided before anything of it is kept, as Signal reads a group's
//! state before a message that names a newer one (`maybeUpdateGroup`) and
//! drops what still doesn't fit after that fetch:
//!
//! - A context ahead of this device's verified state, or on another head,
//!   makes it catch up from the home and read the content again.
//! - A sender who is a member at that state is taken.
//! - A stranger is refused once this device is at the home's latest, or when
//!   their own context isn't ahead of it (a removed member), or when readable
//!   content of theirs carries no context at all.
//! - What can't be decided now is held: a member whose manifest can't be
//!   fetched, or a stranger while the catch-up couldn't be made or failed.
//!   The envelope stays queued and is read again on a later pass, given up
//!   after a week, within the limits of [`HeldEnvelopes`]. A
//!   long-held pairwise envelope relies on libsignal keeping skipped message
//!   keys (2000 per chain, 5 chains); one past that reads as a duplicate.
//! - Catch-ups are bounded per group: a context a small step past this
//!   device's state, not asked for yet, goes after a short gap; anything else
//!   waits a back-off that grows on failure. Neither a removed member, a
//!   forged revision nor an unreachable home makes a catch-up per message.

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

/// The most envelopes a member (unconfirmed now) may have waiting in one
/// group, a stranger, and one group in all; past that they are dropped.
pub(crate) const MAX_HELD_PER_SENDER: usize = 32;
pub(crate) const MAX_HELD_PER_STRANGER: usize = 8;
pub(crate) const MAX_HELD_PER_GROUP: usize = 256;

/// One envelope left waiting in a pass.
#[derive(Debug)]
struct Held {
    sender: String,
    /// The sender is in the verified state (its manifest unconfirmed), not
    /// a stranger.
    member: bool,
    id: String,
    envelope: kutup_chat_proto::DeliveredEnvelope,
}

/// What becomes of an envelope that would wait.
#[derive(Debug)]
pub(crate) enum HoldDecision {
    Keep,
    /// It waits, and an envelope that waited is given up for it (its id and
    /// envelope, to acknowledge).
    KeepEvicting(String, Box<kutup_chat_proto::DeliveredEnvelope>),
    /// Given up: too old, or over the limits.
    Drop,
}

/// The group envelopes left waiting in one pass. A stranger keeps at most
/// [`MAX_HELD_PER_STRANGER`], a member [`MAX_HELD_PER_SENDER`], a group
/// [`MAX_HELD_PER_GROUP`]; a full group gives up the newest envelope of its
/// biggest holder (strangers before members), never a member's for a
/// stranger's, so strangers can't use up members' room.
#[derive(Debug, Default)]
pub(crate) struct HeldEnvelopes {
    by_group: std::collections::BTreeMap<String, Vec<Held>>,
}

impl HeldEnvelopes {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn keep(
        &mut self,
        group_id: &str,
        sender: &str,
        member: bool,
        id: &str,
        envelope: &kutup_chat_proto::DeliveredEnvelope,
        received_at: i64,
        now_ms: i64,
    ) -> HoldDecision {
        if now_ms.saturating_sub(received_at) >= GROUP_HOLD_MS {
            return HoldDecision::Drop;
        }
        let held = self.by_group.entry(group_id.to_string()).or_default();
        let count = |sender: &str| held.iter().filter(|h| h.sender == sender).count();
        let mine = count(sender);
        let cap = if member {
            MAX_HELD_PER_SENDER
        } else {
            MAX_HELD_PER_STRANGER
        };
        if mine >= cap {
            return HoldDecision::Drop;
        }
        let entry = Held {
            sender: sender.to_string(),
            member,
            id: id.to_string(),
            envelope: envelope.clone(),
        };
        if held.len() < MAX_HELD_PER_GROUP {
            held.push(entry);
            return HoldDecision::Keep;
        }
        // Full: the biggest holder gives one up, strangers first; a stranger
        // never takes a member's room.
        let mut holders: Vec<(bool, usize, String)> = Vec::new();
        for h in held.iter() {
            if !holders.iter().any(|(_, _, s)| *s == h.sender) {
                holders.push((h.member, count(&h.sender), h.sender.clone()));
            }
        }
        let victim = holders
            .into_iter()
            .filter(|(victim_member, victim_count, _)| {
                (member && !victim_member) || (*victim_member == member && *victim_count > mine + 1)
            })
            .max_by_key(|(victim_member, victim_count, _)| (!victim_member, *victim_count));
        let Some((_, _, victim)) = victim else {
            return HoldDecision::Drop;
        };
        let place = held
            .iter()
            .rposition(|h| h.sender == victim)
            .expect("a holder holds one");
        let evicted = held.remove(place);
        held.push(entry);
        HoldDecision::KeepEvicting(evicted.id, Box::new(evicted.envelope))
    }
}

/// The first wait between catch-ups of one group that bring nothing new; it
/// doubles on each failure, up to [`CATCH_UP_MAX_BACKOFF_MS`].
const CATCH_UP_BACKOFF_MS: i64 = 10 * 1000;
const CATCH_UP_MAX_BACKOFF_MS: i64 = 15 * 60 * 1000;

/// A context counts as news (worth a catch-up sooner than the back-off) only
/// this far past this device's state, and not sooner than this after the
/// last catch-up.
const NEWS_WINDOW: u64 = 64;
const NEWS_MIN_GAP_MS: i64 = 2 * 1000;

fn backoff_ms(failures: u32) -> i64 {
    CATCH_UP_BACKOFF_MS
        .saturating_mul(1i64 << failures.min(16))
        .min(CATCH_UP_MAX_BACKOFF_MS)
}

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
/// confirmable now. Kept while the state's head is the same: for the
/// known-devices interval when every member was confirmed, otherwise until a
/// back-off for the unconfirmed ones passes (the verified ones' keys are
/// kept apart, so only those are fetched again).
#[derive(Debug, Clone, Default)]
pub(crate) struct GroupMembership {
    pub recheck_at_ms: i64,
    pub failures: u32,
    pub head: Option<String>,
    pub verified: Vec<String>,
    pub unconfirmed: Vec<String>,
    /// The verified administrators' accounts.
    pub administrators: Vec<String>,
    pub announcements_only: bool,
    pub terminated: bool,
}

impl GroupMembership {
    /// Whether content of `kind` from `account` is dropped on receipt (as
    /// Signal): nothing but change notices once the group ended, and only
    /// administrators' messages while it is announcements-only.
    pub(crate) fn silences(&self, account: &str, kind: &str) -> bool {
        if kind == kutup_chat_proto::content::kind::GROUP_CHANGE {
            return false;
        }
        self.terminated
            || (self.announcements_only
                && !self.administrators.iter().any(|admin| admin == account))
    }

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
    /// The highest revision a context asked for as news.
    pub asked_up_to: u64,
    /// When a catch-up last reached the home's latest: content received
    /// before it is decided as caught up (a stranger then is refused).
    pub current_at_ms: i64,
}

impl CatchUps {
    /// Whether a catch-up for content naming `revision` (none for content
    /// without a context) may go now, this device at `verified`.
    pub(crate) fn allows(&self, now_ms: i64, revision: Option<u64>, verified: u64) -> bool {
        let since = now_ms.saturating_sub(self.last_ms);
        news(self, revision, verified) && since >= NEWS_MIN_GAP_MS
            || since >= backoff_ms(self.failures)
    }
}

/// A revision a small step past `verified`, not asked for yet, while the
/// home answers.
fn news(state: &CatchUps, revision: Option<u64>, verified: u64) -> bool {
    state.failures == 0
        && revision.is_some_and(|revision| {
            revision > state.asked_up_to && revision <= verified.saturating_add(NEWS_WINDOW)
        })
}

/// Where a decision stands for one piece of content.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Reading {
    /// Not read since a catch-up for it.
    pub first: bool,
    /// This device reached the home's latest after the content arrived (for
    /// it, or for anything since).
    pub caught_up: bool,
    /// A catch-up may go now.
    pub may_catch_up: bool,
    /// The content was read (not an unreadable message under repair).
    pub readable: bool,
}

/// What group content may do, from how its context compares with this
/// device's state (`None`: it carries none) and its sender's standing.
pub(crate) fn gate_for(
    check: Option<ContextCheck>,
    standing: Standing,
    reading: Reading,
) -> GroupGate {
    let wait = || {
        if reading.first && reading.may_catch_up {
            GroupGate::CatchUp
        } else {
            GroupGate::Hold
        }
    };
    match (check, standing) {
        // The sender is further on, or on another head, and this device hasn't
        // caught up since it came: who is in may have changed, so catch up
        // before deciding.
        (Some(ContextCheck::Behind | ContextCheck::Fork), _)
            if reading.first && !reading.caught_up =>
        {
            wait()
        }
        (_, Standing::Member) => GroupGate::Accept,
        (_, Standing::Unconfirmed) => GroupGate::Hold,
        // A stranger whose own context isn't ahead: not a member at a state
        // this device holds (removed, or never one).
        (Some(ContextCheck::Current | ContextCheck::SenderBehind), Standing::Stranger) => {
            GroupGate::Refuse
        }
        // A stranger after a catch-up that reached the home's latest: not a
        // member, whatever their context says.
        (_, Standing::Stranger) if reading.caught_up => GroupGate::Refuse,
        // Readable content without a context, from a stranger: nothing to
        // catch up for.
        (None, Standing::Stranger) if reading.readable => GroupGate::Refuse,
        // Still ahead without a catch-up that worked, or an unreadable
        // message: wait for one.
        (Some(ContextCheck::Behind | ContextCheck::Fork) | None, Standing::Stranger) => wait(),
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

/// The revision of the record's verified state (0 without one).
fn verified_revision(record: &GroupRecordV1) -> u64 {
    record
        .verified()
        .ok()
        .flatten()
        .map_or(0, |(state, _)| state.revision)
}

impl Engine {
    /// The group's members as this device can tell now: each in the state,
    /// verified against their manifest, or not confirmable now.
    pub(crate) async fn group_membership(&mut self, group_id: &str) -> Result<GroupMembership> {
        let now = self.now_ms();
        let record = self.load_group_record(group_id).await?;
        let mut failures = 0;
        if let Some(seen) = self.group_members_seen.get(group_id) {
            if seen.head == record.head {
                if now < seen.recheck_at_ms {
                    return Ok(seen.clone());
                }
                failures = seen.failures;
            }
        }
        let (members, unconfirmed) = self.group_members_checked(group_id).await?;
        let unconfirmed: Vec<String> = unconfirmed.iter().map(ToString::to_string).collect();
        let state = record
            .verified()
            .map_err(group_error)?
            .map(|(state, _)| state);
        let (failures, wait) = if unconfirmed.is_empty() {
            (0, crate::engine::KNOWN_DEVICES_TTL_MS)
        } else {
            (failures.saturating_add(1), backoff_ms(failures))
        };
        let membership = GroupMembership {
            recheck_at_ms: now.saturating_add(wait),
            failures,
            head: record.head.clone(),
            administrators: members
                .iter()
                .filter(|member| member.role == kutup_chat_proto::group::GroupRole::Administrator)
                .filter_map(|member| member.verified.as_ref().map(|v| v.account.to_string()))
                .collect(),
            verified: members
                .into_iter()
                .filter_map(|member| member.verified.map(|verified| verified.account.to_string()))
                .collect(),
            unconfirmed,
            announcements_only: state.as_ref().is_some_and(|state| state.announcements_only),
            terminated: state.as_ref().is_some_and(|state| state.terminated),
        };
        self.group_members_seen
            .insert(group_id.to_string(), membership.clone());
        Ok(membership)
    }

    /// The group's verified member accounts.
    pub(crate) async fn verified_member_accounts(&mut self, group_id: &str) -> Result<Vec<String>> {
        Ok(self.group_membership(group_id).await?.verified)
    }

    /// Whether a catch-up of `record`'s group for content naming `revision`
    /// may go now.
    fn may_catch_up(&self, record: &GroupRecordV1, revision: Option<u64>) -> bool {
        self.group_catch_ups
            .get(&record.group_id)
            .is_none_or(|state| state.allows(self.now_ms(), revision, verified_revision(record)))
    }

    /// Catches `record`'s group up for incoming content naming `context`
    /// (none for content without one): true when it is current with its
    /// home now. A catch-up that reaches the home's latest while the context
    /// is still ahead counts as a failure for the back-off, so forged
    /// contexts don't make a catch-up every few seconds.
    async fn catch_up_for_content(
        &mut self,
        record: &GroupRecordV1,
        context: Option<&GroupContextV1>,
    ) -> bool {
        let now = self.now_ms();
        let group_id = record.group_id.clone();
        let verified = verified_revision(record);
        let revision = context.map(|context| context.revision);
        let current = matches!(
            self.sync_group(&group_id).await,
            Ok(GroupSync::Current { .. })
        );
        let still_ahead = match (current, context) {
            (true, Some(context)) => self
                .session
                .db()
                .load_group(&group_id)
                .await
                .ok()
                .flatten()
                .and_then(|record| context_check(&record, context))
                .is_some_and(|check| matches!(check, ContextCheck::Behind | ContextCheck::Fork)),
            _ => false,
        };
        let state = self.group_catch_ups.entry(group_id).or_default();
        let was_news = news(state, revision, verified);
        state.last_ms = now;
        if current {
            state.current_at_ms = now;
        }
        state.failures = if current && !still_ahead {
            0
        } else {
            state.failures.saturating_add(1)
        };
        if let (true, Some(revision)) = (was_news, revision) {
            state.asked_up_to = state.asked_up_to.max(revision);
        }
        current
    }

    /// Whether this device reached the group's latest after `received_at`.
    fn caught_up_since(&self, group_id: &str, received_at: i64) -> bool {
        self.group_catch_ups
            .get(group_id)
            .is_some_and(|state| state.current_at_ms >= received_at && state.current_at_ms > 0)
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

    /// What group content `sender` sent pairwise may do (`readable`: false
    /// for an unreadable message under repair): the gate above, catching up
    /// at most once for it.
    pub(crate) async fn decide_group_content(
        &mut self,
        group_id: &str,
        sender: &str,
        context: Option<&GroupContextV1>,
        readable: bool,
        received_at: i64,
    ) -> Result<GroupGate> {
        if self.is_blocked(sender).await? {
            return Ok(GroupGate::Refuse);
        }
        self.settle_if_requesting(group_id).await;
        let mut caught_up = self.caught_up_since(group_id, received_at);
        for first in [true, false] {
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
            let reading = Reading {
                first,
                caught_up,
                may_catch_up: self.may_catch_up(&record, revision),
                readable,
            };
            match gate_for(check, standing, reading) {
                GroupGate::CatchUp => {
                    caught_up = self.catch_up_for_content(&record, context).await;
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

    /// Content of a group this account asked to join: only members send to
    /// it, so it may have been approved meanwhile (the home tells nobody).
    /// The request is settled before the content is decided, so the first
    /// messages after an approval aren't dropped. Best effort.
    async fn settle_if_requesting(&mut self, group_id: &str) {
        let requesting = self
            .session
            .db()
            .load_group(group_id)
            .await
            .ok()
            .flatten()
            .is_some_and(|record| record.status == GroupStatus::Requesting);
        if requesting {
            let _ = self.check_group_request(group_id).await;
        }
    }

    /// A sender-key message: opened, then kept only as the gate says. Read
    /// again after a catch-up; held (left queued) when its sender can't be
    /// confirmed now.
    pub(crate) async fn receive_group_envelope(
        &mut self,
        envelope: &kutup_chat_proto::DeliveredEnvelope,
        inspection: &crate::session::SealedEnvelopeInspection,
        validating_root: &PublicKey,
        received_at: i64,
    ) -> Result<ReceiveOutcome> {
        use std::cell::RefCell;
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
        self.settle_if_requesting(&group_id).await;
        let mut caught_up = self.caught_up_since(&group_id, received_at);
        for first in [true, false] {
            let record = match self.session.db().load_group(&group_id).await? {
                Some(record) if record.status == GroupStatus::Member => record,
                // Not a group this account is in.
                _ => {
                    self.session.ack_dropped(envelope).await?;
                    return Ok(dropped());
                }
            };
            let membership = self.group_membership(&group_id).await?;
            let standing = membership.standing(&inspection.sender);
            let catch_ups = self.group_catch_ups.get(&group_id).copied();
            let now = self.now_ms();
            let verified = verified_revision(&record);
            let seen = RefCell::new(None);
            let gate = |context: &GroupContextV1, kind: &str| {
                let Some(check) = context_check(&record, context) else {
                    return GroupGate::Refuse;
                };
                let reading = Reading {
                    first,
                    caught_up,
                    may_catch_up: catch_ups
                        .is_none_or(|state| state.allows(now, Some(context.revision), verified)),
                    readable: true,
                };
                let mut gate = gate_for(Some(check), standing, reading);
                if gate == GroupGate::Accept && membership.silences(&inspection.sender, kind) {
                    gate = GroupGate::Refuse;
                }
                *seen.borrow_mut() = Some((check, gate, context.clone()));
                gate
            };
            let outcome = self
                .session
                .receive_sealed_group_envelope(envelope, inspection, validating_root, &gate)
                .await?;
            let seen = seen.into_inner();
            if matches!(outcome, ReceiveOutcome::GroupCatchUp) {
                let context = seen.map(|(_, _, context)| context);
                caught_up = self.catch_up_for_content(&record, context.as_ref()).await;
                continue;
            }
            if let Some((check, GroupGate::Accept, context)) = seen {
                self.note_group_context(
                    &group_id,
                    &inspection.sender,
                    check,
                    caught_up,
                    context.revision,
                )
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
        if let Some(removal) = content.as_group_removal() {
            self.take_group_removal(removal).await?;
            return Ok(GroupContentOutcome::Ignored);
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
            let group_id = message
                .group_context()
                .map(|context| context.group_id.clone())
                .unwrap_or_default();
            if self
                .group_membership(&group_id)
                .await?
                .silences(&sender, &message.kind)
            {
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
        // The epoch goes past the list's (another device's) too.
        self.ensure_group_list_read().await;
        let listed = self.listed_join(&group_id);
        let mut record = match group::record_from_invite(
            invite,
            sender,
            previous.as_ref(),
            listed,
            self.group_keys()?,
        ) {
            Ok(record) => record,
            // A stale invitation for a membership that ended: dropped.
            Err(_) if previous.is_some() => return Ok(GroupContentOutcome::Ignored),
            Err(error) => return Err(group_error(error)),
        };
        record.known_since_ms = Some(crate::clock::unix_millis());
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
