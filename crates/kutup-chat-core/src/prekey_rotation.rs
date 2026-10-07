//! Rotation of a device's long-lived prekeys (docs/chat-protocol.md,
//! "Prekeys").
//!
//! The signed EC prekey and the last-resort Kyber prekey are used by every
//! first message to this device that finds no one-time key left, so they are
//! replaced on a schedule, as Signal does: a fresh pair every
//! [`ROTATE_EVERY_MS`]. A replaced key is kept as long as a message made with
//! it may still be waiting in the mailbox (the server's retention, plus a
//! margin), then deleted. Used one-time Kyber prekeys are deleted after the
//! same grace as one-time EC prekeys; only the last-resort key is reused.
//!
//! libsignal's records carry no usable time, so this state, kept beside the
//! keys and written in the same transactions, says which key is which and
//! since when.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// How often the signed and last-resort prekeys are replaced.
pub(crate) const ROTATE_EVERY_MS: i64 = 2 * 24 * 60 * 60 * 1000;
/// Added to the server's mailbox retention before a replaced key goes: a
/// sender's clock, a late delivery, a device that was offline.
pub(crate) const RETIRED_MARGIN_MS: i64 = 7 * 24 * 60 * 60 * 1000;
const DAY_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CurrentKey {
    pub id: u32,
    /// When the server confirmed it (when this state was first made, for a
    /// key published before rotation existed).
    pub published_at_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PendingKeys {
    pub signed: u32,
    pub last_resort: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum KeyKind {
    Signed,
    LastResort,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RetiredKey {
    pub kind: KeyKind,
    pub id: u32,
    pub retired_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PrekeyRotation {
    pub signed: CurrentKey,
    pub last_resort: CurrentKey,
    /// Replacements generated and staged for upload, not yet confirmed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<PendingKeys>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retired: Vec<RetiredKey>,
    /// One-time Kyber prekey id → when a message first used it.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub used_one_time_kyber: BTreeMap<u32, i64>,
}

/// What a sweep removes.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Expired {
    pub signed: Vec<u32>,
    pub kyber: Vec<u32>,
}

impl PrekeyRotation {
    /// A device that registered before rotation: its keys are id 1 (as
    /// registration makes them), counted as published now, so the first
    /// rotation comes one interval later rather than all at once.
    pub(crate) fn initial(now_ms: i64) -> Self {
        Self {
            signed: CurrentKey {
                id: 1,
                published_at_ms: now_ms,
            },
            last_resort: CurrentKey {
                id: 1,
                published_at_ms: now_ms,
            },
            pending: None,
            retired: Vec::new(),
            used_one_time_kyber: BTreeMap::new(),
        }
    }

    /// Whether the current pair is due to be replaced.
    pub(crate) fn due(&self, now_ms: i64) -> bool {
        self.pending.is_none()
            && self
                .signed
                .published_at_ms
                .min(self.last_resort.published_at_ms)
                + ROTATE_EVERY_MS
                <= now_ms
    }

    /// Whether `id` is a last-resort Kyber prekey (current, staged or
    /// retired): one that may be used many times, guarded against replay,
    /// rather than consumed.
    pub(crate) fn is_last_resort(&self, id: u32) -> bool {
        self.last_resort.id == id
            || self
                .pending
                .is_some_and(|pending| pending.last_resort == id)
            || self
                .retired
                .iter()
                .any(|key| key.kind == KeyKind::LastResort && key.id == id)
    }

    /// A one-time Kyber prekey was used (the first time counts).
    pub(crate) fn mark_one_time_kyber_used(&mut self, id: u32, now_ms: i64) -> bool {
        if self.is_last_resort(id) || self.used_one_time_kyber.contains_key(&id) {
            return false;
        }
        self.used_one_time_kyber.insert(id, now_ms);
        true
    }

    /// The server confirmed the staged pair: it becomes current, and the pair
    /// it replaces is retired from now.
    pub(crate) fn confirm(&mut self, now_ms: i64) -> bool {
        let Some(pending) = self.pending.take() else {
            return false;
        };
        self.retired.push(RetiredKey {
            kind: KeyKind::Signed,
            id: self.signed.id,
            retired_at_ms: now_ms,
        });
        self.retired.push(RetiredKey {
            kind: KeyKind::LastResort,
            id: self.last_resort.id,
            retired_at_ms: now_ms,
        });
        self.signed = CurrentKey {
            id: pending.signed,
            published_at_ms: now_ms,
        };
        self.last_resort = CurrentKey {
            id: pending.last_resort,
            published_at_ms: now_ms,
        };
        true
    }

    /// Remove what can no longer be needed: retired keys whose retirement is
    /// older than `keep_ms` (None: the server keeps mail for ever, so they are
    /// kept too), and used one-time Kyber keys older than `grace_ms`.
    pub(crate) fn sweep(&mut self, now_ms: i64, keep_ms: Option<i64>, grace_ms: i64) -> Expired {
        let mut expired = Expired::default();
        if let Some(keep_ms) = keep_ms {
            self.retired.retain(|key| {
                if key.retired_at_ms + keep_ms > now_ms {
                    return true;
                }
                match key.kind {
                    KeyKind::Signed => expired.signed.push(key.id),
                    KeyKind::LastResort => expired.kyber.push(key.id),
                }
                false
            });
        }
        self.used_one_time_kyber.retain(|id, used_at| {
            if *used_at + grace_ms > now_ms {
                return true;
            }
            expired.kyber.push(*id);
            false
        });
        expired
    }
}

/// How long a retired key is kept, for a server keeping mail
/// `mailbox_retention_days` (0: for ever).
pub(crate) fn retired_keep_ms(mailbox_retention_days: u32) -> Option<i64> {
    (mailbox_retention_days > 0)
        .then(|| i64::from(mailbox_retention_days) * DAY_MS + RETIRED_MARGIN_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000_000;

    #[test]
    fn a_pair_is_due_after_the_interval_and_not_while_one_waits_for_upload() {
        let mut state = PrekeyRotation::initial(NOW);
        assert!(!state.due(NOW + ROTATE_EVERY_MS - 1));
        assert!(state.due(NOW + ROTATE_EVERY_MS));
        state.pending = Some(PendingKeys {
            signed: 7,
            last_resort: 8,
        });
        assert!(!state.due(NOW + 10 * ROTATE_EVERY_MS));
    }

    #[test]
    fn a_confirmed_pair_retires_the_old_one_which_goes_after_retention() {
        let mut state = PrekeyRotation::initial(NOW);
        state.pending = Some(PendingKeys {
            signed: 7,
            last_resort: 8,
        });
        assert!(
            state.is_last_resort(8),
            "a staged last-resort key is one already"
        );
        assert!(state.confirm(NOW + 5));
        assert_eq!(state.signed.id, 7);
        assert_eq!(state.last_resort.id, 8);
        assert!(state.is_last_resort(1), "the retired one still is");
        let keep = retired_keep_ms(30);
        assert!(state.sweep(NOW + 30 * DAY_MS, keep, 0).signed.is_empty());
        let expired = state.sweep(NOW + 5 + keep.unwrap(), keep, 0);
        assert_eq!(
            expired,
            Expired {
                signed: vec![1],
                kyber: vec![1]
            }
        );
        assert!(state.retired.is_empty());
    }

    #[test]
    fn with_mail_kept_for_ever_retired_keys_stay() {
        let mut state = PrekeyRotation::initial(NOW);
        state.pending = Some(PendingKeys {
            signed: 7,
            last_resort: 8,
        });
        state.confirm(NOW);
        assert_eq!(retired_keep_ms(0), None);
        assert_eq!(
            state.sweep(NOW + 3650 * DAY_MS, None, 0),
            Expired::default()
        );
        assert_eq!(state.retired.len(), 2);
    }

    #[test]
    fn used_one_time_kyber_keys_go_after_their_grace_and_last_resort_keys_are_never_marked() {
        let mut state = PrekeyRotation::initial(NOW);
        assert!(
            !state.mark_one_time_kyber_used(1, NOW),
            "id 1 is the last-resort key"
        );
        assert!(state.mark_one_time_kyber_used(500, NOW));
        assert!(
            !state.mark_one_time_kyber_used(500, NOW + 1),
            "the first use counts"
        );
        let grace = 14 * DAY_MS;
        assert!(state.sweep(NOW + grace - 1, None, grace).kyber.is_empty());
        assert_eq!(state.sweep(NOW + grace, None, grace).kyber, vec![500]);
    }

    #[test]
    fn the_state_reads_back_as_written() {
        let mut state = PrekeyRotation::initial(NOW);
        state.mark_one_time_kyber_used(500, NOW);
        let bytes = serde_json::to_vec(&state).unwrap();
        assert_eq!(
            serde_json::from_slice::<PrekeyRotation>(&bytes).unwrap(),
            state
        );
    }
}
