//! What a check does to a domain's state (docs/plans/mail-custom-domains.md
//! §3, "Grace, by cause"): pure, so every path is tested without DNS or a
//! clock.
//!
//! - A held domain whose ownership TXT goes missing counts as failing only
//!   after two failing checks at least [`Grace::confirm_after`] apart.
//! - Failing with its MX still ours: `warn` (it keeps working) for
//!   [`Grace::warn_for`], then inactive.
//! - Failing with its MX gone too: sending and delivery stop at once, and it
//!   goes inactive after [`Grace::stopped_for`].
//! - An unknown answer (SERVFAIL, a timeout) changes nothing.
//! - Drift in MX, SPF, DKIM or DMARC alone only changes badges.

/// Proton's `DOMAIN_STATE`.
pub mod state {
    /// Not yet verified, or no longer (inactive when `verified_at` is set).
    pub const DEFAULT: i16 = 0;
    pub const VERIFIED: i16 = 1;
    /// A held domain whose DNS went backwards: still working, for a while.
    pub const WARN: i16 = 2;
}

/// The grace periods, in seconds (site settings, editable by admins).
#[derive(Debug, Clone, Copy)]
pub struct Grace {
    /// Two failing checks at least this far apart before anything changes.
    pub confirm_after: i64,
    /// How long `warn` lasts while the MX is still ours.
    pub warn_for: i64,
    /// How long a domain whose TXT and MX are both gone stays stopped
    /// before it is inactive.
    pub stopped_for: i64,
}

impl Default for Grace {
    fn default() -> Self {
        Grace {
            confirm_after: 12 * 3600,
            warn_for: 14 * 24 * 3600,
            stopped_for: 72 * 3600,
        }
    }
}

/// The parts of a domain row a check reads and writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Status {
    pub state: i16,
    pub verified_at: Option<i64>,
    /// When the ownership check first failed in the current run of failures.
    pub failing_since: Option<i64>,
    pub warned_at: Option<i64>,
    /// When sending and delivery stopped (TXT and MX both gone).
    pub stopped_at: Option<i64>,
}

impl Status {
    /// Whether mail flows: held, and not stopped.
    pub fn usable(&self) -> bool {
        matches!(self.state, state::VERIFIED | state::WARN) && self.stopped_at.is_none()
    }

    /// Once held, no longer.
    pub fn inactive(&self) -> bool {
        self.state == state::DEFAULT && self.verified_at.is_some()
    }
}

/// What one check found: `None` for an unknown answer.
#[derive(Debug, Clone, Copy)]
pub struct Found {
    pub owned: Option<bool>,
    pub mx_ours: Option<bool>,
}

/// What happened, for the notices and the security log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    None,
    Verified,
    Restored,
    Warned,
    Stopped,
    Inactive,
}

/// The status after a check at `now`.
pub fn next(current: Status, found: Found, now: i64, grace: Grace) -> (Status, Change) {
    let Some(owned) = found.owned else {
        return (current, Change::None);
    };
    let mut status = current;
    let held = matches!(current.state, state::VERIFIED | state::WARN);
    if owned {
        status.failing_since = None;
        status.warned_at = None;
        status.stopped_at = None;
        let change = if held && current.state == state::VERIFIED && current.stopped_at.is_none() {
            Change::None
        } else if held || current.inactive() {
            Change::Restored
        } else {
            Change::Verified
        };
        status.state = state::VERIFIED;
        status.verified_at = Some(now);
        return (status, change);
    }
    if !held {
        return (status, Change::None);
    }
    // A first failure only starts the clock.
    let Some(since) = current.failing_since else {
        status.failing_since = Some(now);
        return (status, Change::None);
    };
    if now - since < grace.confirm_after {
        return (status, Change::None);
    }
    let mx_gone = found.mx_ours == Some(false);
    if mx_gone && current.stopped_at.is_none() {
        status.stopped_at = Some(now);
        status.state = state::WARN;
        status.warned_at.get_or_insert(now);
        return (status, Change::Stopped);
    }
    if let Some(stopped) = current.stopped_at {
        if now - stopped >= grace.stopped_for {
            return (inactive(status), Change::Inactive);
        }
        return (status, Change::None);
    }
    match current.warned_at {
        None => {
            status.state = state::WARN;
            status.warned_at = Some(now);
            (status, Change::Warned)
        }
        Some(warned) if now - warned >= grace.warn_for => (inactive(status), Change::Inactive),
        Some(_) => (status, Change::None),
    }
}

fn inactive(mut status: Status) -> Status {
    status.state = state::DEFAULT;
    status.failing_since = None;
    status.warned_at = None;
    status.stopped_at = None;
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: i64 = 3600;
    const DAY: i64 = 24 * HOUR;

    fn check(owned: Option<bool>, mx_ours: Option<bool>) -> Found {
        Found { owned, mx_ours }
    }

    fn held() -> Status {
        Status {
            state: state::VERIFIED,
            verified_at: Some(0),
            ..Status::default()
        }
    }

    #[test]
    fn a_pending_domain_is_verified_once_its_code_is_there() {
        let pending = Status::default();
        let (status, change) = next(pending, check(Some(false), None), 10, Grace::default());
        assert_eq!((status, change), (pending, Change::None));
        let (status, change) = next(pending, check(Some(true), None), 10, Grace::default());
        assert_eq!(change, Change::Verified);
        assert!(status.usable());
    }

    #[test]
    fn an_unknown_answer_changes_nothing() {
        let mut current = held();
        current.failing_since = Some(5);
        assert_eq!(
            next(
                current,
                check(None, Some(false)),
                99 * DAY,
                Grace::default()
            ),
            (current, Change::None)
        );
    }

    #[test]
    fn txt_gone_mx_ours_warns_then_goes_inactive() {
        let grace = Grace::default();
        let (s, c) = next(held(), check(Some(false), Some(true)), 100, grace);
        assert_eq!((s.failing_since, c), (Some(100), Change::None));
        // A second failure too soon changes nothing.
        let (s, c) = next(s, check(Some(false), Some(true)), 100 + HOUR, grace);
        assert_eq!((s.state, c), (state::VERIFIED, Change::None));
        // Twelve hours on: warn, still usable.
        let (s, c) = next(s, check(Some(false), Some(true)), 100 + 12 * HOUR, grace);
        assert_eq!((s.state, c), (state::WARN, Change::Warned));
        assert!(s.usable());
        let (s, c) = next(
            s,
            check(Some(false), Some(true)),
            100 + 12 * HOUR + 13 * DAY,
            grace,
        );
        assert_eq!(c, Change::None);
        let (s, c) = next(
            s,
            check(Some(false), Some(true)),
            100 + 12 * HOUR + 14 * DAY,
            grace,
        );
        assert_eq!(c, Change::Inactive);
        assert!(s.inactive() && !s.usable());
        // Proving it again restores it.
        let (s, c) = next(s, check(Some(true), Some(true)), 200 * DAY, grace);
        assert_eq!(c, Change::Restored);
        assert!(s.usable() && s.failing_since.is_none());
    }

    #[test]
    fn txt_and_mx_gone_stop_at_once_then_go_inactive() {
        let grace = Grace::default();
        let (s, _) = next(held(), check(Some(false), Some(false)), 0, grace);
        let (s, c) = next(s, check(Some(false), Some(false)), 12 * HOUR, grace);
        assert_eq!(c, Change::Stopped);
        assert!(!s.usable() && !s.inactive());
        let (s, c) = next(
            s,
            check(Some(false), Some(false)),
            12 * HOUR + 71 * HOUR,
            grace,
        );
        assert_eq!(c, Change::None);
        let (s, c) = next(
            s,
            check(Some(false), Some(true)),
            12 * HOUR + 72 * HOUR,
            grace,
        );
        assert_eq!(c, Change::Inactive);
        assert!(s.inactive());
    }

    #[test]
    fn a_warned_domain_recovers_when_its_txt_returns() {
        let grace = Grace::default();
        let (s, _) = next(held(), check(Some(false), Some(true)), 0, grace);
        let (s, _) = next(s, check(Some(false), Some(true)), 12 * HOUR, grace);
        assert_eq!(s.state, state::WARN);
        let (s, c) = next(s, check(Some(true), Some(true)), 2 * DAY, grace);
        assert_eq!((s.state, c), (state::VERIFIED, Change::Restored));
        assert_eq!((s.warned_at, s.failing_since), (None, None));
    }

    #[test]
    fn grace_is_configurable() {
        let grace = Grace {
            confirm_after: 0,
            warn_for: DAY,
            stopped_for: HOUR,
        };
        let (s, _) = next(held(), check(Some(false), Some(true)), 0, grace);
        let (s, c) = next(s, check(Some(false), Some(true)), 1, grace);
        assert_eq!(c, Change::Warned);
        let (_, c) = next(s, check(Some(false), Some(true)), 1 + DAY, grace);
        assert_eq!(c, Change::Inactive);
    }
}
