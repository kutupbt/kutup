//! Custom mail domains (docs/plans/mail-custom-domains.md): an account's own
//! domains, verified by a TXT record before any mail flows, checked as
//! Proton checks them, kept in step with Stalwart.
//!
//! - [`name`]: what may be added.
//! - [`records`]: each DNS record's state, in Proton's numbers.
//! - [`policy`]: what a check does to the domain (the grace by cause).
//! - [`reconcile`]: Stalwart's domains and DKIM signatures follow the
//!   database.

pub mod check;
pub mod dkim;
pub mod dns;
pub mod name;
pub mod policy;
pub mod reconcile;
pub mod records;
pub mod settings;
pub mod stalwart;
pub mod store;
pub mod sweep;

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Whether `domain`'s catch-all may take one more message today, within
/// `per_day` (the site setting); past it, RCPT answers as for an unknown
/// name, and senders retry or give up. Counted in memory: a restart only
/// starts the day's count over.
pub fn catch_all_allows(domain: uuid::Uuid, per_day: i64) -> bool {
    static COUNTS: OnceLock<Mutex<HashMap<uuid::Uuid, (i64, i64)>>> = OnceLock::new();
    let today = time::OffsetDateTime::now_utc().unix_timestamp() / 86_400;
    let mut counts = COUNTS
        .get_or_init(Default::default)
        .lock()
        .expect("catch-all counts");
    counts.retain(|_, (day, _)| *day == today);
    let (_, count) = counts.entry(domain).or_insert((today, 0));
    if *count >= per_day {
        return false;
    }
    *count += 1;
    true
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_catch_all_takes_its_daily_cap_and_no_more() {
        let domain = uuid::Uuid::new_v4();
        assert!((0..3).all(|_| super::catch_all_allows(domain, 3)));
        assert!(!super::catch_all_allows(domain, 3));
        assert!(super::catch_all_allows(uuid::Uuid::new_v4(), 3));
        assert!(!super::catch_all_allows(uuid::Uuid::new_v4(), 0));
    }
}
