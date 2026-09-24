//! Which versions of a file to keep (docs/plans/drive-versions-v2.md):
//! everything from the last day, then the newest per hour for a week, then
//! the newest per day up to the owner's retention, nothing beyond it. The
//! newest version and `keep_forever` ones are always kept.

use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// The retention choices an account can make, in days.
pub const RETENTION_DAYS: [i32; 6] = [7, 30, 90, 180, 365, 3650];

pub struct Candidate {
    pub id: Uuid,
    pub created_at: OffsetDateTime,
    pub keep_forever: bool,
}

/// The versions to delete, given one file's versions **newest first**.
pub fn doomed(versions: &[Candidate], now: OffsetDateTime, retention_days: i64) -> Vec<Uuid> {
    let mut out = Vec::new();
    // The newest version seen in each hour / day bucket is its keeper.
    let mut kept_hours = std::collections::HashSet::new();
    let mut kept_days = std::collections::HashSet::new();
    for (index, version) in versions.iter().enumerate() {
        if index == 0 || version.keep_forever {
            continue;
        }
        let age = now - version.created_at;
        if age < Duration::days(1) {
            continue;
        }
        if age > Duration::days(retention_days) {
            out.push(version.id);
            continue;
        }
        let unix = version.created_at.unix_timestamp();
        let fresh = if age < Duration::days(7) {
            kept_hours.insert(unix.div_euclid(3600))
        } else {
            kept_days.insert(unix.div_euclid(86_400))
        };
        if !fresh {
            out.push(version.id);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(n: u128, age: Duration, keep_forever: bool, now: OffsetDateTime) -> Candidate {
        Candidate {
            id: Uuid::from_u128(n),
            created_at: now - age,
            keep_forever,
        }
    }

    fn now() -> OffsetDateTime {
        // A fixed instant on the hour, so bucket edges are predictable.
        OffsetDateTime::from_unix_timestamp(1_790_000_000 - 1_790_000_000 % 86_400).unwrap()
    }

    #[test]
    fn keeps_the_last_day_whole() {
        let now = now();
        let versions: Vec<_> = (0..48)
            .map(|i| version(i, Duration::minutes(i as i64 * 20), false, now))
            .collect();
        let doomed = doomed(&versions, now, 30);
        // 48 versions over 16 hours: all younger than a day.
        assert!(doomed.is_empty());
    }

    #[test]
    fn thins_to_one_per_hour_then_one_per_day() {
        let now = now();
        let versions = vec![
            version(1, Duration::minutes(1), false, now),
            // Two in the same hour, three days ago: the older goes.
            version(2, Duration::days(3) + Duration::minutes(10), false, now),
            version(3, Duration::days(3) + Duration::minutes(40), false, now),
            // Two on the same day, twenty days ago (different hours): the older goes.
            version(4, Duration::days(20) + Duration::hours(1), false, now),
            version(5, Duration::days(20) + Duration::hours(5), false, now),
        ];
        assert_eq!(
            doomed(&versions, now, 30),
            vec![Uuid::from_u128(3), Uuid::from_u128(5)]
        );
    }

    #[test]
    fn drops_what_is_past_retention_but_never_the_newest_or_kept() {
        let now = now();
        let versions = vec![
            // The newest, however old, stays: a file always has its latest.
            version(1, Duration::days(400), false, now),
            version(2, Duration::days(401), true, now),
            version(3, Duration::days(402), false, now),
        ];
        assert_eq!(doomed(&versions, now, 365), vec![Uuid::from_u128(3)]);
        assert_eq!(doomed(&versions, now, 3650), Vec::<Uuid>::new());
    }

    #[test]
    fn kept_versions_do_not_take_a_bucket() {
        let now = now();
        let versions = vec![
            version(1, Duration::minutes(1), false, now),
            version(2, Duration::days(10) + Duration::hours(1), true, now),
            version(3, Duration::days(10) + Duration::hours(2), false, now),
        ];
        // The kept one does not stand in for its day: the other survives too.
        assert!(doomed(&versions, now, 30).is_empty());
    }
}
