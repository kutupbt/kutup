//! Background job heartbeats (docs/plans/restore-drill-and-alerting.md,
//! Part 2 A): each job this process runs registers with its interval, and
//! records its last successful pass in `job_heartbeats`.
//! `/api/health/ready` reports a job that has not succeeded within twice its
//! interval plus `health_job_grace_seconds`.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use sqlx::PgPool;
use time::OffsetDateTime;

/// A job's registration in this process.
#[derive(Clone, Copy, Debug)]
pub struct Registered {
    pub interval: Duration,
    /// When this process started running it.
    pub since: OffsetDateTime,
    /// When this process last wrote its heartbeat.
    written: Option<Instant>,
}

fn jobs() -> &'static Mutex<BTreeMap<&'static str, Registered>> {
    static JOBS: OnceLock<Mutex<BTreeMap<&'static str, Registered>>> = OnceLock::new();
    JOBS.get_or_init(Default::default)
}

/// Says this process runs `job` every `interval`. Called when the job is
/// spawned (so one that never succeeds is still reported) and again when a
/// job's interval is a setting that may have changed.
pub fn register(job: &'static str, interval: Duration) {
    let mut jobs = jobs()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    jobs.entry(job)
        .and_modify(|entry| entry.interval = interval)
        .or_insert(Registered {
            interval,
            since: OffsetDateTime::now_utc(),
            written: None,
        });
}

/// The jobs this process runs, by name.
pub fn registered() -> Vec<(&'static str, Registered)> {
    jobs()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .map(|(name, entry)| (*name, *entry))
        .collect()
}

/// A heartbeat is written at most this often per job, so a job that runs
/// every few seconds doesn't write a row every few seconds.
const WRITE_AT_MOST_EVERY: Duration = Duration::from_secs(60);

/// Records a successful pass of `job`. A failure to record is logged, never
/// raised: the job itself succeeded.
pub async fn beat(pool: &PgPool, job: &'static str) {
    {
        let mut jobs = jobs()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(entry) = jobs.get_mut(job) {
            if entry
                .written
                .is_some_and(|written| written.elapsed() < WRITE_AT_MOST_EVERY)
            {
                return;
            }
            entry.written = Some(Instant::now());
        }
    }
    if let Err(error) = sqlx::query(
        "INSERT INTO job_heartbeats (job, last_success_at) VALUES ($1, now())
         ON CONFLICT (job) DO UPDATE SET last_success_at = EXCLUDED.last_success_at",
    )
    .bind(job)
    .execute(pool)
    .await
    {
        tracing::warn!(job, %error, "job heartbeat not recorded");
    }
}

/// A job's state for the readiness check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    /// It succeeded within its window.
    Ok,
    /// It hasn't succeeded yet, and this process started it within its
    /// window: not a failure yet.
    Starting,
    /// No success within its window.
    Late,
}

/// Judges one job: `last_success` from `job_heartbeats`, `window` twice its
/// interval plus the grace.
pub fn judge(
    now: OffsetDateTime,
    registered: &Registered,
    last_success: Option<OffsetDateTime>,
    grace: Duration,
) -> JobState {
    let window = registered.interval.saturating_mul(2).saturating_add(grace);
    let window = time::Duration::try_from(window).unwrap_or(time::Duration::MAX);
    if last_success.is_some_and(|at| now - at <= window) {
        return JobState::Ok;
    }
    if now - registered.since <= window {
        return JobState::Starting;
    }
    JobState::Late
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(interval_seconds: u64, started_ago: i64, now: OffsetDateTime) -> Registered {
        Registered {
            interval: Duration::from_secs(interval_seconds),
            since: now - time::Duration::seconds(started_ago),
            written: None,
        }
    }

    #[test]
    fn a_job_is_late_only_after_twice_its_interval_and_the_grace() {
        let now = OffsetDateTime::now_utc();
        let grace = Duration::from_secs(600);
        let ago = |seconds: i64| Some(now - time::Duration::seconds(seconds));
        // Hourly: the window is 2 h 10 min.
        let hourly = job(3600, 86_400, now);
        assert_eq!(judge(now, &hourly, ago(10), grace), JobState::Ok);
        assert_eq!(judge(now, &hourly, ago(7800), grace), JobState::Ok);
        assert_eq!(judge(now, &hourly, ago(7801), grace), JobState::Late);
        assert_eq!(judge(now, &hourly, None, grace), JobState::Late);
        // Just started, never succeeded: starting, until its window is over.
        assert_eq!(
            judge(now, &job(3600, 60, now), None, grace),
            JobState::Starting
        );
        assert_eq!(
            judge(now, &job(3600, 7801, now), None, grace),
            JobState::Late
        );
        // A success recorded by an earlier process counts.
        assert_eq!(
            judge(now, &job(3600, 5, now), ago(100), grace),
            JobState::Ok
        );
    }

    #[test]
    fn registering_again_keeps_the_start_and_takes_the_new_interval() {
        register("test.job", Duration::from_secs(5));
        let first = registered()
            .into_iter()
            .find(|(name, _)| *name == "test.job")
            .unwrap()
            .1;
        register("test.job", Duration::from_secs(50));
        let second = registered()
            .into_iter()
            .find(|(name, _)| *name == "test.job")
            .unwrap()
            .1;
        assert_eq!(second.interval, Duration::from_secs(50));
        assert_eq!(first.since, second.since);
    }
}
