//! In-memory rate limiting + brute-force tracking.
//!
//! Three layers of protection, all process-local state:
//!  - **Per-IP sliding-window limiters** — login, login preflight, register, recovery,
//!    federation user-lookup, and the admin API. Defaults are env-overridable (`LIMITS`
//!    below, read and checked at boot); `RATE_LIMITS_RELAXED` raises them on test stacks.
//!  - **Sign-in lockout and ceiling** — N wrong secrets for one account from one client
//!    IP lock that pair out (defaults 5 / 15 min; `LOGIN_LOCKOUT_THRESHOLD`,
//!    `LOGIN_LOCKOUT_MINUTES`), and wrong secrets from clients the account does not
//!    know are capped per account (`LOGIN_ACCOUNT_CEILING`); see `auth_check`.
//!  - **Per-pre-auth-token TOTP tracker** — blocks a token for 15 min after 5 failures.
//!
//! `spawn_cleanup` runs the periodic pruning for all of the above.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, OnceLock};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// Every limit the environment may set, with its default. A `RATE_LIMIT_*`
/// name not listed here stops the server (a typo would silently keep the
/// default).
const LIMITS: &[(&str, u64)] = &[
    ("RATE_LIMIT_RECOVERY_PER_HOUR", 5),
    ("RATE_LIMIT_FED_USERS_PER_MIN", 60),
    ("RATE_LIMIT_LOGIN_PER_MIN", 10),
    ("RATE_LIMIT_FORK_PER_MIN", 120),
    ("RATE_LIMIT_CALL_LINK_PER_MIN", 60),
    ("RATE_LIMIT_CALL_LINK_POLL_PER_MIN", 600),
    ("RATE_LIMIT_PREFLIGHT_PER_MIN", 20),
    ("RATE_LIMIT_USER_LOOKUP_PER_MIN", 30),
    ("RATE_LIMIT_REGISTER_PER_HOUR", 10),
    ("RATE_LIMIT_REPORT_PER_HOUR", 20),
    ("RATE_LIMIT_FEEDBACK_PER_HOUR", 10),
    ("RATE_LIMIT_ADMIN_PER_MIN", 120),
    ("RATE_LIMIT_CHAT_KEYS_PER_MIN", 30),
    ("RATE_LIMIT_CHAT_KEYS_IP_PER_MIN", 120),
    ("RATE_LIMIT_CHAT_ANONYMOUS_IP_PER_MIN", 60),
    ("LOGIN_LOCKOUT_THRESHOLD", 5),
    ("LOGIN_LOCKOUT_MINUTES", 15),
    ("LOGIN_ACCOUNT_CEILING", 20),
    ("LOGIN_ACCOUNT_DAILY_CEILING", 200),
];

/// What a rate limit's default becomes on a test stack (`RATE_LIMITS_RELAXED`):
/// high enough that a test suite signing in hundreds of times never meets
/// it. The per-account lockout keeps its defaults: tests rarely miss a
/// password, and some check that the lockout comes.
const RELAXED: u64 = 100_000;

static CONFIGURED: OnceLock<HashMap<&'static str, u64>> = OnceLock::new();

/// Reads every limit through the boot-time configuration pass (`Env`
/// records a bad value), before any limiter is first used.
pub(crate) fn configure(env: &crate::config::Env, relaxed: bool) {
    if let Some(unknown) = env.unknown_with_prefix("RATE_LIMIT_", LIMITS) {
        for name in unknown {
            env.error(format!("{name} is not a rate limit this server has"));
        }
    }
    let limits = LIMITS
        .iter()
        .map(|&(name, default)| {
            let default = if relaxed && name.starts_with("RATE_LIMIT_") {
                RELAXED
            } else {
                default
            };
            (name, env.positive(name, default))
        })
        .collect();
    let _ = CONFIGURED.set(limits);
}

/// A limit as configured at boot; its default where nothing configured it
/// (unit tests).
fn env_limit(var: &str, default: u64) -> u64 {
    CONFIGURED
        .get()
        .and_then(|limits| limits.get(var).copied())
        .unwrap_or(default)
}

/// Sliding-window limiter — mirrors `rateLimiter`.
pub struct RateLimiter {
    requests: Mutex<HashMap<String, Vec<Instant>>>,
    limit: usize,
    window: Duration,
}

impl RateLimiter {
    pub(crate) fn new(limit: usize, window: Duration) -> Self {
        Self {
            requests: Mutex::new(HashMap::new()),
            limit,
            window,
        }
    }

    /// Records an attempt for `key`, returning false when over the limit — mirrors `Allow`.
    pub fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut map = self.requests.lock().unwrap();
        let times = map.entry(key.to_string()).or_default();
        times.retain(|t| now.duration_since(*t) < self.window);
        if times.len() >= self.limit {
            return false;
        }
        times.push(now);
        true
    }

    /// Gives back the newest event of `key` (an attempt that turned out
    /// right).
    pub fn pop(&self, key: &str) {
        let mut map = self.requests.lock().unwrap();
        if let Some(times) = map.get_mut(key) {
            times.pop();
        }
    }

    /// Drops empty/expired entries — mirrors the Go `cleanup` goroutine body.
    pub(crate) fn cleanup(&self) {
        let now = Instant::now();
        let mut map = self.requests.lock().unwrap();
        map.retain(|_, times| {
            times.retain(|t| now.duration_since(*t) < self.window);
            !times.is_empty()
        });
    }
}

/// Recovery: 5 attempts / hour / IP (`RATE_LIMIT_RECOVERY_PER_HOUR`).
pub static RECOVERY: LazyLock<RateLimiter> = LazyLock::new(|| {
    RateLimiter::new(
        env_limit("RATE_LIMIT_RECOVERY_PER_HOUR", 5) as usize,
        Duration::from_secs(3600),
    )
});
/// Federation username lookup: 60 / minute / IP (`RATE_LIMIT_FED_USERS_PER_MIN`).
pub static FED_USERS: LazyLock<RateLimiter> = LazyLock::new(|| {
    RateLimiter::new(
        env_limit("RATE_LIMIT_FED_USERS_PER_MIN", 60) as usize,
        Duration::from_secs(60),
    )
});
/// Login (+ the 2FA step): 10 / minute / IP (`RATE_LIMIT_LOGIN_PER_MIN`).
pub static LOGIN: LazyLock<RateLimiter> = LazyLock::new(|| {
    RateLimiter::new(
        env_limit("RATE_LIMIT_LOGIN_PER_MIN", 10) as usize,
        Duration::from_secs(60),
    )
});
/// Session hand-off to an app: 120 / minute / IP (`RATE_LIMIT_FORK_PER_MIN`).
/// Every app a person opens redeems one fork, so a signed-in household
/// spends several a minute; a fork is redeemed with a one-time random
/// selector, not a credential, so this is a flood wall rather than a
/// guessing budget and must not share the login allowance.
pub static FORK: LazyLock<RateLimiter> = LazyLock::new(|| {
    RateLimiter::new(
        env_limit("RATE_LIMIT_FORK_PER_MIN", 120) as usize,
        Duration::from_secs(60),
    )
});
/// Opening and joining a call through a link, which need no account: 60 /
/// minute / IP (`RATE_LIMIT_CALL_LINK_PER_MIN`).
pub static CALL_LINK: LazyLock<RateLimiter> = LazyLock::new(|| {
    RateLimiter::new(
        env_limit("RATE_LIMIT_CALL_LINK_PER_MIN", 60) as usize,
        Duration::from_secs(60),
    )
});
/// Waiting to be let into a meeting, and watching who waits: each side asks
/// every few seconds, and several people may share an address. 600 / minute
/// / IP (`RATE_LIMIT_CALL_LINK_POLL_PER_MIN`).
pub static CALL_LINK_POLL: LazyLock<RateLimiter> = LazyLock::new(|| {
    RateLimiter::new(
        env_limit("RATE_LIMIT_CALL_LINK_POLL_PER_MIN", 600) as usize,
        Duration::from_secs(60),
    )
});
/// Login preflight: 20 / minute / IP (`RATE_LIMIT_PREFLIGHT_PER_MIN`).
pub static PREFLIGHT: LazyLock<RateLimiter> = LazyLock::new(|| {
    RateLimiter::new(
        env_limit("RATE_LIMIT_PREFLIGHT_PER_MIN", 20) as usize,
        Duration::from_secs(60),
    )
});
/// Looking a user up by email: 30 / minute / IP (`RATE_LIMIT_USER_LOOKUP_PER_MIN`).
/// Sharing needs a handful; a higher rate is someone enumerating accounts.
pub static USER_LOOKUP: LazyLock<RateLimiter> = LazyLock::new(|| {
    RateLimiter::new(
        env_limit("RATE_LIMIT_USER_LOOKUP_PER_MIN", 30) as usize,
        Duration::from_secs(60),
    )
});
/// Register: 10 / hour / IP (`RATE_LIMIT_REGISTER_PER_HOUR`). Registration is rare
/// per-human; this mostly stops scripted account spam on open-registration servers.
pub static REGISTER: LazyLock<RateLimiter> = LazyLock::new(|| {
    RateLimiter::new(
        env_limit("RATE_LIMIT_REGISTER_PER_HOUR", 10) as usize,
        Duration::from_secs(3600),
    )
});
/// Reports on public links: 20 / hour / IP (`RATE_LIMIT_REPORT_PER_HOUR`). Anyone
/// may report, without an account; a person reports a few, a script many.
pub static REPORT: LazyLock<RateLimiter> = LazyLock::new(|| {
    RateLimiter::new(
        env_limit("RATE_LIMIT_REPORT_PER_HOUR", 20) as usize,
        Duration::from_secs(3600),
    )
});
/// Feedback: 10 / hour / account (`RATE_LIMIT_FEEDBACK_PER_HOUR`). A person
/// sends a few; more is someone filling the administrators' inbox.
pub static FEEDBACK: LazyLock<RateLimiter> = LazyLock::new(|| {
    RateLimiter::new(
        env_limit("RATE_LIMIT_FEEDBACK_PER_HOUR", 10) as usize,
        Duration::from_secs(3600),
    )
});
/// Admin API: 120 / minute / IP (`RATE_LIMIT_ADMIN_PER_MIN`). The dashboard fires a
/// handful of requests per view; 120/min is generous for a human and a wall for a script.
pub static ADMIN: LazyLock<RateLimiter> = LazyLock::new(|| {
    RateLimiter::new(
        env_limit("RATE_LIMIT_ADMIN_PER_MIN", 120) as usize,
        Duration::from_secs(60),
    )
});
/// Chat prekey-bundle fetch: 30 / minute / authenticated account
/// (`RATE_LIMIT_CHAT_KEYS_PER_MIN`). Bundle fetches consume one-time prekeys, so
/// this is the primary anti-drain budget regardless of source IP.
pub static CHAT_KEYS_ACCOUNT: LazyLock<RateLimiter> = LazyLock::new(|| {
    RateLimiter::new(
        env_limit("RATE_LIMIT_CHAT_KEYS_PER_MIN", 30) as usize,
        Duration::from_secs(60),
    )
});

/// Coarse 120 / minute / IP outer wall for chat bundle fetches. This is
/// deliberately looser than the account budget so unrelated mobile users behind
/// one CGNAT address do not consume each other's primary allowance.
pub static CHAT_KEYS_IP: LazyLock<RateLimiter> = LazyLock::new(|| {
    RateLimiter::new(
        env_limit("RATE_LIMIT_CHAT_KEYS_IP_PER_MIN", 120) as usize,
        Duration::from_secs(60),
    )
});

/// Anonymous sealed-delivery outer wall: 60 attempts/minute/IP. Durable
/// capability, recipient, and origin counters remain the authoritative layer.
pub static CHAT_ANONYMOUS_IP: LazyLock<RateLimiter> = LazyLock::new(|| {
    RateLimiter::new(
        env_limit("RATE_LIMIT_CHAT_ANONYMOUS_IP_PER_MIN", 60) as usize,
        Duration::from_secs(60),
    )
});

// --- per-account login lockout ---

/// Wrong-secret tracker for the sign-in check (`auth_check`), keyed by a hash
/// of what the caller locks (an account or name with a client). Each attempt
/// takes its slot before the check (`reserve`), so parallel attempts get no
/// more than the threshold; a right secret clears it.
pub struct LoginLockout {
    state: Mutex<LockoutState>,
    threshold: u32,
    ttl: Duration,
}

struct LockoutState {
    /// Attempts counted, and when the last one came.
    failures: HashMap<String, (u32, Instant)>,
    locked_at: HashMap<String, Instant>,
}

impl LoginLockout {
    fn new(threshold: u32, ttl: Duration) -> Self {
        Self {
            state: Mutex::new(LockoutState {
                failures: HashMap::new(),
                locked_at: HashMap::new(),
            }),
            threshold,
            ttl,
        }
    }

    fn key(subject: &str) -> String {
        hash_token(&subject.to_lowercase())
    }

    fn locked(&self, st: &mut LockoutState, key: &str) -> bool {
        if let Some(at) = st.locked_at.get(key).copied() {
            if at.elapsed() < self.ttl {
                return true;
            }
            st.locked_at.remove(key);
            st.failures.remove(key);
        }
        false
    }

    /// Whether `subject` is locked out now.
    #[cfg(test)]
    fn is_locked(&self, subject: &str) -> bool {
        let key = Self::key(subject);
        let mut st = self.state.lock().unwrap();
        self.locked(&mut st, &key)
    }

    /// Takes a slot for one attempt: `false` while locked. The attempt counts
    /// as a miss until [`Self::succeeded`] says otherwise; the threshold-th
    /// one locks the subject for the cooldown.
    pub fn reserve(&self, subject: &str) -> bool {
        let key = Self::key(subject);
        let mut st = self.state.lock().unwrap();
        if self.locked(&mut st, &key) {
            return false;
        }
        let now = Instant::now();
        let entry = st.failures.entry(key.clone()).or_insert((0, now));
        if entry.1.elapsed() >= self.ttl {
            *entry = (0, now);
        }
        entry.0 += 1;
        entry.1 = now;
        if entry.0 >= self.threshold {
            st.locked_at.insert(key, now);
        }
        true
    }

    /// A right secret: the subject's misses (and any lock) are cleared.
    pub fn succeeded(&self, subject: &str) {
        let key = Self::key(subject);
        let mut st = self.state.lock().unwrap();
        st.failures.remove(&key);
        st.locked_at.remove(&key);
    }

    fn cleanup(&self) {
        let mut st = self.state.lock().unwrap();
        let ttl = self.ttl;
        st.locked_at.retain(|_, at| at.elapsed() < ttl);
        // Counters expire one by one with the window: spraying many
        // subjects never resets anyone else's.
        st.failures.retain(|_, (_, last)| last.elapsed() < ttl);
    }
}

/// 5 failures → 15 min lockout (`LOGIN_LOCKOUT_THRESHOLD`, `LOGIN_LOCKOUT_MINUTES`).
pub static LOGIN_LOCKOUT: LazyLock<LoginLockout> = LazyLock::new(|| {
    LoginLockout::new(
        env_limit("LOGIN_LOCKOUT_THRESHOLD", 5) as u32,
        Duration::from_secs(env_limit("LOGIN_LOCKOUT_MINUTES", 15) * 60),
    )
});

/// Attempts on one account from clients it does not know, all of them
/// together, in the lockout's window (`LOGIN_ACCOUNT_CEILING`, 20) and per
/// day (`LOGIN_ACCOUNT_DAILY_CEILING`, 200): the cap on guessing spread over
/// many addresses (`auth_check`). Slots are taken before the check and given
/// back on a right secret.
pub static LOGIN_CEILING: LazyLock<RateLimiter> = LazyLock::new(|| {
    RateLimiter::new(
        env_limit("LOGIN_ACCOUNT_CEILING", 20) as usize,
        Duration::from_secs(env_limit("LOGIN_LOCKOUT_MINUTES", 15) * 60),
    )
});

pub static LOGIN_DAILY_CEILING: LazyLock<RateLimiter> = LazyLock::new(|| {
    RateLimiter::new(
        env_limit("LOGIN_ACCOUNT_DAILY_CEILING", 200) as usize,
        Duration::from_secs(24 * 3600),
    )
});

// --- TOTP brute-force tracker (mirrors the `totpTracker` struct) ---

const MAX_TOTP_ATTEMPTS: u32 = 5;
const TOTP_BLOCK_TTL: Duration = Duration::from_secs(15 * 60);

struct TotpTracker {
    attempts: HashMap<String, u32>,
    blocked_at: HashMap<String, Instant>,
}

static TOTP_TRACKER: LazyLock<Mutex<TotpTracker>> = LazyLock::new(|| {
    Mutex::new(TotpTracker {
        attempts: HashMap::new(),
        blocked_at: HashMap::new(),
    })
});

/// SHA-256 hex of a token — mirrors `hashToken` (tokens are never stored in the clear).
pub(crate) fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex::encode(digest)
}

/// Whether this pre-auth token is currently blocked — mirrors `IsTOTPBlocked`.
pub fn is_totp_blocked(pre_auth_token: &str) -> bool {
    let key = hash_token(pre_auth_token);
    let tracker = TOTP_TRACKER.lock().unwrap();
    tracker.blocked_at.contains_key(&key)
}

/// Records a TOTP attempt result; returns false once the token is blocked — mirrors
/// `RecordTOTPAttempt`. Success clears the counter; the 5th failure blocks the token.
pub fn record_totp_attempt(pre_auth_token: &str, success: bool) -> bool {
    let key = hash_token(pre_auth_token);
    let mut tracker = TOTP_TRACKER.lock().unwrap();

    if tracker.blocked_at.contains_key(&key) {
        return false;
    }
    if success {
        tracker.attempts.remove(&key);
        return true;
    }
    let count = tracker.attempts.entry(key.clone()).or_insert(0);
    *count += 1;
    if *count >= MAX_TOTP_ATTEMPTS {
        tracker.blocked_at.insert(key, Instant::now());
        return false;
    }
    true
}

/// Prunes expired TOTP blocks — mirrors the Go `init()` cleanup goroutine.
fn cleanup_totp_tracker() {
    let now = Instant::now();
    let mut tracker = TOTP_TRACKER.lock().unwrap();
    let expired: Vec<String> = tracker
        .blocked_at
        .iter()
        .filter(|(_, t)| now.duration_since(**t) >= TOTP_BLOCK_TTL)
        .map(|(k, _)| k.clone())
        .collect();
    for key in expired {
        tracker.blocked_at.remove(&key);
        tracker.attempts.remove(&key);
    }
}

/// Spawns the 5-minute background pruning task — replaces the Go `init()` goroutines.
pub fn spawn_cleanup() {
    tokio::spawn(async {
        let mut tick = tokio::time::interval(Duration::from_secs(5 * 60));
        tick.tick().await; // consume the immediate first tick
        loop {
            tick.tick().await;
            RECOVERY.cleanup();
            FED_USERS.cleanup();
            LOGIN.cleanup();
            PREFLIGHT.cleanup();
            FORK.cleanup();
            CALL_LINK.cleanup();
            CALL_LINK_POLL.cleanup();
            USER_LOOKUP.cleanup();
            REGISTER.cleanup();
            ADMIN.cleanup();
            CHAT_KEYS_ACCOUNT.cleanup();
            CHAT_KEYS_IP.cleanup();
            LOGIN_LOCKOUT.cleanup();
            LOGIN_CEILING.cleanup();
            LOGIN_DAILY_CEILING.cleanup();
            cleanup_totp_tracker();
            // Per-feature limiters kept beside their handlers.
            crate::handlers::chat_link_preview::LINK_PREVIEWS.cleanup();
            crate::handlers::pass_icons::PASS_ICONS.cleanup();
            crate::handlers::pass_icons::PASS_ICON_FETCHES.cleanup();
            crate::handlers::mail_images::MAIL_IMAGES.cleanup();
            crate::handlers::mail_images::cleanup();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_blocks_after_limit() {
        let rl = RateLimiter::new(3, Duration::from_secs(60));
        assert!(rl.allow("ip"));
        assert!(rl.allow("ip"));
        assert!(rl.allow("ip"));
        assert!(!rl.allow("ip")); // 4th in window is denied
        assert!(rl.allow("other")); // separate key unaffected
    }

    #[test]
    fn totp_blocks_after_five_failures() {
        let token = "pre-auth-token-A";
        for _ in 0..4 {
            assert!(record_totp_attempt(token, false));
            assert!(!is_totp_blocked(token));
        }
        // 5th failure trips the block.
        assert!(!record_totp_attempt(token, false));
        assert!(is_totp_blocked(token));
        // Once blocked, further attempts stay denied.
        assert!(!record_totp_attempt(token, true));
    }

    #[test]
    fn lockout_trips_after_threshold_and_expires() {
        let lo = LoginLockout::new(3, Duration::from_millis(50));
        let subject = "account:A";
        assert!(lo.reserve(subject));
        assert!(lo.reserve(subject));
        assert!(!lo.is_locked(subject));
        assert!(lo.reserve(subject)); // the 3rd attempt still runs, and locks
        assert!(lo.is_locked(subject));
        assert!(!lo.reserve(subject));
        // The lock expires after the TTL, and the counter with it.
        std::thread::sleep(Duration::from_millis(60));
        assert!(lo.reserve(subject));
        assert!(!lo.is_locked(subject));
    }

    #[test]
    fn lockout_success_clears_failures() {
        let lo = LoginLockout::new(3, Duration::from_secs(60));
        let subject = "account:B";
        lo.reserve(subject);
        lo.reserve(subject);
        lo.succeeded(subject); // a right secret resets the counter
        lo.reserve(subject);
        lo.reserve(subject);
        assert!(!lo.is_locked(subject));
    }

    #[test]
    fn lockout_cleanup_keeps_other_subjects_counters() {
        let lo = LoginLockout::new(3, Duration::from_secs(60));
        lo.reserve("victim");
        lo.reserve("victim");
        for i in 0..20_000 {
            lo.reserve(&format!("spray-{i}"));
        }
        lo.cleanup();
        lo.reserve("victim");
        assert!(lo.is_locked("victim"));
    }

    #[test]
    fn totp_success_clears_counter() {
        let token = "pre-auth-token-B";
        assert!(record_totp_attempt(token, false));
        assert!(record_totp_attempt(token, false));
        assert!(record_totp_attempt(token, true)); // success resets
                                                   // Counter cleared: can fail 4 more times without blocking.
        for _ in 0..4 {
            assert!(record_totp_attempt(token, false));
        }
        assert!(!is_totp_blocked(token));
    }
}
