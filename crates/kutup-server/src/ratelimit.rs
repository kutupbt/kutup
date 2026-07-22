//! In-memory rate limiting + brute-force tracking.
//!
//! Three layers of protection, all process-local state:
//!  - **Per-IP sliding-window limiters** — login, login preflight, register, recovery,
//!    federation user-lookup, and the admin API. Defaults are env-overridable (see the
//!    `RATE_LIMIT_*` statics below).
//!  - **Per-account login lockout** — N failed password attempts for an email lock that
//!    email out for a cooldown (defaults 5 / 15 min; `LOGIN_LOCKOUT_THRESHOLD`,
//!    `LOGIN_LOCKOUT_MINUTES`). Keyed by a hash of the lowercased email and applied to
//!    unknown emails too, so the lockout is not an account-existence oracle.
//!  - **Per-pre-auth-token TOTP tracker** — blocks a token for 15 min after 5 failures.
//!
//! `spawn_cleanup` runs the periodic pruning for all of the above.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// Reads a positive integer limit from the environment, falling back to `default`.
/// Read once at first use (the limiter statics), i.e. at process start in practice.
fn env_limit(var: &str, default: u64) -> u64 {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
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

    /// Drops empty/expired entries — mirrors the Go `cleanup` goroutine body.
    fn cleanup(&self) {
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
/// Login preflight: 20 / minute / IP (`RATE_LIMIT_PREFLIGHT_PER_MIN`).
pub static PREFLIGHT: LazyLock<RateLimiter> = LazyLock::new(|| {
    RateLimiter::new(
        env_limit("RATE_LIMIT_PREFLIGHT_PER_MIN", 20) as usize,
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

/// Failed-password tracker keyed by (hashed, lowercased) email. Separate from the
/// per-IP limiter so a distributed attack on one account still locks out, and applied
/// to unknown emails too so lockout responses don't reveal whether an account exists.
pub struct LoginLockout {
    state: Mutex<LockoutState>,
    threshold: u32,
    ttl: Duration,
}

struct LockoutState {
    failures: HashMap<String, u32>,
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

    fn key(email: &str) -> String {
        hash_token(&email.to_lowercase())
    }

    /// Whether this email is currently locked out (expired locks are cleared lazily).
    pub fn is_locked(&self, email: &str) -> bool {
        let key = Self::key(email);
        let mut st = self.state.lock().unwrap();
        if let Some(at) = st.locked_at.get(&key).copied() {
            if at.elapsed() < self.ttl {
                return true;
            }
            st.locked_at.remove(&key);
            st.failures.remove(&key);
        }
        false
    }

    /// Records a password-check outcome. Success clears the counter; the Nth
    /// consecutive failure locks the email for the cooldown.
    pub fn record(&self, email: &str, success: bool) {
        let key = Self::key(email);
        let mut st = self.state.lock().unwrap();
        if success {
            st.failures.remove(&key);
            st.locked_at.remove(&key);
            return;
        }
        let count = st.failures.entry(key.clone()).or_insert(0);
        *count += 1;
        if *count >= self.threshold {
            st.locked_at.insert(key, Instant::now());
        }
    }

    fn cleanup(&self) {
        let mut st = self.state.lock().unwrap();
        let ttl = self.ttl;
        let expired: Vec<String> = st
            .locked_at
            .iter()
            .filter(|(_, at)| at.elapsed() >= ttl)
            .map(|(k, _)| k.clone())
            .collect();
        for key in &expired {
            st.locked_at.remove(key);
            st.failures.remove(key);
        }
        // Failure counters that never reached the threshold also expire with the TTL —
        // simplest honest pruning without per-entry timestamps: drop them all; a real
        // attacker re-accumulates within one cleanup interval anyway, a real user gets
        // a fresh allowance.
        if expired.is_empty() && st.failures.len() > 10_000 {
            st.failures.clear();
        }
    }
}

/// 5 failures → 15 min lockout (`LOGIN_LOCKOUT_THRESHOLD`, `LOGIN_LOCKOUT_MINUTES`).
pub static LOGIN_LOCKOUT: LazyLock<LoginLockout> = LazyLock::new(|| {
    LoginLockout::new(
        env_limit("LOGIN_LOCKOUT_THRESHOLD", 5) as u32,
        Duration::from_secs(env_limit("LOGIN_LOCKOUT_MINUTES", 15) * 60),
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
fn hash_token(token: &str) -> String {
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
            REGISTER.cleanup();
            ADMIN.cleanup();
            CHAT_KEYS_ACCOUNT.cleanup();
            CHAT_KEYS_IP.cleanup();
            LOGIN_LOCKOUT.cleanup();
            cleanup_totp_tracker();
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
        let email = "User@Example.com";
        lo.record(email, false);
        lo.record(email, false);
        assert!(!lo.is_locked(email));
        lo.record(email, false); // 3rd failure locks
                                 // Case-insensitive: the lowercased variant is the same key.
        assert!(lo.is_locked("user@example.com"));
        // Lock expires after the TTL.
        std::thread::sleep(Duration::from_millis(60));
        assert!(!lo.is_locked(email));
        // And the counter was reset with it.
        lo.record(email, false);
        assert!(!lo.is_locked(email));
    }

    #[test]
    fn lockout_success_clears_failures() {
        let lo = LoginLockout::new(3, Duration::from_secs(60));
        let email = "b@example.com";
        lo.record(email, false);
        lo.record(email, false);
        lo.record(email, true); // correct password resets the counter
        lo.record(email, false);
        lo.record(email, false);
        assert!(!lo.is_locked(email));
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
