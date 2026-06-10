//! In-memory rate limiting + TOTP brute-force tracking — mirrors
//! `backend/middleware/ratelimit.go`.
//!
//! Per-IP sliding-window limiters (login 10/min, preflight 20/min, recovery 5/hr,
//! federation user-lookup 60/min) and a per-pre-auth-token TOTP attempt tracker that
//! blocks a token for 15 min after 5 failures. All state is process-local, exactly like
//! the Go maps; `spawn_cleanup` runs the periodic pruning the Go `init()` goroutines did.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// Sliding-window limiter — mirrors `rateLimiter`.
pub struct RateLimiter {
    requests: Mutex<HashMap<String, Vec<Instant>>>,
    limit: usize,
    window: Duration,
}

impl RateLimiter {
    fn new(limit: usize, window: Duration) -> Self {
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

/// Recovery: 5 attempts / hour / IP — mirrors `recoveryLimiter`.
pub static RECOVERY: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(5, Duration::from_secs(3600)));
/// Federation username lookup: 60 / minute / IP — mirrors `fedUsersLimiter`.
pub static FED_USERS: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(60, Duration::from_secs(60)));
/// Login: 10 / minute / IP — mirrors `loginLimiter`.
pub static LOGIN: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(10, Duration::from_secs(60)));
/// Login preflight: 20 / minute / IP — mirrors `preflightLimiter`.
pub static PREFLIGHT: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(20, Duration::from_secs(60)));

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
