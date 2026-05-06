package middleware

import (
	"testing"
	"time"
)

// We test the rateLimiter directly (rather than via the fiber.Handler) so
// we can control the limit + window per test without sharing state across
// the package-level limiters (loginLimiter, recoveryLimiter, etc.).

func TestRateLimiter_AllowsUpToLimit(t *testing.T) {
	rl := newRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !rl.Allow("ip-1") {
			t.Fatalf("call %d denied, want allowed", i+1)
		}
	}
	if rl.Allow("ip-1") {
		t.Error("4th call must be denied (limit=3)")
	}
}

func TestRateLimiter_PerKeyIsolation(t *testing.T) {
	rl := newRateLimiter(2, time.Minute)
	if !rl.Allow("ip-A") || !rl.Allow("ip-A") {
		t.Fatal("ip-A first two should be allowed")
	}
	if rl.Allow("ip-A") {
		t.Error("ip-A 3rd must be denied")
	}
	// ip-B has its own counter — must still be allowed.
	if !rl.Allow("ip-B") {
		t.Error("ip-B must be allowed (separate key)")
	}
}

func TestRateLimiter_WindowExpiresEntries(t *testing.T) {
	// Tiny window so the test runs fast.
	rl := newRateLimiter(1, 50*time.Millisecond)
	if !rl.Allow("k") {
		t.Fatal("first call denied")
	}
	if rl.Allow("k") {
		t.Fatal("second call inside window must be denied")
	}
	time.Sleep(80 * time.Millisecond)
	if !rl.Allow("k") {
		t.Error("after window elapses, must allow again")
	}
}

func TestTOTPTracker_BlocksAfterMaxFailures(t *testing.T) {
	// Use a fresh, unique token so we don't collide with other tests.
	token := "test-token-" + t.Name()
	if IsTOTPBlocked(token) {
		t.Fatal("fresh token should not be blocked")
	}
	for i := 0; i < maxTOTPAttempts-1; i++ {
		if !RecordTOTPAttempt(token, false) {
			t.Fatalf("attempt %d must still be allowed", i+1)
		}
	}
	// Final attempt must trip the block.
	if RecordTOTPAttempt(token, false) {
		t.Error("final failed attempt should return false (blocked)")
	}
	if !IsTOTPBlocked(token) {
		t.Error("token must be blocked after maxTOTPAttempts failures")
	}
	// Subsequent attempts on a blocked token must keep returning false.
	if RecordTOTPAttempt(token, true) {
		t.Error("blocked token must remain blocked even on success attempt")
	}
}

func TestTOTPTracker_SuccessClearsAttempts(t *testing.T) {
	token := "test-token-clear-" + t.Name()
	for i := 0; i < maxTOTPAttempts-1; i++ {
		RecordTOTPAttempt(token, false)
	}
	// One under the limit. Success here should clear the counter.
	if !RecordTOTPAttempt(token, true) {
		t.Error("success at maxAttempts-1 must be allowed")
	}
	// Now we should be able to fail (maxTOTPAttempts-1) more times before being blocked.
	for i := 0; i < maxTOTPAttempts-1; i++ {
		if !RecordTOTPAttempt(token, false) {
			t.Errorf("after success-clear, fresh failure %d must be allowed", i+1)
		}
	}
}

func TestTOTPTracker_HashedTokens(t *testing.T) {
	// Tokens should be sha256-hashed before lookup, not stored plaintext.
	// We verify indirectly: two different tokens must not share state.
	a := "ttkn-A-" + t.Name()
	b := "ttkn-B-" + t.Name()
	for i := 0; i < maxTOTPAttempts; i++ {
		RecordTOTPAttempt(a, false)
	}
	if !IsTOTPBlocked(a) {
		t.Fatal("a should be blocked")
	}
	if IsTOTPBlocked(b) {
		t.Error("b should NOT be blocked just because a is")
	}
}
