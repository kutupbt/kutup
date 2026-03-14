package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
)

type rateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
	go rl.cleanup()
	return rl
}

func (rl *rateLimiter) cleanup() {
	for range time.Tick(5 * time.Minute) {
		rl.mu.Lock()
		now := time.Now()
		for key, times := range rl.requests {
			filtered := times[:0]
			for _, t := range times {
				if now.Sub(t) < rl.window {
					filtered = append(filtered, t)
				}
			}
			if len(filtered) == 0 {
				delete(rl.requests, key)
			} else {
				rl.requests[key] = filtered
			}
		}
		rl.mu.Unlock()
	}
}

func (rl *rateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	times := rl.requests[key]
	// Filter to window
	valid := times[:0]
	for _, t := range times {
		if now.Sub(t) < rl.window {
			valid = append(valid, t)
		}
	}
	if len(valid) >= rl.limit {
		rl.requests[key] = valid
		return false
	}
	rl.requests[key] = append(valid, now)
	return true
}

var recoveryLimiter = newRateLimiter(5, time.Hour)

// RecoveryRateLimit limits password recovery attempts to 5 per hour per IP.
func RecoveryRateLimit() fiber.Handler {
	return func(c *fiber.Ctx) error {
		ip := c.IP()
		if !recoveryLimiter.Allow(ip) {
			return c.Status(429).JSON(fiber.Map{"error": "too many requests"})
		}
		return c.Next()
	}
}

var fedUsersLimiter = newRateLimiter(60, time.Minute)

// FedUsersRateLimit limits public username-lookup requests to 60 per minute per IP.
func FedUsersRateLimit() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !fedUsersLimiter.Allow(c.IP()) {
			return c.Status(429).JSON(fiber.Map{"error": "too many requests"})
		}
		return c.Next()
	}
}

var loginLimiter = newRateLimiter(10, time.Minute)

// LoginRateLimit limits login attempts to 10 per minute per IP.
func LoginRateLimit() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !loginLimiter.Allow(c.IP()) {
			return c.Status(429).JSON(fiber.Map{"error": "too many requests"})
		}
		return c.Next()
	}
}

var preflightLimiter = newRateLimiter(20, time.Minute)

// PreflightRateLimit limits login preflight requests to 20 per minute per IP.
func PreflightRateLimit() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !preflightLimiter.Allow(c.IP()) {
			return c.Status(429).JSON(fiber.Map{"error": "too many requests"})
		}
		return c.Next()
	}
}

// totpTracker tracks failed TOTP attempts per pre-auth token.
// After maxTOTPAttempts failures, the token is blacklisted for the remainder of its TTL.
var totpTracker = struct {
	mu       sync.Mutex
	attempts map[string]int
	blocked  map[string]bool
}{
	attempts: make(map[string]int),
	blocked:  make(map[string]bool),
}

const maxTOTPAttempts = 5

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// IsTOTPBlocked returns true if this pre-auth token has exceeded the failed attempt limit.
func IsTOTPBlocked(preAuthToken string) bool {
	key := hashToken(preAuthToken)
	totpTracker.mu.Lock()
	defer totpTracker.mu.Unlock()
	return totpTracker.blocked[key]
}

// RecordTOTPAttempt records a TOTP attempt result. Returns false if the token is now blocked.
// On success, clears the attempt counter for this token.
func RecordTOTPAttempt(preAuthToken string, success bool) bool {
	key := hashToken(preAuthToken)
	totpTracker.mu.Lock()
	defer totpTracker.mu.Unlock()

	if totpTracker.blocked[key] {
		return false
	}

	if success {
		delete(totpTracker.attempts, key)
		return true
	}

	totpTracker.attempts[key]++
	if totpTracker.attempts[key] >= maxTOTPAttempts {
		totpTracker.blocked[key] = true
		return false
	}
	return true
}
