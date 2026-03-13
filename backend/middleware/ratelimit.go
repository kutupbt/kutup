package middleware

import (
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
