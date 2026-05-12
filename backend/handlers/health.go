package handlers

import "github.com/gofiber/fiber/v2"

// HealthHandler answers liveness probes used by clients (e.g. the desktop
// app's server-URL prompt) to confirm a URL points at a kutup backend.
//
// Anonymous, idempotent, no DB hit — must succeed during DB / storage
// outages too, so users can still confirm the URL is reachable.
type HealthHandler struct {
	Version string
}

// Get returns server identity for client-side URL validation.
func (h *HealthHandler) Get(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"name":        "kutup",
		"version":     h.Version,
		"tusVersions": []string{"1.0.0"},
	})
}
