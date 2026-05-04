package handlers

import (
	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CollabHandler handles WebSocket upgrades for the collaborative-edit feature.
// Real frame logic (validation, persistence, broadcast) lands in D2-D5.
type CollabHandler struct {
	DB        *pgxpool.Pool
	JWTSecret string
	Hub       any // populated in D3 (will be retyped to *Hub once the type lands)
}

// Upgrade returns a Fiber middleware that performs the WebSocket handshake.
// For D1 it just sends a stub "hello" payload and exits — D4 replaces this
// with the per-connection lifecycle (Hub join, frame validation, broadcast).
func (h *CollabHandler) Upgrade() fiber.Handler {
	return websocket.New(func(ws *websocket.Conn) {
		fileID := ws.Params("fileId")
		_ = ws.WriteJSON(fiber.Map{
			"type":            "hello",
			"fileId":          fileID,
			"currentDocKeyId": 1,
			"headSeq":         0,
			"peers":           []any{},
		})
	})
}

// PreUpgrade is the Fiber middleware that authenticates the request and confirms
// file access BEFORE upgrading. Stub for D1; real implementation in D2.
func (h *CollabHandler) PreUpgrade() fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Locals("placeholder", true)
		return c.Next()
	}
}
