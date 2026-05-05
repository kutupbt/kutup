package handlers

import (
	"strings"

	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kutup/backend/middleware"
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

// PreUpgrade authenticates the request and confirms file access BEFORE the
// WebSocket upgrade. Browsers can't set custom headers on `new WebSocket(url)`,
// so the token may arrive either via the standard `Authorization: Bearer ...`
// header (server-to-server tests) or via a `?token=...` query param (browser).
// On success, sets c.Locals("userID"|"fileID"|"collectionID") for the upgrade
// handler. Read-only share recipients are admitted here — frame-level
// can_upload/can_delete enforcement is the relay's job (D4).
func (h *CollabHandler) PreUpgrade(authMW *middleware.AuthMiddleware) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Token from Authorization header or ?token= query.
		tok := c.Get("Authorization")
		if strings.HasPrefix(tok, "Bearer ") {
			tok = tok[7:]
		} else {
			tok = c.Query("token")
		}
		if tok == "" {
			return c.Status(401).JSON(fiber.Map{"error": "missing token"})
		}
		userID, _, err := authMW.ValidateTokenString(tok)
		if err != nil {
			return c.Status(401).JSON(fiber.Map{"error": "invalid token"})
		}

		// Confirm user has access to this file's collection.
		fileID := c.Params("fileId")
		var ownerID, collID string
		var sharedWith bool
		err = h.DB.QueryRow(c.Context(), `
			SELECT c.owner_user_id::text, c.id::text,
			       EXISTS(SELECT 1 FROM collection_shares cs
			              WHERE cs.collection_id = c.id AND cs.recipient_user_id = $2)
			FROM files f JOIN collections c ON c.id = f.collection_id
			WHERE f.id = $1
		`, fileID, userID).Scan(&ownerID, &collID, &sharedWith)
		if err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "file not found"})
		}
		if ownerID != userID && !sharedWith {
			return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
		}
		c.Locals("userId", userID)
		c.Locals("fileId", fileID)
		c.Locals("collectionId", collID)
		return c.Next()
	}
}
