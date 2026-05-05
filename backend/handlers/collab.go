package handlers

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kutup/backend/middleware"
	"github.com/kutup/backend/services/envelope"
)

// CollabHandler handles WebSocket upgrades for the collaborative-edit feature.
type CollabHandler struct {
	DB        *pgxpool.Pool
	JWTSecret string
	Hub       *Hub
}

const wsOutBuf = 64

// wsConn is the production HubConn implementation backed by a real WebSocket.
type wsConn struct {
	ws        *websocket.Conn
	deviceID  int64
	userID    string
	pubKey    ed25519.PublicKey
	out       chan []byte
	closed    atomic.Bool
	closeOnce sync.Once
}

func (c *wsConn) DeviceID() int64 { return c.deviceID }
func (c *wsConn) UserID() string  { return c.userID }

// WriteFrame is non-blocking — drops the frame and closes the conn on backpressure.
// (See HubConn doc on the interface for why this contract is mandatory.)
func (c *wsConn) WriteFrame(b []byte) error {
	if c.closed.Load() {
		return errors.New("conn closed")
	}
	select {
	case c.out <- b:
		return nil
	default:
		c.Close()
		return errors.New("backpressure")
	}
}

func (c *wsConn) Close() {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		close(c.out)
		_ = c.ws.Close()
	})
}

// writePump fans frames from c.out to the WebSocket as binary messages.
func (c *wsConn) writePump() {
	for b := range c.out {
		if err := c.ws.WriteMessage(websocket.BinaryMessage, b); err != nil {
			c.Close()
			return
		}
	}
}

// Upgrade returns a Fiber handler that performs the WebSocket handshake and
// hands control to HandleConnection. The deviceId comes from the query string
// (browsers can't set custom headers on `new WebSocket(url)`); we look up its
// pubkey + verify it belongs to userID + is_active before admitting the conn.
func (h *CollabHandler) Upgrade() fiber.Handler {
	return websocket.New(func(ws *websocket.Conn) {
		userID, _ := ws.Locals("userId").(string)
		fileID, _ := ws.Locals("fileId").(string)
		deviceIDStr := ws.Query("deviceId")
		var deviceID int64
		if _, err := fmt.Sscan(deviceIDStr, &deviceID); err != nil || deviceID == 0 {
			_ = ws.WriteJSON(fiber.Map{"error": "missing or invalid deviceId"})
			return
		}
		// Look up the device's pubkey + verify it belongs to userID + is_active.
		var pub []byte
		var active bool
		var ownerID string
		err := h.DB.QueryRow(context.Background(), `
			SELECT public_signing, is_active, user_id::text
			FROM user_devices WHERE id = $1
		`, deviceID).Scan(&pub, &active, &ownerID)
		if err != nil || !active || ownerID != userID {
			_ = ws.WriteJSON(fiber.Map{"error": "device not registered or revoked"})
			return
		}
		h.HandleConnection(ws, userID, fileID, deviceID, ed25519.PublicKey(pub))
	})
}

// HandleConnection is the per-connection coroutine. It owns the read loop and
// orchestrates Hub join/leave, hello, writePump start, and frame dispatch.
func (h *CollabHandler) HandleConnection(
	ws *websocket.Conn, userID, fileID string, deviceID int64, pubKey ed25519.PublicKey,
) {
	c := &wsConn{
		ws: ws, deviceID: deviceID, userID: userID, pubKey: pubKey,
		out: make(chan []byte, wsOutBuf),
	}
	defer func() {
		h.Hub.Leave(fileID, c)
		c.Close()
	}()

	// Stamp last_seen_at on every successful upgrade. (Phase D5 also relies on this.)
	_, _ = h.DB.Exec(context.Background(),
		`UPDATE user_devices SET last_seen_at = now() WHERE id = $1`, deviceID)

	// Look up current_doc_key_id + head seq for the hello payload.
	var docKeyID int64
	_ = h.DB.QueryRow(context.Background(),
		`SELECT current_doc_key_id FROM files WHERE id = $1`, fileID,
	).Scan(&docKeyID)
	var headSeq int64
	_ = h.DB.QueryRow(context.Background(),
		`SELECT COALESCE(MAX(seq), 0) FROM file_update_log WHERE file_id = $1`, fileID,
	).Scan(&headSeq)

	// Send hello.
	hello := fiber.Map{
		"type":            "hello",
		"fileId":          fileID,
		"currentDocKeyId": docKeyID,
		"headSeq":         headSeq,
		"peers":           h.peerSummaries(fileID),
	}
	if err := ws.WriteJSON(hello); err != nil {
		return
	}

	go c.writePump()
	h.Hub.Join(fileID, c)

	// Read loop.
	for {
		mt, data, err := ws.ReadMessage()
		if err != nil {
			return
		}
		switch mt {
		case websocket.TextMessage:
			h.handleControl(c, fileID, data)
		case websocket.BinaryMessage:
			h.handleFrame(c, fileID, data)
		}
	}
}

func (h *CollabHandler) peerSummaries(fileID string) []fiber.Map {
	out := []fiber.Map{}
	for _, p := range h.Hub.Peers(fileID) {
		out = append(out, fiber.Map{
			"deviceId": p.DeviceID(),
			"userId":   p.UserID(),
		})
	}
	return out
}

// handleControl handles JSON control messages. v1 only supports {"type":"resume","lastSeenSeq":N}.
func (h *CollabHandler) handleControl(c *wsConn, fileID string, data []byte) {
	var m struct {
		Type        string `json:"type"`
		LastSeenSeq int64  `json:"lastSeenSeq"`
	}
	if err := json.Unmarshal(data, &m); err != nil || m.Type != "resume" {
		return
	}
	h.replayLog(c, fileID, m.LastSeenSeq)
}

// handleFrame validates and persists a binary CollabFrame, then broadcasts.
//
// Validation order:
//  1. Unpack — must succeed
//  2. SenderDeviceID == c.deviceID (rejects forged sender)
//  3. Ed25519 Verify — must succeed (rejects tampered or replay-from-another-device frames)
//  4. Dispatch by kind: awareness = broadcast-only, others = persist + broadcast.
func (h *CollabHandler) handleFrame(c *wsConn, fileID string, data []byte) {
	f, err := envelope.Unpack(data)
	if err != nil {
		return
	}
	if f.SenderDeviceID != uint64(c.deviceID) {
		return // sender mismatch — drop
	}
	if err := envelope.Verify(data, c.pubKey); err != nil {
		return
	}

	// Awareness frames: broadcast only, no persistence.
	if f.Kind == envelope.KindYjsAwareness {
		h.Hub.Broadcast(fileID, c, data)
		return
	}

	// All other persisted kinds (yjs_update, snapshot_announce, oo_op/lock/checkpoint_meta).
	if _, err := h.persistFrame(fileID, c.deviceID, f, data); err != nil {
		return
	}
	h.Hub.Broadcast(fileID, c, data)
}

// persistFrame inserts a frame into file_update_log and returns the assigned seq.
//
// Known race (acceptable for v1): the seq is computed via
//   COALESCE((SELECT MAX(seq) FROM file_update_log WHERE file_id = $1), 0) + 1
// which is non-atomic under concurrent inserts. Two clients can both compute
// seq=N, in which case the second INSERT fails on the (file_id, seq) PRIMARY
// KEY constraint and the frame is dropped — the client retransmits on resume.
// A future hardening pass can replace this with a per-file advisory lock or
// a CTE that locks the max row.
func (h *CollabHandler) persistFrame(fileID string, deviceID int64, f envelope.Frame, raw []byte) (int64, error) {
	var seq int64
	err := h.DB.QueryRow(context.Background(), `
		INSERT INTO file_update_log (file_id, seq, sender_device, doc_key_id, kind, frame)
		VALUES (
		  $1,
		  COALESCE((SELECT MAX(seq) FROM file_update_log WHERE file_id = $1), 0) + 1,
		  $2, $3, $4, $5
		)
		RETURNING seq
	`, fileID, deviceID, int64(f.DocKeyID), int16(f.Kind), raw).Scan(&seq)
	return seq, err
}

// replayLog streams every frame with seq > sinceSeq to the joining client.
func (h *CollabHandler) replayLog(c *wsConn, fileID string, sinceSeq int64) {
	rows, err := h.DB.Query(context.Background(), `
		SELECT frame FROM file_update_log
		WHERE file_id = $1 AND seq > $2
		ORDER BY seq ASC
	`, fileID, sinceSeq)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return
		}
		if err := c.WriteFrame(b); err != nil {
			return
		}
	}
}

// PreUpgrade authenticates the request and confirms file access BEFORE the
// WebSocket upgrade. Browsers can't set custom headers on `new WebSocket(url)`,
// so the token may arrive either via the standard `Authorization: Bearer ...`
// header (server-to-server tests) or via a `?token=...` query param (browser).
// On success, sets c.Locals("userId"|"fileId"|"collectionId") for the upgrade
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
