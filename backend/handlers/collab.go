package handlers

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

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

const (
	wsOutBuf            = 256
	backpressureTimeout = 2 * time.Second
)

// wsConn is the production HubConn implementation backed by a real WebSocket.
type wsConn struct {
	ws        *websocket.Conn
	deviceID  int64
	userID    string
	username  string
	pubKey    ed25519.PublicKey
	out       chan []byte // binary collab frames
	outText   chan []byte // JSON control messages (e.g. peer-list)
	done      chan struct{}
	closeOnce sync.Once
}

func (c *wsConn) DeviceID() int64 { return c.deviceID }
func (c *wsConn) UserID() string  { return c.userID }
func (c *wsConn) Username() string { return c.username }

// WriteFrame waits up to backpressureTimeout for c.out to have room before
// closing the conn. Original v1 was strictly non-blocking with default close
// on full buffer — under fast typing bursts this evicted healthy peers from
// the room mid-session. A short bounded wait absorbs typical bursts while
// still detecting genuinely-stuck writers.
//
// Uses `done` (closed in Close) as the synchronization point so we never
// risk a send-on-closed-channel panic. c.out itself is never closed —
// writePump exits via `done`.
func (c *wsConn) WriteFrame(b []byte) error {
	select {
	case <-c.done:
		return errors.New("conn closed")
	default:
	}
	t := time.NewTimer(backpressureTimeout)
	defer t.Stop()
	select {
	case c.out <- b:
		return nil
	case <-c.done:
		return errors.New("conn closed")
	case <-t.C:
		c.Close()
		return errors.New("backpressure timeout")
	}
}

func (c *wsConn) Close() {
	c.closeOnce.Do(func() {
		close(c.done)
		_ = c.ws.Close()
	})
}

// writePump drains c.out (binary collab frames) and c.outText (JSON control
// messages like peer-list) to the WebSocket. Exits on done.
func (c *wsConn) writePump() {
	for {
		select {
		case b := <-c.out:
			if err := c.ws.WriteMessage(websocket.BinaryMessage, b); err != nil {
				c.Close()
				return
			}
		case b := <-c.outText:
			if err := c.ws.WriteMessage(websocket.TextMessage, b); err != nil {
				c.Close()
				return
			}
		case <-c.done:
			return
		}
	}
}

// WriteText queues a JSON control message for delivery as a text-frame
// WebSocket message. Same backpressure semantics as WriteFrame: bounded
// wait, then close-and-drop on stuck writers. Only used for low-volume
// control traffic (peer-list announcements); collab frames keep using
// WriteFrame's binary path.
func (c *wsConn) WriteText(b []byte) error {
	select {
	case <-c.done:
		return errors.New("conn closed")
	default:
	}
	t := time.NewTimer(backpressureTimeout)
	defer t.Stop()
	select {
	case c.outText <- b:
		return nil
	case <-c.done:
		return errors.New("conn closed")
	case <-t.C:
		c.Close()
		return errors.New("backpressure timeout")
	}
}

// Upgrade returns a Fiber handler that performs the WebSocket handshake and
// hands control to HandleConnection. All auth/access/device checks have been
// performed by PreUpgrade — this handler trusts c.Locals values.
func (h *CollabHandler) Upgrade() fiber.Handler {
	return websocket.New(func(ws *websocket.Conn) {
		userID, _ := ws.Locals("userId").(string)
		fileID, _ := ws.Locals("fileId").(string)
		deviceID, _ := ws.Locals("deviceId").(int64)
		pub, _ := ws.Locals("devicePubKey").([]byte)
		h.HandleConnection(ws, userID, fileID, deviceID, ed25519.PublicKey(pub))
	})
}

// HandleConnection is the per-connection coroutine. It owns the read loop and
// orchestrates Hub join/leave, hello, writePump start, and frame dispatch.
func (h *CollabHandler) HandleConnection(
	ws *websocket.Conn, userID, fileID string, deviceID int64, pubKey ed25519.PublicKey,
) {
	// Look up the username for the peer-list (peers payload uses it as the
	// label OnlyOffice's `connectState` / users dropdown shows).
	var username string
	_ = h.DB.QueryRow(context.Background(),
		`SELECT COALESCE(username, '') FROM users WHERE id = $1`, userID,
	).Scan(&username)

	c := &wsConn{
		ws: ws, deviceID: deviceID, userID: userID, username: username, pubKey: pubKey,
		out:     make(chan []byte, wsOutBuf),
		outText: make(chan []byte, wsOutBuf),
		done:    make(chan struct{}),
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
	// Highest sender_seq this device has already used for this file. The
	// client uses this to resume its per-device outbound counter so a
	// refresh / remount doesn't replay sequence numbers and 23505 every
	// frame against the (file_id, sender_device, sender_seq) UNIQUE index.
	var mySenderSeq int64
	_ = h.DB.QueryRow(context.Background(),
		`SELECT COALESCE(MAX(sender_seq), 0)
		   FROM file_update_log
		  WHERE file_id = $1 AND sender_device = $2`,
		fileID, deviceID,
	).Scan(&mySenderSeq)

	// Send hello.
	hello := fiber.Map{
		"type":             "hello",
		"fileId":           fileID,
		"currentDocKeyId":  docKeyID,
		"headSeq":          headSeq,
		"mySenderSeqHigh":  mySenderSeq,
		"peers":            h.peerSummaries(fileID),
	}
	if err := ws.WriteJSON(hello); err != nil {
		return
	}

	go c.writePump()
	h.Hub.Join(fileID, c)
	log.Printf("collab: device=%d joined fileId=%s, peers=%d", deviceID, fileID, len(h.Hub.Peers(fileID)))
	// Tell every connected peer (including the new one) that the peer set
	// changed. The OnlyOffice bridge needs this to call connectState on its
	// editor so the new peer's edits aren't rejected as coming from an
	// unknown user. Mirrors CryptPad's handleNewIds (inner.js:1097).
	h.broadcastPeers(fileID)
	defer func() {
		// Logged via defer-stack ordering: Hub.Leave runs first (the outer
		// defer) and removes us from peers, so this print reflects the
		// post-leave state.
		log.Printf("collab: device=%d left fileId=%s, peers=%d", deviceID, fileID, len(h.Hub.Peers(fileID)))
		// Same broadcast on departure so peers can drop the leaver from
		// their participant list (and OO can release any locks it held).
		h.broadcastPeers(fileID)
	}()

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

// peerSummaries returns the JSON shape clients use for their participant
// list. `username` is best-effort — we add it via a wsConn type assertion
// (HubConn doesn't carry the field for portability with the test fakeConn).
func (h *CollabHandler) peerSummaries(fileID string) []fiber.Map {
	out := []fiber.Map{}
	for _, p := range h.Hub.Peers(fileID) {
		row := fiber.Map{
			"deviceId": p.DeviceID(),
			"userId":   p.UserID(),
		}
		if wc, ok := p.(*wsConn); ok && wc.username != "" {
			row["username"] = wc.username
		}
		out = append(out, row)
	}
	return out
}

// broadcastPeers sends the current peer-list as a JSON text message to
// every conn in the room. Called from join + leave; lets clients keep
// their OnlyOffice connectState up to date so remote saveChanges from
// late-joining peers aren't rejected as unknown-user.
//
// Best-effort: WriteText errors close the offending conn, which then
// triggers a fresh broadcast via the Leave path. No retry needed here.
func (h *CollabHandler) broadcastPeers(fileID string) {
	peers := h.peerSummaries(fileID)
	payload, err := json.Marshal(fiber.Map{
		"type":  "peers",
		"list":  peers,
		"ts":    time.Now().UnixMilli(),
	})
	if err != nil {
		return
	}
	for _, p := range h.Hub.Peers(fileID) {
		wc, ok := p.(*wsConn)
		if !ok {
			continue
		}
		_ = wc.WriteText(payload)
	}
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

	// Epoch check: reject frames signed under an older doc_key_id than the file's current.
	// (Rotation isn't implemented in v1, but enforcing now closes the door before D5/E lands.)
	var currentEpoch int64
	if err := h.DB.QueryRow(context.Background(),
		`SELECT current_doc_key_id FROM files WHERE id = $1`, fileID,
	).Scan(&currentEpoch); err != nil {
		return
	}
	if int64(f.DocKeyID) < currentEpoch {
		return
	}

	// Ephemeral broadcast-only kinds (no file_update_log entry):
	//   - KindYjsAwareness: notes cursor / selection presence.
	//   - KindOOCursor:     office cell-selection presence (xlsx range
	//     rectangles; mirrors notes cursor presence for sheets).
	if f.Kind == envelope.KindYjsAwareness || f.Kind == envelope.KindOOCursor {
		peers := len(h.Hub.Peers(fileID))
		log.Printf("collab: bcast ephemeral file=%s sender=%d kind=%d peers=%d", fileID, c.deviceID, f.Kind, peers)
		h.Hub.Broadcast(fileID, c, data)
		return
	}

	// All other persisted kinds (yjs_update, snapshot_announce, oo_op/lock/checkpoint_meta).
	if _, err := h.persistFrame(fileID, c.deviceID, f, data); err != nil {
		log.Printf("collab: persist failed file=%s sender=%d err=%v", fileID, c.deviceID, err)
		return
	}
	peers := len(h.Hub.Peers(fileID))
	log.Printf("collab: bcast yjs_update file=%s sender=%d kind=%d peers=%d", fileID, c.deviceID, f.Kind, peers)
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
		INSERT INTO file_update_log (file_id, seq, sender_device, sender_seq, doc_key_id, kind, frame)
		VALUES (
		  $1,
		  COALESCE((SELECT MAX(seq) FROM file_update_log WHERE file_id = $1), 0) + 1,
		  $2, $3, $4, $5, $6
		)
		RETURNING seq
	`, fileID, deviceID, int64(f.Sequence), int64(f.DocKeyID), int16(f.Kind), raw).Scan(&seq)
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

		// Device validation: deviceId from query, must belong to userID + be active.
		deviceIDStr := c.Query("deviceId")
		var deviceID int64
		if _, err := fmt.Sscan(deviceIDStr, &deviceID); err != nil || deviceID == 0 {
			return c.Status(401).JSON(fiber.Map{"error": "missing or invalid deviceId"})
		}
		var pub []byte
		var active bool
		var devOwnerID string
		err = h.DB.QueryRow(c.Context(), `
			SELECT public_signing, is_active, user_id::text
			FROM user_devices WHERE id = $1
		`, deviceID).Scan(&pub, &active, &devOwnerID)
		if err != nil || !active || devOwnerID != userID {
			return c.Status(401).JSON(fiber.Map{"error": "device not registered or revoked"})
		}
		c.Locals("deviceId", deviceID)
		c.Locals("devicePubKey", pub)
		return c.Next()
	}
}
