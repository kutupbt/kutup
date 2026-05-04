// backend/handlers/devices.go
package handlers

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/kutup/backend/middleware"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RevokeHookFn is invoked when a device is marked inactive, so the collab Hub
// can drop any open WebSocket connections from that device. Wired in main.go
// once the Hub exists (Phase D).
type RevokeHookFn func(deviceID int64)

type DevicesHandler struct {
	DB         *pgxpool.Pool
	RevokeHook RevokeHookFn
}

// WithRevokeHook installs a callback fired whenever a device is revoked.
func (h *DevicesHandler) WithRevokeHook(fn RevokeHookFn) { h.RevokeHook = fn }

type registerDeviceRequest struct {
	PublicSigning string `json:"publicSigning"` // base64 32-byte Ed25519 pubkey
	Label         string `json:"label,omitempty"`
	AuthSig       string `json:"authSig"`   // signed by master-derived signing key (verified in v2)
	Timestamp     int64  `json:"timestamp"` // unix seconds; reject if >5min skew
}

type registerDeviceResponse struct {
	DeviceID  int64     `json:"deviceId"`
	Label     string    `json:"label"`
	CreatedAt time.Time `json:"createdAt"`
}

// @Summary      Register a device signing key
// @Tags         Devices
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body      registerDeviceRequest  true  "Device pubkey + master-key signature"
// @Success      201   {object}  registerDeviceResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      401   {object}  ErrorResponse
// @Router       /devices [post]
func (h *DevicesHandler) Register(c *fiber.Ctx) error {
	userID := middleware.UserID(c)

	var req registerDeviceRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	pub, err := base64.StdEncoding.DecodeString(req.PublicSigning)
	if err != nil || len(pub) != 32 {
		return c.Status(400).JSON(fiber.Map{"error": "publicSigning must be base64 32 bytes"})
	}
	if absInt64(time.Now().Unix()-req.Timestamp) > 300 {
		return c.Status(400).JSON(fiber.Map{"error": "timestamp skew"})
	}
	// AuthSig verification deferred to a future hardening pass — the JWT itself
	// is the v1 trust anchor; AuthSig is recorded for forward compat but not
	// validated. (Spec §14 question 6.)
	_ = req.AuthSig

	var id int64
	var createdAt time.Time
	err = h.DB.QueryRow(context.Background(), `
		INSERT INTO user_devices (user_id, public_signing, label)
		VALUES ($1, $2, NULLIF($3, ''))
		RETURNING id, created_at
	`, userID, pub, req.Label).Scan(&id, &createdAt)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	return c.Status(201).JSON(registerDeviceResponse{
		DeviceID: id, Label: req.Label, CreatedAt: createdAt,
	})
}

type deviceRow struct {
	DeviceID   int64      `json:"deviceId"`
	Label      string     `json:"label"`
	IsActive   bool       `json:"isActive"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastSeenAt *time.Time `json:"lastSeenAt"`
}

// @Summary List user's devices
// @Tags    Devices
// @Security BearerAuth
// @Produce json
// @Success 200 {array} deviceRow
// @Router /devices [get]
func (h *DevicesHandler) List(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	rows, err := h.DB.Query(context.Background(), `
		SELECT id, COALESCE(label, ''), is_active, created_at, last_seen_at
		FROM user_devices
		WHERE user_id = $1
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	defer rows.Close()
	out := []deviceRow{}
	for rows.Next() {
		var d deviceRow
		if err := rows.Scan(&d.DeviceID, &d.Label, &d.IsActive, &d.CreatedAt, &d.LastSeenAt); err == nil {
			out = append(out, d)
		}
	}
	return c.JSON(out)
}

// @Summary Revoke a device
// @Tags    Devices
// @Security BearerAuth
// @Param   id path int true "Device ID"
// @Success 204
// @Failure 404 {object} ErrorResponse
// @Router  /devices/{id} [delete]
func (h *DevicesHandler) Revoke(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	var id int64
	if _, err := fmt.Sscan(c.Params("id"), &id); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid id"})
	}
	tag, err := h.DB.Exec(context.Background(),
		`UPDATE user_devices SET is_active = false WHERE id = $1 AND user_id = $2`,
		id, userID,
	)
	if err != nil || tag.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	if h.RevokeHook != nil {
		h.RevokeHook(id)
	}
	return c.SendStatus(204)
}

func absInt64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
