package api

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// DeviceRow mirrors backend/handlers/devices.go:deviceRow.
//
// Note: we already have a `DeviceRow` exported from client.go for an older
// shape. To avoid breakage, this file renames to UserDevice and the
// existing client.go DeviceRow stays — they may be unifiable in a later
// cleanup.
type UserDevice struct {
	DeviceID   int64      `json:"deviceId"`
	Label      string     `json:"label"`
	IsActive   bool       `json:"isActive"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastSeenAt *time.Time `json:"lastSeenAt"`
}

// ListUserDevices returns every device row for the authenticated user.
// The backend orders newest-first.
func (c *Client) ListUserDevices() ([]UserDevice, error) {
	resp, err := c.get("/devices")
	if err != nil {
		return nil, err
	}
	var out []UserDevice
	return out, decodeJSON(resp, &out)
}

// RevokeUserDevice deletes a device. Closes any in-flight WebSocket
// connection signed by that device's key (server-side hook). Destructive;
// the CLI prompts for confirmation.
func (c *Client) RevokeUserDevice(deviceID int64) error {
	url := fmt.Sprintf("%s/api/devices/%d", c.base, deviceID)
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return nil
}
