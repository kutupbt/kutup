// devices_handler_test.go — integration tests for DevicesHandler.
// Filename has _handler_ suffix to avoid colliding with the existing
// devices_test.go (which only does Ed25519 sanity checks).
package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kutup/backend/internal/testdb"
	"github.com/kutup/backend/middleware"
	"github.com/kutup/backend/utils"
)

func newDevicesApp(t *testing.T) (*fiber.App, *pgxpool.Pool, string) {
	t.Helper()
	pool := testdb.Setup(t)
	var uid string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (
			email, username, login_key_hash,
			encrypted_master_key, master_key_nonce,
			encrypted_recovery_key, recovery_key_nonce,
			encrypted_private_key, private_key_nonce,
			public_key, kdf_salt, login_key_salt,
			is_admin, is_first_login
		) VALUES ('dev@example.com','dev','h','','','','','','','','','',false,false)
		RETURNING id`).Scan(&uid); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	h := &DevicesHandler{DB: pool}
	authMW := middleware.NewAuth(testJWTSecret)
	app := fiber.New()
	api := app.Group("/api")
	devices := api.Group("/devices", authMW.Required())
	devices.Post("/", h.Register)
	devices.Get("/", h.List)
	devices.Delete("/:id", h.Revoke)
	return app, pool, uid
}

func devReq(t *testing.T, method, path, body, uid string) *http.Request {
	t.Helper()
	tok, _ := utils.GenerateAccessToken(uid, false, testJWTSecret)
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	return req
}

func TestDevicesRegister_HappyPath(t *testing.T) {
	app, _, uid := newDevicesApp(t)
	pub := base64.StdEncoding.EncodeToString(make([]byte, 32))
	body := fmt.Sprintf(`{"publicSigning":%q,"label":"my-tab","authSig":"AAAA","timestamp":%d}`,
		pub, time.Now().Unix())
	req := devReq(t, http.MethodPost, "/api/devices/", body, uid)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 201 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got["deviceId"] == nil {
		t.Error("response missing deviceId")
	}
	if got["label"] != "my-tab" {
		t.Errorf("label = %v, want my-tab", got["label"])
	}
}

func TestDevicesRegister_RejectsBadPubKey(t *testing.T) {
	app, _, uid := newDevicesApp(t)
	cases := []struct {
		name string
		pub  string
	}{
		{"not base64", "!!!"},
		{"wrong length 16", base64.StdEncoding.EncodeToString(make([]byte, 16))},
		{"wrong length 64", base64.StdEncoding.EncodeToString(make([]byte, 64))},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"publicSigning":%q,"timestamp":%d}`, tc.pub, time.Now().Unix())
			resp, _ := app.Test(devReq(t, http.MethodPost, "/api/devices/", body, uid), -1)
			if resp.StatusCode != 400 {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
		})
	}
}

func TestDevicesRegister_RejectsTimestampSkew(t *testing.T) {
	app, _, uid := newDevicesApp(t)
	pub := base64.StdEncoding.EncodeToString(make([]byte, 32))
	// Timestamp from 1 hour ago — must be rejected (>5min skew).
	body := fmt.Sprintf(`{"publicSigning":%q,"timestamp":%d}`, pub, time.Now().Add(-time.Hour).Unix())
	resp, _ := app.Test(devReq(t, http.MethodPost, "/api/devices/", body, uid), -1)
	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestDevicesList_OnlyOwnDevices(t *testing.T) {
	app, pool, uid := newDevicesApp(t)

	// Seed another user + their device.
	var otherUID string
	pool.QueryRow(context.Background(),
		`INSERT INTO users (email, username, login_key_hash,
			encrypted_master_key, master_key_nonce,
			encrypted_recovery_key, recovery_key_nonce,
			encrypted_private_key, private_key_nonce,
			public_key, kdf_salt, login_key_salt,
			is_admin, is_first_login)
		 VALUES ('other@example.com','other','h','','','','','','','','','',false,false)
		 RETURNING id`).Scan(&otherUID)
	pool.Exec(context.Background(),
		`INSERT INTO user_devices (user_id, public_signing, label) VALUES ($1, decode('00','hex'), 'other-tab')`, otherUID)

	// Register one device for uid.
	pub := base64.StdEncoding.EncodeToString(make([]byte, 32))
	body := fmt.Sprintf(`{"publicSigning":%q,"label":"mine","timestamp":%d}`, pub, time.Now().Unix())
	if r, _ := app.Test(devReq(t, http.MethodPost, "/api/devices/", body, uid), -1); r.StatusCode != 201 {
		t.Fatalf("register: %d", r.StatusCode)
	}

	// List as uid — must only see their own device.
	resp, _ := app.Test(devReq(t, http.MethodGet, "/api/devices/", "", uid), -1)
	var devices []map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&devices)
	if len(devices) != 1 {
		t.Fatalf("got %d devices, want 1 (only own)", len(devices))
	}
	if devices[0]["label"] != "mine" {
		t.Errorf("label = %v, want 'mine'", devices[0]["label"])
	}
}
