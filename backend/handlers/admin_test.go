package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/kutup/backend/internal/testdb"
	"github.com/kutup/backend/middleware"
	"github.com/kutup/backend/utils"
)

// newAdminApp wires AdminHandler behind both Required() (any user) and
// AdminRequired() (must be admin). Returns the app + the admin's userID.
func newAdminApp(t *testing.T) (app *fiber.App, adminUID string, regularUID string) {
	t.Helper()
	pool := testdb.Setup(t)

	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (
			email, username, login_key_hash,
			encrypted_master_key, master_key_nonce,
			encrypted_recovery_key, recovery_key_nonce,
			encrypted_private_key, private_key_nonce,
			public_key, kdf_salt, login_key_salt,
			is_admin, is_first_login
		) VALUES ('admin@example.com','admin','h','','','','','','','','','',true,false)
		RETURNING id`).Scan(&adminUID); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (
			email, username, login_key_hash,
			encrypted_master_key, master_key_nonce,
			encrypted_recovery_key, recovery_key_nonce,
			encrypted_private_key, private_key_nonce,
			public_key, kdf_salt, login_key_salt,
			is_admin, is_first_login
		) VALUES ('user@example.com','regular','h','','','','','','','','','',false,false)
		RETURNING id`).Scan(&regularUID); err != nil {
		t.Fatalf("seed regular: %v", err)
	}

	h := &AdminHandler{DB: pool}
	authMW := middleware.NewAuth(testJWTSecret)
	app = fiber.New()
	api := app.Group("/api")
	admin := api.Group("/admin", authMW.Required(), middleware.AdminRequired())
	admin.Get("/users", h.ListUsers)
	admin.Post("/users", h.CreateUser)
	admin.Put("/users/:id", h.UpdateUser)
	admin.Delete("/users/:id", h.DeleteUser)
	admin.Get("/stats", h.GetStats)
	return app, adminUID, regularUID
}

func adminAuthedReq(t *testing.T, method, path, body, uid string, isAdmin bool) *http.Request {
	t.Helper()
	tok, err := utils.GenerateAccessToken(uid, isAdmin, testJWTSecret)
	if err != nil {
		t.Fatal(err)
	}
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

func TestListUsers_RequiresAdmin(t *testing.T) {
	app, _, regularUID := newAdminApp(t)

	// Regular user gets 403 from AdminRequired() middleware.
	req := adminAuthedReq(t, http.MethodGet, "/api/admin/users", "", regularUID, false)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 403 {
		t.Errorf("regular user: status = %d, want 403", resp.StatusCode)
	}

	// Anon gets 401.
	resp2, _ := app.Test(httptest.NewRequest(http.MethodGet, "/api/admin/users", nil), -1)
	if resp2.StatusCode != 401 {
		t.Errorf("anon: status = %d, want 401", resp2.StatusCode)
	}
}

func TestListUsers_ReturnsBothSeededUsers(t *testing.T) {
	app, adminUID, _ := newAdminApp(t)
	req := adminAuthedReq(t, http.MethodGet, "/api/admin/users", "", adminUID, true)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var users []map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&users)
	if len(users) != 2 {
		t.Errorf("got %d users, want 2", len(users))
	}
}

func TestCreateUser_RoundTrip(t *testing.T) {
	app, adminUID, _ := newAdminApp(t)
	body := `{
		"email": "newuser@example.com",
		"username": "newuser",
		"tempPassword": "TempPassword123",
		"storageQuotaBytes": 1073741824
	}`
	req := adminAuthedReq(t, http.MethodPost, "/api/admin/users", body, adminUID, true)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 201 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestCreateUser_RejectsBadInput(t *testing.T) {
	app, adminUID, _ := newAdminApp(t)
	cases := []struct {
		name string
		body string
	}{
		{"empty email", `{"email":"","username":"u","tempPassword":"p"}`},
		{"empty pw", `{"email":"a@b.c","username":"u","tempPassword":""}`},
		{"empty username", `{"email":"a@b.c","username":"","tempPassword":"p"}`},
		{"bad username", `{"email":"a@b.c","username":"AAAA","tempPassword":"p"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := adminAuthedReq(t, http.MethodPost, "/api/admin/users", tc.body, adminUID, true)
			resp, _ := app.Test(req, -1)
			if resp.StatusCode != 400 {
				t.Errorf("%s: status = %d, want 400", tc.name, resp.StatusCode)
			}
		})
	}
}

func TestDeleteUser_404OnUnknown(t *testing.T) {
	app, adminUID, _ := newAdminApp(t)
	req := adminAuthedReq(t, http.MethodDelete, "/api/admin/users/00000000-0000-0000-0000-000000000000", "", adminUID, true)
	resp, _ := app.Test(req, -1)
	if resp.StatusCode != 404 {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestGetStats_Counts(t *testing.T) {
	app, adminUID, _ := newAdminApp(t)
	req := adminAuthedReq(t, http.MethodGet, "/api/admin/stats", "", adminUID, true)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var stats map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&stats)
	if stats["totalUsers"] != float64(2) {
		t.Errorf("totalUsers = %v, want 2 (admin + regular seed)", stats["totalUsers"])
	}
	if stats["activeUsers"] != float64(2) {
		t.Errorf("activeUsers = %v, want 2", stats["activeUsers"])
	}
}
