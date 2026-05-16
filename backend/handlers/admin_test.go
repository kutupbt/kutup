package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kutup/backend/internal/testdb"
	"github.com/kutup/backend/middleware"
	"github.com/kutup/backend/utils"
)

// buildAdminApp wires AdminHandler behind both Required() (any user) and
// AdminRequired() (must be admin). breakGlassEmail, when non-empty, marks
// that account as the protected break-glass admin. Returns the app, the
// DB pool (for tests that need to set up / assert state directly), and the
// two seeded user IDs.
func buildAdminApp(t *testing.T, breakGlassEmail string) (app *fiber.App, pool *pgxpool.Pool, adminUID string, regularUID string) {
	t.Helper()
	pool = testdb.Setup(t)

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

	h := &AdminHandler{DB: pool, BreakGlassAdminEmail: breakGlassEmail}
	authMW := middleware.NewAuth(testJWTSecret)
	app = fiber.New()
	api := app.Group("/api")
	admin := api.Group("/admin", authMW.Required(), middleware.AdminRequired())
	admin.Get("/users", h.ListUsers)
	admin.Post("/users", h.CreateUser)
	admin.Put("/users/:id", h.UpdateUser)
	admin.Delete("/users/:id", h.DeleteUser)
	admin.Delete("/users/:id/2fa", h.ForceDisable2FA)
	admin.Get("/stats", h.GetStats)
	return app, pool, adminUID, regularUID
}

// newAdminApp is the no-break-glass variant used by most tests.
func newAdminApp(t *testing.T) (app *fiber.App, adminUID string, regularUID string) {
	t.Helper()
	app, _, adminUID, regularUID = buildAdminApp(t, "")
	return app, adminUID, regularUID
}

// newAdminAppBG marks the seeded admin@example.com as the break-glass admin.
func newAdminAppBG(t *testing.T) (app *fiber.App, adminUID string, regularUID string) {
	t.Helper()
	app, _, adminUID, regularUID = buildAdminApp(t, "admin@example.com")
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

// userField fetches a single field of one user from GET /admin/users.
func userField(t *testing.T, app *fiber.App, adminUID, targetUID, field string) any {
	t.Helper()
	req := adminAuthedReq(t, http.MethodGet, "/api/admin/users", "", adminUID, true)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	var users []map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&users)
	for _, u := range users {
		if u["id"] == targetUID {
			return u[field]
		}
	}
	t.Fatalf("user %s not found in /admin/users", targetUID)
	return nil
}

func TestUpdateUser_PromoteDemote(t *testing.T) {
	app, adminUID, regularUID := newAdminApp(t)

	// Promote the regular user.
	req := adminAuthedReq(t, http.MethodPut, "/api/admin/users/"+regularUID, `{"isAdmin":true}`, adminUID, true)
	if resp, _ := app.Test(req, -1); resp.StatusCode != 200 {
		t.Fatalf("promote: status = %d, want 200", resp.StatusCode)
	}
	if got := userField(t, app, adminUID, regularUID, "isAdmin"); got != true {
		t.Errorf("after promote: isAdmin = %v, want true", got)
	}

	// Demote back — allowed, the seeded admin is still a usable admin.
	req = adminAuthedReq(t, http.MethodPut, "/api/admin/users/"+regularUID, `{"isAdmin":false}`, adminUID, true)
	if resp, _ := app.Test(req, -1); resp.StatusCode != 200 {
		t.Fatalf("demote: status = %d, want 200", resp.StatusCode)
	}
	if got := userField(t, app, adminUID, regularUID, "isAdmin"); got != false {
		t.Errorf("after demote: isAdmin = %v, want false", got)
	}
}

func TestUpdateUser_CannotDemoteLastAdmin(t *testing.T) {
	// No break-glass admin configured — the generic last-admin guard applies.
	app, adminUID, _ := newAdminApp(t)
	req := adminAuthedReq(t, http.MethodPut, "/api/admin/users/"+adminUID, `{"isAdmin":false}`, adminUID, true)
	resp, _ := app.Test(req, -1)
	if resp.StatusCode != 400 {
		t.Errorf("demote sole admin: status = %d, want 400", resp.StatusCode)
	}
}

func TestUpdateUser_CannotDisableLastAdmin(t *testing.T) {
	app, adminUID, _ := newAdminApp(t)
	req := adminAuthedReq(t, http.MethodPut, "/api/admin/users/"+adminUID, `{"isActive":false}`, adminUID, true)
	resp, _ := app.Test(req, -1)
	if resp.StatusCode != 400 {
		t.Errorf("disable sole admin: status = %d, want 400", resp.StatusCode)
	}
}

func TestUpdateUser_BreakGlassAdminCannotBeDemoted(t *testing.T) {
	app, adminUID, _ := newAdminAppBG(t)
	req := adminAuthedReq(t, http.MethodPut, "/api/admin/users/"+adminUID, `{"isAdmin":false}`, adminUID, true)
	resp, _ := app.Test(req, -1)
	if resp.StatusCode != 403 {
		t.Errorf("demote break-glass admin: status = %d, want 403", resp.StatusCode)
	}
}

func TestUpdateUser_BreakGlassAdminCannotBeDisabled(t *testing.T) {
	app, adminUID, _ := newAdminAppBG(t)
	req := adminAuthedReq(t, http.MethodPut, "/api/admin/users/"+adminUID, `{"isActive":false}`, adminUID, true)
	resp, _ := app.Test(req, -1)
	if resp.StatusCode != 403 {
		t.Errorf("disable break-glass admin: status = %d, want 403", resp.StatusCode)
	}
}

func TestUpdateUser_BreakGlassAdminQuotaStillEditable(t *testing.T) {
	// Break-glass protection only blocks demote/disable — quota edits work.
	app, adminUID, _ := newAdminAppBG(t)
	req := adminAuthedReq(t, http.MethodPut, "/api/admin/users/"+adminUID, `{"storageQuotaBytes":2147483648}`, adminUID, true)
	resp, _ := app.Test(req, -1)
	if resp.StatusCode != 200 {
		t.Errorf("quota edit on break-glass admin: status = %d, want 200", resp.StatusCode)
	}
}

func TestDeleteUser_BreakGlassAdminProtected(t *testing.T) {
	app, adminUID, _ := newAdminAppBG(t)
	req := adminAuthedReq(t, http.MethodDelete, "/api/admin/users/"+adminUID, "", adminUID, true)
	resp, _ := app.Test(req, -1)
	if resp.StatusCode != 403 {
		t.Errorf("delete break-glass admin: status = %d, want 403", resp.StatusCode)
	}
}

func TestListUsers_MarksBreakGlassProtected(t *testing.T) {
	app, adminUID, regularUID := newAdminAppBG(t)
	if got := userField(t, app, adminUID, adminUID, "isProtected"); got != true {
		t.Errorf("break-glass admin: isProtected = %v, want true", got)
	}
	if got := userField(t, app, adminUID, regularUID, "isProtected"); got != false {
		t.Errorf("regular user: isProtected = %v, want false", got)
	}
}

func TestForceDisable2FA(t *testing.T) {
	app, pool, adminUID, regularUID := buildAdminApp(t, "")

	// Give the regular user 2FA, then have an admin force-disable it.
	if _, err := pool.Exec(context.Background(),
		`UPDATE users SET totp_enabled=true, totp_secret='SECRET' WHERE id=$1`, regularUID); err != nil {
		t.Fatalf("seed totp: %v", err)
	}

	req := adminAuthedReq(t, http.MethodDelete, "/api/admin/users/"+regularUID+"/2fa", "", adminUID, true)
	resp, _ := app.Test(req, -1)
	if resp.StatusCode != 200 {
		t.Fatalf("force-disable 2fa: status = %d, want 200", resp.StatusCode)
	}

	var enabled bool
	var secret *string
	if err := pool.QueryRow(context.Background(),
		`SELECT totp_enabled, totp_secret FROM users WHERE id=$1`, regularUID).Scan(&enabled, &secret); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if enabled {
		t.Error("totp_enabled still true after force-disable")
	}
	if secret != nil {
		t.Errorf("totp_secret = %v, want NULL after force-disable", *secret)
	}

	// Unknown user → 404.
	req = adminAuthedReq(t, http.MethodDelete, "/api/admin/users/00000000-0000-0000-0000-000000000000/2fa", "", adminUID, true)
	if resp, _ := app.Test(req, -1); resp.StatusCode != 404 {
		t.Errorf("force-disable 2fa unknown: status = %d, want 404", resp.StatusCode)
	}
}
