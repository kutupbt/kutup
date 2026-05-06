package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/kutup/backend/utils"
)

const testSecret = "mw-test-secret-do-not-use-in-prod"

// helper: a Fiber app with a single protected route that echoes the userId
// + isAdmin from Locals as JSON.
func newProtectedApp(secret string) *fiber.App {
	mw := NewAuth(secret)
	app := fiber.New()
	app.Get("/protected", mw.Required(), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"userId": UserID(c), "isAdmin": IsAdmin(c)})
	})
	return app
}

func do(t *testing.T, app *fiber.App, header string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if header != "" {
		req.Header.Set("Authorization", header)
	}
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 1024)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, string(buf[:n])
}

func TestRequired_AllowsValidAccessToken(t *testing.T) {
	app := newProtectedApp(testSecret)
	tok, err := utils.GenerateAccessToken("alice", true, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	status, body := do(t, app, "Bearer "+tok)
	if status != 200 {
		t.Fatalf("status = %d, body=%s", status, body)
	}
	if !contains(body, "alice") {
		t.Errorf("body should contain userId=alice, got %s", body)
	}
	if !contains(body, "true") {
		t.Errorf("body should contain isAdmin=true, got %s", body)
	}
}

func TestRequired_RejectsMissingHeader(t *testing.T) {
	app := newProtectedApp(testSecret)
	status, _ := do(t, app, "")
	if status != 401 {
		t.Errorf("status = %d, want 401", status)
	}
}

func TestRequired_RejectsNonBearer(t *testing.T) {
	app := newProtectedApp(testSecret)
	tok, _ := utils.GenerateAccessToken("u", false, testSecret)
	// Same valid token, wrong scheme.
	status, _ := do(t, app, "Basic "+tok)
	if status != 401 {
		t.Errorf("status = %d, want 401", status)
	}
}

func TestRequired_RejectsWrongSecret(t *testing.T) {
	app := newProtectedApp(testSecret)
	tok, _ := utils.GenerateAccessToken("u", false, "different-secret")
	status, _ := do(t, app, "Bearer "+tok)
	if status != 401 {
		t.Errorf("status = %d, want 401", status)
	}
}

func TestRequired_RejectsSetupToken(t *testing.T) {
	// A setup token must NOT be accepted as a full access token. The bug this
	// guards against: an attacker who steals a short-lived setup token
	// (e.g. from a logged email) using it to read the user's files.
	app := newProtectedApp(testSecret)
	tok, _ := utils.GenerateSetupToken("u", testSecret)
	status, _ := do(t, app, "Bearer "+tok)
	if status != 401 {
		t.Errorf("setup token must be rejected at Required, got %d", status)
	}
}

func TestRequired_RejectsPreAuthToken(t *testing.T) {
	app := newProtectedApp(testSecret)
	tok, _ := utils.GeneratePreAuthToken("u", testSecret)
	status, _ := do(t, app, "Bearer "+tok)
	if status != 401 {
		t.Errorf("pre-auth token must be rejected at Required, got %d", status)
	}
}

func TestValidateTokenString_AcceptsAccessToken(t *testing.T) {
	mw := NewAuth(testSecret)
	tok, _ := utils.GenerateAccessToken("u-id", true, testSecret)
	uid, isAdmin, err := mw.ValidateTokenString(tok)
	if err != nil {
		t.Fatal(err)
	}
	if uid != "u-id" || !isAdmin {
		t.Errorf("uid=%q isAdmin=%v, want u-id true", uid, isAdmin)
	}
}

func TestValidateTokenString_RejectsSetupToken(t *testing.T) {
	mw := NewAuth(testSecret)
	tok, _ := utils.GenerateSetupToken("u", testSecret)
	if _, _, err := mw.ValidateTokenString(tok); err == nil {
		t.Error("setup token must be rejected by ValidateTokenString")
	}
}

func TestUserID_IsAdmin_WithoutLocals(t *testing.T) {
	// When the middleware hasn't populated Locals (e.g. on an unauthenticated
	// route that nonetheless calls UserID), helpers must return zero-values
	// rather than panic.
	app := fiber.New()
	app.Get("/zero", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"u": UserID(c), "a": IsAdmin(c)})
	})
	req := httptest.NewRequest(http.MethodGet, "/zero", nil)
	resp, _ := app.Test(req, -1)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func contains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
