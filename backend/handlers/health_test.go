package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestHealthHandler_Get(t *testing.T) {
	h := &HealthHandler{Version: "1.2.3"}
	app := fiber.New()
	app.Get("/api/health", h.Get)

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)

	var got struct {
		Name        string   `json:"name"`
		Version     string   `json:"version"`
		TusVersions []string `json:"tusVersions"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("json: %v\nbody=%s", err, body)
	}
	if got.Name != "kutup" {
		t.Errorf("name = %q, want kutup", got.Name)
	}
	if got.Version != "1.2.3" {
		t.Errorf("version = %q, want 1.2.3", got.Version)
	}
	if len(got.TusVersions) != 1 || got.TusVersions[0] != "1.0.0" {
		t.Errorf("tusVersions = %v, want [1.0.0]", got.TusVersions)
	}
}
