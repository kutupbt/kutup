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

// newCollectionsApp wires CollectionsHandler behind the real auth middleware
// against a fresh schema. Returns the app, pool, and a userID we already
// inserted into `users` so subsequent calls can act as that user.
func newCollectionsApp(t *testing.T) (*fiber.App, *pgxpool.Pool, string) {
	t.Helper()
	pool := testdb.Setup(t)

	// Insert a user we can act as.
	var uid string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (
			email, username, login_key_hash,
			encrypted_master_key, master_key_nonce,
			encrypted_recovery_key, recovery_key_nonce,
			encrypted_private_key, private_key_nonce,
			public_key, kdf_salt, login_key_salt,
			is_admin, is_first_login
		) VALUES ('alice@example.com','alice','hash','','','','','','','','','',false,false)
		RETURNING id`).Scan(&uid); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	h := &CollectionsHandler{DB: pool, ServerURL: "https://test.local", AppEnv: "test"}
	authMW := middleware.NewAuth(testJWTSecret)

	app := fiber.New()
	api := app.Group("/api")
	collections := api.Group("/collections", authMW.Required())
	collections.Get("/", h.ListCollections)
	collections.Post("/", h.CreateCollection)
	collections.Get("/:id", h.GetCollection)
	collections.Delete("/:id", h.DeleteCollection)
	return app, pool, uid
}

func authedReq(t *testing.T, method, path string, body string, uid string) *http.Request {
	t.Helper()
	tok, err := utils.GenerateAccessToken(uid, false, testJWTSecret)
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

func TestListCollections_RequiresAuth(t *testing.T) {
	app, _, _ := newCollectionsApp(t)
	req := httptest.NewRequest(http.MethodGet, "/api/collections/", nil)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestListCollections_EmptyForFreshUser(t *testing.T) {
	app, _, uid := newCollectionsApp(t)
	req := authedReq(t, http.MethodGet, "/api/collections/", "", uid)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got []any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty list, got %d entries", len(got))
	}
}

func TestCreateCollection_RoundTripsThroughList(t *testing.T) {
	app, _, uid := newCollectionsApp(t)
	body := `{
		"encryptedName": "AAAA",
		"nameNonce": "BBBB",
		"encryptedKey": "CCCC",
		"encryptedKeyNonce": "DDDD",
		"parentCollectionId": null
	}`
	req := authedReq(t, http.MethodPost, "/api/collections/", body, uid)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 201 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.ID == "" {
		t.Fatal("created collection id is empty")
	}

	// List should now return one row, owned by the requesting user.
	listReq := authedReq(t, http.MethodGet, "/api/collections/", "", uid)
	listResp, err := app.Test(listReq, -1)
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	_ = json.NewDecoder(listResp.Body).Decode(&rows)
	if len(rows) != 1 {
		t.Fatalf("list returned %d rows, want 1", len(rows))
	}
	if rows[0]["ownerUserId"] != uid {
		t.Errorf("ownerUserId = %v, want %v", rows[0]["ownerUserId"], uid)
	}
}

func TestGetCollection_ReturnsOwnerOnly(t *testing.T) {
	app, pool, uid := newCollectionsApp(t)

	// Seed a second user + their collection — uid must NOT see it.
	var otherUID, otherCollID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (email, username, login_key_hash,
			encrypted_master_key, master_key_nonce,
			encrypted_recovery_key, recovery_key_nonce,
			encrypted_private_key, private_key_nonce,
			public_key, kdf_salt, login_key_salt,
			is_admin, is_first_login)
		 VALUES ('mallory@example.com','mallory','h','','','','','','','','','',false,false)
		 RETURNING id`).Scan(&otherUID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO collections (owner_user_id, encrypted_name, name_nonce,
			encrypted_key, encrypted_key_nonce, parent_collection_id)
		 VALUES ($1,'X','Y','Z','W',NULL) RETURNING id`, otherUID).Scan(&otherCollID); err != nil {
		t.Fatal(err)
	}

	// Requesting alice's session for mallory's collection: 404 (not 403 —
	// the handler doesn't reveal existence).
	req := authedReq(t, http.MethodGet, "/api/collections/"+otherCollID, "", uid)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 404 {
		t.Errorf("alice viewing mallory's collection: status = %d, want 404", resp.StatusCode)
	}
}

func TestDeleteCollection_OwnerOnly(t *testing.T) {
	app, pool, uid := newCollectionsApp(t)

	var otherUID, otherCollID string
	pool.QueryRow(context.Background(),
		`INSERT INTO users (email, username, login_key_hash,
			encrypted_master_key, master_key_nonce,
			encrypted_recovery_key, recovery_key_nonce,
			encrypted_private_key, private_key_nonce,
			public_key, kdf_salt, login_key_salt,
			is_admin, is_first_login)
		 VALUES ('victim@example.com','victim','h','','','','','','','','','',false,false)
		 RETURNING id`).Scan(&otherUID)
	pool.QueryRow(context.Background(),
		`INSERT INTO collections (owner_user_id, encrypted_name, name_nonce,
			encrypted_key, encrypted_key_nonce, parent_collection_id)
		 VALUES ($1,'X','Y','Z','W',NULL) RETURNING id`, otherUID).Scan(&otherCollID)

	// alice trying to delete victim's collection.
	req := authedReq(t, http.MethodDelete, "/api/collections/"+otherCollID, "", uid)
	resp, _ := app.Test(req, -1)
	// Handler returns 200 even when no row was affected — but the row
	// must still be in the DB (the WHERE clause filters by owner).
	var still int
	pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM collections WHERE id=$1`, otherCollID).Scan(&still)
	if still != 1 {
		t.Errorf("victim's collection was deleted by non-owner (status=%d)", resp.StatusCode)
	}
}
