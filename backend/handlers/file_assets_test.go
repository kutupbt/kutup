package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kutup/backend/internal/testdb"
	"github.com/kutup/backend/middleware"
)

// newAssetApp wires the FileAssetsHandler routes against a fresh schema
// with one user, one collection, one file. Storage is left nil because the
// auth + path-validation gates fire before any S3 call. Round-trip
// behaviour is covered by the e2e suite (specs/23-whiteboard-image.spec.ts)
// against a real SeaweedFS.
func newAssetApp(t *testing.T) (app *fiber.App, pool *pgxpool.Pool, ownerUID string, fileID string) {
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
		) VALUES ('asset@example.com','asset','h','','','','','','','','','',false,false)
		RETURNING id`).Scan(&ownerUID); err != nil {
		t.Fatal(err)
	}
	var collID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO collections (owner_user_id, encrypted_name, name_nonce,
			encrypted_key, encrypted_key_nonce, parent_collection_id)
		 VALUES ($1,'X','Y','Z','W',NULL) RETURNING id`, ownerUID).Scan(&collID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO files (collection_id, uploader_user_id,
			encrypted_metadata, metadata_nonce,
			encrypted_file_key, file_key_nonce,
			storage_path, encrypted_size_bytes)
		 VALUES ($1,$2,'meta','mn','fk','fkn','/some/path',0)
		 RETURNING id`, collID, ownerUID).Scan(&fileID); err != nil {
		t.Fatal(err)
	}

	h := &FileAssetsHandler{DB: pool}
	authMW := middleware.NewAuth(testJWTSecret)

	app = fiber.New()
	api := app.Group("/api")
	api.Put("/files/:fileId/assets/:assetId", authMW.Required(), h.Upload)
	api.Get("/files/:fileId/assets/:assetId", authMW.Required(), h.Download)
	return app, pool, ownerUID, fileID
}

func TestAssetUpload_RequiresAuth(t *testing.T) {
	app, _, _, fid := newAssetApp(t)
	req := httptest.NewRequest(http.MethodPut, "/api/files/"+fid+"/assets/abc", nil)
	resp, _ := app.Test(req, -1)
	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAssetDownload_RejectsCrossUser(t *testing.T) {
	app, pool, _, fid := newAssetApp(t)
	var strangerUID string
	pool.QueryRow(context.Background(),
		`INSERT INTO users (email, username, login_key_hash,
			encrypted_master_key, master_key_nonce,
			encrypted_recovery_key, recovery_key_nonce,
			encrypted_private_key, private_key_nonce,
			public_key, kdf_salt, login_key_salt,
			is_admin, is_first_login)
		 VALUES ('stranger@example.com','stranger','h','','','','','','','','','',false,false)
		 RETURNING id`).Scan(&strangerUID)

	req := authedReq(t, http.MethodGet, "/api/files/"+fid+"/assets/abc", "", strangerUID)
	resp, _ := app.Test(req, -1)
	if resp.StatusCode != 403 {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAssetUpload_RejectsCrossUser(t *testing.T) {
	app, pool, _, fid := newAssetApp(t)
	var strangerUID string
	pool.QueryRow(context.Background(),
		`INSERT INTO users (email, username, login_key_hash,
			encrypted_master_key, master_key_nonce,
			encrypted_recovery_key, recovery_key_nonce,
			encrypted_private_key, private_key_nonce,
			public_key, kdf_salt, login_key_salt,
			is_admin, is_first_login)
		 VALUES ('stranger2@example.com','stranger2','h','','','','','','','','','',false,false)
		 RETURNING id`).Scan(&strangerUID)

	req := authedReq(t, http.MethodPut, "/api/files/"+fid+"/assets/abc", "", strangerUID)
	resp, _ := app.Test(req, -1)
	if resp.StatusCode != 403 {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAssetUpload_ValidatesAssetID(t *testing.T) {
	app, _, uid, fid := newAssetApp(t)
	// Path traversal: the .. component must be rejected before we hit the
	// canAccessFile gate. Fiber decodes URL params, so the raw colon in the
	// route forces the value through c.Params unchanged.
	for _, bad := range []string{"..", "../etc", "a/b", "x\\y"} {
		req := authedReq(t, http.MethodPut, "/api/files/"+fid+"/assets/"+bad, "", uid)
		resp, _ := app.Test(req, -1)
		// Fiber may 404 on slashes (route doesn't match) or our handler
		// returns 400. Either way, never a 200/204 — that's the only thing
		// that would indicate a real upload happened with a bad assetId.
		if resp.StatusCode == 200 || resp.StatusCode == 204 {
			t.Errorf("assetId %q produced status %d, expected rejection", bad, resp.StatusCode)
		}
	}
}

func TestAssetDownload_ReturnsNotFoundForUnknownAsset(t *testing.T) {
	// Owner can access the file, but the asset blob doesn't exist in S3.
	// With a nil Storage, GetObject would panic — so this test only runs
	// the path that succeeds before storage is hit. We assert the auth
	// gate passes (status != 403) using a HEAD-ish probe... actually since
	// our handler doesn't expose a "does this exist?" path without S3,
	// skip this test. The not-found path is covered by manual smoke.
	t.Skip("requires real Storage; covered by e2e smoke")
}
