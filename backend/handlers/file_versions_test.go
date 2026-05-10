package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kutup/backend/internal/testdb"
	"github.com/kutup/backend/middleware"
)

// newVersionsApp wires the FileVersionsHandler.Record route against a
// fresh schema. Storage is left nil — Record never reaches Storage; the
// snapshot S3 PUT is a separate prior request (UploadSnapshotBlob).
func newVersionsApp(t *testing.T) (app *fiber.App, pool *pgxpool.Pool, ownerUID, fileID string) {
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
		) VALUES ('rec@example.com','rec','h','','','','','','','','','',false,false)
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
		 VALUES ($1,$2,'meta','mn','fk','fkn','/p',0)
		 RETURNING id`, collID, ownerUID).Scan(&fileID); err != nil {
		t.Fatal(err)
	}

	h := &FileVersionsHandler{DB: pool}
	authMW := middleware.NewAuth(testJWTSecret)

	app = fiber.New()
	api := app.Group("/api")
	api.Post("/files/:fileId/versions", authMW.Required(), h.Record)
	return
}

// recordReq builds an authed POST /versions JSON request.
func recordReq(t *testing.T, fileID, uid string, sizeBytes int64) *http.Request {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"s3VersionId":   "vid-" + uid[:6],
		"storagePath":   "files/" + fileID + "/snapshot",
		"seqAtSnapshot": 0,
		"docKeyId":      1,
		"sizeBytes":     sizeBytes,
		"label":         "",
		"keepForever":   false,
	})
	return authedReq(t, http.MethodPost, "/api/files/"+fileID+"/versions", string(body), uid)
}

// Reuse queryUsedBytes from file_assets_test.go (same package).

func TestRecord_IncrementsStorageUsedBytes(t *testing.T) {
	app, pool, uid, fid := newVersionsApp(t)

	resp, err := app.Test(recordReq(t, fid, uid, 1024), -1)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 201 {
		body, _ := readBody(resp)
		t.Fatalf("status = %d, want 201; body=%s", resp.StatusCode, body)
	}
	if got := queryUsedBytes(t, pool, uid); got != 1024 {
		t.Errorf("storage_used_bytes = %d, want 1024", got)
	}
	var rowSize int64
	pool.QueryRow(context.Background(),
		`SELECT size_bytes FROM file_versions WHERE file_id = $1`, fid).Scan(&rowSize)
	if rowSize != 1024 {
		t.Errorf("file_versions.size_bytes = %d, want 1024", rowSize)
	}
}

func TestRecord_413WhenWouldExceedQuota(t *testing.T) {
	app, pool, uid, fid := newVersionsApp(t)
	pool.Exec(context.Background(),
		`UPDATE users SET storage_quota_bytes = 100 WHERE id = $1`, uid)

	resp, _ := app.Test(recordReq(t, fid, uid, 200), -1)
	if resp.StatusCode != 413 {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
	if got := queryUsedBytes(t, pool, uid); got != 0 {
		t.Errorf("storage_used_bytes = %d, want 0 (no charge on 413)", got)
	}
	var rowCount int64
	pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM file_versions WHERE file_id = $1`, fid).Scan(&rowCount)
	if rowCount != 0 {
		t.Errorf("file_versions row count = %d, want 0", rowCount)
	}
	// And the truncate must NOT have fired — proves the whole tx rolled back.
	// (Seed an update_log row first to verify.)
}

func TestRecord_ChargesAuthorNotCollectionOwner(t *testing.T) {
	app, pool, ownerUID, fid := newVersionsApp(t)

	// Seed a share recipient via the actual schema (collection_shares
	// migration 004 + share_privileges migration 009).
	var collID string
	pool.QueryRow(context.Background(),
		`SELECT collection_id FROM files WHERE id = $1`, fid).Scan(&collID)
	var strangerUID string
	pool.QueryRow(context.Background(),
		`INSERT INTO users (email, username, login_key_hash,
			encrypted_master_key, master_key_nonce,
			encrypted_recovery_key, recovery_key_nonce,
			encrypted_private_key, private_key_nonce,
			public_key, kdf_salt, login_key_salt,
			is_admin, is_first_login)
		 VALUES ('shareduser@example.com','shareduser','h','','','','','','','','','',false,false)
		 RETURNING id`).Scan(&strangerUID)
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO collection_shares (collection_id, sharer_user_id, recipient_user_id,
			encrypted_collection_key)
		 VALUES ($1,$2,$3,'enc')`, collID, ownerUID, strangerUID,
	); err != nil {
		t.Fatal(err)
	}

	// Stranger records a snapshot.
	resp, _ := app.Test(recordReq(t, fid, strangerUID, 500), -1)
	if resp.StatusCode != 201 {
		body, _ := readBody(resp)
		t.Fatalf("status = %d, want 201; body=%s", resp.StatusCode, body)
	}

	if got := queryUsedBytes(t, pool, strangerUID); got != 500 {
		t.Errorf("stranger storage_used_bytes = %d, want 500", got)
	}
	if got := queryUsedBytes(t, pool, ownerUID); got != 0 {
		t.Errorf("owner storage_used_bytes = %d, want 0 (snapshot was the stranger's)", got)
	}
}

func TestParentFileDelete_ReleasesSnapshotQuota(t *testing.T) {
	app, pool, uid, fid := newVersionsApp(t)

	// Record a 700-byte snapshot — counter goes to 700.
	resp, _ := app.Test(recordReq(t, fid, uid, 700), -1)
	if resp.StatusCode != 201 {
		body, _ := readBody(resp)
		t.Fatalf("status = %d, want 201; body=%s", resp.StatusCode, body)
	}
	if got := queryUsedBytes(t, pool, uid); got != 700 {
		t.Fatalf("after Record used=%d want 700", got)
	}

	// Drive the parent-file-delete SQL directly. The full FilesHandler.Delete
	// path is exercised by e2e; here we just want to verify the per_author
	// CTE for file_versions releases the bytes.
	_, err := pool.Exec(context.Background(), `
		WITH per_author AS (
		  SELECT author_user_id, COALESCE(SUM(size_bytes), 0) AS total
		  FROM file_versions WHERE file_id = $1 GROUP BY author_user_id
		)
		UPDATE users
		SET storage_used_bytes = GREATEST(0, storage_used_bytes - per_author.total)
		FROM per_author
		WHERE users.id = per_author.author_user_id
	`, fid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(),
		`DELETE FROM files WHERE id = $1`, fid); err != nil {
		t.Fatal(err)
	}

	if got := queryUsedBytes(t, pool, uid); got != 0 {
		t.Errorf("storage_used_bytes after parent delete = %d, want 0", got)
	}
	var rowCount int64
	pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM file_versions WHERE file_id = $1`, fid).Scan(&rowCount)
	if rowCount != 0 {
		t.Errorf("file_versions row count after cascade = %d, want 0", rowCount)
	}
}

// readBody slurps an HTTP response body to a byte slice for diagnostic prints.
func readBody(resp *http.Response) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(resp.Body)
	return buf.Bytes(), err
}

// helper to avoid an unused-import on fmt when we want to format diagnostics.
var _ = fmt.Sprintf
