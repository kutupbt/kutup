package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kutup/backend/internal/testdb"
	"github.com/kutup/backend/middleware"
)

// newClaimSeedApp wires the FilesHandler.ClaimSeed route against a fresh
// schema with one user, one collection, one file. Returns app, pool, the
// owner userID, and the fileID we just inserted.
func newClaimSeedApp(t *testing.T) (app *fiber.App, pool *pgxpool.Pool, ownerUID string, fileID string) {
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
		) VALUES ('claim@example.com','claim','h','','','','','','','','','',false,false)
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

	h := &FilesHandler{DB: pool}
	authMW := middleware.NewAuth(testJWTSecret)

	app = fiber.New()
	api := app.Group("/api")
	api.Post("/files/:fileId/claim-seed", authMW.Required(), h.ClaimSeed)
	return app, pool, ownerUID, fileID
}

func TestClaimSeed_FirstCallerWins(t *testing.T) {
	app, _, uid, fid := newClaimSeedApp(t)
	req := authedReq(t, http.MethodPost, "/api/files/"+fid+"/claim-seed", "", uid)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got ClaimSeedResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !got.Committed {
		t.Error("first caller must get committed=true")
	}
}

func TestClaimSeed_SecondCallerLoses(t *testing.T) {
	app, _, uid, fid := newClaimSeedApp(t)
	// First call wins.
	r1, _ := app.Test(authedReq(t, http.MethodPost, "/api/files/"+fid+"/claim-seed", "", uid), -1)
	if r1.StatusCode != 200 {
		t.Fatalf("first call status = %d", r1.StatusCode)
	}
	// Second call must observe committed=false (NOT a 404 / 500).
	r2, _ := app.Test(authedReq(t, http.MethodPost, "/api/files/"+fid+"/claim-seed", "", uid), -1)
	if r2.StatusCode != 200 {
		t.Fatalf("second call status = %d, want 200", r2.StatusCode)
	}
	var got ClaimSeedResponse
	_ = json.NewDecoder(r2.Body).Decode(&got)
	if got.Committed {
		t.Error("second caller must get committed=false")
	}
}

func TestClaimSeed_ConcurrentExactlyOneWins(t *testing.T) {
	// The race-condition guard: spawn N goroutines that all try to claim
	// the same file at the same instant. Postgres's row-level lock on
	// the UPDATE ... WHERE seed_committed=false RETURNING id must ensure
	// exactly one of them sees the row before the false→true flip.
	app, _, uid, fid := newClaimSeedApp(t)

	const N = 8
	var wins int32
	var wg sync.WaitGroup
	wg.Add(N)
	start := make(chan struct{})

	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			<-start
			req := authedReq(t, http.MethodPost, "/api/files/"+fid+"/claim-seed", "", uid)
			resp, err := app.Test(req, -1)
			if err != nil || resp.StatusCode != 200 {
				return
			}
			var got ClaimSeedResponse
			if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
				return
			}
			if got.Committed {
				atomic.AddInt32(&wins, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt32(&wins); got != 1 {
		t.Errorf("concurrent claim winners = %d, want exactly 1", got)
	}
}

func TestClaimSeed_RejectsForUnknownFile(t *testing.T) {
	app, _, uid, _ := newClaimSeedApp(t)
	req := authedReq(t, http.MethodPost, "/api/files/00000000-0000-0000-0000-000000000000/claim-seed", "", uid)
	resp, _ := app.Test(req, -1)
	if resp.StatusCode != 404 {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestClaimSeed_RejectsCrossUser(t *testing.T) {
	app, pool, _, fid := newClaimSeedApp(t)

	// Seed a stranger.
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

	req := authedReq(t, http.MethodPost, "/api/files/"+fid+"/claim-seed", "", strangerUID)
	resp, _ := app.Test(req, -1)
	if resp.StatusCode != 403 {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}
