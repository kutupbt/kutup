package services

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kutup/backend/internal/testdb"
)

// seedUser inserts a user and one collection, returns the user id and
// collection id. Used to set up reconciliation drift scenarios.
// `slug` is used for both email and username (must satisfy the
// users_username_format check: ^[a-z0-9_-]{3,32}$).
func seedUser(t *testing.T, pool *pgxpool.Pool, slug string) (uid, collID string) {
	t.Helper()
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (
			email, username, login_key_hash,
			encrypted_master_key, master_key_nonce,
			encrypted_recovery_key, recovery_key_nonce,
			encrypted_private_key, private_key_nonce,
			public_key, kdf_salt, login_key_salt,
			is_admin, is_first_login
		) VALUES ($1 || '@example.com',$1,'h','','','','','','','','','',false,false)
		RETURNING id`, slug).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO collections (owner_user_id, encrypted_name, name_nonce,
			encrypted_key, encrypted_key_nonce, parent_collection_id)
		 VALUES ($1,'X','Y','Z','W',NULL) RETURNING id`, uid).Scan(&collID); err != nil {
		t.Fatal(err)
	}
	return
}

func TestReconcile_FixesDriftedCounter(t *testing.T) {
	pool := testdb.Setup(t)
	uid, collID := seedUser(t, pool, "drift_user")

	// Insert a file (1000 bytes) + two assets (300 + 200) — true total 1500.
	var fileID string
	pool.QueryRow(context.Background(),
		`INSERT INTO files (collection_id, uploader_user_id,
			encrypted_metadata, metadata_nonce, encrypted_file_key, file_key_nonce,
			storage_path, encrypted_size_bytes)
		 VALUES ($1,$2,'m','n','k','kn','/p',1000)
		 RETURNING id`, collID, uid).Scan(&fileID)
	pool.Exec(context.Background(),
		`INSERT INTO file_assets (file_id, asset_id, size_bytes, uploader_user_id)
		 VALUES ($1,'a',300,$2), ($1,'b',200,$2)`, fileID, uid)

	// Manually drift the counter to a wrong value.
	pool.Exec(context.Background(),
		`UPDATE users SET storage_used_bytes = 9999 WHERE id = $1`, uid)

	q := &QuotaReconcile{DB: pool}
	corrected := q.Tick(context.Background())
	if corrected < 1 {
		t.Errorf("Tick returned %d corrected users, expected >= 1", corrected)
	}

	var got int64
	pool.QueryRow(context.Background(),
		`SELECT storage_used_bytes FROM users WHERE id = $1`, uid).Scan(&got)
	if got != 1500 {
		t.Errorf("after reconcile storage_used_bytes = %d, want 1500", got)
	}
}

func TestReconcile_NoOpWhenAccurate(t *testing.T) {
	pool := testdb.Setup(t)
	uid, collID := seedUser(t, pool, "accurate_user")

	var fileID string
	pool.QueryRow(context.Background(),
		`INSERT INTO files (collection_id, uploader_user_id,
			encrypted_metadata, metadata_nonce, encrypted_file_key, file_key_nonce,
			storage_path, encrypted_size_bytes)
		 VALUES ($1,$2,'m','n','k','kn','/p',500)
		 RETURNING id`, collID, uid).Scan(&fileID)
	pool.Exec(context.Background(),
		`INSERT INTO file_assets (file_id, asset_id, size_bytes, uploader_user_id)
		 VALUES ($1,'a',100,$2)`, fileID, uid)
	// Pre-set the counter to the correct value.
	pool.Exec(context.Background(),
		`UPDATE users SET storage_used_bytes = 600 WHERE id = $1`, uid)

	q := &QuotaReconcile{DB: pool}
	corrected := q.Tick(context.Background())
	if corrected != 0 {
		t.Errorf("Tick rewrote %d users when none drifted", corrected)
	}

	var got int64
	pool.QueryRow(context.Background(),
		`SELECT storage_used_bytes FROM users WHERE id = $1`, uid).Scan(&got)
	if got != 600 {
		t.Errorf("counter changed from 600 to %d on no-op tick", got)
	}
}

func TestReconcile_IncludesSnapshotBytes(t *testing.T) {
	// Three byte-charged tables — the reconciler must sum all three.
	pool := testdb.Setup(t)
	uid, collID := seedUser(t, pool, "snapsum_user")

	var fileID string
	pool.QueryRow(context.Background(),
		`INSERT INTO files (collection_id, uploader_user_id,
			encrypted_metadata, metadata_nonce, encrypted_file_key, file_key_nonce,
			storage_path, encrypted_size_bytes)
		 VALUES ($1,$2,'m','n','k','kn','/p',100)
		 RETURNING id`, collID, uid).Scan(&fileID)
	pool.Exec(context.Background(),
		`INSERT INTO file_assets (file_id, asset_id, size_bytes, uploader_user_id)
		 VALUES ($1,'a',50,$2)`, fileID, uid)
	pool.Exec(context.Background(),
		`INSERT INTO file_versions (file_id, s3_version_id, storage_path, seq_at_snapshot,
			doc_key_id, author_user_id, size_bytes)
		 VALUES ($1,'vid',$2,0,1,$3,200)`,
		fileID, "files/"+fileID+"/snapshot", uid)

	// Drift the counter to a wrong value.
	pool.Exec(context.Background(),
		`UPDATE users SET storage_used_bytes = 9999 WHERE id = $1`, uid)

	q := &QuotaReconcile{DB: pool}
	q.Tick(context.Background())

	var got int64
	pool.QueryRow(context.Background(),
		`SELECT storage_used_bytes FROM users WHERE id = $1`, uid).Scan(&got)
	want := int64(100 + 50 + 200)
	if got != want {
		t.Errorf("storage_used_bytes = %d, want %d (file:100 + asset:50 + snapshot:200)", got, want)
	}
}

func TestReconcile_FixesUserWithZeroFiles(t *testing.T) {
	// A user with corrupted counter but no files must reconcile to 0.
	pool := testdb.Setup(t)
	uid, _ := seedUser(t, pool, "empty_user")
	pool.Exec(context.Background(),
		`UPDATE users SET storage_used_bytes = 1234 WHERE id = $1`, uid)

	q := &QuotaReconcile{DB: pool}
	q.Tick(context.Background())

	var got int64
	pool.QueryRow(context.Background(),
		`SELECT storage_used_bytes FROM users WHERE id = $1`, uid).Scan(&got)
	if got != 0 {
		t.Errorf("zero-file user reconciled to %d, want 0", got)
	}
}
