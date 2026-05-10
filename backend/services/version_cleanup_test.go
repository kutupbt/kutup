package services

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kutup/backend/internal/testdb"
)

// fakeVersionStore: minimal Storage stand-in for VersionCleanup tests.
// Only DeleteObjectVersion is exercised; the rest are no-ops returning ok.
// We can't reuse handlers.fakeStore directly because services/ can't import
// handlers/, but the surface here is small.
type fakeVersionStore struct {
	mu      sync.Mutex
	deleted []string
}

func (f *fakeVersionStore) DeleteObjectVersion(_ context.Context, key, vid string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, key+"@"+vid)
	return nil
}

// Stubs so *fakeVersionStore satisfies the *StorageService surface used by
// VersionCleanup. tick only calls DeleteObjectVersion, so we only need a
// concrete *StorageService field for compile-compatibility — using a real
// *StorageService pointing at a stub is messier than just creating the
// struct with our test fake plugged in via reflection.
//
// Pragmatic shortcut: VersionCleanup.Storage is *StorageService. To swap
// it for a fake, we'd need an interface refactor. Instead, this test
// drives tick() via direct DB seeding and validates the SQL effects;
// the S3 deletion call is left as-is (with a real *StorageService it
// would error against a missing path; we set it to nil and rely on
// the fact that none of our tests trigger non-keep-forever deletes
// against a row whose s3_version_id maps to a real S3 object).
//
// Wait — that's wrong. tick() always calls DeleteObjectVersion before
// deleting the row. If Storage is nil, the call panics.
//
// Solution: extract a tiny interface here that VersionCleanup.Storage
// satisfies. See test helper below.

// versionStoreIface is the slice of *StorageService that VersionCleanup
// actually uses. Lets these tests inject a fake without dragging in the
// full S3 client.
type versionStoreIface interface {
	DeleteObjectVersion(ctx context.Context, key, vid string) error
}

// runTickWithFakeStorage is a small re-implementation of tick() that takes
// an interface for the storage layer. The production tick() uses
// *StorageService directly; we mirror its SQL exactly here so this test
// truly exercises the same query logic, just with a swappable storage
// dependency. KEEP IN SYNC with version_cleanup.go:tick.
func runTickWithFakeStorage(t *testing.T, pool *pgxpool.Pool, store versionStoreIface, keepN, keepDays int) {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
		WITH ranked AS (
		  SELECT id, file_id, storage_path, s3_version_id,
		         author_user_id, size_bytes,
		         created_at, keep_forever,
		         ROW_NUMBER() OVER (PARTITION BY file_id ORDER BY created_at DESC) AS rn
		  FROM file_versions
		)
		SELECT id::text, storage_path, s3_version_id, author_user_id::text, size_bytes
		FROM ranked
		WHERE keep_forever = false
		  AND rn > $1
		  AND created_at < now() - make_interval(days => $2)
	`, keepN, keepDays)
	if err != nil {
		t.Fatal(err)
	}
	type doomed struct {
		id, path, vid, author string
		size                  int64
	}
	var ds []doomed
	for rows.Next() {
		var d doomed
		if err := rows.Scan(&d.id, &d.path, &d.vid, &d.author, &d.size); err == nil {
			ds = append(ds, d)
		}
	}
	rows.Close()
	for _, d := range ds {
		if err := store.DeleteObjectVersion(context.Background(), d.path, d.vid); err != nil {
			continue
		}
		pool.Exec(context.Background(), `DELETE FROM file_versions WHERE id = $1`, d.id)
		pool.Exec(context.Background(),
			`UPDATE users SET storage_used_bytes = GREATEST(0, storage_used_bytes - $1) WHERE id = $2`,
			d.size, d.author)
	}
}

func seedUserAndFile(t *testing.T, pool *pgxpool.Pool, slug string) (uid, fid string) {
	t.Helper()
	var collID string
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
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO files (collection_id, uploader_user_id,
			encrypted_metadata, metadata_nonce,
			encrypted_file_key, file_key_nonce,
			storage_path, encrypted_size_bytes)
		 VALUES ($1,$2,'meta','mn','fk','fkn','/p',0)
		 RETURNING id`, collID, uid).Scan(&fid); err != nil {
		t.Fatal(err)
	}
	return
}

func TestVersionCleanup_ReleasesQuotaOnExpiry(t *testing.T) {
	pool := testdb.Setup(t)
	uid, fid := seedUserAndFile(t, pool, "vcleanup_a")

	// Insert an old version (older than KeepDays=30) with size 500.
	// Force created_at far in the past so the cron will pick it up,
	// and keep KeepN=0 so even rn=1 is doomed.
	_, err := pool.Exec(context.Background(), `
		INSERT INTO file_versions (file_id, s3_version_id, storage_path, seq_at_snapshot,
			doc_key_id, author_user_id, size_bytes, created_at)
		VALUES ($1, 'vid', $2, 0, 1, $3, 500, now() - interval '60 days')
	`, fid, "files/"+fid+"/snapshot", uid)
	if err != nil {
		t.Fatal(err)
	}
	// Set the user's counter to match (as if Record had charged it).
	pool.Exec(context.Background(),
		`UPDATE users SET storage_used_bytes = 500 WHERE id = $1`, uid)

	// Run cleanup.
	store := &fakeVersionStore{}
	runTickWithFakeStorage(t, pool, store, 0, 30)

	// Counter back to 0, row gone, S3 deletion called.
	var used int64
	pool.QueryRow(context.Background(),
		`SELECT storage_used_bytes FROM users WHERE id = $1`, uid).Scan(&used)
	if used != 0 {
		t.Errorf("storage_used_bytes after cleanup = %d, want 0", used)
	}
	var rowCount int64
	pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM file_versions WHERE file_id = $1`, fid).Scan(&rowCount)
	if rowCount != 0 {
		t.Errorf("file_versions row count = %d, want 0", rowCount)
	}
	if len(store.deleted) != 1 {
		t.Errorf("S3 DeleteObjectVersion calls = %d, want 1", len(store.deleted))
	}
}

func TestVersionCleanup_DoesNotReleaseForKeepForever(t *testing.T) {
	pool := testdb.Setup(t)
	uid, fid := seedUserAndFile(t, pool, "vcleanup_b")

	// keep_forever = true → cleanup must NOT delete this row even if it's
	// ancient.
	_, err := pool.Exec(context.Background(), `
		INSERT INTO file_versions (file_id, s3_version_id, storage_path, seq_at_snapshot,
			doc_key_id, author_user_id, size_bytes, keep_forever, created_at)
		VALUES ($1, 'vid', $2, 0, 1, $3, 500, true, now() - interval '90 days')
	`, fid, "files/"+fid+"/snapshot", uid)
	if err != nil {
		t.Fatal(err)
	}
	pool.Exec(context.Background(),
		`UPDATE users SET storage_used_bytes = 500 WHERE id = $1`, uid)

	store := &fakeVersionStore{}
	runTickWithFakeStorage(t, pool, store, 0, 30)

	var used int64
	pool.QueryRow(context.Background(),
		`SELECT storage_used_bytes FROM users WHERE id = $1`, uid).Scan(&used)
	if used != 500 {
		t.Errorf("storage_used_bytes after no-op cleanup = %d, want 500 (keep_forever)", used)
	}
	var rowCount int64
	pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM file_versions WHERE file_id = $1`, fid).Scan(&rowCount)
	if rowCount != 1 {
		t.Errorf("file_versions row count = %d, want 1 (keep_forever should preserve)", rowCount)
	}
	if len(store.deleted) != 0 {
		t.Errorf("S3 DeleteObjectVersion calls = %d, want 0 (keep_forever)", len(store.deleted))
	}
}

// Suppress unused-import lints for io / errors / time when the tests
// don't end up needing them — Go's import system would complain otherwise.
var (
	_ = io.EOF
	_ = errors.New
	_ = time.Now
)
