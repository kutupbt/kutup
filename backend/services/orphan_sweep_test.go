package services

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kutup/backend/internal/testdb"
)

// fakeSweepStore is an in-memory SweepStore for orphan-sweep tests.
// Each entry has a key, size, and LastModified. ListObjectsPaged paginates
// the entries 1000 at a time (matching real S3 behavior). DeleteObjectsBatch
// removes them from the map.
type fakeSweepStore struct {
	mu      sync.Mutex
	objects map[string]ObjectInfo // key → metadata
	pages   int                   // increments per ListObjectsPaged page invocation
}

func newFakeSweepStore() *fakeSweepStore {
	return &fakeSweepStore{objects: map[string]ObjectInfo{}}
}

func (f *fakeSweepStore) put(key string, size int64, lm time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = ObjectInfo{Key: key, Size: size, LastModified: lm}
}

func (f *fakeSweepStore) ListObjectsPaged(_ context.Context, _ string, page func(objs []ObjectInfo) error) error {
	f.mu.Lock()
	keys := make([]string, 0, len(f.objects))
	for k := range f.objects {
		keys = append(keys, k)
	}
	f.mu.Unlock()
	// Sort keys deterministically so tests can reason about pagination.
	// Don't import sort/slices to keep imports minimal — bubble.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	const pageSize = 1000
	for i := 0; i < len(keys); i += pageSize {
		end := i + pageSize
		if end > len(keys) {
			end = len(keys)
		}
		objs := make([]ObjectInfo, 0, end-i)
		f.mu.Lock()
		for _, k := range keys[i:end] {
			if o, ok := f.objects[k]; ok {
				objs = append(objs, o)
			}
		}
		f.mu.Unlock()
		f.mu.Lock()
		f.pages++
		f.mu.Unlock()
		if err := page(objs); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeSweepStore) DeleteObjectsBatch(_ context.Context, keys []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range keys {
		delete(f.objects, k)
	}
	return nil
}

// seedSweepUser inserts a user + collection and returns (uid, collID).
func seedSweepUser(t *testing.T, pool *pgxpool.Pool, slug string) (uid, collID string) {
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

// seedFile inserts a files row and returns its UUID. Used to create "live"
// fileIds whose under-prefix S3 keys must NOT be reported as orphans.
func seedFile(t *testing.T, pool *pgxpool.Pool, collID, uid string) string {
	t.Helper()
	var fid string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO files (collection_id, uploader_user_id,
			encrypted_metadata, metadata_nonce,
			encrypted_file_key, file_key_nonce,
			storage_path, encrypted_size_bytes)
		 VALUES ($1,$2,'meta','mn','fk','fkn','/p',0)
		 RETURNING id::text`, collID, uid).Scan(&fid); err != nil {
		t.Fatal(err)
	}
	return fid
}

func TestOrphanSweep_FindsOrphansWithoutFileRow(t *testing.T) {
	pool := testdb.Setup(t)
	uid, collID := seedSweepUser(t, pool, "orph_find")
	liveFid := seedFile(t, pool, collID, uid)
	const orphanFid = "00000000-0000-0000-0000-000000000000"

	store := newFakeSweepStore()
	ancient := time.Now().Add(-48 * time.Hour)
	store.put("files/"+liveFid+"/snapshot", 100, ancient)
	store.put("files/"+orphanFid+"/snapshot", 200, ancient)
	store.put("files/"+orphanFid+"/assets/abc", 300, ancient)

	sweep := &OrphanSweep{DB: pool, Storage: store, PageSleep: 0}
	res, err := sweep.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if res.OrphansFound != 2 {
		t.Errorf("OrphansFound = %d, want 2", res.OrphansFound)
	}
	if res.BytesReclaimed != 500 {
		t.Errorf("BytesReclaimed = %d, want 500", res.BytesReclaimed)
	}
	if res.DeletedCount != 0 {
		t.Errorf("DeletedCount = %d, want 0 (dry-run default)", res.DeletedCount)
	}
}

func TestOrphanSweep_RespectsAgeFloor(t *testing.T) {
	pool := testdb.Setup(t)
	const orphanFid = "00000000-0000-0000-0000-000000000000"

	store := newFakeSweepStore()
	// Recent (1h ago) — must be skipped.
	store.put("files/"+orphanFid+"/snapshot", 100, time.Now().Add(-1*time.Hour))

	sweep := &OrphanSweep{DB: pool, Storage: store, AgeFloor: 24 * time.Hour, PageSleep: 0}
	res, _ := sweep.Run(context.Background())

	if res.OrphansFound != 0 {
		t.Errorf("OrphansFound = %d, want 0 (key newer than age floor)", res.OrphansFound)
	}
	if res.SkippedAgeCount != 1 {
		t.Errorf("SkippedAgeCount = %d, want 1", res.SkippedAgeCount)
	}
}

func TestOrphanSweep_DryRunDoesNotDelete(t *testing.T) {
	pool := testdb.Setup(t)
	const orphanFid = "11111111-1111-1111-1111-111111111111"

	store := newFakeSweepStore()
	store.put("files/"+orphanFid+"/snapshot", 100, time.Now().Add(-48*time.Hour))

	sweep := &OrphanSweep{DB: pool, Storage: store, PageSleep: 0, Delete: false}
	res, _ := sweep.Run(context.Background())

	if res.OrphansFound != 1 {
		t.Errorf("OrphansFound = %d, want 1", res.OrphansFound)
	}
	if res.DeletedCount != 0 {
		t.Errorf("DeletedCount = %d, want 0 (dry-run)", res.DeletedCount)
	}
	if _, exists := store.objects["files/"+orphanFid+"/snapshot"]; !exists {
		t.Error("dry-run deleted the orphan key (should still be present)")
	}
}

func TestOrphanSweep_DeleteRemovesOrphans(t *testing.T) {
	pool := testdb.Setup(t)
	uid, collID := seedSweepUser(t, pool, "orph_del")
	liveFid := seedFile(t, pool, collID, uid)
	const orphanFid = "22222222-2222-2222-2222-222222222222"

	store := newFakeSweepStore()
	ancient := time.Now().Add(-48 * time.Hour)
	store.put("files/"+liveFid+"/snapshot", 100, ancient)
	store.put("files/"+orphanFid+"/snapshot", 200, ancient)

	sweep := &OrphanSweep{DB: pool, Storage: store, PageSleep: 0, Delete: true}
	res, _ := sweep.Run(context.Background())

	if res.DeletedCount != 1 {
		t.Errorf("DeletedCount = %d, want 1", res.DeletedCount)
	}
	if _, exists := store.objects["files/"+orphanFid+"/snapshot"]; exists {
		t.Error("orphan key was NOT removed by --delete sweep")
	}
	if _, exists := store.objects["files/"+liveFid+"/snapshot"]; !exists {
		t.Error("live key was incorrectly deleted (sweep deleted a referenced blob)")
	}
}

func TestOrphanSweep_SkipsForeignShape(t *testing.T) {
	pool := testdb.Setup(t)

	store := newFakeSweepStore()
	ancient := time.Now().Add(-48 * time.Hour)
	// Path that doesn't match files/<UUID>/... — must be skipped, never
	// deleted (sweep stays narrow to the prefix shape it understands).
	store.put("files/not-a-uuid/something", 999, ancient)
	store.put("foo/bar.txt", 999, ancient) // different prefix entirely; sweep wouldn't even LIST this normally, but the in-memory fake serves all keys

	sweep := &OrphanSweep{DB: pool, Storage: store, PageSleep: 0, Delete: true}
	res, _ := sweep.Run(context.Background())

	if res.OrphansFound != 0 {
		t.Errorf("OrphansFound = %d, want 0", res.OrphansFound)
	}
	if res.SkippedShape < 1 {
		t.Errorf("SkippedShape = %d, want >= 1", res.SkippedShape)
	}
	if _, exists := store.objects["files/not-a-uuid/something"]; !exists {
		t.Error("foreign-shape key was incorrectly deleted")
	}
}

func TestOrphanSweep_HandlesPagination(t *testing.T) {
	pool := testdb.Setup(t)
	const orphanFid = "33333333-3333-3333-3333-333333333333"

	store := newFakeSweepStore()
	ancient := time.Now().Add(-48 * time.Hour)
	// 1500 ancient orphans — forces 2 list pages.
	for i := 0; i < 1500; i++ {
		store.put("files/"+orphanFid+"/assets/k"+intStr(i), 1, ancient)
	}

	sweep := &OrphanSweep{DB: pool, Storage: store, PageSleep: 0}
	res, _ := sweep.Run(context.Background())

	if res.OrphansFound != 1500 {
		t.Errorf("OrphansFound = %d, want 1500", res.OrphansFound)
	}
	if store.pages != 2 {
		t.Errorf("pages emitted by fake list = %d, want 2", store.pages)
	}
}

// intStr: small non-fmt helper to avoid importing strconv in test-only code.
func intStr(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
