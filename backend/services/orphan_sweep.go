package services

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// OrphanSweep walks the S3 bucket under PrefixRoot and identifies blobs
// whose containing file_id has no row in `files` (i.e. the parent file
// was deleted, or the blob was written by a crashed handler before its
// DB row landed). Operator-driven: dry-run by default; pass Delete=true
// to actually remove the orphans.
//
// Pattern follows GitLab's list_orphan_job_artifact_final_objects rake
// task and Garage's repair commands:
//
//   - S3-first walk via ListObjectsV2 (1000 keys/page).
//   - 24h LastModified age threshold so in-flight uploads aren't racy
//     candidates. This single check absorbs the PUT-then-crash window;
//     anything older than the threshold has settled.
//   - Per-page batched DB query: SELECT id FROM files WHERE id = ANY($1).
//     One round-trip per page; deduplicates fileIds within the page first.
//   - Fixed PageSleep between pages to avoid hammering S3 LIST.
//   - Counter accumulator returned in SweepResult.
//
// Resume-on-crash deferred: at our scale (10K → 1M objects, 5–60 min wall)
// a crash means rerunning from scratch. Add continuation-token
// checkpointing in v2 if the bucket grows past ~500K.
//
// Bucket-prefix invariant assumed: every blob lives under
// `files/<UUID>/...` (snapshot, assets/<id>, etc.). This matches every
// path emitted by FilesHandler.Upload, FileVersionsHandler.UploadSnapshotBlob,
// and FileAssetsHandler.Upload as of commit 5c298c5. Keys not matching
// that pattern are skipped (counted as KeysScanned but not as orphans).
// SweepStore is the slice of *StorageService that OrphanSweep needs.
// Extracted so tests can inject an in-memory fake.
type SweepStore interface {
	ListObjectsPaged(ctx context.Context, prefix string, page func(objs []ObjectInfo) error) error
	DeleteObjectsBatch(ctx context.Context, keys []string) error
}

type OrphanSweep struct {
	DB         *pgxpool.Pool
	Storage    SweepStore
	AgeFloor   time.Duration // default 24h
	PageSleep  time.Duration // default 200ms
	PrefixRoot string        // default "files/"
	Delete     bool          // false = dry-run; safety default
}

// SweepResult summarises one Run.
type SweepResult struct {
	PagesScanned    int
	KeysScanned     int
	OrphansFound    int
	BytesReclaimed  int64
	SkippedAgeCount int
	SkippedShape    int // keys not matching files/<uuid>/... — never deleted
	DeletedCount    int
}

// fileIDFromKey: matches `files/<UUID>/<rest>`. Returns the UUID and ok=true,
// or ok=false if the key shape is foreign and should be skipped.
//
// We accept only canonical lower-hex 8-4-4-4-12 UUIDs because that's the
// shape Postgres emits for files.id::text. Anything outside that set is a
// foreign key (e.g. left over from an older path scheme or a future
// non-file-scoped prefix).
var keyShapeRE = regexp.MustCompile(`^files/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/`)

func fileIDFromKey(key string) (string, bool) {
	m := keyShapeRE.FindStringSubmatch(key)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// Run executes one sweep pass and returns its result. The caller logs the
// summary and decides what to do with it.
func (o *OrphanSweep) Run(ctx context.Context) (*SweepResult, error) {
	if o.AgeFloor == 0 {
		o.AgeFloor = 24 * time.Hour
	}
	if o.PageSleep == 0 {
		o.PageSleep = 200 * time.Millisecond
	}
	if o.PrefixRoot == "" {
		o.PrefixRoot = "files/"
	}

	res := &SweepResult{}
	cutoff := time.Now().Add(-o.AgeFloor)

	err := o.Storage.ListObjectsPaged(ctx, o.PrefixRoot, func(objs []ObjectInfo) error {
		res.PagesScanned++
		res.KeysScanned += len(objs)

		// Collect candidate keys per page after the age + shape filters.
		type cand struct {
			key, fileID string
			size        int64
		}
		cands := make([]cand, 0, len(objs))
		seen := make(map[string]struct{})

		for _, obj := range objs {
			if obj.LastModified.After(cutoff) {
				res.SkippedAgeCount++
				continue
			}
			fid, ok := fileIDFromKey(obj.Key)
			if !ok {
				res.SkippedShape++
				continue
			}
			cands = append(cands, cand{key: obj.Key, fileID: fid, size: obj.Size})
			seen[fid] = struct{}{}
		}

		if len(cands) == 0 {
			time.Sleep(o.PageSleep)
			return nil
		}

		// Single batched DB query to identify which fileIds are still alive.
		fids := make([]string, 0, len(seen))
		for fid := range seen {
			fids = append(fids, fid)
		}
		alive, err := o.queryAliveFileIDs(ctx, fids)
		if err != nil {
			return fmt.Errorf("alive lookup: %w", err)
		}

		// Anything whose fileId is NOT alive is an orphan. Collect.
		var orphanKeys []string
		var orphanBytes int64
		for _, c := range cands {
			if _, isAlive := alive[c.fileID]; isAlive {
				continue
			}
			res.OrphansFound++
			orphanBytes += c.size
			orphanKeys = append(orphanKeys, c.key)
			action := "dry-run"
			if o.Delete {
				action = "delete"
			}
			log.Printf("orphan-sweep: orphan key=%s size=%d action=%s", c.key, c.size, action)
		}
		res.BytesReclaimed += orphanBytes

		if o.Delete && len(orphanKeys) > 0 {
			// Chunk to S3's 1000-key cap (already true: per-page input ≤ 1000).
			if err := o.Storage.DeleteObjectsBatch(ctx, orphanKeys); err != nil {
				log.Printf("orphan-sweep: delete batch failed: %v", err)
			} else {
				res.DeletedCount += len(orphanKeys)
			}
		}

		time.Sleep(o.PageSleep)
		return nil
	})
	if err != nil {
		return res, err
	}
	return res, nil
}

// queryAliveFileIDs returns the subset of `fids` that have a row in `files`.
// Single round-trip via ANY($1::uuid[]).
func (o *OrphanSweep) queryAliveFileIDs(ctx context.Context, fids []string) (map[string]struct{}, error) {
	alive := make(map[string]struct{})
	if len(fids) == 0 {
		return alive, nil
	}
	rows, err := o.DB.Query(ctx,
		`SELECT id::text FROM files WHERE id = ANY($1::uuid[])`,
		fids,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		alive[strings.ToLower(id)] = struct{}{}
	}
	return alive, nil
}

// LogSummary writes a single human-readable summary line. Called by the
// CLI wrapper after Run returns.
func (r *SweepResult) LogSummary(dryRun bool) {
	mode := "dry-run"
	if !dryRun {
		mode = "delete"
	}
	log.Printf("orphan-sweep summary: pages=%d keys=%d orphans=%d skipped-age=%d skipped-shape=%d deleted=%d bytes-reclaimed=%d mode=%s",
		r.PagesScanned, r.KeysScanned, r.OrphansFound,
		r.SkippedAgeCount, r.SkippedShape, r.DeletedCount,
		r.BytesReclaimed, mode)
}
