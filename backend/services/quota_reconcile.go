package services

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// QuotaReconcile periodically rewrites users.storage_used_bytes from the
// authoritative row sums across all three byte-charged tables:
//   - files.encrypted_size_bytes
//   - file_assets.size_bytes (whiteboard image binaries)
//   - file_versions.size_bytes (per-file snapshot blobs)
//
// Drift can creep in via crashes between an S3 PUT succeeding and the
// counter UPDATE landing, version_cleanup failing to release a counter
// after deleting a row, or direct admin SQL touching these tables.
//
// The query is a single CTE that touches at most one row per drifted user
// per tick; the WHERE storage_used_bytes <> expected clause skips no-op
// updates so the change set logged is exactly the drift count.
type QuotaReconcile struct {
	DB       *pgxpool.Pool
	Interval time.Duration
}

// Run is the cron loop. Block until ctx is cancelled. Tick once per Interval.
func (q *QuotaReconcile) Run(ctx context.Context) {
	if q.Interval == 0 {
		q.Interval = 6 * time.Hour
	}
	t := time.NewTicker(q.Interval)
	defer t.Stop()
	q.Tick(ctx) // run once on startup
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			q.Tick(ctx)
		}
	}
}

// Tick is exported for tests + admin tooling. Returns the number of users
// whose counter was rewritten (zero on a clean tick).
//
// LEFT JOIN from users (rather than UNION-ing files+file_assets) is what
// makes "user with 0 files but counter > 0" reconcilable — a pure UNION
// produces no row for a user with no children, and the UPDATE would skip
// them. The COALESCE(...,0) handles both the no-children case and the
// case where one of the two child tables happens to be empty.
func (q *QuotaReconcile) Tick(ctx context.Context) int {
	rows, err := q.DB.Query(ctx, `
		WITH child_bytes AS (
		  SELECT uploader_user_id AS user_id, encrypted_size_bytes AS bytes FROM files
		  UNION ALL
		  SELECT uploader_user_id,            size_bytes              FROM file_assets
		  UNION ALL
		  SELECT author_user_id,              size_bytes              FROM file_versions
		),
		expected AS (
		  SELECT u.id AS user_id, COALESCE(SUM(c.bytes), 0) AS bytes
		  FROM users u
		  LEFT JOIN child_bytes c ON c.user_id = u.id
		  GROUP BY u.id
		)
		UPDATE users
		SET storage_used_bytes = expected.bytes
		FROM expected
		WHERE users.id = expected.user_id
		  AND users.storage_used_bytes <> expected.bytes
		RETURNING users.id::text, users.storage_used_bytes
	`)
	if err != nil {
		log.Printf("quota reconcile: query failed: %v", err)
		return 0
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var uid string
		var newUsed int64
		if err := rows.Scan(&uid, &newUsed); err != nil {
			continue
		}
		count++
		log.Printf("quota reconcile: user=%s storage_used_bytes=%d (drift corrected)", uid, newUsed)
	}
	if count > 0 {
		log.Printf("quota reconcile: corrected %d users", count)
	}
	return count
}
