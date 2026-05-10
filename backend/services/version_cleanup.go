package services

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// VersionCleanup periodically prunes old file_versions rows + their S3 noncurrent objects.
// Default policy: keep the last KeepDays days OR last KeepN versions per file (whichever yields
// more) plus all keep_forever=true versions.
type VersionCleanup struct {
	DB       *pgxpool.Pool
	Storage  *StorageService
	Interval time.Duration
	KeepDays int
	KeepN    int
}

// Run is the cron loop. Block until ctx is cancelled. Tick once per Interval.
func (v *VersionCleanup) Run(ctx context.Context) {
	if v.Interval == 0 {
		v.Interval = time.Hour
	}
	if v.KeepDays == 0 {
		v.KeepDays = 30
	}
	if v.KeepN == 0 {
		v.KeepN = 50
	}
	t := time.NewTicker(v.Interval)
	defer t.Stop()
	// Run once immediately on startup so old data starts pruning right away.
	v.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			v.tick(ctx)
		}
	}
}

// tick deletes any (non-keep_forever) version that's BOTH older than KeepDays AND beyond KeepN per file.
// On each successful row delete, decrements users.storage_used_bytes for the
// version's author by size_bytes — the row's quota charge is symmetric to the
// charge we made in FileVersionsHandler.Record. GREATEST(0, ...) defends
// against double-decrement if the cron crashes mid-tick and resumes.
func (v *VersionCleanup) tick(ctx context.Context) {
	rows, err := v.DB.Query(ctx, `
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
	`, v.KeepN, v.KeepDays)
	if err != nil {
		log.Printf("version cleanup: query failed: %v", err)
		return
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
		if err := v.Storage.DeleteObjectVersion(ctx, d.path, d.vid); err != nil {
			log.Printf("version cleanup: delete %s@%s failed: %v", d.path, d.vid, err)
			continue
		}
		if _, err := v.DB.Exec(ctx, `DELETE FROM file_versions WHERE id = $1`, d.id); err != nil {
			log.Printf("version cleanup: row delete %s failed: %v", d.id, err)
			continue
		}
		// Quota release. Best-effort: a failure leaves the counter inflated;
		// the periodic reconcile cron will heal that on its next tick.
		if _, err := v.DB.Exec(ctx,
			`UPDATE users SET storage_used_bytes = GREATEST(0, storage_used_bytes - $1) WHERE id = $2`,
			d.size, d.author,
		); err != nil {
			log.Printf("version cleanup: quota release for user=%s size=%d failed: %v",
				d.author, d.size, err)
		}
	}
	if len(ds) > 0 {
		log.Printf("version cleanup: pruned %d versions", len(ds))
	}
}
