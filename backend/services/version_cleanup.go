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
func (v *VersionCleanup) tick(ctx context.Context) {
	rows, err := v.DB.Query(ctx, `
		WITH ranked AS (
		  SELECT id, file_id, storage_path, s3_version_id, created_at, keep_forever,
		         ROW_NUMBER() OVER (PARTITION BY file_id ORDER BY created_at DESC) AS rn
		  FROM file_versions
		)
		SELECT id::text, storage_path, s3_version_id
		FROM ranked
		WHERE keep_forever = false
		  AND rn > $1
		  AND created_at < now() - ($2 || ' days')::interval
	`, v.KeepN, v.KeepDays)
	if err != nil {
		log.Printf("version cleanup: query failed: %v", err)
		return
	}
	type doomed struct {
		id, path, vid string
	}
	var ds []doomed
	for rows.Next() {
		var d doomed
		if err := rows.Scan(&d.id, &d.path, &d.vid); err == nil {
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
	}
	if len(ds) > 0 {
		log.Printf("version cleanup: pruned %d versions", len(ds))
	}
}
