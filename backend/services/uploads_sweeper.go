package services

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// UploadsSweeper reaps abandoned tus uploads (rows in `uploads` whose
// updated_at hasn't moved in 24h). For each stale row it Aborts the S3
// multipart upload, freeing SeaweedFS staging space, then deletes the
// row — which frees the user's soft-reserved quota for new uploads.
//
// The interval is on the long side because tus clients can sit on a
// resumable upload for a while (sleep, lock screen, etc.). 24h matches
// the "if it hasn't progressed for a day, it's not coming back" heuristic
// other tus servers use (e.g. tusd defaults).
type UploadsSweeper struct {
	DB      *pgxpool.Pool
	Storage *StorageService

	// StaleAfter is how long an upload row's updated_at can lag now()
	// before we reap it. Defaulted in Run if zero.
	StaleAfter time.Duration
	// Interval between sweeps. Defaulted in Run if zero.
	Interval time.Duration
}

func (s *UploadsSweeper) Run(ctx context.Context) {
	if s.StaleAfter == 0 {
		s.StaleAfter = 24 * time.Hour
	}
	if s.Interval == 0 {
		s.Interval = 1 * time.Hour
	}
	t := time.NewTicker(s.Interval)
	defer t.Stop()
	// Run once on boot so a server restart doesn't leak the existing
	// stale set for up to a full interval.
	s.once(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.once(ctx)
		}
	}
}

func (s *UploadsSweeper) once(ctx context.Context) {
	rows, err := s.DB.Query(ctx, `
		SELECT id, storage_temp_key, s3_upload_id
		FROM uploads
		WHERE updated_at < NOW() - $1::interval
	`, s.StaleAfter.String())
	if err != nil {
		log.Printf("uploads-sweeper: list: %v", err)
		return
	}

	type stale struct {
		id, tempKey, s3UploadID string
	}
	var batch []stale
	for rows.Next() {
		var x stale
		if err := rows.Scan(&x.id, &x.tempKey, &x.s3UploadID); err != nil {
			log.Printf("uploads-sweeper: scan: %v", err)
			continue
		}
		batch = append(batch, x)
	}
	rows.Close()

	for _, x := range batch {
		// Abort first; if it fails we leave the row in place so the next
		// sweep can retry. A successful Abort is a precondition for
		// dropping the row.
		if err := s.Storage.AbortMultipart(ctx, x.tempKey, x.s3UploadID); err != nil {
			log.Printf("uploads-sweeper: abort %s: %v", x.id, err)
			continue
		}
		if _, err := s.DB.Exec(ctx, `DELETE FROM uploads WHERE id=$1`, x.id); err != nil {
			log.Printf("uploads-sweeper: delete %s: %v", x.id, err)
			continue
		}
		log.Printf("uploads-sweeper: reaped upload=%s temp=%s", x.id, x.tempKey)
	}
}
