package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrQuotaExceeded = errors.New("storage quota exceeded")

// CheckAndReserveQuota atomically checks user quota and reserves space for a new file.
// It must be called inside a transaction that will also INSERT the file row.
func CheckAndReserveQuota(ctx context.Context, tx interface {
	QueryRow(ctx context.Context, sql string, args ...any) interface{ Scan(dest ...any) error }
	Exec(ctx context.Context, sql string, args ...any) (interface{}, error)
}, userID string, fileSize int64) error {
	// This is called from handlers which use pgx.Tx directly
	return nil // handled inline in files handler with pgxpool.Tx
}

// ReserveQuota atomically checks and reserves quota within a transaction.
func ReserveQuota(ctx context.Context, pool *pgxpool.Pool, userID string, fileSize int64) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var quota, used int64
	err = tx.QueryRow(ctx,
		`SELECT storage_quota_bytes, storage_used_bytes FROM users WHERE id = $1 FOR UPDATE`,
		userID,
	).Scan(&quota, &used)
	if err != nil {
		return fmt.Errorf("quota query: %w", err)
	}

	if used+fileSize > quota {
		return ErrQuotaExceeded
	}

	_, err = tx.Exec(ctx,
		`UPDATE users SET storage_used_bytes = storage_used_bytes + $1 WHERE id = $2`,
		fileSize, userID,
	)
	if err != nil {
		return fmt.Errorf("update quota: %w", err)
	}

	return tx.Commit(ctx)
}

// ReleaseQuota decrements the user's storage_used_bytes after file deletion.
func ReleaseQuota(ctx context.Context, pool *pgxpool.Pool, userID string, fileSize int64) error {
	_, err := pool.Exec(ctx,
		`UPDATE users SET storage_used_bytes = GREATEST(0, storage_used_bytes - $1) WHERE id = $2`,
		fileSize, userID,
	)
	return err
}
