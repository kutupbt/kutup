package handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kutup/backend/middleware"
)

// ObjectStore is the slice of services.StorageService that FileAssetsHandler
// needs. Extracted so tests can inject a fake whose Upload returns an error,
// exercising the compensating-transaction path.
type ObjectStore interface {
	Upload(ctx context.Context, path string, body io.Reader, size int64) error
	GetObject(ctx context.Context, path string) (io.ReadCloser, int64, error)
	Delete(ctx context.Context, path string) error
}

// FileAssetsHandler exposes per-file binary asset blobs (currently used by
// the whiteboard for embedded image binaries — Excalidraw's content-addressed
// `fileId` becomes our `assetId`). Mirrors the snapshot-blob pattern in
// file_versions.go: encrypted bytes go straight to S3, the server is blind.
//
// Path layout in S3: files/{fileId}/assets/{assetId}.
//
// Lifecycle: assets are GC'd transitively when the parent file is deleted —
// FilesHandler.Delete first releases the quota (SUM size_bytes per uploader),
// then DELETE FROM files cascades the file_assets rows, and the S3 prefix
// wipe (Storage.DeletePrefix) cleans the blobs.
//
// Quota: every successful upload INSERTs a (file_id, asset_id, size_bytes)
// row and increments users.storage_used_bytes in the same transaction.
// Re-uploading the same content-addressed asset is a no-op for quota
// (ON CONFLICT DO NOTHING). A nightly QuotaReconcile cron in services/
// quota_reconcile.go heals any drift.
type FileAssetsHandler struct {
	DB      *pgxpool.Pool
	Storage ObjectStore
}

// canAccessFile mirrors FileVersionsHandler.canAccessFile (file_versions.go:269).
// Duplicated rather than extracted to a shared helper because the access check
// is small and the two handlers have separate concerns.
func (h *FileAssetsHandler) canAccessFile(ctx context.Context, userID, fileID string) bool {
	var owner string
	var shared bool
	err := h.DB.QueryRow(ctx, `
		SELECT c.owner_user_id::text,
		       EXISTS(SELECT 1 FROM collection_shares cs
		              WHERE cs.collection_id = c.id AND cs.recipient_user_id = $2)
		FROM files f JOIN collections c ON c.id = f.collection_id
		WHERE f.id = $1
	`, fileID, userID).Scan(&owner, &shared)
	return err == nil && (owner == userID || shared)
}

// validAssetID rejects empty, slashed, or path-traversing asset ids. Excalidraw's
// fileIds are SHA1-hex strings so this is generous; we just need to ensure no
// caller can escape the files/{fileId}/assets/ prefix.
func validAssetID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	if strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		return false
	}
	return true
}

func assetStoragePath(fileID, assetID string) string {
	return fmt.Sprintf("files/%s/assets/%s", fileID, assetID)
}

// @Summary Upload an encrypted asset blob (whiteboard image binary, etc).
// @Tags    Files
// @Security BearerAuth
// @Accept  multipart/form-data
// @Produce json
// @Param   fileId  path string true "Parent file UUID"
// @Param   assetId path string true "Asset id (Excalidraw fileId)"
// @Param   file    formData file true "Encrypted asset bytes"
// @Success 204
// @Failure 400 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 413 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router  /files/{fileId}/assets/{assetId} [put]
func (h *FileAssetsHandler) Upload(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	fileID := c.Params("fileId")
	assetID := c.Params("assetId")

	if !validAssetID(assetID) {
		return c.Status(400).JSON(fiber.Map{"error": "invalid assetId"})
	}
	if !h.canAccessFile(c.Context(), userID, fileID) {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}

	fh, err := c.FormFile("file")
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "missing file"})
	}
	size := fh.Size

	// --- Atomic pre-flight: lock user row, check quota, INSERT row,
	//     increment counter — all before any S3 I/O. The FOR UPDATE
	//     serializes concurrent uploads from the same user.
	tx, err := h.DB.Begin(c.Context())
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	defer tx.Rollback(c.Context())

	var quota, used int64
	err = tx.QueryRow(c.Context(),
		`SELECT storage_quota_bytes, storage_used_bytes FROM users WHERE id = $1 FOR UPDATE`,
		userID,
	).Scan(&quota, &used)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	// INSERT idempotently. If a row already exists (re-PUT of the same
	// content-addressed asset), we get zero rows and skip both the quota
	// check and the counter bump — the storage was already paid for.
	var insertedSize int64
	err = tx.QueryRow(c.Context(), `
		INSERT INTO file_assets (file_id, asset_id, size_bytes, uploader_user_id)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (file_id, asset_id) DO NOTHING
		RETURNING size_bytes
	`, fileID, assetID, size, userID).Scan(&insertedSize)
	isNewRow := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	if isNewRow {
		if used+size > quota {
			// Roll back: don't charge, don't write S3.
			return c.Status(413).JSON(fiber.Map{"error": "storage quota exceeded"})
		}
		if _, err := tx.Exec(c.Context(),
			`UPDATE users SET storage_used_bytes = storage_used_bytes + $1 WHERE id = $2`,
			size, userID,
		); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "internal error"})
		}
	}

	// --- S3 PUT. Performed AFTER the DB increment but BEFORE the commit
	//     so we still hold the lock. If the PUT fails we ROLLBACK the
	//     entire pre-flight (insert + counter increment), leaving DB and
	//     S3 convergent. This keeps the "PUT first, DB second" failure
	//     mode (orphan blob with no row) impossible.
	src, err := fh.Open()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	defer src.Close()
	if err := h.Storage.Upload(c.Context(), assetStoragePath(fileID, assetID), src, size); err != nil {
		// tx.Rollback will fire from defer — both the file_assets row and
		// the counter increment vanish.
		return c.Status(500).JSON(fiber.Map{"error": "storage error"})
	}

	if err := tx.Commit(c.Context()); err != nil {
		// Best-effort cleanup of the just-uploaded blob; if this fails the
		// nightly orphan sweep (future work) will catch it.
		_ = h.Storage.Delete(context.Background(), assetStoragePath(fileID, assetID))
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	return c.SendStatus(204)
}

// @Summary Fetch an encrypted asset blob.
// @Tags    Files
// @Security BearerAuth
// @Produce application/octet-stream
// @Param   fileId  path string true "Parent file UUID"
// @Param   assetId path string true "Asset id (Excalidraw fileId)"
// @Success 200
// @Failure 400 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router  /files/{fileId}/assets/{assetId} [get]
func (h *FileAssetsHandler) Download(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	fileID := c.Params("fileId")
	assetID := c.Params("assetId")

	if !validAssetID(assetID) {
		return c.Status(400).JSON(fiber.Map{"error": "invalid assetId"})
	}
	if !h.canAccessFile(c.Context(), userID, fileID) {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}

	body, size, err := h.Storage.GetObject(c.Context(), assetStoragePath(fileID, assetID))
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	defer body.Close()

	c.Set(fiber.HeaderContentType, fiber.MIMEOctetStream)
	if size > 0 {
		c.Set(fiber.HeaderContentLength, fmt.Sprintf("%d", size))
	}
	if _, err := io.Copy(c.Response().BodyWriter(), body); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	return nil
}
