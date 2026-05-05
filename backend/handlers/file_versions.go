package handlers

import (
	"context"
	"time"

	"github.com/kutup/backend/middleware"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

type FileVersionsHandler struct {
	DB *pgxpool.Pool
}

type versionRow struct {
	ID            string    `json:"id"`
	S3VersionID   string    `json:"s3VersionId"`
	StoragePath   string    `json:"storagePath"`
	SeqAtSnapshot int64     `json:"seqAtSnapshot"`
	DocKeyID      int64     `json:"docKeyId"`
	AuthorUserID  string    `json:"authorUserId"`
	SizeBytes     int64     `json:"sizeBytes"`
	Label         *string   `json:"label"`
	KeepForever   bool      `json:"keepForever"`
	CreatedAt     time.Time `json:"createdAt"`
}

// @Summary List versions for a file
// @Tags    Files
// @Security BearerAuth
// @Produce json
// @Param   fileId path string true "File UUID"
// @Success 200 {array} versionRow
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Router  /files/{fileId}/versions [get]
func (h *FileVersionsHandler) List(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	fileID := c.Params("fileId")
	if !h.canAccessFile(c.Context(), userID, fileID) {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}
	rows, err := h.DB.Query(context.Background(), `
		SELECT id::text, s3_version_id, storage_path, seq_at_snapshot,
		       doc_key_id, author_user_id::text, size_bytes,
		       label, keep_forever, created_at
		FROM file_versions
		WHERE file_id = $1
		ORDER BY created_at DESC
	`, fileID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	defer rows.Close()
	out := []versionRow{}
	for rows.Next() {
		var v versionRow
		if err := rows.Scan(&v.ID, &v.S3VersionID, &v.StoragePath, &v.SeqAtSnapshot,
			&v.DocKeyID, &v.AuthorUserID, &v.SizeBytes,
			&v.Label, &v.KeepForever, &v.CreatedAt); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "internal error"})
		}
		out = append(out, v)
	}
	return c.JSON(out)
}

// canAccessFile returns true if the user owns the collection or is a share recipient.
// Same shape as the existing canAccessCollection in files.go but joins through files.
func (h *FileVersionsHandler) canAccessFile(ctx context.Context, userID, fileID string) bool {
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
