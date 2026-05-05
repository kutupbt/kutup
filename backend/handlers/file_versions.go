package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/kutup/backend/middleware"
	"github.com/kutup/backend/services"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

type FileVersionsHandler struct {
	DB      *pgxpool.Pool
	Storage *services.StorageService
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

// @Summary Download a specific version of a file
// @Tags    Files
// @Security BearerAuth
// @Produce application/octet-stream
// @Param   fileId path string true "File UUID"
// @Param   vid path string true "Version row UUID"
// @Success 200
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router  /files/{fileId}/versions/{vid}/download [get]
func (h *FileVersionsHandler) Download(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	fileID := c.Params("fileId")
	vid := c.Params("vid")
	if !h.canAccessFile(c.Context(), userID, fileID) {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}
	var path, s3Version string
	var docKeyID, seq int64
	err := h.DB.QueryRow(context.Background(), `
		SELECT storage_path, s3_version_id, doc_key_id, seq_at_snapshot
		FROM file_versions WHERE id = $1 AND file_id = $2
	`, vid, fileID).Scan(&path, &s3Version, &docKeyID, &seq)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	c.Set("X-Kutup-Doc-Key-Id", fmt.Sprintf("%d", docKeyID))
	c.Set("X-Kutup-Seq", fmt.Sprintf("%d", seq))
	c.Set("X-Kutup-S3-Version", s3Version)
	body, size, err := h.Storage.GetObjectVersion(c.Context(), path, s3Version)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	c.Set("Content-Type", "application/octet-stream")
	c.Set("Content-Length", fmt.Sprintf("%d", size))
	return c.SendStream(body, int(size))
}

type patchVersionRequest struct {
	Label       *string `json:"label,omitempty"`
	KeepForever *bool   `json:"keepForever,omitempty"`
}

// @Summary Update a version's label or keep-forever flag
// @Tags    Files
// @Security BearerAuth
// @Accept  json
// @Produce json
// @Param   fileId path string true "File UUID"
// @Param   vid path string true "Version row UUID"
// @Param   body body patchVersionRequest true "Fields to update"
// @Success 200 {object} versionRow
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router  /files/{fileId}/versions/{vid} [patch]
func (h *FileVersionsHandler) Patch(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	fileID := c.Params("fileId")
	vid := c.Params("vid")
	if !h.canAccessFile(c.Context(), userID, fileID) {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}
	var req patchVersionRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	if req.Label != nil {
		if _, err := h.DB.Exec(c.Context(),
			`UPDATE file_versions SET label = NULLIF($1, '') WHERE id = $2 AND file_id = $3`,
			*req.Label, vid, fileID); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "internal error"})
		}
	}
	if req.KeepForever != nil {
		if _, err := h.DB.Exec(c.Context(),
			`UPDATE file_versions SET keep_forever = $1 WHERE id = $2 AND file_id = $3`,
			*req.KeepForever, vid, fileID); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "internal error"})
		}
	}
	var v versionRow
	err := h.DB.QueryRow(c.Context(), `
		SELECT id::text, s3_version_id, storage_path, seq_at_snapshot,
		       doc_key_id, author_user_id::text, size_bytes,
		       label, keep_forever, created_at
		FROM file_versions WHERE id = $1 AND file_id = $2
	`, vid, fileID).Scan(&v.ID, &v.S3VersionID, &v.StoragePath, &v.SeqAtSnapshot,
		&v.DocKeyID, &v.AuthorUserID, &v.SizeBytes,
		&v.Label, &v.KeepForever, &v.CreatedAt)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	return c.JSON(v)
}

// @Summary Upload a snapshot blob (multipart). Companion to POST /versions.
// @Tags    Files
// @Security BearerAuth
// @Accept  multipart/form-data
// @Produce json
// @Param   fileId path string true "File UUID"
// @Param   file formData file true "Encrypted snapshot bytes"
// @Success 200 {object} fiber.Map
// @Failure 400 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router  /files/{fileId}/snapshot-blob [post]
func (h *FileVersionsHandler) UploadSnapshotBlob(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	fileID := c.Params("fileId")
	if !h.canAccessFile(c.Context(), userID, fileID) {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}
	fh, err := c.FormFile("file")
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "missing file"})
	}
	f, err := fh.Open()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	defer f.Close()
	storagePath := fmt.Sprintf("files/%s/snapshot", fileID)
	versionID, err := h.Storage.PutObjectVersioned(c.Context(), storagePath, f, fh.Size)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	return c.JSON(fiber.Map{
		"storagePath": storagePath,
		"s3VersionId": versionID,
	})
}

type recordSnapshotRequest struct {
	S3VersionID   string `json:"s3VersionId"`
	StoragePath   string `json:"storagePath"`
	SeqAtSnapshot int64  `json:"seqAtSnapshot"`
	DocKeyID      int64  `json:"docKeyId"`
	SizeBytes     int64  `json:"sizeBytes"`
	Label         string `json:"label,omitempty"`
	KeepForever   bool   `json:"keepForever,omitempty"`
}

// @Summary Record a snapshot version + truncate the update log up to seqAtSnapshot.
// @Tags    Files
// @Security BearerAuth
// @Accept  json
// @Produce json
// @Param   fileId path string true "File UUID"
// @Param   body body recordSnapshotRequest true "Snapshot metadata"
// @Success 201 {object} fiber.Map
// @Failure 400 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router  /files/{fileId}/versions [post]
func (h *FileVersionsHandler) Record(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	fileID := c.Params("fileId")
	if !h.canAccessFile(c.Context(), userID, fileID) {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}
	var req recordSnapshotRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	if req.S3VersionID == "" || req.StoragePath == "" {
		return c.Status(400).JSON(fiber.Map{"error": "s3VersionId and storagePath are required"})
	}
	var id string
	err := h.DB.QueryRow(c.Context(), `
		INSERT INTO file_versions (file_id, s3_version_id, storage_path, seq_at_snapshot,
		                           doc_key_id, author_user_id, size_bytes, label, keep_forever)
		VALUES ($1,$2,$3,$4,$5,$6,$7, NULLIF($8, ''),$9)
		RETURNING id::text
	`, fileID, req.S3VersionID, req.StoragePath, req.SeqAtSnapshot,
		req.DocKeyID, userID, req.SizeBytes, req.Label, req.KeepForever).Scan(&id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	// Truncate the log up to seq_at_snapshot.
	if _, err := h.DB.Exec(c.Context(),
		`DELETE FROM file_update_log WHERE file_id = $1 AND seq <= $2`,
		fileID, req.SeqAtSnapshot); err != nil {
		// Snapshot already committed; log truncation is best-effort. Don't 500 the caller.
		// (A future cleanup job would catch up if this drops.)
	}
	return c.Status(201).JSON(fiber.Map{"id": id})
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
