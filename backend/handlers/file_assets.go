package handlers

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kutup/backend/middleware"
	"github.com/kutup/backend/services"
)

// FileAssetsHandler exposes per-file binary asset blobs (currently used by
// the whiteboard for embedded image binaries — Excalidraw's content-addressed
// `fileId` becomes our `assetId`). Mirrors the snapshot-blob pattern in
// file_versions.go: encrypted bytes go straight to S3, the server is blind.
//
// Path layout in S3: files/{fileId}/assets/{assetId}.
//
// Lifecycle: assets are GC'd transitively when the parent file is deleted —
// FilesHandler.Delete calls Storage.DeletePrefix("files/{fileId}/").
type FileAssetsHandler struct {
	DB      *pgxpool.Pool
	Storage *services.StorageService
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
	f, err := fh.Open()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	defer f.Close()

	if err := h.Storage.Upload(c.Context(), assetStoragePath(fileID, assetID), f, fh.Size); err != nil {
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
