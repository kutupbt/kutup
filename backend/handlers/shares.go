package handlers

import (
	"context"
	"time"

	"github.com/kutup/backend/middleware"
	"github.com/kutup/backend/services"
	"github.com/kutup/backend/utils"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SharesHandler struct {
	DB      *pgxpool.Pool
	Storage *services.StorageService
}

// CreatePublicShare creates a public share link.
// CRITICAL: The linkKey is NEVER sent here — it lives only in the URL #fragment.
// We only store the collection key already encrypted with that linkKey by the client.
// @Summary      Create a public share link
// @Tags         Public Shares
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      CreateShareRequest  true  "Share details"
// @Success      201   {object}  CreateShareResult
// @Failure      400   {object}  ErrorResponse
// @Failure      401   {object}  ErrorResponse
// @Failure      403   {object}  ErrorResponse
// @Router       /share [post]
func (h *SharesHandler) CreatePublicShare(c *fiber.Ctx) error {
	userID := middleware.UserID(c)

	var req struct {
		ShareType                   string  `json:"shareType"` // "collection" or "file"
		TargetID                    string  `json:"targetId"`
		EncryptedCollectionKey      string  `json:"encryptedCollectionKey"`
		EncryptedCollectionKeyNonce string  `json:"encryptedCollectionKeyNonce"`
		ExpiresInHours              *int    `json:"expiresInHours"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}

	// Verify user owns the target
	if !h.userOwnsTarget(c.Context(), userID, req.ShareType, req.TargetID) {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}

	token, err := utils.RandomToken(32)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	var expiresAt *time.Time
	if req.ExpiresInHours != nil {
		t := time.Now().Add(time.Duration(*req.ExpiresInHours) * time.Hour)
		expiresAt = &t
	}

	var id string
	err = h.DB.QueryRow(context.Background(), `
		INSERT INTO public_shares (share_type, target_id, token,
		                           encrypted_collection_key, encrypted_collection_key_nonce,
		                           expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id
	`, req.ShareType, req.TargetID, token,
		req.EncryptedCollectionKey, req.EncryptedCollectionKeyNonce,
		expiresAt,
	).Scan(&id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	return c.Status(201).JSON(fiber.Map{
		"id":    id,
		"token": token,
	})
}

// GetPublicShare returns encrypted key material for a public share.
// No auth required — anyone with the token can get the ciphertext.
// Without the linkKey (URL fragment), the ciphertext is useless.
// @Summary      Get public share metadata
// @Tags         Public Shares
// @Produce      json
// @Param        token  path      string  true  "Share token"
// @Success      200    {object}  PublicShareResponse
// @Failure      404    {object}  ErrorResponse
// @Failure      410    {object}  ErrorResponse  "Link expired"
// @Router       /share/{token} [get]
func (h *SharesHandler) GetPublicShare(c *fiber.Ctx) error {
	token := c.Params("token")

	var share struct {
		ID                          string     `json:"id"`
		ShareType                   string     `json:"shareType"`
		TargetID                    string     `json:"targetId"`
		EncryptedCollectionKey      *string    `json:"encryptedCollectionKey"`
		EncryptedCollectionKeyNonce *string    `json:"encryptedCollectionKeyNonce"`
		ExpiresAt                   *time.Time `json:"expiresAt"`
	}

	err := h.DB.QueryRow(context.Background(), `
		SELECT id, share_type, target_id,
		       encrypted_collection_key, encrypted_collection_key_nonce,
		       expires_at
		FROM public_shares
		WHERE token = $1
	`, token).Scan(
		&share.ID, &share.ShareType, &share.TargetID,
		&share.EncryptedCollectionKey, &share.EncryptedCollectionKeyNonce,
		&share.ExpiresAt,
	)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}

	if share.ExpiresAt != nil && time.Now().After(*share.ExpiresAt) {
		return c.Status(410).JSON(fiber.Map{"error": "link expired"})
	}

	return c.JSON(share)
}

// ListPublicShareFiles lists files in a public share (no auth, no decryption).
// @Summary      List files in a public share
// @Tags         Public Shares
// @Produce      json
// @Param        token  path      string  true  "Share token"
// @Success      200    {array}   FileRow
// @Failure      400    {object}  ErrorResponse
// @Failure      404    {object}  ErrorResponse
// @Failure      410    {object}  ErrorResponse  "Link expired"
// @Router       /share/{token}/files [get]
func (h *SharesHandler) ListPublicShareFiles(c *fiber.Ctx) error {
	token := c.Params("token")

	var targetID, shareType string
	var expiresAt *time.Time
	err := h.DB.QueryRow(context.Background(),
		`SELECT target_id, share_type, expires_at FROM public_shares WHERE token = $1`,
		token,
	).Scan(&targetID, &shareType, &expiresAt)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}

	if expiresAt != nil && time.Now().After(*expiresAt) {
		return c.Status(410).JSON(fiber.Map{"error": "link expired"})
	}

	if shareType != "collection" {
		return c.Status(400).JSON(fiber.Map{"error": "not a collection share"})
	}

	rows, err := h.DB.Query(context.Background(), `
		SELECT id, collection_id, encrypted_metadata, metadata_nonce,
		       encrypted_file_key, file_key_nonce, encrypted_size_bytes, created_at
		FROM files WHERE collection_id = $1
		ORDER BY created_at DESC
	`, targetID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	defer rows.Close()

	type FileRow struct {
		ID                 string `json:"id"`
		CollectionID       string `json:"collectionId"`
		EncryptedMetadata  string `json:"encryptedMetadata"`
		MetadataNonce      string `json:"metadataNonce"`
		EncryptedFileKey   string `json:"encryptedFileKey"`
		FileKeyNonce       string `json:"fileKeyNonce"`
		EncryptedSizeBytes int64  `json:"encryptedSizeBytes"`
		CreatedAt          string `json:"createdAt"`
	}

	var files []FileRow
	for rows.Next() {
		var f FileRow
		if err := rows.Scan(
			&f.ID, &f.CollectionID, &f.EncryptedMetadata, &f.MetadataNonce,
			&f.EncryptedFileKey, &f.FileKeyNonce, &f.EncryptedSizeBytes, &f.CreatedAt,
		); err != nil {
			continue
		}
		files = append(files, f)
	}
	if files == nil {
		files = []FileRow{}
	}
	return c.JSON(files)
}

// DownloadPublicShareFile returns a presigned URL for a public share file.
// @Summary      Get presigned download URL for a public share file
// @Tags         Public Shares
// @Produce      json
// @Param        token   path      string  true  "Share token"
// @Param        fileId  path      string  true  "File UUID"
// @Success      200     {object}  DownloadURLResponse
// @Failure      403     {object}  ErrorResponse
// @Failure      404     {object}  ErrorResponse
// @Failure      410     {object}  ErrorResponse  "Link expired"
// @Router       /share/{token}/download/{fileId} [get]
func (h *SharesHandler) DownloadPublicShareFile(c *fiber.Ctx) error {
	token := c.Params("token")
	fileID := c.Params("fileId")

	// Validate share is still valid
	var targetID, shareType string
	var expiresAt *time.Time
	err := h.DB.QueryRow(context.Background(),
		`SELECT target_id, share_type, expires_at FROM public_shares WHERE token = $1`,
		token,
	).Scan(&targetID, &shareType, &expiresAt)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}

	if expiresAt != nil && time.Now().After(*expiresAt) {
		return c.Status(410).JSON(fiber.Map{"error": "link expired"})
	}

	// Verify file belongs to the shared collection
	var storagePath string
	var collID string
	err = h.DB.QueryRow(context.Background(),
		`SELECT storage_path, collection_id FROM files WHERE id = $1`,
		fileID,
	).Scan(&storagePath, &collID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}

	if shareType == "collection" && collID != targetID {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}
	if shareType == "file" && fileID != targetID {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}

	url, err := h.Storage.PresignedDownload(c.Context(), storagePath)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	return c.JSON(fiber.Map{"url": url})
}

func (h *SharesHandler) userOwnsTarget(ctx context.Context, userID, shareType, targetID string) bool {
	var count int
	switch shareType {
	case "collection":
		h.DB.QueryRow(ctx,
			`SELECT COUNT(*) FROM collections WHERE id = $1 AND owner_user_id = $2`,
			targetID, userID,
		).Scan(&count)
	case "file":
		h.DB.QueryRow(ctx,
			`SELECT COUNT(*) FROM files WHERE id = $1 AND uploader_user_id = $2`,
			targetID, userID,
		).Scan(&count)
	}
	return count > 0
}
