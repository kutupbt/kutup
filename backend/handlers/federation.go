package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/kutup/backend/services"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type FederationHandler struct {
	DB      *pgxpool.Pool
	Storage *services.StorageService
}

// GET /api/fed/users?username=alice  (no auth, public)
// @Summary      Look up a local user (federation)
// @Description  Called by remote Kutup servers during federated sharing. Rate-limited to 60/min per IP.
// @Tags         Federation
// @Produce      json
// @Param        username  query     string  true  "Username to look up"
// @Success      200       {object}  PubkeyResponse
// @Failure      400       {object}  ErrorResponse
// @Failure      404       {object}  ErrorResponse
// @Failure      429       {object}  ErrorResponse  "Rate limited"
// @Router       /fed/users [get]
func (h *FederationHandler) GetUserByUsername(c *fiber.Ctx) error {
	username := c.Query("username")
	if username == "" {
		return c.Status(400).JSON(fiber.Map{"error": "username required"})
	}
	var publicKey string
	err := h.DB.QueryRow(context.Background(),
		`SELECT public_key FROM users WHERE username = $1 AND is_active = true`,
		username,
	).Scan(&publicKey)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "user not found"})
	}
	return c.JSON(fiber.Map{"publicKey": publicKey})
}

// GET /api/fed/invites/{token}  (no auth - token is the auth)
// @Summary      Get federated invite metadata
// @Tags         Federation
// @Produce      json
// @Param        token  path      string  true  "Invite token"
// @Success      200    {object}  FedInviteResponse
// @Failure      404    {object}  ErrorResponse
// @Router       /fed/invites/{token} [get]
func (h *FederationHandler) GetInvite(c *fiber.Ctx) error {
	token := c.Params("token")
	var row struct {
		EncryptedCollectionKey string
		EncryptedName          string
		NameNonce              string
		CanUpload              bool
		CanDelete              bool
		UploadQuotaBytes       *int64
	}
	err := h.DB.QueryRow(context.Background(), `
		SELECT fos.encrypted_collection_key,
		       c.encrypted_name, c.name_nonce,
		       fos.can_upload, fos.can_delete, fos.upload_quota_bytes
		FROM federated_outgoing_shares fos
		JOIN collections c ON c.id = fos.collection_id
		WHERE fos.access_token = $1
	`, token).Scan(
		&row.EncryptedCollectionKey, &row.EncryptedName, &row.NameNonce,
		&row.CanUpload, &row.CanDelete, &row.UploadQuotaBytes,
	)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "invite not found"})
	}
	return c.JSON(fiber.Map{
		"wrappedKey":       row.EncryptedCollectionKey,
		"encryptedName":    row.EncryptedName,
		"nameNonce":        row.NameNonce,
		"canUpload":        row.CanUpload,
		"canDelete":        row.CanDelete,
		"uploadQuotaBytes": row.UploadQuotaBytes,
	})
}

// GET /api/fed/shares/{token}/files  (token is auth)
// @Summary      List files in a federated share
// @Tags         Federation
// @Produce      json
// @Param        token  path      string  true  "Share access token"
// @Success      200    {array}   FileRow
// @Failure      403    {object}  ErrorResponse
// @Router       /fed/shares/{token}/files [get]
func (h *FederationHandler) ListShareFiles(c *fiber.Ctx) error {
	token := c.Params("token")
	var collectionID string
	err := h.DB.QueryRow(context.Background(),
		`SELECT collection_id FROM federated_outgoing_shares WHERE access_token = $1`,
		token,
	).Scan(&collectionID)
	if err != nil {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}

	rows, err := h.DB.Query(context.Background(), `
		SELECT id, collection_id, uploader_user_id,
		       encrypted_metadata, metadata_nonce,
		       encrypted_file_key, file_key_nonce,
		       encrypted_size_bytes, created_at, updated_at
		FROM files WHERE collection_id = $1 ORDER BY created_at DESC
	`, collectionID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	defer rows.Close()

	type FileRow struct {
		ID                 string    `json:"id"`
		CollectionID       string    `json:"collectionId"`
		UploaderUserID     string    `json:"uploaderUserId"`
		EncryptedMetadata  string    `json:"encryptedMetadata"`
		MetadataNonce      string    `json:"metadataNonce"`
		EncryptedFileKey   string    `json:"encryptedFileKey"`
		FileKeyNonce       string    `json:"fileKeyNonce"`
		EncryptedSizeBytes int64     `json:"encryptedSizeBytes"`
		CreatedAt          time.Time `json:"createdAt"`
		UpdatedAt          time.Time `json:"updatedAt"`
	}

	var files []FileRow
	for rows.Next() {
		var f FileRow
		if err := rows.Scan(&f.ID, &f.CollectionID, &f.UploaderUserID,
			&f.EncryptedMetadata, &f.MetadataNonce,
			&f.EncryptedFileKey, &f.FileKeyNonce,
			&f.EncryptedSizeBytes, &f.CreatedAt, &f.UpdatedAt); err != nil {
			continue
		}
		files = append(files, f)
	}
	if files == nil {
		files = []FileRow{}
	}
	return c.JSON(files)
}

// GET /api/fed/shares/{token}/files/{fileId}/download
// @Summary      Download a file from a federated share
// @Tags         Federation
// @Produce      octet-stream
// @Param        token   path  string  true  "Share access token"
// @Param        fileId  path  string  true  "File UUID"
// @Success      200
// @Failure      403  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Router       /fed/shares/{token}/files/{fileId}/download [get]
func (h *FederationHandler) DownloadShareFile(c *fiber.Ctx) error {
	token := c.Params("token")
	fileID := c.Params("fileId")

	// Validate token
	var collectionID string
	err := h.DB.QueryRow(context.Background(),
		`SELECT collection_id FROM federated_outgoing_shares WHERE access_token = $1`,
		token,
	).Scan(&collectionID)
	if err != nil {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}

	// Get file
	var storagePath string
	var fileSize int64
	err = h.DB.QueryRow(context.Background(),
		`SELECT storage_path, encrypted_size_bytes FROM files WHERE id = $1 AND collection_id = $2`,
		fileID, collectionID,
	).Scan(&storagePath, &fileSize)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}

	body, size, err := h.Storage.GetObject(c.Context(), storagePath)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	c.Set("Content-Type", "application/octet-stream")
	c.Set("Content-Length", fmt.Sprintf("%d", size))
	return c.SendStream(body, int(size))
}

// POST /api/fed/shares/{token}/files  (upload via federation)
// @Summary      Upload a file to a federated share
// @Tags         Federation
// @Accept       mpfd
// @Produce      json
// @Param        token              path      string  true  "Share access token"
// @Param        encryptedMetadata  formData  string  true  "Encrypted metadata (base64)"
// @Param        metadataNonce      formData  string  true  "Metadata nonce (base64)"
// @Param        encryptedFileKey   formData  string  true  "Encrypted file key (base64)"
// @Param        fileKeyNonce       formData  string  true  "File key nonce (base64)"
// @Param        file               formData  file    true  "Encrypted file content"
// @Success      201  {object}  UploadResult
// @Failure      400  {object}  ErrorResponse
// @Failure      403  {object}  ErrorResponse
// @Failure      413  {object}  ErrorResponse
// @Router       /fed/shares/{token}/files [post]
func (h *FederationHandler) UploadShareFile(c *fiber.Ctx) error {
	token := c.Params("token")

	// Validate token and check can_upload
	var shareID, collectionID, sharerUserID string
	var canUpload bool
	var uploadQuotaBytes *int64
	err := h.DB.QueryRow(context.Background(), `
		SELECT id, collection_id, sharer_user_id, can_upload, upload_quota_bytes
		FROM federated_outgoing_shares WHERE access_token = $1
	`, token).Scan(&shareID, &collectionID, &sharerUserID, &canUpload, &uploadQuotaBytes)
	if err != nil {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}
	if !canUpload {
		return c.Status(403).JSON(fiber.Map{"error": "upload not permitted"})
	}

	// Parse multipart
	form, err := c.MultipartForm()
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid multipart form"})
	}
	encMetadata := firstField(form.Value, "encryptedMetadata")
	metadataNonce := firstField(form.Value, "metadataNonce")
	encFileKey := firstField(form.Value, "encryptedFileKey")
	fileKeyNonce := firstField(form.Value, "fileKeyNonce")

	fileHeaders := form.File["file"]
	if len(fileHeaders) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "no file provided"})
	}
	fileHeader := fileHeaders[0]
	fileSize := fileHeader.Size

	fileID := uuid.New().String()
	storagePath := fmt.Sprintf("fed/%s/%s/%s", shareID, collectionID, fileID)

	src, err := fileHeader.Open()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "cannot read file"})
	}
	defer src.Close()

	if err := h.Storage.Upload(c.Context(), storagePath, src, fileSize); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "storage error"})
	}

	// S3-5: Use a transaction with FOR UPDATE to atomically check and update
	// the federated quota, preventing concurrent uploads from bypassing it.
	tx, err := h.DB.Begin(c.Context())
	if err != nil {
		h.Storage.Delete(context.Background(), storagePath)
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	defer tx.Rollback(c.Context())

	if uploadQuotaBytes != nil {
		var used int64
		tx.QueryRow(c.Context(),
			`SELECT COALESCE(upload_used_bytes, 0) FROM federated_outgoing_shares WHERE id = $1 FOR UPDATE`,
			shareID,
		).Scan(&used)
		if used+fileSize > *uploadQuotaBytes {
			h.Storage.Delete(context.Background(), storagePath)
			return c.Status(413).JSON(fiber.Map{"error": "share quota exceeded"})
		}
	}

	// Insert file record (uploader is the sharer user - best proxy; actual remote user unknown)
	_, err = tx.Exec(c.Context(), `
		INSERT INTO files (id, collection_id, uploader_user_id,
		                   encrypted_metadata, metadata_nonce,
		                   encrypted_file_key, file_key_nonce,
		                   storage_path, encrypted_size_bytes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`, fileID, collectionID, sharerUserID,
		encMetadata, metadataNonce,
		encFileKey, fileKeyNonce,
		storagePath, fileSize)
	if err != nil {
		h.Storage.Delete(context.Background(), storagePath)
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	// Update upload_used_bytes on the share
	tx.Exec(c.Context(),
		`UPDATE federated_outgoing_shares SET upload_used_bytes = upload_used_bytes + $1 WHERE id = $2`,
		fileSize, shareID)

	// Update sharer's storage quota
	tx.Exec(c.Context(),
		`UPDATE users SET storage_used_bytes = storage_used_bytes + $1 WHERE id = $2`,
		fileSize, sharerUserID)

	if err := tx.Commit(c.Context()); err != nil {
		h.Storage.Delete(context.Background(), storagePath)
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	return c.Status(201).JSON(fiber.Map{"id": fileID})
}

// DELETE /api/fed/shares/{token}/files/{fileId}
// @Summary      Delete a file from a federated share
// @Tags         Federation
// @Param        token   path  string  true  "Share access token"
// @Param        fileId  path  string  true  "File UUID"
// @Success      204
// @Failure      403  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Router       /fed/shares/{token}/files/{fileId} [delete]
func (h *FederationHandler) DeleteShareFile(c *fiber.Ctx) error {
	token := c.Params("token")
	fileID := c.Params("fileId")

	var shareID, collectionID, sharerUserID string
	var canDelete bool
	err := h.DB.QueryRow(context.Background(), `
		SELECT id, collection_id, sharer_user_id, can_delete
		FROM federated_outgoing_shares WHERE access_token = $1
	`, token).Scan(&shareID, &collectionID, &sharerUserID, &canDelete)
	if err != nil {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}
	if !canDelete {
		return c.Status(403).JSON(fiber.Map{"error": "delete not permitted"})
	}

	var storagePath string
	var fileSize int64
	err = h.DB.QueryRow(context.Background(),
		`SELECT storage_path, encrypted_size_bytes FROM files WHERE id = $1 AND collection_id = $2`,
		fileID, collectionID,
	).Scan(&storagePath, &fileSize)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}

	_, err = h.DB.Exec(context.Background(), `DELETE FROM files WHERE id = $1`, fileID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	h.DB.Exec(context.Background(),
		`UPDATE federated_outgoing_shares SET upload_used_bytes = GREATEST(0, upload_used_bytes - $1) WHERE id = $2`,
		fileSize, shareID)
	h.DB.Exec(context.Background(),
		`UPDATE users SET storage_used_bytes = GREATEST(0, storage_used_bytes - $1) WHERE id = $2`,
		fileSize, sharerUserID)
	h.Storage.Delete(context.Background(), storagePath)

	return c.SendStatus(204)
}
