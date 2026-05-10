package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/kutup/backend/middleware"
	"github.com/kutup/backend/services"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type FilesHandler struct {
	DB      *pgxpool.Pool
	Storage *services.StorageService
}

// @Summary      List files in a collection
// @Tags         Files
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Collection UUID"
// @Success      200  {array}   FileRow
// @Failure      401  {object}  ErrorResponse
// @Failure      403  {object}  ErrorResponse
// @Router       /collections/{id}/files [get]
func (h *FilesHandler) ListFiles(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	collID := c.Params("id")

	// Verify access: owner or valid share recipient
	if !h.canAccessCollection(c.Context(), userID, collID) {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}

	rows, err := h.DB.Query(context.Background(), `
		SELECT id, collection_id, uploader_user_id,
		       encrypted_metadata, metadata_nonce,
		       encrypted_file_key, file_key_nonce,
		       encrypted_size_bytes, created_at, updated_at
		FROM files
		WHERE collection_id = $1
		ORDER BY created_at DESC
	`, collID)
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
		if err := rows.Scan(
			&f.ID, &f.CollectionID, &f.UploaderUserID,
			&f.EncryptedMetadata, &f.MetadataNonce,
			&f.EncryptedFileKey, &f.FileKeyNonce,
			&f.EncryptedSizeBytes, &f.CreatedAt, &f.UpdatedAt,
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

// @Summary      Upload an encrypted file
// @Tags         Files
// @Accept       mpfd
// @Produce      json
// @Security     BearerAuth
// @Param        collectionId       formData  string  true  "Target collection UUID"
// @Param        encryptedMetadata  formData  string  true  "Encrypted filename/size/MIME (base64)"
// @Param        metadataNonce      formData  string  true  "Metadata nonce (base64)"
// @Param        encryptedFileKey   formData  string  true  "Per-file key encrypted with collection key (base64)"
// @Param        fileKeyNonce       formData  string  true  "File key nonce (base64)"
// @Param        file               formData  file    true  "Encrypted file content"
// @Success      201  {object}  UploadResult
// @Failure      400  {object}  ErrorResponse
// @Failure      401  {object}  ErrorResponse
// @Failure      403  {object}  ErrorResponse
// @Failure      413  {object}  ErrorResponse  "Storage quota exceeded"
// @Router       /files/upload [post]
func (h *FilesHandler) Upload(c *fiber.Ctx) error {
	userID := middleware.UserID(c)

	// Parse multipart form
	form, err := c.MultipartForm()
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid multipart form"})
	}

	collID := firstField(form.Value, "collectionId")
	encMetadata := firstField(form.Value, "encryptedMetadata")
	metadataNonce := firstField(form.Value, "metadataNonce")
	encFileKey := firstField(form.Value, "encryptedFileKey")
	fileKeyNonce := firstField(form.Value, "fileKeyNonce")

	if collID == "" || encMetadata == "" || encFileKey == "" {
		return c.Status(400).JSON(fiber.Map{"error": "missing required fields"})
	}

	// Get file from multipart first so we know the size
	files := form.File["file"]
	if len(files) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "no file provided"})
	}
	fileHeader := files[0]
	fileSize := fileHeader.Size

	// Verify write access — owner or share with can_upload
	isOwner := false
	var ownerCheckCount int
	h.DB.QueryRow(c.Context(),
		`SELECT COUNT(*) FROM collections WHERE id = $1 AND owner_user_id = $2`,
		collID, userID,
	).Scan(&ownerCheckCount)
	if ownerCheckCount > 0 {
		isOwner = true
	}

	// For non-owners, fetch share permission (but defer quota check to inside transaction)
	var canUpload bool
	var uploadQuotaBytes *int64
	if !isOwner {
		err := h.DB.QueryRow(c.Context(),
			`SELECT can_upload, upload_quota_bytes FROM collection_shares
			 WHERE collection_id = $1 AND recipient_user_id = $2`,
			collID, userID,
		).Scan(&canUpload, &uploadQuotaBytes)
		if err != nil || !canUpload {
			return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
		}
	}

	fileID := uuid.New().String()
	storagePath := fmt.Sprintf("%s/%s/%s", userID, collID, fileID)

	// Atomic quota check + reserve
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

	if used+fileSize > quota {
		return c.Status(413).JSON(fiber.Map{"error": "storage quota exceeded"})
	}

	// S3-6: Check share quota inside the transaction to prevent race conditions.
	// Re-read the current SUM inside the TX so concurrent uploads see each other.
	if !isOwner && uploadQuotaBytes != nil {
		var usedShareBytes int64
		tx.QueryRow(c.Context(),
			`SELECT COALESCE(SUM(encrypted_size_bytes), 0) FROM files WHERE collection_id = $1 AND uploader_user_id = $2`,
			collID, userID,
		).Scan(&usedShareBytes)
		if usedShareBytes+fileSize > *uploadQuotaBytes {
			return c.Status(413).JSON(fiber.Map{"error": "share upload quota exceeded"})
		}
	}

	// Open file for streaming
	src, err := fileHeader.Open()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "cannot read file"})
	}
	defer src.Close()

	// Stream directly to SeaweedFS — no disk buffering
	if err := h.Storage.Upload(c.Context(), storagePath, src, fileSize); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "storage error"})
	}

	// Insert file record
	_, err = tx.Exec(c.Context(), `
		INSERT INTO files (id, collection_id, uploader_user_id,
		                   encrypted_metadata, metadata_nonce,
		                   encrypted_file_key, file_key_nonce,
		                   storage_path, encrypted_size_bytes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`, fileID, collID, userID,
		encMetadata, metadataNonce,
		encFileKey, fileKeyNonce,
		storagePath, fileSize,
	)
	if err != nil {
		// Clean up uploaded file on DB failure
		h.Storage.Delete(context.Background(), storagePath)
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	// Update quota
	_, err = tx.Exec(c.Context(),
		`UPDATE users SET storage_used_bytes = storage_used_bytes + $1 WHERE id = $2`,
		fileSize, userID,
	)
	if err != nil {
		h.Storage.Delete(context.Background(), storagePath)
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	if err := tx.Commit(c.Context()); err != nil {
		h.Storage.Delete(context.Background(), storagePath)
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	return c.Status(201).JSON(fiber.Map{"id": fileID})
}

// @Summary      Download an encrypted file
// @Tags         Files
// @Produce      octet-stream
// @Security     BearerAuth
// @Param        id   path  string  true  "File UUID"
// @Success      200
// @Failure      401  {object}  ErrorResponse
// @Failure      403  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Router       /files/{id}/download [get]
func (h *FilesHandler) Download(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	fileID := c.Params("id")

	var collID, storagePath, uploaderID string
	err := h.DB.QueryRow(context.Background(),
		`SELECT collection_id, storage_path, uploader_user_id FROM files WHERE id = $1`,
		fileID,
	).Scan(&collID, &storagePath, &uploaderID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}

	if !h.canAccessCollection(c.Context(), userID, collID) {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}

	body, size, err := h.Storage.GetObject(c.Context(), storagePath)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	// Do NOT defer body.Close() — fasthttp reads the stream lazily after
	// the handler returns and will close it. Closing here causes 502s.

	c.Set("Content-Type", "application/octet-stream")
	c.Set("Content-Length", fmt.Sprintf("%d", size))
	return c.SendStream(body, int(size))
}

// @Summary      Update file metadata (rename)
// @Description  Re-encrypted metadata blob with the new filename. Backend
// @Description  is E2EE-blind to the plaintext name; clients are responsible
// @Description  for preserving the file extension where required (office /
// @Description  text-editor dispatch).
// @Tags         Files
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path      string                true  "File UUID"
// @Param        body  body      UpdateFileMetadataRequest true  "New encrypted metadata"
// @Success      200   {object}  MessageResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      401   {object}  ErrorResponse
// @Failure      403   {object}  ErrorResponse
// @Failure      404   {object}  ErrorResponse
// @Router       /files/{id} [put]
func (h *FilesHandler) UpdateMetadata(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	fileID := c.Params("id")

	var req struct {
		EncryptedMetadata string `json:"encryptedMetadata"`
		MetadataNonce     string `json:"metadataNonce"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	if req.EncryptedMetadata == "" || req.MetadataNonce == "" {
		return c.Status(400).JSON(fiber.Map{"error": "encryptedMetadata and metadataNonce required"})
	}

	// Permission: collection owner OR uploader-with-can-delete (same gate
	// the Delete handler uses — rename is a softer mutation than delete,
	// so the same set of users can do it).
	var collID, uploaderID string
	if err := h.DB.QueryRow(context.Background(),
		`SELECT collection_id, uploader_user_id FROM files WHERE id = $1`,
		fileID,
	).Scan(&collID, &uploaderID); err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	var ownerID string
	h.DB.QueryRow(context.Background(),
		`SELECT owner_user_id FROM collections WHERE id = $1`, collID,
	).Scan(&ownerID)
	if ownerID != userID {
		if uploaderID != userID {
			return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
		}
		var canDelete bool
		h.DB.QueryRow(context.Background(),
			`SELECT can_delete FROM collection_shares WHERE collection_id = $1 AND recipient_user_id = $2`,
			collID, userID,
		).Scan(&canDelete)
		if !canDelete {
			return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
		}
	}

	if _, err := h.DB.Exec(context.Background(), `
		UPDATE files SET encrypted_metadata = $1, metadata_nonce = $2
		WHERE id = $3
	`, req.EncryptedMetadata, req.MetadataNonce, fileID); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	return c.JSON(fiber.Map{"message": "updated"})
}

// UpdateFileMetadataRequest documents the rename body shape for swagger.
type UpdateFileMetadataRequest struct {
	EncryptedMetadata string `json:"encryptedMetadata"`
	MetadataNonce     string `json:"metadataNonce"`
}

// @Summary      Delete a file
// @Tags         Files
// @Security     BearerAuth
// @Param        id  path  string  true  "File UUID"
// @Success      204
// @Failure      401  {object}  ErrorResponse
// @Failure      403  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Router       /files/{id} [delete]
func (h *FilesHandler) Delete(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	fileID := c.Params("id")

	var collID, storagePath string
	var fileSize int64
	var uploaderID string
	err := h.DB.QueryRow(context.Background(),
		`SELECT collection_id, storage_path, encrypted_size_bytes, uploader_user_id
		 FROM files WHERE id = $1`,
		fileID,
	).Scan(&collID, &storagePath, &fileSize, &uploaderID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}

	// Only owner of collection, or uploader with can_delete share permission can delete
	var ownerID string
	h.DB.QueryRow(context.Background(),
		`SELECT owner_user_id FROM collections WHERE id = $1`, collID,
	).Scan(&ownerID)

	if ownerID != userID {
		// Check if user is uploader AND has can_delete share
		if uploaderID != userID {
			return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
		}
		var canDelete bool
		h.DB.QueryRow(context.Background(),
			`SELECT can_delete FROM collection_shares WHERE collection_id = $1 AND recipient_user_id = $2`,
			collID, userID,
		).Scan(&canDelete)
		if !canDelete {
			return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
		}
	}

	_, err = h.DB.Exec(context.Background(), `DELETE FROM files WHERE id = $1`, fileID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	// Release quota (best-effort, no rollback needed)
	h.DB.Exec(context.Background(),
		`UPDATE users SET storage_used_bytes = GREATEST(0, storage_used_bytes - $1) WHERE id = $2`,
		fileSize, uploaderID,
	)

	// Delete from SeaweedFS (best-effort).
	// Wipe the entire files/{fileId}/ prefix so per-file children
	// (snapshot blobs, whiteboard image asset blobs, …) get GC'd along
	// with the parent. The single-key Delete on storagePath stays for
	// safety: legacy main blobs may not live under that prefix.
	h.Storage.Delete(context.Background(), storagePath)
	h.Storage.DeletePrefix(context.Background(), "files/"+fileID+"/")

	return c.SendStatus(204)
}

// ClaimSeed atomically arbitrates the first-seeder for a freshly-created
// collaborative file. Two browser tabs of the same file racing on open
// must NOT both insert the cold-start `initialContent` into Yjs (that
// would CRDT-merge into duplicated content). Exactly one tab gets
// committed=true; all later callers get committed=false and skip seeding.
//
// @Summary      Claim the first-seeder slot for a fresh collab file
// @Description  Atomic UPDATE; exactly one caller for a given file gets committed=true. Idempotent — once true, it stays true.
// @Tags         Files
// @Produce      json
// @Security     BearerAuth
// @Param        fileId  path      string  true  "File UUID"
// @Success      200     {object}  ClaimSeedResponse
// @Failure      401     {object}  ErrorResponse
// @Failure      403     {object}  ErrorResponse
// @Failure      404     {object}  ErrorResponse
// @Router       /files/{fileId}/claim-seed [post]
func (h *FilesHandler) ClaimSeed(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	fileID := c.Params("fileId")

	// Resolve the collection_id and verify access first. This is two DB
	// round-trips instead of one fancy CTE, but it keeps the access check
	// identical to the rest of the file-scoped routes (canAccessCollection
	// covers owners + share recipients).
	var collID string
	if err := h.DB.QueryRow(c.Context(),
		`SELECT collection_id FROM files WHERE id = $1`, fileID,
	).Scan(&collID); err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	if !h.canAccessCollection(c.Context(), userID, collID) {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}

	// Atomic transition false → true. RETURNING reports whether *this*
	// statement flipped the column. Postgres takes a row-level lock for
	// the UPDATE so concurrent calls serialise even without an explicit
	// transaction.
	var claimedID string
	err := h.DB.QueryRow(c.Context(), `
		UPDATE files SET seed_committed = true
		WHERE id = $1 AND seed_committed = false
		RETURNING id
	`, fileID).Scan(&claimedID)

	if err != nil {
		// pgx returns ErrNoRows when the WHERE clause matches zero rows
		// — i.e. someone else already committed. That's the "you lost"
		// outcome, not a server error.
		return c.JSON(ClaimSeedResponse{Committed: false})
	}
	return c.JSON(ClaimSeedResponse{Committed: true})
}

type ClaimSeedResponse struct {
	Committed bool `json:"committed"`
}

// --- helpers ---

func (h *FilesHandler) canAccessCollection(ctx context.Context, userID, collID string) bool {
	var count int
	// Owner check
	h.DB.QueryRow(ctx,
		`SELECT COUNT(*) FROM collections WHERE id = $1 AND owner_user_id = $2`,
		collID, userID,
	).Scan(&count)
	if count > 0 {
		return true
	}
	// Share check
	h.DB.QueryRow(ctx,
		`SELECT COUNT(*) FROM collection_shares WHERE collection_id = $1 AND recipient_user_id = $2`,
		collID, userID,
	).Scan(&count)
	return count > 0
}


func firstField(m map[string][]string, key string) string {
	if v, ok := m[key]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}
