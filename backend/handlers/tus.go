// Package handlers — tus.io 1.0 resumable upload endpoint.
//
// The browser- and CLI-side multipart POST (handlers/files.go: Upload)
// works fine for small files but buffers the encrypted blob entirely in
// memory and starts over from byte zero on any network blip. For the
// "upload a 100 GB photo folder without a CLI" desktop story we need:
//
//   1. Bounded memory regardless of file size  → S3 multipart upload
//   2. Resume after disconnect                 → tus offset bookkeeping
//   3. Encrypted-metadata commit up-front      → tus Upload-Metadata
//
// The flow:
//
//   POST   /api/uploads          — create session, allocate S3 multipart
//   PATCH  /api/uploads/{id}     — append a part, update offset
//   PATCH  /api/uploads/{id}     — repeat …
//   PATCH  /api/uploads/{id}     — final part: complete multipart, copy to
//                                  canonical path, insert files row, commit
//                                  quota, delete uploads row
//   HEAD   /api/uploads/{id}     — resume: returns current Upload-Offset
//   DELETE /api/uploads/{id}     — cancel: abort multipart, free quota
//   OPTIONS /api/uploads         — discovery (Tus-Version etc.)
//
// Quota is soft-reserved: a user's available bytes are
//     storage_quota_bytes - storage_used_bytes - SUM(uploads.total_bytes)
// so a half-uploaded 50 GB file blocks a concurrent 50 GB attempt without
// polluting storage_used_bytes. Final commit happens atomically with the
// files INSERT.
package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kutup/backend/middleware"
	"github.com/kutup/backend/services"
)

// tusVersion is the protocol version we advertise + require. Clients send
// `Tus-Resumable: 1.0.0` on every request; we 412 if it doesn't match.
const tusVersion = "1.0.0"

// minPartSize is S3's lower bound on multipart parts except the last.
// 5 MiB. Enforced on PATCH — clients sending sub-5MiB chunks before the
// final one get 400.
const minPartSize int64 = 5 * 1024 * 1024

type TusHandler struct {
	DB      *pgxpool.Pool
	Storage *services.StorageService
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// requireTusResumable enforces the protocol-version header on every
// non-OPTIONS request. Per spec, mismatched / missing version → 412.
func requireTusResumable(c *fiber.Ctx) bool {
	if c.Get("Tus-Resumable") != tusVersion {
		c.Set("Tus-Resumable", tusVersion)
		c.Set("Tus-Version", tusVersion)
		c.Status(fiber.StatusPreconditionFailed).
			SendString("Tus-Resumable header must be " + tusVersion)
		return false
	}
	return true
}

// parseUploadMetadata decodes the `Upload-Metadata` header.
//
//	Upload-Metadata: collectionId <b64>, encryptedMetadata <b64>, ...
//
// Comma-separated key/value pairs; values are base64-encoded UTF-8. Per
// tus spec the values may be omitted for boolean-flag keys; we ignore
// such pairs since none of kutup's required fields are flag-shaped.
func parseUploadMetadata(header string) (map[string]string, error) {
	out := make(map[string]string)
	if header == "" {
		return out, nil
	}
	for _, pair := range strings.Split(header, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, " ", 2)
		key := strings.TrimSpace(parts[0])
		if key == "" {
			continue
		}
		if len(parts) == 1 {
			// flag-style key with no value; ignored
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("upload-metadata: bad base64 for %q: %w", key, err)
		}
		out[key] = string(raw)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// OPTIONS /api/uploads — discovery
// ---------------------------------------------------------------------------

// Options advertises supported protocol version + extensions. No auth —
// the tus spec treats this as discovery. Tus-Max-Size is set conservatively
// to the user-quota maximum (10 GiB default); the per-user check at POST
// rejects anything that wouldn't fit in *that* user's remaining quota.
func (h *TusHandler) Options(c *fiber.Ctx) error {
	c.Set("Tus-Resumable", tusVersion)
	c.Set("Tus-Version", tusVersion)
	c.Set("Tus-Extension", "creation,termination")
	// Conservative ceiling; real check is per-user at create time.
	c.Set("Tus-Max-Size", strconv.FormatInt(1024*1024*1024*1024, 10)) // 1 TiB
	return c.SendStatus(fiber.StatusNoContent)
}

// ---------------------------------------------------------------------------
// POST /api/uploads — Create
// ---------------------------------------------------------------------------

// Create opens a new tus upload session. Headers:
//
//	Upload-Length: <bytes>                     (required)
//	Upload-Metadata: k v, k v, …               (required — must include
//	     collectionId, encryptedMetadata, metadataNonce, encryptedFileKey,
//	     fileKeyNonce)
//	Tus-Resumable: 1.0.0                       (required)
//
// On success returns 201 with `Location: /api/uploads/{id}` plus
// `Tus-Resumable` + `Upload-Offset: 0`.
func (h *TusHandler) Create(c *fiber.Ctx) error {
	if !requireTusResumable(c) {
		return nil
	}
	userID := middleware.UserID(c)

	totalBytesStr := c.Get("Upload-Length")
	if totalBytesStr == "" {
		return c.Status(fiber.StatusBadRequest).
			SendString("Upload-Length header required")
	}
	totalBytes, err := strconv.ParseInt(totalBytesStr, 10, 64)
	if err != nil || totalBytes < 0 {
		return c.Status(fiber.StatusBadRequest).
			SendString("Upload-Length must be a non-negative integer")
	}

	meta, err := parseUploadMetadata(c.Get("Upload-Metadata"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}
	collID := meta["collectionId"]
	encMetadata := meta["encryptedMetadata"]
	metadataNonce := meta["metadataNonce"]
	encFileKey := meta["encryptedFileKey"]
	fileKeyNonce := meta["fileKeyNonce"]
	if collID == "" || encMetadata == "" || metadataNonce == "" ||
		encFileKey == "" || fileKeyNonce == "" {
		return c.Status(fiber.StatusBadRequest).SendString(
			"Upload-Metadata must include collectionId, encryptedMetadata, " +
				"metadataNonce, encryptedFileKey, fileKeyNonce")
	}

	// Permission check + quota gate, mirroring handlers/files.go: Upload.
	tx, err := h.DB.Begin(c.Context())
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("db begin")
	}
	defer tx.Rollback(c.Context())

	var isOwner bool
	{
		var n int
		_ = tx.QueryRow(c.Context(),
			`SELECT COUNT(*) FROM collections WHERE id=$1 AND owner_user_id=$2`,
			collID, userID,
		).Scan(&n)
		isOwner = n > 0
	}
	var uploadQuotaBytes *int64
	if !isOwner {
		var canUpload bool
		err := tx.QueryRow(c.Context(),
			`SELECT can_upload, upload_quota_bytes FROM collection_shares
			 WHERE collection_id=$1 AND recipient_user_id=$2`,
			collID, userID,
		).Scan(&canUpload, &uploadQuotaBytes)
		if err != nil || !canUpload {
			return c.Status(fiber.StatusForbidden).SendString("forbidden")
		}
	}

	// User-level quota: committed + reserved (in-flight uploads) + this one
	// must not exceed the cap. FOR UPDATE locks the user row until commit
	// so concurrent Creates can't race past the cap together.
	var quota, used int64
	err = tx.QueryRow(c.Context(),
		`SELECT storage_quota_bytes, storage_used_bytes FROM users
		 WHERE id=$1 FOR UPDATE`,
		userID,
	).Scan(&quota, &used)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("db read user")
	}
	var reserved int64
	_ = tx.QueryRow(c.Context(),
		`SELECT COALESCE(SUM(total_bytes - received_bytes), 0)
		 FROM uploads WHERE user_id=$1`,
		userID,
	).Scan(&reserved)
	if used+reserved+totalBytes > quota {
		return c.Status(fiber.StatusRequestEntityTooLarge).
			SendString("storage quota exceeded")
	}

	// Per-share upload-quota check, same as files.go.
	if !isOwner && uploadQuotaBytes != nil {
		var usedShareBytes, reservedShare int64
		_ = tx.QueryRow(c.Context(),
			`SELECT COALESCE(SUM(encrypted_size_bytes),0) FROM files
			 WHERE collection_id=$1 AND uploader_user_id=$2`,
			collID, userID,
		).Scan(&usedShareBytes)
		_ = tx.QueryRow(c.Context(),
			`SELECT COALESCE(SUM(total_bytes - received_bytes),0) FROM uploads
			 WHERE collection_id=$1 AND user_id=$2`,
			collID, userID,
		).Scan(&reservedShare)
		if usedShareBytes+reservedShare+totalBytes > *uploadQuotaBytes {
			return c.Status(fiber.StatusRequestEntityTooLarge).
				SendString("share upload quota exceeded")
		}
	}

	// Allocate S3 multipart upload at a temp key. Temp keys live under
	// {userId}/tmp/{uploadId}/ so the existing per-user orphan sweep can
	// reach them; on completion we CopyObject to the canonical path.
	uploadID := uuid.New()
	tempKey := fmt.Sprintf("%s/tmp/%s", userID, uploadID.String())
	s3UploadID, err := h.Storage.CreateMultipart(c.Context(), tempKey)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).
			SendString("storage create multipart")
	}

	_, err = tx.Exec(c.Context(), `
		INSERT INTO uploads
		    (id, user_id, collection_id, total_bytes,
		     encrypted_metadata, metadata_nonce,
		     encrypted_file_key, file_key_nonce,
		     storage_temp_key, s3_upload_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`, uploadID, userID, collID, totalBytes,
		encMetadata, metadataNonce, encFileKey, fileKeyNonce,
		tempKey, s3UploadID,
	)
	if err != nil {
		// Best-effort cleanup of the S3 multipart we just allocated.
		_ = h.Storage.AbortMultipart(context.Background(), tempKey, s3UploadID)
		return c.Status(fiber.StatusInternalServerError).
			SendString("db insert upload")
	}
	if err := tx.Commit(c.Context()); err != nil {
		_ = h.Storage.AbortMultipart(context.Background(), tempKey, s3UploadID)
		return c.Status(fiber.StatusInternalServerError).SendString("db commit")
	}

	c.Set("Tus-Resumable", tusVersion)
	c.Set("Location", "/api/uploads/"+uploadID.String())
	c.Set("Upload-Offset", "0")
	return c.SendStatus(fiber.StatusCreated)
}

// ---------------------------------------------------------------------------
// HEAD /api/uploads/{id} — resume
// ---------------------------------------------------------------------------

// Head returns the current `Upload-Offset` so the client can resume from
// the right byte. 404 if the upload doesn't exist or isn't owned by the
// caller. Per tus spec, response includes `Cache-Control: no-store`.
func (h *TusHandler) Head(c *fiber.Ctx) error {
	if !requireTusResumable(c) {
		return nil
	}
	userID := middleware.UserID(c)
	id := c.Params("id")

	var totalBytes, receivedBytes int64
	err := h.DB.QueryRow(c.Context(),
		`SELECT total_bytes, received_bytes FROM uploads
		 WHERE id=$1 AND user_id=$2`,
		id, userID,
	).Scan(&totalBytes, &receivedBytes)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c.SendStatus(fiber.StatusNotFound)
		}
		return c.Status(fiber.StatusInternalServerError).SendString("db read")
	}

	c.Set("Tus-Resumable", tusVersion)
	c.Set("Upload-Offset", strconv.FormatInt(receivedBytes, 10))
	c.Set("Upload-Length", strconv.FormatInt(totalBytes, 10))
	c.Set("Cache-Control", "no-store")
	return c.SendStatus(fiber.StatusOK)
}

// ---------------------------------------------------------------------------
// PATCH /api/uploads/{id} — extend
// ---------------------------------------------------------------------------

// Patch appends bytes. Required headers:
//
//	Tus-Resumable: 1.0.0
//	Upload-Offset: <current offset>             (must match server's stored offset; 409 otherwise)
//	Content-Length: <chunk size>
//	Content-Type: application/offset+octet-stream
//
// Each PATCH becomes one S3 multipart part. Parts before the final must
// be ≥ 5 MiB. On the PATCH that brings received_bytes == total_bytes we
// run the finaliser: CompleteMultipartUpload, CopyObject to the canonical
// {userId}/{collectionId}/{fileId} path, INSERT into files, bump
// storage_used_bytes, DELETE the uploads row.
func (h *TusHandler) Patch(c *fiber.Ctx) error {
	if !requireTusResumable(c) {
		return nil
	}
	if c.Get("Content-Type") != "application/offset+octet-stream" {
		return c.Status(fiber.StatusUnsupportedMediaType).
			SendString("Content-Type must be application/offset+octet-stream")
	}

	userID := middleware.UserID(c)
	id := c.Params("id")

	clientOffsetStr := c.Get("Upload-Offset")
	clientOffset, err := strconv.ParseInt(clientOffsetStr, 10, 64)
	if err != nil || clientOffset < 0 {
		return c.Status(fiber.StatusBadRequest).
			SendString("Upload-Offset must be a non-negative integer")
	}

	chunkLen := int64(len(c.Body()))
	// Note: Fiber buffers the body even with StreamRequestBody=true unless
	// we use c.Context().RequestBodyStream(). For now we accept the buffer
	// — each chunk is ≤ 5–10 MiB which is fine. Switch to the streaming
	// path once we want >100 MiB chunks.
	if chunkLen == 0 {
		return c.Status(fiber.StatusBadRequest).
			SendString("empty body")
	}

	// Read the upload row + lock it FOR UPDATE so the finaliser path is
	// race-free against a concurrent PATCH on the same upload.
	tx, err := h.DB.Begin(c.Context())
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("db begin")
	}
	defer tx.Rollback(c.Context())

	var (
		collID, encMetadata, metadataNonce, encFileKey, fileKeyNonce string
		totalBytes, receivedBytes                                    int64
		tempKey, s3UploadID                                          string
		partEtagsJSON                                                []byte
	)
	err = tx.QueryRow(c.Context(), `
		SELECT collection_id, total_bytes, received_bytes,
		       encrypted_metadata, metadata_nonce,
		       encrypted_file_key, file_key_nonce,
		       storage_temp_key, s3_upload_id, s3_part_etags
		FROM uploads
		WHERE id=$1 AND user_id=$2
		FOR UPDATE
	`, id, userID).Scan(
		&collID, &totalBytes, &receivedBytes,
		&encMetadata, &metadataNonce, &encFileKey, &fileKeyNonce,
		&tempKey, &s3UploadID, &partEtagsJSON,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c.SendStatus(fiber.StatusNotFound)
		}
		return c.Status(fiber.StatusInternalServerError).SendString("db read")
	}

	if clientOffset != receivedBytes {
		c.Set("Upload-Offset", strconv.FormatInt(receivedBytes, 10))
		return c.Status(fiber.StatusConflict).
			SendString("Upload-Offset mismatch")
	}
	if receivedBytes+chunkLen > totalBytes {
		return c.Status(fiber.StatusRequestEntityTooLarge).
			SendString("chunk exceeds Upload-Length")
	}

	// Decode existing part-etags JSON, decide the next part number.
	var parts []services.CompletedPart
	if len(partEtagsJSON) > 0 {
		if err := json.Unmarshal(partEtagsJSON, &parts); err != nil {
			return c.Status(fiber.StatusInternalServerError).
				SendString("corrupt part etags")
		}
	}
	nextPart := int32(len(parts)) + 1
	isFinalPart := receivedBytes+chunkLen == totalBytes
	if !isFinalPart && chunkLen < minPartSize {
		return c.Status(fiber.StatusBadRequest).
			SendString(fmt.Sprintf(
				"non-final part must be at least %d bytes (got %d)",
				minPartSize, chunkLen))
	}

	// Stream the chunk to S3 multipart. Body is bytes; the SDK reader
	// can swallow a buffered []byte without re-copying. (When we move to
	// true streaming bodies, swap for a fasthttp stream reader.)
	etag, err := h.Storage.UploadPart(
		c.Context(), tempKey, s3UploadID, nextPart,
		bytes.NewReader(c.Body()), chunkLen,
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).
			SendString("storage upload part: " + err.Error())
	}
	parts = append(parts, services.CompletedPart{PartNumber: nextPart, ETag: etag})
	partsJSON, _ := json.Marshal(parts)
	newReceived := receivedBytes + chunkLen

	_, err = tx.Exec(c.Context(), `
		UPDATE uploads
		SET received_bytes=$1, s3_part_etags=$2, updated_at=NOW()
		WHERE id=$3
	`, newReceived, partsJSON, id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("db update")
	}

	if !isFinalPart {
		if err := tx.Commit(c.Context()); err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("db commit")
		}
		c.Set("Tus-Resumable", tusVersion)
		c.Set("Upload-Offset", strconv.FormatInt(newReceived, 10))
		return c.SendStatus(fiber.StatusNoContent)
	}

	// --- finaliser path ---
	// 1. CompleteMultipartUpload — stitches parts into one temp object.
	// 2. CopyObject from temp key to canonical {userId}/{collectionId}/{fileId}.
	// 3. INSERT into files, bump users.storage_used_bytes.
	// 4. Delete uploads row.
	// 5. Delete the temp object.
	// Storage side-effects happen after the DB commit so a crash in
	// between leaves an orphan temp object (cleanable by the orphan
	// sweep) rather than an orphan DB row pointing at nothing.
	if err := h.Storage.CompleteMultipart(c.Context(), tempKey, s3UploadID, parts); err != nil {
		return c.Status(fiber.StatusInternalServerError).
			SendString("storage complete multipart: " + err.Error())
	}
	fileID := uuid.New()
	finalKey := fmt.Sprintf("%s/%s/%s", userID, collID, fileID.String())
	if err := h.Storage.CopyObject(c.Context(), tempKey, finalKey); err != nil {
		return c.Status(fiber.StatusInternalServerError).
			SendString("storage copy: " + err.Error())
	}

	_, err = tx.Exec(c.Context(), `
		INSERT INTO files
		    (id, collection_id, uploader_user_id,
		     encrypted_metadata, metadata_nonce,
		     encrypted_file_key, file_key_nonce,
		     storage_path, encrypted_size_bytes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`, fileID, collID, userID,
		encMetadata, metadataNonce, encFileKey, fileKeyNonce,
		finalKey, totalBytes,
	)
	if err != nil {
		_ = h.Storage.Delete(context.Background(), finalKey)
		return c.Status(fiber.StatusInternalServerError).SendString("db insert file")
	}
	_, err = tx.Exec(c.Context(),
		`UPDATE users SET storage_used_bytes = storage_used_bytes + $1 WHERE id=$2`,
		totalBytes, userID,
	)
	if err != nil {
		_ = h.Storage.Delete(context.Background(), finalKey)
		return c.Status(fiber.StatusInternalServerError).SendString("db quota update")
	}
	_, err = tx.Exec(c.Context(), `DELETE FROM uploads WHERE id=$1`, id)
	if err != nil {
		_ = h.Storage.Delete(context.Background(), finalKey)
		return c.Status(fiber.StatusInternalServerError).SendString("db delete upload")
	}
	if err := tx.Commit(c.Context()); err != nil {
		_ = h.Storage.Delete(context.Background(), finalKey)
		return c.Status(fiber.StatusInternalServerError).SendString("db commit")
	}

	// Best-effort temp-object cleanup. Orphan sweep handles failures.
	_ = h.Storage.Delete(context.Background(), tempKey)

	c.Set("Tus-Resumable", tusVersion)
	c.Set("Upload-Offset", strconv.FormatInt(newReceived, 10))
	c.Set("X-Kutup-File-Id", fileID.String())
	return c.SendStatus(fiber.StatusNoContent)
}

// ---------------------------------------------------------------------------
// DELETE /api/uploads/{id} — cancel
// ---------------------------------------------------------------------------

// Delete cancels an in-flight upload. Aborts the S3 multipart (freeing
// SeaweedFS-side staging) and removes the DB row (freeing reserved quota).
// 404 if the upload doesn't exist / isn't owned by the caller.
func (h *TusHandler) Delete(c *fiber.Ctx) error {
	if !requireTusResumable(c) {
		return nil
	}
	userID := middleware.UserID(c)
	id := c.Params("id")

	var tempKey, s3UploadID string
	err := h.DB.QueryRow(c.Context(),
		`SELECT storage_temp_key, s3_upload_id FROM uploads
		 WHERE id=$1 AND user_id=$2`,
		id, userID,
	).Scan(&tempKey, &s3UploadID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c.SendStatus(fiber.StatusNotFound)
		}
		return c.Status(fiber.StatusInternalServerError).SendString("db read")
	}

	// Abort first, then delete the row. If we deleted the row first and
	// the Abort failed, we'd leak the multipart with no record of how to
	// reach it; this ordering means a failed Abort is recoverable from
	// the row.
	if err := h.Storage.AbortMultipart(c.Context(), tempKey, s3UploadID); err != nil {
		return c.Status(fiber.StatusInternalServerError).
			SendString("storage abort: " + err.Error())
	}
	if _, err := h.DB.Exec(c.Context(),
		`DELETE FROM uploads WHERE id=$1 AND user_id=$2`,
		id, userID,
	); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("db delete")
	}

	c.Set("Tus-Resumable", tusVersion)
	return c.SendStatus(fiber.StatusNoContent)
}

