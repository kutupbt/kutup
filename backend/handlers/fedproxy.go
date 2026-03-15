package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/depo/backend/middleware"
	"github.com/depo/backend/utils"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fedHTTPClient never follows redirects, preventing a malicious federation
// server from issuing a 301/302 redirect to an internal address and bypassing
// the SSRF validation that was applied to the original hostname.
var fedHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

type FedProxyHandler struct {
	DB     *pgxpool.Pool
	AppEnv string
}

type IncomingShare struct {
	ID                     string    `json:"id"`
	RemoteServer           string    `json:"remoteServer"`
	EncryptedCollectionKey string    `json:"encryptedCollectionKey"`
	EncryptedName          string    `json:"encryptedName"`
	NameNonce              string    `json:"nameNonce"`
	CanUpload              bool      `json:"canUpload"`
	CanDelete              bool      `json:"canDelete"`
	UploadQuotaBytes       *int64    `json:"uploadQuotaBytes"`
	CreatedAt              time.Time `json:"createdAt"`
}

// POST /api/fed-proxy/incoming  — add incoming share by pasting invite URL
// @Summary      Accept a federated share invite
// @Tags         Federation Proxy
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      AddIncomingShareRequest  true  "Invite URL"
// @Success      201   {object}  IncomingShare
// @Failure      400   {object}  ErrorResponse
// @Failure      401   {object}  ErrorResponse
// @Failure      502   {object}  ErrorResponse
// @Router       /fed-proxy/incoming [post]
func (h *FedProxyHandler) AddIncomingShare(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	var req struct {
		InviteURL string `json:"inviteUrl"` // https://server-b.com/invite/{token}
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	if req.InviteURL == "" {
		return c.Status(400).JSON(fiber.Map{"error": "inviteUrl required"})
	}

	// Parse: https://server-b.com/invite/{token}
	// URL format: {scheme}://{host}/invite/{token}
	u := req.InviteURL
	idx := strings.Index(u, "/invite/")
	if idx < 0 {
		return c.Status(400).JSON(fiber.Map{"error": "invalid invite URL"})
	}
	remoteServer := u[:idx]
	token := u[idx+len("/invite/"):]
	if remoteServer == "" || token == "" {
		return c.Status(400).JSON(fiber.Map{"error": "invalid invite URL"})
	}

	// S1-4: Validate remote server URL to prevent SSRF
	allowHTTP := h.AppEnv != "production"
	if err := utils.ValidateFederationURL(remoteServer, allowHTTP); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid server URL: " + err.Error()})
	}

	// Fetch invite from remote server
	fetchURL := fmt.Sprintf("%s/api/fed/invites/%s", remoteServer, token)
	resp, err := fedHTTPClient.Get(fetchURL) //nolint:gosec — URL validated above
	if err != nil || resp.StatusCode != 200 {
		return c.Status(502).JSON(fiber.Map{"error": "failed to fetch invite from remote server"})
	}
	defer resp.Body.Close()

	var inviteData struct {
		WrappedKey       string `json:"wrappedKey"`
		EncryptedName    string `json:"encryptedName"`
		NameNonce        string `json:"nameNonce"`
		CanUpload        bool   `json:"canUpload"`
		CanDelete        bool   `json:"canDelete"`
		UploadQuotaBytes *int64 `json:"uploadQuotaBytes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&inviteData); err != nil {
		return c.Status(502).JSON(fiber.Map{"error": "invalid invite data"})
	}

	// Store in federated_incoming_shares
	var shareID string
	err = h.DB.QueryRow(context.Background(), `
		INSERT INTO federated_incoming_shares (user_id, remote_server, remote_access_token,
		    encrypted_collection_key, encrypted_name, name_nonce,
		    can_upload, can_delete, upload_quota_bytes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (user_id, remote_server, remote_access_token) DO UPDATE
		    SET encrypted_collection_key = EXCLUDED.encrypted_collection_key
		RETURNING id
	`, userID, remoteServer, token,
		inviteData.WrappedKey, inviteData.EncryptedName, inviteData.NameNonce,
		inviteData.CanUpload, inviteData.CanDelete, inviteData.UploadQuotaBytes,
	).Scan(&shareID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	return c.Status(201).JSON(fiber.Map{
		"id":                     shareID,
		"remoteServer":           remoteServer,
		"encryptedCollectionKey": inviteData.WrappedKey,
		"encryptedName":          inviteData.EncryptedName,
		"nameNonce":              inviteData.NameNonce,
		"canUpload":              inviteData.CanUpload,
		"canDelete":              inviteData.CanDelete,
		"uploadQuotaBytes":       inviteData.UploadQuotaBytes,
	})
}

// GET /api/fed-proxy/incoming  — list all incoming shares
// @Summary      List incoming federated shares
// @Tags         Federation Proxy
// @Produce      json
// @Security     BearerAuth
// @Success      200  {array}   IncomingShare
// @Failure      401  {object}  ErrorResponse
// @Router       /fed-proxy/incoming [get]
func (h *FedProxyHandler) ListIncomingShares(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	rows, err := h.DB.Query(context.Background(), `
		SELECT id, remote_server, encrypted_collection_key, encrypted_name, name_nonce,
		       can_upload, can_delete, upload_quota_bytes, created_at
		FROM federated_incoming_shares WHERE user_id = $1 ORDER BY created_at ASC
	`, userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	defer rows.Close()

	var shares []IncomingShare
	for rows.Next() {
		var s IncomingShare
		if err := rows.Scan(&s.ID, &s.RemoteServer, &s.EncryptedCollectionKey,
			&s.EncryptedName, &s.NameNonce, &s.CanUpload, &s.CanDelete,
			&s.UploadQuotaBytes, &s.CreatedAt); err != nil {
			continue
		}
		shares = append(shares, s)
	}
	if shares == nil {
		shares = []IncomingShare{}
	}
	return c.JSON(shares)
}

// DELETE /api/fed-proxy/incoming/{shareId}  — remove incoming share
// @Summary      Remove an incoming federated share
// @Tags         Federation Proxy
// @Security     BearerAuth
// @Param        shareId  path  string  true  "Share UUID"
// @Success      204
// @Failure      401  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Router       /fed-proxy/incoming/{shareId} [delete]
func (h *FedProxyHandler) RemoveIncomingShare(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	shareID := c.Params("shareId")
	result, err := h.DB.Exec(context.Background(),
		`DELETE FROM federated_incoming_shares WHERE id = $1 AND user_id = $2`,
		shareID, userID)
	if err != nil || result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	return c.SendStatus(204)
}

// GET /api/fed-proxy/{shareId}/files  — proxy list files
// @Summary      List files in a federated share (proxied)
// @Tags         Federation Proxy
// @Produce      json
// @Security     BearerAuth
// @Param        shareId  path      string  true  "Incoming share UUID"
// @Success      200      {array}   FileRow
// @Failure      401      {object}  ErrorResponse
// @Failure      404      {object}  ErrorResponse
// @Failure      502      {object}  ErrorResponse
// @Router       /fed-proxy/{shareId}/files [get]
func (h *FedProxyHandler) ProxyListFiles(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	shareID := c.Params("shareId")
	remoteServer, remoteToken, err := h.getShare(context.Background(), shareID, userID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "share not found"})
	}
	url := fmt.Sprintf("%s/api/fed/shares/%s/files", remoteServer, remoteToken)
	resp, err := fedHTTPClient.Get(url) //nolint:gosec — remoteServer validated at insert time
	if err != nil {
		return c.Status(502).JSON(fiber.Map{"error": "remote error"})
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	c.Set("Content-Type", "application/json")
	return c.Status(resp.StatusCode).Send(body)
}

// GET /api/fed-proxy/{shareId}/files/{fileId}/download  — proxy download
// @Summary      Download a file from a federated share (proxied)
// @Tags         Federation Proxy
// @Produce      octet-stream
// @Security     BearerAuth
// @Param        shareId  path  string  true  "Incoming share UUID"
// @Param        fileId   path  string  true  "File UUID"
// @Success      200
// @Failure      401  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Failure      502  {object}  ErrorResponse
// @Router       /fed-proxy/{shareId}/files/{fileId}/download [get]
func (h *FedProxyHandler) ProxyDownload(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	shareID := c.Params("shareId")
	fileID := c.Params("fileId")
	remoteServer, remoteToken, err := h.getShare(context.Background(), shareID, userID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "share not found"})
	}
	url := fmt.Sprintf("%s/api/fed/shares/%s/files/%s/download", remoteServer, remoteToken, fileID)
	resp, err := fedHTTPClient.Get(url) //nolint:gosec — remoteServer validated at insert time
	if err != nil || resp.StatusCode != 200 {
		return c.Status(502).JSON(fiber.Map{"error": "remote error"})
	}
	// Do NOT defer resp.Body.Close() — fasthttp reads stream lazily
	c.Set("Content-Type", "application/octet-stream")
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		c.Set("Content-Length", cl)
	}
	return c.SendStream(resp.Body, -1)
}

// POST /api/fed-proxy/{shareId}/upload  — proxy upload
// @Summary      Upload a file to a federated share (proxied)
// @Tags         Federation Proxy
// @Accept       mpfd
// @Produce      json
// @Security     BearerAuth
// @Param        shareId            path      string  true  "Incoming share UUID"
// @Param        encryptedMetadata  formData  string  true  "Encrypted metadata (base64)"
// @Param        metadataNonce      formData  string  true  "Metadata nonce (base64)"
// @Param        encryptedFileKey   formData  string  true  "Encrypted file key (base64)"
// @Param        fileKeyNonce       formData  string  true  "File key nonce (base64)"
// @Param        file               formData  file    true  "Encrypted file content"
// @Success      201  {object}  MessageResponse
// @Failure      401  {object}  ErrorResponse
// @Failure      403  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Failure      502  {object}  ErrorResponse
// @Router       /fed-proxy/{shareId}/upload [post]
func (h *FedProxyHandler) ProxyUpload(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	shareID := c.Params("shareId")
	remoteServer, remoteToken, err := h.getShare(context.Background(), shareID, userID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "share not found"})
	}
	url := fmt.Sprintf("%s/api/fed/shares/%s/files", remoteServer, remoteToken)

	// Forward the raw multipart body
	body := c.Body()
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	req.Header.Set("Content-Type", c.Get("Content-Type"))
	resp, err := fedHTTPClient.Do(req)
	if err != nil {
		return c.Status(502).JSON(fiber.Map{"error": "remote error"})
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	c.Set("Content-Type", "application/json")
	return c.Status(resp.StatusCode).Send(respBody)
}

// DELETE /api/fed-proxy/{shareId}/files/{fileId}  — proxy delete
// @Summary      Delete a file in a federated share (proxied)
// @Tags         Federation Proxy
// @Security     BearerAuth
// @Param        shareId  path  string  true  "Incoming share UUID"
// @Param        fileId   path  string  true  "File UUID"
// @Success      204
// @Failure      401  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Failure      502  {object}  ErrorResponse
// @Router       /fed-proxy/{shareId}/files/{fileId} [delete]
func (h *FedProxyHandler) ProxyDelete(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	shareID := c.Params("shareId")
	fileID := c.Params("fileId")
	remoteServer, remoteToken, err := h.getShare(context.Background(), shareID, userID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "share not found"})
	}
	url := fmt.Sprintf("%s/api/fed/shares/%s/files/%s", remoteServer, remoteToken, fileID)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	resp, err := fedHTTPClient.Do(req)
	if err != nil {
		return c.Status(502).JSON(fiber.Map{"error": "remote error"})
	}
	defer resp.Body.Close()
	return c.SendStatus(resp.StatusCode)
}

func (h *FedProxyHandler) getShare(ctx context.Context, shareID, userID string) (remoteServer, remoteToken string, err error) {
	err = h.DB.QueryRow(ctx,
		`SELECT remote_server, remote_access_token FROM federated_incoming_shares WHERE id = $1 AND user_id = $2`,
		shareID, userID,
	).Scan(&remoteServer, &remoteToken)
	return
}
