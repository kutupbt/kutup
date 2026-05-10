package api

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// PublicShare describes the metadata returned by GET /share/{token}.
//
// The endpoint is unauthenticated — anyone with the token gets the
// ciphertext. Decryption requires the URL fragment (#linkKey) which is
// never sent to the server. EncryptedCollectionKey is the collection
// master key wrapped under the linkKey.
type PublicShare struct {
	ID                          string     `json:"id"`
	ShareType                   string     `json:"shareType"` // "collection" | "file"
	TargetID                    string     `json:"targetId"`
	EncryptedCollectionKey      *string    `json:"encryptedCollectionKey"`
	EncryptedCollectionKeyNonce *string    `json:"encryptedCollectionKeyNonce"`
	ExpiresAt                   *time.Time `json:"expiresAt"`
}

// DownloadURLResponse is what /share/:token/download/:fid returns —
// a presigned (short-lived) S3 URL.
type DownloadURLResponse struct {
	URL string `json:"url"`
}

// GetPublicShare fetches the share metadata. The Client's bearer token
// is sent if set, but the backend handler doesn't require auth.
func (c *Client) GetPublicShare(token string) (*PublicShare, error) {
	resp, err := c.get("/share/" + token)
	if err != nil {
		return nil, err
	}
	var r PublicShare
	return &r, decodeJSON(resp, &r)
}

// ListPublicShareFiles returns the encrypted file rows for a collection-
// type public share. The shape matches the local /collections/:id/files
// endpoint; the URL fragment key wraps the inner file_keys.
func (c *Client) ListPublicShareFiles(token string) ([]File, error) {
	resp, err := c.get("/share/" + token + "/files")
	if err != nil {
		return nil, err
	}
	var out []File
	return out, decodeJSON(resp, &out)
}

// PublicShareDownloadURL returns the presigned URL for a file inside a
// public share. Caller fetches the URL directly (no auth header) to get
// the encrypted bytes, then DecryptStream with the per-file key.
func (c *Client) PublicShareDownloadURL(token, fileID string) (*DownloadURLResponse, error) {
	resp, err := c.get("/share/" + token + "/download/" + fileID)
	if err != nil {
		return nil, err
	}
	var r DownloadURLResponse
	return &r, decodeJSON(resp, &r)
}

// FetchPresignedURL pulls bytes from an absolute S3 presigned URL with no
// auth header — the URL itself carries the (short-lived) authorization.
// Used by both PublicShareDownloadURL consumers and any future presigned
// flows.
func FetchPresignedURL(presigned string) ([]byte, error) {
	resp, err := http.Get(presigned) //nolint:gosec — presigned, short-lived, server-issued
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return io.ReadAll(resp.Body)
}
