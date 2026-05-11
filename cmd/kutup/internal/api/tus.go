// tus.io 1.0 protocol client.
//
// Companion to backend/handlers/tus.go. The desktop / mobile Tauri shells
// (eventually) and the CLI both speak this protocol to stream-upload big
// files without buffering in RAM. Resumability comes from the server-side
// Upload-Offset bookkeeping; this client just shuttles bytes.
package api

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const tusVersion = "1.0.0"

// TusCreate opens a new tus session. `totalBytes` is the ciphertext byte
// count (the upload package's `CipherSize(plainBytes)` knows how to derive
// it). The five encrypted-metadata strings are the same base64 values the
// multipart /files/upload endpoint expects — we re-base64 them per tus
// spec so they round-trip cleanly through the Upload-Metadata header.
//
// Returns the upload ID extracted from the Location header.
func (c *Client) TusCreate(
	totalBytes int64,
	collectionID string,
	encryptedMetadata, metadataNonce string,
	encryptedFileKey, fileKeyNonce string,
) (string, error) {
	enc := base64.StdEncoding
	uploadMeta := strings.Join([]string{
		"collectionId " + enc.EncodeToString([]byte(collectionID)),
		"encryptedMetadata " + enc.EncodeToString([]byte(encryptedMetadata)),
		"metadataNonce " + enc.EncodeToString([]byte(metadataNonce)),
		"encryptedFileKey " + enc.EncodeToString([]byte(encryptedFileKey)),
		"fileKeyNonce " + enc.EncodeToString([]byte(fileKeyNonce)),
	}, ",")

	req, err := http.NewRequest(http.MethodPost, c.base+"/api/uploads/", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Tus-Resumable", tusVersion)
	req.Header.Set("Upload-Length", strconv.FormatInt(totalBytes, 10))
	req.Header.Set("Upload-Metadata", uploadMeta)

	resp, err := c.do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("tus create: HTTP %d: %s", resp.StatusCode, string(body))
	}

	loc := resp.Header.Get("Location")
	// Server returns absolute path like /api/uploads/<uuid>; take the
	// last path segment.
	if idx := strings.LastIndex(loc, "/"); idx >= 0 {
		return loc[idx+1:], nil
	}
	return "", fmt.Errorf("tus create: missing/garbled Location header %q", loc)
}

// TusHead returns the server's current Upload-Offset (the high-water mark
// of received bytes) and the original Upload-Length. Used for resume on
// the next CLI run; not exercised yet by v1's upload-from-scratch flow.
func (c *Client) TusHead(uploadID string) (offset, length int64, err error) {
	req, err := http.NewRequest(http.MethodHead, c.base+"/api/uploads/"+uploadID, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("Tus-Resumable", tusVersion)
	resp, err := c.do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("tus head: HTTP %d", resp.StatusCode)
	}
	off, _ := strconv.ParseInt(resp.Header.Get("Upload-Offset"), 10, 64)
	ln, _ := strconv.ParseInt(resp.Header.Get("Upload-Length"), 10, 64)
	return off, ln, nil
}

// TusPatch ships one chunk. Returns the new offset reported by the server
// and the file ID (only set on the final chunk that triggers the
// finaliser; empty on intermediate chunks).
func (c *Client) TusPatch(uploadID string, offset int64, body []byte) (int64, string, error) {
	req, err := http.NewRequest(http.MethodPatch,
		c.base+"/api/uploads/"+uploadID,
		bytes.NewReader(body),
	)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Tus-Resumable", tusVersion)
	req.Header.Set("Upload-Offset", strconv.FormatInt(offset, 10))
	req.Header.Set("Content-Type", "application/offset+octet-stream")
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	// Each PATCH may be up to ~5 MB; bump beyond the client's default
	// 60 s so cold-storage SeaweedFS doesn't trip us on the first part.
	req.ContentLength = int64(len(body))

	resp, err := c.do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		return 0, "", fmt.Errorf("tus patch: HTTP %d: %s", resp.StatusCode, string(b))
	}
	newOff, _ := strconv.ParseInt(resp.Header.Get("Upload-Offset"), 10, 64)
	fileID := resp.Header.Get("X-Kutup-File-Id")
	return newOff, fileID, nil
}

// TusDelete cancels an in-flight upload. Best-effort — the server-side
// stale sweeper will reap abandoned sessions after 24h anyway.
func (c *Client) TusDelete(uploadID string) error {
	req, err := http.NewRequest(http.MethodDelete, c.base+"/api/uploads/"+uploadID, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Tus-Resumable", tusVersion)
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("tus delete: HTTP %d", resp.StatusCode)
	}
	return nil
}
