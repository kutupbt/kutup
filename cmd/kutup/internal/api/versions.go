package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"time"
)

// VersionRow mirrors backend/handlers/file_versions.go:versionRow.
type VersionRow struct {
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

// ListVersions returns the file_versions rows for fileID, newest-first
// (server side ordering). Used by:
//   - download / sync to fetch the latest authoritative content (the main
//     /files/:id/download endpoint returns only the cold-start initial)
//   - the `kutup versions list` command.
func (c *Client) ListVersions(fileID string) ([]VersionRow, error) {
	resp, err := c.get("/files/" + fileID + "/versions")
	if err != nil {
		return nil, err
	}
	var out []VersionRow
	return out, decodeJSON(resp, &out)
}

// DownloadVersion fetches the encrypted bytes for a specific snapshot
// version. The bytes use the same XChaCha20-Poly1305 stream format as the
// main /files/:id/download endpoint, so callers can reuse crypto.DecryptStream.
func (c *Client) DownloadVersion(fileID, versionID string) ([]byte, error) {
	resp, err := c.get("/files/" + fileID + "/versions/" + versionID + "/download")
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

// DownloadVersionStream is the streaming counterpart to DownloadVersion,
// matching DownloadFileStream's contract. Used by LatestEncryptedStream
// for the version-first download path in `kutup download`.
func (c *Client) DownloadVersionStream(fileID, versionID string) (io.ReadCloser, error) {
	req, err := http.NewRequest(http.MethodGet,
		c.base+"/api/files/"+fileID+"/versions/"+versionID+"/download", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.doUpload(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return resp.Body, nil
}

// LatestEncryptedStream mirrors LatestEncryptedBytes but returns an
// io.ReadCloser the caller can pipe through a streaming decryptor.
// Same version-snapshot-preferred fallback logic. Bool tells the
// caller whether they got a version snapshot (vs the main blob).
func (c *Client) LatestEncryptedStream(fileID string) (io.ReadCloser, bool, error) {
	versions, err := c.ListVersions(fileID)
	if err == nil && len(versions) > 0 {
		rc, dlErr := c.DownloadVersionStream(fileID, versions[0].ID)
		if dlErr == nil {
			return rc, true, nil
		}
	}
	rc, err := c.DownloadFileStream(fileID)
	return rc, false, err
}

// SnapshotBlobResponse is what POST /files/:fid/snapshot-blob returns.
type SnapshotBlobResponse struct {
	StoragePath string `json:"storagePath"`
	S3VersionID string `json:"s3VersionId"`
}

// UploadSnapshotBlob multipart-POSTs encryptedContent to the snapshot-blob
// endpoint. Companion to RecordSnapshot — a snapshot is two requests:
// upload + record.
func (c *Client) UploadSnapshotBlob(fileID string, encryptedContent []byte) (*SnapshotBlobResponse, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="file"; filename="snapshot"`)
	h.Set("Content-Type", "application/octet-stream")
	part, err := w.CreatePart(h)
	if err != nil {
		return nil, err
	}
	if _, err := part.Write(encryptedContent); err != nil {
		return nil, err
	}
	w.Close()

	req, err := http.NewRequest(http.MethodPost, c.base+"/api/files/"+fileID+"/snapshot-blob", &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var r SnapshotBlobResponse
	return &r, decodeJSON(resp, &r)
}

// RecordSnapshotRequest mirrors backend/handlers/file_versions.go:recordSnapshotRequest.
type RecordSnapshotRequest struct {
	S3VersionID   string `json:"s3VersionId"`
	StoragePath   string `json:"storagePath"`
	SeqAtSnapshot int64  `json:"seqAtSnapshot"`
	DocKeyID      int64  `json:"docKeyId"`
	SizeBytes     int64  `json:"sizeBytes"`
	Label         string `json:"label,omitempty"`
	KeepForever   bool   `json:"keepForever,omitempty"`
}

// RecordSnapshotResponse is the {id: ...} returned on 201.
type RecordSnapshotResponse struct {
	ID string `json:"id"`
}

// RecordSnapshot inserts a file_versions row + truncates the update log.
// The backend gates on quota and may return 413; surface the error so the
// caller can show the right message.
func (c *Client) RecordSnapshot(fileID string, body RecordSnapshotRequest) (*RecordSnapshotResponse, error) {
	resp, err := c.postJSON("/files/"+fileID+"/versions", body)
	if err != nil {
		return nil, err
	}
	var r RecordSnapshotResponse
	return &r, decodeJSON(resp, &r)
}

// PatchVersionRequest is the body for PATCH /files/:fid/versions/:vid.
// Pointer fields preserve "absent" semantics — only the supplied fields
// are touched server-side.
type PatchVersionRequest struct {
	Label       *string `json:"label,omitempty"`
	KeepForever *bool   `json:"keepForever,omitempty"`
}

// LatestEncryptedBytes returns the encrypted bytes for fileID, preferring
// the newest /versions snapshot and falling back to the main
// /files/:id/download blob if no versions exist or the version download
// fails. Second return is true iff the snapshot path won.
//
// Required for any collab-edited file (notes / office / whiteboard) —
// /files/:id/download alone returns only the cold-start initial state.
// Mirrors frontend/src/pages/FileEditorPage.tsx:170-188.
func (c *Client) LatestEncryptedBytes(fileID string) ([]byte, bool, error) {
	versions, err := c.ListVersions(fileID)
	if err == nil && len(versions) > 0 {
		// versionRow query orders by created_at DESC server-side
		// (file_versions.go:List), so versions[0] is newest.
		bytes, dlErr := c.DownloadVersion(fileID, versions[0].ID)
		if dlErr == nil {
			return bytes, true, nil
		}
		// Fall through on download error — main blob is the safe fallback.
	}
	bytes, err := c.DownloadFile(fileID)
	return bytes, false, err
}

// PatchVersion updates a version's label and/or keep_forever flag.
func (c *Client) PatchVersion(fileID, versionID string, patch PatchVersionRequest) (*VersionRow, error) {
	data, err := json.Marshal(patch)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPatch, c.base+"/api/files/"+fileID+"/versions/"+versionID, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var r VersionRow
	return &r, decodeJSON(resp, &r)
}
