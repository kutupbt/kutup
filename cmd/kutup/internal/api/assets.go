package api

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
)

// UploadAsset PUTs an encrypted asset blob (whiteboard image binary) to
// /api/files/:fileID/assets/:assetID. The bytes must be already encrypted
// by crypto.EncryptAsset — server stores them opaque.
//
// Idempotent: re-PUTting the same (fileID, assetID) is a no-op for quota
// (server uses INSERT ON CONFLICT DO NOTHING). Caller can retry safely.
func (c *Client) UploadAsset(fileID, assetID string, ciphertext []byte) error {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="file"; filename="asset"`)
	h.Set("Content-Type", "application/octet-stream")
	part, err := w.CreatePart(h)
	if err != nil {
		return err
	}
	if _, err := part.Write(ciphertext); err != nil {
		return err
	}
	w.Close()

	req, err := http.NewRequest(http.MethodPut,
		c.base+"/api/files/"+fileID+"/assets/"+assetID, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// DownloadAsset fetches the encrypted asset blob. Caller must
// crypto.DecryptAsset to recover the plaintext (the dataURL string for
// whiteboard images).
func (c *Client) DownloadAsset(fileID, assetID string) ([]byte, error) {
	resp, err := c.get("/files/" + fileID + "/assets/" + assetID)
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
