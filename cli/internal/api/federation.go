package api

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// IncomingShare mirrors backend/handlers/fedproxy.go:IncomingShare.
//
// EncryptedCollectionKey is a sealed-box: the inviting server's user
// encrypted the collection key under our public key. The CLI unwraps it
// with crypto.OpenAnonymous(privateKey, publicKey) to recover the
// shared-collection symmetric key, then decrypts encryptedName with that.
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

// ListIncomingShares returns the federated shares this user has accepted.
func (c *Client) ListIncomingShares() ([]IncomingShare, error) {
	resp, err := c.get("/fed-proxy/incoming")
	if err != nil {
		return nil, err
	}
	var out []IncomingShare
	return out, decodeJSON(resp, &out)
}

// AddIncomingShareRequest body for POST /fed-proxy/incoming.
type AddIncomingShareRequest struct {
	InviteURL string `json:"inviteUrl"`
}

// AddIncomingShare accepts a federated invite URL of the form
// `https://server-b.example/invite/{token}`. The local server proxies
// the invite-token resolution to the remote.
func (c *Client) AddIncomingShare(inviteURL string) (*IncomingShare, error) {
	resp, err := c.postJSON("/fed-proxy/incoming", AddIncomingShareRequest{InviteURL: inviteURL})
	if err != nil {
		return nil, err
	}
	var r IncomingShare
	return &r, decodeJSON(resp, &r)
}

// RemoveIncomingShare deletes the local pointer to a federated share.
// Doesn't notify the remote server (federation today is one-way: the
// owner controls revocation).
func (c *Client) RemoveIncomingShare(shareID string) error {
	resp, err := c.deleteReq("/fed-proxy/incoming/" + shareID)
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

// ProxyListFiles lists files inside a federated share. Returns the same
// FileRow shape as the local /collections/:id/files endpoint — keys are
// wrapped with the federated-share collection key (not the local user's
// master key).
func (c *Client) ProxyListFiles(shareID string) ([]File, error) {
	resp, err := c.get("/fed-proxy/" + shareID + "/files")
	if err != nil {
		return nil, err
	}
	var out []File
	return out, decodeJSON(resp, &out)
}

// ProxyDownload fetches the encrypted file bytes for a file inside a
// federated share. Same encryption-at-rest format as /files/:id/download.
func (c *Client) ProxyDownload(shareID, fileID string) ([]byte, error) {
	resp, err := c.get("/fed-proxy/" + shareID + "/files/" + fileID + "/download")
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

// ProxyDeleteFile removes a file from a federated share. Requires
// can_delete on the share.
func (c *Client) ProxyDeleteFile(shareID, fileID string) error {
	url := c.base + "/api/fed-proxy/" + shareID + "/files/" + fileID
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
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
