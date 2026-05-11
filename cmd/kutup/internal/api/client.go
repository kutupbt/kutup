// HTTP client for the Kutup API. Handles token refresh transparently.
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"time"
)

// Client wraps two http.Clients: a 60 s-total-timeout one for short JSON
// calls (login, ls, mv, etc.) and a per-phase-timeout one for tus PATCH
// streaming where a 60 s total deadline would trip on slow uplinks or
// final-chunk server-side finalisation work.
//
// Per Cloudflare's "complete guide to net/http timeouts," Client.Timeout
// is a *total* deadline covering connect + body upload + response, so
// it's the wrong knob for arbitrarily-long upload bodies. The upload
// client uses a Transport with per-phase limits + no overall deadline;
// context cancellation + TCP keepalive bound stalled streams.
type Client struct {
	base             string
	token            string
	httpClient       *http.Client
	uploadClient     *http.Client
	OnTokenRefreshed func(newToken string)
}

func New(baseURL, token string) *Client {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 5 * time.Minute, // final-chunk includes DB work
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   8,
	}
	return &Client{
		base:         baseURL,
		token:        token,
		httpClient:   &http.Client{Timeout: 60 * time.Second},
		uploadClient: &http.Client{Transport: transport}, // no overall Timeout
	}
}

func (c *Client) SetToken(token string) { c.token = token }

func (c *Client) do(req *http.Request) (*http.Response, error) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return c.httpClient.Do(req)
}

// doUpload is do() that routes through the per-phase-timeout upload
// client. Use for tus PATCH and any other arbitrarily-long body streams.
func (c *Client) doUpload(req *http.Request) (*http.Response, error) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return c.uploadClient.Do(req)
}

func (c *Client) get(path string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, c.base+"/api"+path, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

func (c *Client) postJSON(path string, body any) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, c.base+"/api"+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

func (c *Client) deleteReq(path string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodDelete, c.base+"/api"+path, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

func (c *Client) putJSON(path string, body any) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPut, c.base+"/api"+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

func decodeJSON(resp *http.Response, out any) error {
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// --- Auth ---

type PreflightResponse struct {
	KdfSalt      string `json:"kdfSalt"`
	LoginKeySalt string `json:"loginKeySalt"`
}

func (c *Client) LoginPreflight(email string) (*PreflightResponse, error) {
	resp, err := c.get("/auth/login/preflight?email=" + email)
	if err != nil {
		return nil, err
	}
	var r PreflightResponse
	return &r, decodeJSON(resp, &r)
}

type LoginRequest struct {
	Email    string `json:"email"`
	LoginKey string `json:"loginKey"` // base64
}

type LoginResponse struct {
	AccessToken         string `json:"accessToken"`
	RefreshToken        string `json:"refreshToken"`
	UserID              string `json:"userId"`
	Username            string `json:"username"`
	IsAdmin             bool   `json:"isAdmin"`
	StorageQuotaBytes   int64  `json:"storageQuotaBytes"`
	StorageUsedBytes    int64  `json:"storageUsedBytes"`
	EncryptedMasterKey  string `json:"encryptedMasterKey"`
	MasterKeyNonce      string `json:"masterKeyNonce"`
	EncryptedPrivateKey string `json:"encryptedPrivateKey"`
	PrivateKeyNonce     string `json:"privateKeyNonce"`
	PublicKey           string `json:"publicKey"`
	RequiresTotp        bool   `json:"requiresTotp"`
	PreAuthToken        string `json:"preAuthToken"`
	RequiresSetup       bool   `json:"requiresSetup"`
}

func (c *Client) Login(req LoginRequest) (*LoginResponse, error) {
	resp, err := c.postJSON("/auth/login", req)
	if err != nil {
		return nil, err
	}
	var r LoginResponse
	return &r, decodeJSON(resp, &r)
}

type TotpRequest struct {
	PreAuthToken string `json:"preAuthToken"`
	Code         string `json:"code"`
}

func (c *Client) LoginTOTP(req TotpRequest) (*LoginResponse, error) {
	resp, err := c.postJSON("/auth/login/2fa", req)
	if err != nil {
		return nil, err
	}
	var r LoginResponse
	return &r, decodeJSON(resp, &r)
}

type RefreshResponse struct {
	AccessToken string `json:"accessToken"`
}

func (c *Client) RefreshToken(refreshToken string) (*RefreshResponse, error) {
	resp, err := c.postJSON("/auth/refresh", map[string]string{"refreshToken": refreshToken})
	if err != nil {
		return nil, err
	}
	var r RefreshResponse
	return &r, decodeJSON(resp, &r)
}

// --- User ---

type UserMe struct {
	ID                string `json:"id"`
	Email             string `json:"email"`
	Username          string `json:"username"`
	IsAdmin           bool   `json:"isAdmin"`
	TotpEnabled       bool   `json:"totpEnabled"`
	StorageQuotaBytes int64  `json:"storageQuotaBytes"`
	StorageUsedBytes  int64  `json:"storageUsedBytes"`
}

func (c *Client) Me() (*UserMe, error) {
	resp, err := c.get("/user/me")
	if err != nil {
		return nil, err
	}
	var r UserMe
	return &r, decodeJSON(resp, &r)
}

// --- Collections ---

type Collection struct {
	ID                   string  `json:"id"`
	OwnerUserID          string  `json:"ownerUserId"`
	EncryptedName        string  `json:"encryptedName"`
	NameNonce            string  `json:"nameNonce"`
	EncryptedKey         string  `json:"encryptedKey"`
	EncryptedKeyNonce    string  `json:"encryptedKeyNonce"`
	ParentCollectionID   *string `json:"parentCollectionId"`
	Color                *string `json:"color"`
	IsShared             bool    `json:"isShared"`
	IsRemote             bool    `json:"isRemote"`
	CanUpload            bool    `json:"canUpload"`
	CanDelete            bool    `json:"canDelete"`
	UploadQuotaBytes     *int64  `json:"uploadQuotaBytes"`
	// Decrypted (populated client-side)
	Name string `json:"-"`
}

func (c *Client) ListCollections() ([]Collection, error) {
	resp, err := c.get("/collections/")
	if err != nil {
		return nil, err
	}
	var r []Collection
	return r, decodeJSON(resp, &r)
}

type CreateCollectionRequest struct {
	EncryptedName      string  `json:"encryptedName"`
	NameNonce          string  `json:"nameNonce"`
	EncryptedKey       string  `json:"encryptedKey"`
	EncryptedKeyNonce  string  `json:"encryptedKeyNonce"`
	ParentCollectionID *string `json:"parentCollectionId,omitempty"`
}

type CreateCollectionResponse struct {
	ID string `json:"id"`
}

func (c *Client) CreateCollection(req CreateCollectionRequest) (*CreateCollectionResponse, error) {
	resp, err := c.postJSON("/collections/", req)
	if err != nil {
		return nil, err
	}
	var r CreateCollectionResponse
	return &r, decodeJSON(resp, &r)
}

type RenameCollectionRequest struct {
	EncryptedName string `json:"encryptedName"`
	NameNonce     string `json:"nameNonce"`
}

func (c *Client) RenameCollection(id string, req RenameCollectionRequest) error {
	resp, err := c.putJSON("/collections/"+id, req)
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

func (c *Client) DeleteCollection(id string) error {
	resp, err := c.deleteReq("/collections/" + id)
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

// --- Files ---

type File struct {
	ID                  string `json:"id"`
	CollectionID        string `json:"collectionId"`
	EncryptedMetadata   string `json:"encryptedMetadata"`
	MetadataNonce       string `json:"metadataNonce"`
	EncryptedFileKey    string `json:"encryptedFileKey"`
	FileKeyNonce        string `json:"fileKeyNonce"`
	EncryptedSizeBytes  int64  `json:"encryptedSizeBytes"`
	CreatedAt           string `json:"createdAt"`
	// Decrypted (populated client-side)
	Name     string `json:"-"`
	MimeType string `json:"-"`
	Size     int64  `json:"-"`
}

type FileMetadata struct {
	Name     string `json:"name"`
	MimeType string `json:"mimeType"`
	Size     int64  `json:"size"`
}

func (c *Client) ListFiles(collectionID string) ([]File, error) {
	resp, err := c.get("/collections/" + collectionID + "/files")
	if err != nil {
		return nil, err
	}
	var r []File
	return r, decodeJSON(resp, &r)
}

type UploadResponse struct {
	ID string `json:"id"`
}

func (c *Client) UploadFile(
	collectionID string,
	encryptedMetadata, metadataNonce string,
	encryptedFileKey, fileKeyNonce string,
	encryptedContent []byte,
) (*UploadResponse, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	_ = w.WriteField("collectionId", collectionID)
	_ = w.WriteField("encryptedMetadata", encryptedMetadata)
	_ = w.WriteField("metadataNonce", metadataNonce)
	_ = w.WriteField("encryptedFileKey", encryptedFileKey)
	_ = w.WriteField("fileKeyNonce", fileKeyNonce)

	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="file"; filename="blob"`)
	h.Set("Content-Type", "application/octet-stream")
	part, err := w.CreatePart(h)
	if err != nil {
		return nil, err
	}
	if _, err = part.Write(encryptedContent); err != nil {
		return nil, err
	}
	w.Close()

	req, err := http.NewRequest(http.MethodPost, c.base+"/api/files/upload", &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var r UploadResponse
	return &r, decodeJSON(resp, &r)
}

func (c *Client) DownloadFile(fileID string) ([]byte, error) {
	resp, err := c.get("/files/" + fileID + "/download")
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

// DownloadFileStream is the streaming counterpart to DownloadFile —
// returns the raw HTTP response body for the caller to read in chunks.
// Used by `kutup download` to decrypt 5 MB + 17 B ciphertext frames
// one at a time and write plaintext straight to disk, keeping RAM
// flat regardless of file size.
//
// Routes through the per-phase-timeout uploadClient (no overall
// Client.Timeout) so multi-GB transfers aren't cut by the 60 s
// safety net the standard `do()` carries.
//
// Caller is responsible for closing the returned ReadCloser.
func (c *Client) DownloadFileStream(fileID string) (io.ReadCloser, error) {
	req, err := http.NewRequest(http.MethodGet, c.base+"/api/files/"+fileID+"/download", nil)
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

// UpdateFileMetadataRequest carries the new encrypted name for PUT /files/:id.
// Mirrors backend/handlers/files.go:UpdateMetadata's body.
type UpdateFileMetadataRequest struct {
	EncryptedMetadata string `json:"encryptedMetadata"`
	MetadataNonce     string `json:"metadataNonce"`
}

// UpdateFileMetadata replaces a file's encrypted metadata (name, etc).
// Used by `kutup mv`.
func (c *Client) UpdateFileMetadata(fileID string, req UpdateFileMetadataRequest) error {
	resp, err := c.putJSON("/files/"+fileID, req)
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

// UpdateCollectionColor patches just the color hex on a collection.
// Used by `kutup color`. Pass "" to clear.
func (c *Client) UpdateCollectionColor(collectionID, color string) error {
	body := map[string]any{"color": color}
	if color == "" {
		body["color"] = nil
	}
	req, err := http.NewRequest(http.MethodPatch, c.base+"/api/collections/"+collectionID+"/color", nil)
	if err != nil {
		return err
	}
	// Re-build body via the helper to set Content-Type — the existing
	// patchJSON pattern isn't a method, so inline.
	resp, err := c.patchJSONBody("/collections/"+collectionID+"/color", body)
	_ = req
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		errBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(errBody))
	}
	return nil
}

// patchJSONBody is a small helper to avoid duplicating the JSON marshal
// + Content-Type set in callers. Mirrors postJSON / putJSON.
func (c *Client) patchJSONBody(path string, body any) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPatch, c.base+"/api"+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

func (c *Client) DeleteFile(fileID string) error {
	resp, err := c.deleteReq("/files/" + fileID)
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

// --- Sharing ---

type ShareRequest struct {
	RecipientUserID      string `json:"recipientUserId"`
	EncryptedCollectionKey string `json:"encryptedCollectionKey"`
	CanUpload            bool   `json:"canUpload"`
	CanDelete            bool   `json:"canDelete"`
	UploadQuotaBytes     *int64 `json:"uploadQuotaBytes,omitempty"`
}

func (c *Client) ShareCollection(collectionID string, req ShareRequest) error {
	resp, err := c.postJSON("/collections/"+collectionID+"/share", req)
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

type FederatedShareRequest struct {
	RecipientUsername    string `json:"recipientUsername"`
	RecipientServer      string `json:"recipientServer"`
	EncryptedCollectionKey string `json:"encryptedCollectionKey"`
	CanUpload            bool   `json:"canUpload"`
	CanDelete            bool   `json:"canDelete"`
	UploadQuotaBytes     *int64 `json:"uploadQuotaBytes,omitempty"`
}

type FederatedShareResponse struct {
	InviteToken string `json:"inviteToken"`
	InviteURL   string `json:"inviteUrl"`
}

func (c *Client) ShareFederated(collectionID string, req FederatedShareRequest) (*FederatedShareResponse, error) {
	resp, err := c.postJSON("/collections/"+collectionID+"/share-federated", req)
	if err != nil {
		return nil, err
	}
	var r FederatedShareResponse
	return &r, decodeJSON(resp, &r)
}

type PublicShareRequest struct {
	ShareType                  string  `json:"shareType"`
	TargetID                   string  `json:"targetId"`
	EncryptedCollectionKey     string  `json:"encryptedCollectionKey"`
	EncryptedCollectionKeyNonce string `json:"encryptedCollectionKeyNonce"`
	ExpiresInHours             *int    `json:"expiresInHours,omitempty"`
}

type PublicShareResponse struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

func (c *Client) CreatePublicShare(req PublicShareRequest) (*PublicShareResponse, error) {
	resp, err := c.postJSON("/share/", req)
	if err != nil {
		return nil, err
	}
	var r PublicShareResponse
	return &r, decodeJSON(resp, &r)
}

type UserByEmail struct {
	UserID    string `json:"userId"`
	PublicKey string `json:"publicKey"`
}

func (c *Client) GetUserByEmail(email string) (*UserByEmail, error) {
	resp, err := c.get("/users/by-email/" + email)
	if err != nil {
		return nil, err
	}
	var r UserByEmail
	return &r, decodeJSON(resp, &r)
}

type FedPubKeyResponse struct {
	PublicKey string `json:"publicKey"`
}

func (c *Client) GetFedPubKey(username, server string) (*FedPubKeyResponse, error) {
	resp, err := c.get("/collections/fed-pubkey?username=" + username + "&server=" + server)
	if err != nil {
		return nil, err
	}
	var r FedPubKeyResponse
	return &r, decodeJSON(resp, &r)
}
