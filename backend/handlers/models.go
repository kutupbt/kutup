package handlers

import "time"

// ErrorResponse wraps API error messages.
type ErrorResponse struct {
	Error string `json:"error"`
}

// MessageResponse wraps simple success messages.
type MessageResponse struct {
	Message string `json:"message"`
}

// SettingsResponse is returned by GET /api/auth/settings and settings admin endpoints.
type SettingsResponse struct {
	RegistrationEnabled bool `json:"registrationEnabled"`
}

// PreflightLoginResponse is returned by GET /api/auth/login/preflight.
type PreflightLoginResponse struct {
	KDFSalt      string `json:"kdfSalt"`
	LoginKeySalt string `json:"loginKeySalt"`
}

// PreflightRecoverResponse is returned by GET /api/auth/recover/preflight.
type PreflightRecoverResponse struct {
	EncryptedRecoveryKey string `json:"encryptedRecoveryKey"`
	RecoveryKeyNonce     string `json:"recoveryKeyNonce"`
	EncryptedPrivateKey  string `json:"encryptedPrivateKey"`
	PrivateKeyNonce      string `json:"privateKeyNonce"`
}

// RefreshResponse is returned by POST /api/auth/refresh.
type RefreshResponse struct {
	AccessToken string `json:"accessToken"`
}

// MeResponse is returned by GET /api/user/me.
type MeResponse struct {
	ID                string `json:"id"`
	Email             string `json:"email"`
	Username          string `json:"username"`
	PublicKey         string `json:"publicKey"`
	TOTPEnabled       bool   `json:"totpEnabled"`
	StorageQuotaBytes int64  `json:"storageQuotaBytes"`
	StorageUsedBytes  int64  `json:"storageUsedBytes"`
	IsAdmin           bool   `json:"isAdmin"`
}

// TOTPSetupResponse is returned by POST /api/user/2fa/setup.
type TOTPSetupResponse struct {
	Secret string `json:"secret"`
	QRUri  string `json:"qrUri"`
}

// TOTPCodeRequest is the body for TOTP verify and disable endpoints.
type TOTPCodeRequest struct {
	Code string `json:"code"`
}

// UserLookupResponse is returned by GET /api/users/by-email/:email.
type UserLookupResponse struct {
	UserID    string `json:"userId"`
	PublicKey string `json:"publicKey"`
}

// CollectionRow is returned by collection list and get endpoints.
type CollectionRow struct {
	ID                 string  `json:"id"`
	OwnerUserID        string  `json:"ownerUserId"`
	EncryptedName      string  `json:"encryptedName"`
	NameNonce          string  `json:"nameNonce"`
	EncryptedKey       string  `json:"encryptedKey"`
	EncryptedKeyNonce  string  `json:"encryptedKeyNonce"`
	ParentCollectionID *string `json:"parentCollectionId,omitempty"`
	Color              *string `json:"color,omitempty"`
	CanUpload          *bool   `json:"canUpload,omitempty"`
	CanDelete          *bool   `json:"canDelete,omitempty"`
	UploadQuotaBytes   *int64  `json:"uploadQuotaBytes,omitempty"`
	UploadUsedBytes    *int64  `json:"uploadUsedBytes,omitempty"`
	IsShared           bool    `json:"isShared,omitempty"`
}

// CreateCollectionRequest is the request body for POST /api/collections.
type CreateCollectionRequest struct {
	EncryptedName      string  `json:"encryptedName"`
	NameNonce          string  `json:"nameNonce"`
	EncryptedKey       string  `json:"encryptedKey"`
	EncryptedKeyNonce  string  `json:"encryptedKeyNonce"`
	ParentCollectionID *string `json:"parentCollectionId"`
}

// CreateCollectionResult is returned by POST /api/collections.
type CreateCollectionResult struct {
	ID string `json:"id"`
}

// UpdateCollectionRequest is the request body for PUT /api/collections/{id}.
type UpdateCollectionRequest struct {
	EncryptedName string `json:"encryptedName"`
	NameNonce     string `json:"nameNonce"`
}

// UpdateColorRequest is the request body for PATCH /api/collections/{id}/color.
type UpdateColorRequest struct {
	Color *string `json:"color"`
}

// ShareCollectionRequest is the request body for POST /api/collections/{id}/share.
type ShareCollectionRequest struct {
	RecipientUserID        string `json:"recipientUserId"`
	EncryptedCollectionKey string `json:"encryptedCollectionKey"`
	CanUpload              bool   `json:"canUpload"`
	CanDelete              bool   `json:"canDelete"`
	UploadQuotaBytes       *int64 `json:"uploadQuotaBytes"`
}

// ShareFederatedRequest is the request body for POST /api/collections/{id}/share-federated.
type ShareFederatedRequest struct {
	RecipientUsername      string `json:"recipientUsername"`
	RecipientServer        string `json:"recipientServer"`
	EncryptedCollectionKey string `json:"encryptedCollectionKey"`
	CanUpload              bool   `json:"canUpload"`
	CanDelete              bool   `json:"canDelete"`
	UploadQuotaBytes       *int64 `json:"uploadQuotaBytes"`
}

// ShareFederatedResult is returned by POST /api/collections/{id}/share-federated.
type ShareFederatedResult struct {
	InviteToken string `json:"inviteToken"`
	InviteURL   string `json:"inviteUrl"`
}

// PubkeyResponse is returned by federation user lookup endpoints.
type PubkeyResponse struct {
	PublicKey string `json:"publicKey"`
}

// FileRow is returned by file listing endpoints.
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

// UploadResult is returned by file upload endpoints.
type UploadResult struct {
	ID string `json:"id"`
}

// CreateShareRequest is the request body for POST /api/share.
type CreateShareRequest struct {
	ShareType                   string `json:"shareType"`
	TargetID                    string `json:"targetId"`
	EncryptedCollectionKey      string `json:"encryptedCollectionKey"`
	EncryptedCollectionKeyNonce string `json:"encryptedCollectionKeyNonce"`
	ExpiresInHours              *int   `json:"expiresInHours"`
}

// CreateShareResult is returned by POST /api/share.
type CreateShareResult struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

// PublicShareResponse is returned by GET /api/share/{token}.
type PublicShareResponse struct {
	ID                          string     `json:"id"`
	ShareType                   string     `json:"shareType"`
	TargetID                    string     `json:"targetId"`
	EncryptedCollectionKey      *string    `json:"encryptedCollectionKey"`
	EncryptedCollectionKeyNonce *string    `json:"encryptedCollectionKeyNonce"`
	ExpiresAt                   *time.Time `json:"expiresAt"`
}

// DownloadURLResponse is returned by public share file download.
type DownloadURLResponse struct {
	URL string `json:"url"`
}

// FedInviteResponse is returned by GET /api/fed/invites/{token}.
type FedInviteResponse struct {
	WrappedKey       string `json:"wrappedKey"`
	EncryptedName    string `json:"encryptedName"`
	NameNonce        string `json:"nameNonce"`
	CanUpload        bool   `json:"canUpload"`
	CanDelete        bool   `json:"canDelete"`
	UploadQuotaBytes *int64 `json:"uploadQuotaBytes"`
}

// AddIncomingShareRequest is the request body for POST /api/fed-proxy/incoming.
type AddIncomingShareRequest struct {
	InviteURL string `json:"inviteUrl"`
}

// UserRow is returned by admin user list and create endpoints.
type UserRow struct {
	ID                string    `json:"id"`
	Email             string    `json:"email"`
	Username          string    `json:"username"`
	StorageQuotaBytes int64     `json:"storageQuotaBytes"`
	StorageUsedBytes  int64     `json:"storageUsedBytes"`
	IsAdmin           bool      `json:"isAdmin"`
	IsActive          bool      `json:"isActive"`
	TOTPEnabled       bool      `json:"totpEnabled"`
	CreatedAt         time.Time `json:"createdAt"`
}

// CreateAdminUserRequest is the request body for POST /api/admin/users.
type CreateAdminUserRequest struct {
	Email             string `json:"email"`
	Username          string `json:"username"`
	TempPassword      string `json:"tempPassword"`
	StorageQuotaBytes int64  `json:"storageQuotaBytes"`
}

// UpdateAdminUserRequest is the request body for PUT /api/admin/users/{id}.
type UpdateAdminUserRequest struct {
	StorageQuotaBytes *int64 `json:"storageQuotaBytes"`
	IsActive          *bool  `json:"isActive"`
	IsAdmin           *bool  `json:"isAdmin"`
}

// UpdateAdminSettingsRequest is the request body for PUT /api/admin/settings.
type UpdateAdminSettingsRequest struct {
	RegistrationEnabled bool `json:"registrationEnabled"`
}

// StatsResponse is returned by GET /api/admin/stats.
type StatsResponse struct {
	TotalUsers       int64 `json:"totalUsers"`
	ActiveUsers      int64 `json:"activeUsers"`
	TotalFiles       int64 `json:"totalFiles"`
	TotalStorageUsed int64 `json:"totalStorageUsedBytes"`
	TotalCollections int64 `json:"totalCollections"`
}
