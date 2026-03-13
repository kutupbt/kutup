package models

import "time"

type User struct {
	ID                    string    `json:"id"`
	Email                 string    `json:"email"`
	EncryptedMasterKey    string    `json:"encryptedMasterKey"`
	MasterKeyNonce        string    `json:"masterKeyNonce"`
	EncryptedRecoveryKey  string    `json:"encryptedRecoveryKey"`
	RecoveryKeyNonce      string    `json:"recoveryKeyNonce"`
	EncryptedPrivateKey   string    `json:"encryptedPrivateKey"`
	PrivateKeyNonce       string    `json:"privateKeyNonce"`
	PublicKey             string    `json:"publicKey"`
	KDFSalt               string    `json:"kdfSalt"`
	LoginKeySalt          string    `json:"loginKeySalt"`
	LoginKeyHash          string    `json:"-"`
	TOTPSecret            *string   `json:"-"`
	TOTPEnabled           bool      `json:"totpEnabled"`
	StorageQuotaBytes     int64     `json:"storageQuotaBytes"`
	StorageUsedBytes      int64     `json:"storageUsedBytes"`
	IsAdmin               bool      `json:"isAdmin"`
	IsActive              bool      `json:"isActive"`
	CreatedAt             time.Time `json:"createdAt"`
	UpdatedAt             time.Time `json:"updatedAt"`
}

// KeyBundle is what clients receive after login (all encrypted, server cannot read)
type KeyBundle struct {
	EncryptedMasterKey   string `json:"encryptedMasterKey"`
	MasterKeyNonce       string `json:"masterKeyNonce"`
	EncryptedPrivateKey  string `json:"encryptedPrivateKey"`
	PrivateKeyNonce      string `json:"privateKeyNonce"`
	PublicKey            string `json:"publicKey"`
}
