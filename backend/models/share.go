package models

import "time"

type CollectionShare struct {
	ID                     string    `json:"id"`
	CollectionID           string    `json:"collectionId"`
	SharerUserID           string    `json:"sharerUserId"`
	RecipientUserID        string    `json:"recipientUserId"`
	EncryptedCollectionKey string    `json:"encryptedCollectionKey"`
	CanWrite               bool      `json:"canWrite"`
	CreatedAt              time.Time `json:"createdAt"`
}

type PublicShare struct {
	ID                          string     `json:"id"`
	ShareType                   string     `json:"shareType"`
	TargetID                    string     `json:"targetId"`
	Token                       string     `json:"token"`
	EncryptedCollectionKey      *string    `json:"encryptedCollectionKey,omitempty"`
	EncryptedCollectionKeyNonce *string    `json:"encryptedCollectionKeyNonce,omitempty"`
	ExpiresAt                   *time.Time `json:"expiresAt,omitempty"`
	CreatedAt                   time.Time  `json:"createdAt"`
}
