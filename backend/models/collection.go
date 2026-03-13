package models

import "time"

type Collection struct {
	ID                   string    `json:"id"`
	OwnerUserID          string    `json:"ownerUserId"`
	EncryptedName        string    `json:"encryptedName"`
	NameNonce            string    `json:"nameNonce"`
	EncryptedKey         string    `json:"encryptedKey"`
	EncryptedKeyNonce    string    `json:"encryptedKeyNonce"`
	ParentCollectionID   *string   `json:"parentCollectionId,omitempty"`
	CreatedAt            time.Time `json:"createdAt"`
	UpdatedAt            time.Time `json:"updatedAt"`
}

// CollectionWithShare includes the share-specific encrypted key when the
// collection is accessed by a non-owner recipient.
type CollectionWithShare struct {
	Collection
	// When accessed via share, this replaces EncryptedKey
	SharedEncryptedKey *string `json:"sharedEncryptedKey,omitempty"`
	CanWrite           bool    `json:"canWrite"`
}
