package models

import "time"

type File struct {
	ID                 string    `json:"id"`
	CollectionID       string    `json:"collectionId"`
	UploaderUserID     string    `json:"uploaderUserId"`
	EncryptedMetadata  string    `json:"encryptedMetadata"`
	MetadataNonce      string    `json:"metadataNonce"`
	EncryptedFileKey   string    `json:"encryptedFileKey"`
	FileKeyNonce       string    `json:"fileKeyNonce"`
	StoragePath        string    `json:"-"`
	EncryptedSizeBytes int64     `json:"encryptedSizeBytes"`
	CreatedAt          time.Time `json:"createdAt"`
	UpdatedAt          time.Time `json:"updatedAt"`
}
