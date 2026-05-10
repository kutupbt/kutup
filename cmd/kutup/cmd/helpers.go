// Shared decryption helpers used across multiple commands.
package cmd

import (
	"encoding/base64"
	"encoding/json"

	"github.com/kutupbulut/kutup/cmd/kutup/internal/api"
	"github.com/kutupbulut/kutup/cmd/kutup/internal/crypto"
	"github.com/kutupbulut/kutup/cmd/kutup/internal/session"
)

func decryptCollections(cols []api.Collection, masterKey []byte, sess *session.Session) []api.Collection {
	result := make([]api.Collection, 0, len(cols))
	for _, col := range cols {
		col.Name = decryptCollectionName(&col, masterKey, sess)
		result = append(result, col)
	}
	return result
}

func decryptCollectionName(col *api.Collection, masterKey []byte, sess *session.Session) string {
	collectionKey, err := decryptCollectionKey(col, masterKey, sess)
	if err != nil {
		return "[encrypted]"
	}
	name, err := crypto.SecretBoxOpenB64(col.EncryptedName, col.NameNonce, collectionKey)
	if err != nil {
		return "[encrypted]"
	}
	return string(name)
}

func decryptCollectionKey(col *api.Collection, masterKey []byte, sess *session.Session) ([]byte, error) {
	if col.IsShared {
		privateKey, err := base64.StdEncoding.DecodeString(sess.PrivateKey)
		if err != nil {
			return nil, err
		}
		publicKey, err := base64.StdEncoding.DecodeString(sess.PublicKey)
		if err != nil {
			return nil, err
		}
		encKey, err := base64.StdEncoding.DecodeString(col.EncryptedKey)
		if err != nil {
			return nil, err
		}
		return crypto.OpenAnonymous(encKey, publicKey, privateKey)
	}
	return crypto.SecretBoxOpenB64(col.EncryptedKey, col.EncryptedKeyNonce, masterKey)
}

func decryptFileMeta(f *api.File, collectionKey []byte) (name string, size int64) {
	fileKey, err := crypto.SecretBoxOpenB64(f.EncryptedFileKey, f.FileKeyNonce, collectionKey)
	if err != nil {
		return "[encrypted]", 0
	}
	metaBytes, err := crypto.SecretBoxOpenB64(f.EncryptedMetadata, f.MetadataNonce, fileKey)
	if err != nil {
		return "[encrypted]", 0
	}
	var meta api.FileMetadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return "[encrypted]", 0
	}
	return meta.Name, meta.Size
}

func findCollection(cols []api.Collection, id string) *api.Collection {
	for i := range cols {
		if cols[i].ID == id {
			return &cols[i]
		}
	}
	return nil
}
