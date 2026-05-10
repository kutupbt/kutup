package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// Argon2id parameters — must match the frontend exactly (kdf.ts).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MB in KiB
	argonThreads = 1
	argonKeyLen  = 32
)

// DeriveKEK derives the Key Encryption Key from password + kdfSalt.
// Used to decrypt the master key returned by the server.
func DeriveKEK(password string, saltB64 string) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, fmt.Errorf("invalid kdfSalt: %w", err)
	}
	return argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen), nil
}

// DeriveLoginKey derives the login key from password + loginKeySalt.
// This is sent (base64-encoded) to the server for authentication.
// Uses a separate salt from KEK — two independent Argon2id derivations.
func DeriveLoginKey(password string, saltB64 string) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, fmt.Errorf("invalid loginKeySalt: %w", err)
	}
	return argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen), nil
}

// DeriveContentKey returns the per-file content key used for AEAD-encrypted
// child blobs (currently: whiteboard image asset blobs at
// files/{fileId}/assets/*). Mirrors frontend/src/collab/cryptoFrame.ts:61
// exactly:
//
//	HKDF-SHA256(ikm  = collectionMaster,
//	            salt = "kutup/file-content/v1",
//	            info = fileId-bytes)  → 32 bytes.
//
// The same key is used by the WS frame layer in the web; the CLI doesn't
// touch WS but reuses the derivation for asset blobs. Returns 32 bytes.
func DeriveContentKey(collectionMaster []byte, fileID string) ([]byte, error) {
	salt := []byte("kutup/file-content/v1")
	info := []byte(fileID)
	r := hkdf.New(sha256.New, collectionMaster, salt, info)
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("hkdf expand: %w", err)
	}
	return out, nil
}
