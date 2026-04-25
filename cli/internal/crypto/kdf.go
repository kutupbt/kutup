package crypto

import (
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/argon2"
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
