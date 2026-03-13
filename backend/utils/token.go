package utils

import (
	"crypto/rand"
	"encoding/base64"
)

// RandomToken generates a cryptographically random URL-safe token.
func RandomToken(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
