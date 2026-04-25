package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/nacl/secretbox"
)

var errSecretBoxOpen = errors.New("secretbox: decryption failed")

// SecretBoxSeal encrypts plaintext with key using XSalsa20-Poly1305.
// Returns ciphertext and a random 24-byte nonce.
// Compatible with libsodium crypto_secretbox_easy.
func SecretBoxSeal(plaintext, key []byte) (ciphertext, nonce []byte, err error) {
	var k [32]byte
	var n [24]byte
	if len(key) != 32 {
		return nil, nil, errors.New("secretbox: key must be 32 bytes")
	}
	copy(k[:], key)
	if _, err = rand.Read(n[:]); err != nil {
		return nil, nil, err
	}
	out := secretbox.Seal(nil, plaintext, &n, &k)
	return out, n[:], nil
}

// SecretBoxOpen decrypts ciphertext using XSalsa20-Poly1305.
// Compatible with libsodium crypto_secretbox_open_easy.
func SecretBoxOpen(ciphertext, nonce, key []byte) ([]byte, error) {
	if len(nonce) != 24 || len(key) != 32 {
		return nil, errSecretBoxOpen
	}
	var k [32]byte
	var n [24]byte
	copy(k[:], key)
	copy(n[:], nonce)
	plain, ok := secretbox.Open(nil, ciphertext, &n, &k)
	if !ok {
		return nil, errSecretBoxOpen
	}
	return plain, nil
}

// SecretBoxOpenB64 is a convenience wrapper that accepts base64-encoded inputs.
func SecretBoxOpenB64(ciphertextB64, nonceB64 string, key []byte) ([]byte, error) {
	ct, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, err
	}
	n, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, err
	}
	return SecretBoxOpen(ct, n, key)
}
