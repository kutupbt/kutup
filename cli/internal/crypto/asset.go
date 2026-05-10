package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// EncryptAsset / DecryptAsset implement the at-rest asset blob format
// shipped to /api/files/{fileId}/assets/{assetId}. Used by the CLI for
// whiteboard image binaries to round-trip with the web.
//
// Format:    nonce(24) || ciphertext-and-tag(16)
// Cipher:    XChaCha20-Poly1305-IETF
// Key:       HKDF-SHA256(collectionMaster, salt="kutup/file-content/v1",
//                        info=fileID)  — see DeriveContentKey
// AAD:       "kutup-asset/v1" || assetID
//
// Reference: frontend/src/api/whiteboardAssets.ts:uploadAsset / fetchAsset.

const aadPrefix = "kutup-asset/v1"

func buildAssetAAD(assetID string) []byte {
	return []byte(aadPrefix + assetID)
}

// EncryptAsset encrypts plaintext for the given (fileID, assetID) under
// the per-file content key derived from collectionMaster. Returns the
// at-rest blob (nonce || ciphertext+tag) ready to upload.
func EncryptAsset(plaintext []byte, fileID, assetID string, collectionMaster []byte) ([]byte, error) {
	key, err := DeriveContentKey(collectionMaster, fileID)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("aead init: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	ct := aead.Seal(nil, nonce, plaintext, buildAssetAAD(assetID))
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// DecryptAsset reverses EncryptAsset. Returns the plaintext bytes; errors
// on bad nonce/tag/AAD.
func DecryptAsset(blob []byte, fileID, assetID string, collectionMaster []byte) ([]byte, error) {
	if len(blob) < 24+chacha20poly1305.Overhead {
		return nil, fmt.Errorf("asset: ciphertext too short")
	}
	nonce := blob[:24]
	ct := blob[24:]
	key, err := DeriveContentKey(collectionMaster, fileID)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("aead init: %w", err)
	}
	pt, err := aead.Open(nil, nonce, ct, buildAssetAAD(assetID))
	if err != nil {
		return nil, fmt.Errorf("asset open: %w", err)
	}
	return pt, nil
}
