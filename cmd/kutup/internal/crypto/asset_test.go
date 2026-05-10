package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptAsset_RoundTrip(t *testing.T) {
	master := bytes.Repeat([]byte{0xAA}, 32)
	fileID := "11111111-1111-1111-1111-111111111111"
	assetID := "asset-abc"
	plain := []byte("data:image/png;base64,iVBORw0KGgo=")

	blob, err := EncryptAsset(plain, fileID, assetID, master)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(blob) < 24+16 {
		t.Fatalf("blob too short: %d", len(blob))
	}

	got, err := DecryptAsset(blob, fileID, assetID, master)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("plaintext mismatch:\n want %q\n  got %q", plain, got)
	}
}

func TestDecryptAsset_TamperedAAD_AssetIDMismatch(t *testing.T) {
	master := bytes.Repeat([]byte{0xBB}, 32)
	fileID := "22222222-2222-2222-2222-222222222222"
	plain := []byte("payload")

	blob, err := EncryptAsset(plain, fileID, "id-1", master)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptAsset(blob, fileID, "id-2", master); err == nil {
		t.Error("decrypt with mismatched assetId should fail (AAD)")
	}
}

func TestDecryptAsset_TamperedAAD_FileIDMismatch(t *testing.T) {
	master := bytes.Repeat([]byte{0xCC}, 32)
	plain := []byte("payload")

	blob, err := EncryptAsset(plain, "fid-A", "asset-1", master)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptAsset(blob, "fid-B", "asset-1", master); err == nil {
		t.Error("decrypt with mismatched fileId should fail (HKDF info)")
	}
}

func TestDecryptAsset_TamperedCiphertext(t *testing.T) {
	master := bytes.Repeat([]byte{0xDD}, 32)
	plain := []byte("payload")

	blob, err := EncryptAsset(plain, "fid", "asset", master)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte deep in the ciphertext (skip nonce + tag).
	blob[len(blob)/2] ^= 0xff
	if _, err := DecryptAsset(blob, "fid", "asset", master); err == nil {
		t.Error("decrypt of tampered ciphertext should fail")
	}
}

func TestDecryptAsset_TooShort(t *testing.T) {
	if _, err := DecryptAsset([]byte{1, 2, 3}, "fid", "asset", make([]byte, 32)); err == nil {
		t.Error("decrypt of too-short blob should fail")
	}
}
