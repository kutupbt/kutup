// backend/handlers/devices_test.go
package handlers_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// Sanity check: stdlib gives 32-byte Ed25519 pubkeys. The handler stores those
// in user_devices.public_signing (BYTEA NOT NULL).
func TestDevicePubkeySize(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != 32 {
		t.Fatalf("want 32, got %d", len(pub))
	}
}
