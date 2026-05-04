package envelope

import (
	"crypto/ed25519"
	"errors"
)

// Sign computes the Ed25519 signature over the frame body (everything except
// the trailing 64 signature bytes) and returns the full packed wire bytes.
//
// Mutates f.Signature in place.
func Sign(f Frame, priv ed25519.PrivateKey) []byte {
	// Pack with empty signature first, take the body (everything but the last 64 bytes).
	packed := Pack(f)
	body := packed[:len(packed)-64]
	sig := ed25519.Sign(priv, body)
	copy(f.Signature[:], sig)
	return Pack(f)
}

// Verify checks the signature on already-packed bytes.
func Verify(bs []byte, pub ed25519.PublicKey) error {
	if len(bs) < 64 {
		return errors.New("envelope: too short to verify")
	}
	body := bs[:len(bs)-64]
	sig := bs[len(bs)-64:]
	if !ed25519.Verify(pub, body, sig) {
		return errors.New("envelope: bad signature")
	}
	return nil
}
