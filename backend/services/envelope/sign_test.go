package envelope

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := Frame{Version: 1, Kind: KindYjsUpdate, Ciphertext: []byte("data")}
	bs := Sign(f, priv)
	if err := Verify(bs, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyTamperFails(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := Frame{Version: 1, Kind: KindYjsUpdate, Ciphertext: []byte("data")}
	bs := Sign(f, priv)
	bs[40] ^= 0xff // flip a byte inside the nonce/ciphertext region
	if err := Verify(bs, pub); err == nil {
		t.Fatal("expected verify to fail on tampered frame")
	}
}

func TestVerifyWrongKeyFails(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	bs := Sign(Frame{Version: 1, Kind: 1, Ciphertext: []byte("x")}, priv)
	if err := Verify(bs, otherPub); err == nil {
		t.Fatal("expected verify to fail with wrong key")
	}
}
