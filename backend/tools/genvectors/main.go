// Command genvectors emits collab-envelope test vectors as JSON, using the REAL
// backend/services/envelope package (and stdlib Ed25519) as the oracle. The Rust
// port in crates/kutup-crypto::envelope consumes these to prove parity of the
// wire format and signature.
//
// Run from the repo root:
//
//	go -C backend run ./tools/genvectors > ../crates/kutup-crypto/tests/vectors/envelope.json
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"

	"github.com/kutup/backend/services/envelope"
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

type envVec struct {
	Seed           string `json:"seed"` // base64 32-byte Ed25519 seed
	Pub            string `json:"pub"`  // base64 32-byte public key
	Version        uint8  `json:"version"`
	Kind           uint8  `json:"kind"`
	DocKeyID       uint32 `json:"docKeyId"`
	SenderDeviceID uint64 `json:"senderDeviceId"`
	Sequence       uint64 `json:"sequence"`
	Nonce          string `json:"nonce"`      // base64 24 bytes
	Ciphertext     string `json:"ciphertext"` // base64
	Packed         string `json:"packed"`     // base64 full signed wire bytes
}

func main() {
	// Deterministic keypair from a fixed seed so vectors are reproducible.
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	rng := rand.New(rand.NewSource(42))

	type tc struct {
		version, kind  uint8
		docKeyID       uint32
		senderDeviceID uint64
		sequence       uint64
		ctLen          int
	}
	var out []envVec
	for _, c := range []tc{
		{1, envelope.KindYjsUpdate, 1, 0x1122334455667788, 0, 0},
		{1, envelope.KindYjsUpdate, 7, 42, 99, 32},
		{1, envelope.KindExcalidrawOp, 0xDEADBEEF, 1, 0xFFFFFFFFFFFFFFFF, 257},
	} {
		var nonce [24]byte
		rng.Read(nonce[:])
		ct := make([]byte, c.ctLen)
		rng.Read(ct)

		f := envelope.Frame{
			Version:        c.version,
			Kind:           c.kind,
			DocKeyID:       c.docKeyID,
			SenderDeviceID: c.senderDeviceID,
			Sequence:       c.sequence,
			Nonce:          nonce,
			Ciphertext:     ct,
		}
		packed := envelope.Sign(f, priv)
		// sanity: verifies in Go
		if err := envelope.Verify(packed, pub); err != nil {
			fmt.Fprintln(os.Stderr, "genvectors: self-verify failed:", err)
			os.Exit(1)
		}
		out = append(out, envVec{
			Seed: b64(seed), Pub: b64(pub),
			Version: c.version, Kind: c.kind, DocKeyID: c.docKeyID,
			SenderDeviceID: c.senderDeviceID, Sequence: c.sequence,
			Nonce: b64(nonce[:]), Ciphertext: b64(ct), Packed: b64(packed),
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "genvectors:", err)
		os.Exit(1)
	}
}
