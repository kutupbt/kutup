// Command genvectors emits cross-language crypto test vectors as JSON, using
// the REAL cmd/kutup/internal/crypto package as the oracle. The Rust port in
// crates/kutup-crypto consumes these vectors to prove byte-for-byte parity.
//
// Run from the repo root:
//
//	go -C cmd/kutup run ./tools/genvectors > ../../crates/kutup-crypto/tests/vectors/crypto.json
//
// Vectors are deterministic where the primitive allows (KDF/HKDF/secretbox with
// a fixed nonce) and otherwise pin the Go-produced ciphertext so the Rust side
// can verify the decrypt direction (sealed box, secretstream, asset).
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/kutupbulut/kutup/cmd/kutup/internal/crypto"
	"golang.org/x/crypto/nacl/box"
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

type kdfVec struct {
	Password string `json:"password"`
	Salt     string `json:"salt"`     // base64 raw salt bytes
	Expected string `json:"expected"` // base64 32-byte key
}

type hkdfVec struct {
	Master   string `json:"master"`
	FileID   string `json:"fileId"`
	Expected string `json:"expected"`
}

type secretboxVec struct {
	Key        string `json:"key"`
	Nonce      string `json:"nonce"`
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
}

type sealedboxVec struct {
	RecipientPub  string `json:"recipientPub"`
	RecipientPriv string `json:"recipientPriv"`
	Plaintext     string `json:"plaintext"`
	Sealed        string `json:"sealed"`
}

type streamVec struct {
	Key        string `json:"key"`
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
}

type assetVec struct {
	Master    string `json:"master"`
	FileID    string `json:"fileId"`
	AssetID   string `json:"assetId"`
	Plaintext string `json:"plaintext"`
	Blob      string `json:"blob"`
}

type vectors struct {
	KDF       []kdfVec       `json:"kdf"`
	HKDF      []hkdfVec      `json:"hkdf"`
	Secretbox []secretboxVec `json:"secretbox"`
	Sealedbox []sealedboxVec `json:"sealedbox"`
	Stream    []streamVec    `json:"stream"`
	Asset     []assetVec     `json:"asset"`
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "genvectors:", err)
		os.Exit(1)
	}
}

func main() {
	var v vectors

	// --- KDF (Argon2id, deterministic) -------------------------------------
	for _, tc := range []struct {
		pw   string
		salt []byte
	}{
		{"correct horse battery staple", []byte("0123456789abcdef")},
		{"", []byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f")},
		{"ünïcödé🔐 pässwörd", []byte("salty-salt-16byt")},
	} {
		key, err := crypto.DeriveKEK(tc.pw, b64(tc.salt))
		must(err)
		v.KDF = append(v.KDF, kdfVec{Password: tc.pw, Salt: b64(tc.salt), Expected: b64(key)})
	}

	// --- HKDF content key (deterministic) ----------------------------------
	for _, tc := range []struct {
		master []byte
		fileID string
	}{
		{repeat(0xAA, 32), "11111111-1111-1111-1111-111111111111"},
		{repeat(0x00, 32), "file-id"},
		{repeat(0xFF, 32), ""},
	} {
		key, err := crypto.DeriveContentKey(tc.master, tc.fileID)
		must(err)
		v.HKDF = append(v.HKDF, hkdfVec{Master: b64(tc.master), FileID: tc.fileID, Expected: b64(key)})
	}

	// --- secretbox (fixed nonce → deterministic KAT) -----------------------
	// SecretBoxSeal picks a random nonce; we re-seal via the package and pin
	// (nonce, ciphertext) so the Rust side checks BOTH encrypt-with-nonce and
	// decrypt directions.
	for _, tc := range []struct {
		key   []byte
		plain []byte
	}{
		{repeat(0x01, 32), []byte("hello secretbox")},
		{repeat(0x42, 32), []byte("")},
		{repeat(0x99, 32), repeat(0x7e, 1000)},
	} {
		ct, nonce, err := crypto.SecretBoxSeal(tc.plain, tc.key)
		must(err)
		// sanity: round-trips in Go
		_, err = crypto.SecretBoxOpen(ct, nonce, tc.key)
		must(err)
		v.Secretbox = append(v.Secretbox, secretboxVec{
			Key: b64(tc.key), Nonce: b64(nonce), Plaintext: b64(tc.plain), Ciphertext: b64(ct),
		})
	}

	// --- sealed box (anonymous; pin Go ciphertext, verify decrypt) ---------
	for _, plain := range [][]byte{[]byte("collection-key-material"), []byte(""), repeat(0x5a, 64)} {
		pub, priv, err := box.GenerateKey(rand.Reader)
		must(err)
		sealed, err := crypto.SealAnonymous(plain, pub[:])
		must(err)
		_, err = crypto.OpenAnonymous(sealed, pub[:], priv[:])
		must(err)
		v.Sealedbox = append(v.Sealedbox, sealedboxVec{
			RecipientPub: b64(pub[:]), RecipientPriv: b64(priv[:]), Plaintext: b64(plain), Sealed: b64(sealed),
		})
	}

	// --- secretstream (pin Go ciphertext, verify decrypt) ------------------
	// Single-chunk sizes only (< 5 MiB) to keep the committed file small; the
	// multi-chunk framing is exercised by a Rust round-trip test.
	key := repeat(0x33, 32)
	for _, n := range []int{0, 1, 100, 70000} {
		plain := pattern(n)
		ct, err := crypto.EncryptStream(plain, key)
		must(err)
		v.Stream = append(v.Stream, streamVec{Key: b64(key), Plaintext: b64(plain), Ciphertext: b64(ct)})
	}

	// --- asset AEAD (pin Go blob, verify decrypt) --------------------------
	for _, tc := range []struct {
		master  []byte
		fileID  string
		assetID string
		plain   []byte
	}{
		{repeat(0xAA, 32), "11111111-1111-1111-1111-111111111111", "asset-abc", []byte("data:image/png;base64,iVBORw0KGgo=")},
		{repeat(0xBB, 32), "fid", "id-1", []byte("")},
	} {
		blob, err := crypto.EncryptAsset(tc.plain, tc.fileID, tc.assetID, tc.master)
		must(err)
		_, err = crypto.DecryptAsset(blob, tc.fileID, tc.assetID, tc.master)
		must(err)
		v.Asset = append(v.Asset, assetVec{
			Master: b64(tc.master), FileID: tc.fileID, AssetID: tc.assetID, Plaintext: b64(tc.plain), Blob: b64(blob),
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	must(enc.Encode(v))
}

func repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// pattern returns n deterministic, non-uniform bytes.
func pattern(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte((i*31 + 7) & 0xff)
	}
	return out
}
