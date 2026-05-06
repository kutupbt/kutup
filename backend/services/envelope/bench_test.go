package envelope

import (
	"crypto/ed25519"
	"testing"
)

// Microbenchmarks for the wire envelope. Run with:
//   go test -bench=. -benchmem ./services/envelope/
//
// These set a perf floor for every collab frame the relay handles. A
// regression > 2× on Pack/Unpack/Sign/Verify is worth investigating.

func benchFrame(payloadSize int) Frame {
	body := make([]byte, payloadSize)
	for i := range body {
		body[i] = byte(i)
	}
	var nonce [24]byte
	var sig [64]byte
	return Frame{
		Version:        1,
		Kind:           KindYjsUpdate,
		DocKeyID:       42,
		SenderDeviceID: 1234,
		Sequence:       1,
		Nonce:          nonce,
		Ciphertext:     body,
		Signature:      sig,
	}
}

func BenchmarkPack_64B(b *testing.B) {
	f := benchFrame(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Pack(f)
	}
}

func BenchmarkPack_4KB(b *testing.B) {
	f := benchFrame(4 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Pack(f)
	}
}

func BenchmarkPack_64KB(b *testing.B) {
	f := benchFrame(64 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Pack(f)
	}
}

func BenchmarkUnpack_4KB(b *testing.B) {
	bytes := Pack(benchFrame(4 * 1024))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Unpack(bytes)
	}
}

func BenchmarkSign_4KB(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_ = pub
	bytes := Pack(benchFrame(4 * 1024))
	body := bytes[:len(bytes)-64]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ed25519.Sign(priv, body)
	}
}

func BenchmarkVerify_4KB(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	bytes := Pack(benchFrame(4 * 1024))
	body := bytes[:len(bytes)-64]
	sig := ed25519.Sign(priv, body)
	copy(bytes[len(bytes)-64:], sig)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Verify(bytes, pub)
	}
}
