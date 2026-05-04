package envelope

import (
	"bytes"
	"testing"
)

func TestPackUnpackRoundTrip(t *testing.T) {
	in := Frame{
		Version:        1,
		Kind:           KindYjsUpdate,
		DocKeyID:       42,
		SenderDeviceID: 1234,
		Sequence:       1,
		Nonce:          [24]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24},
		Ciphertext:     []byte("hello world"),
		Signature:      [64]byte{},
	}
	for i := range in.Signature {
		in.Signature[i] = byte(i)
	}

	bs := Pack(in)
	out, err := Unpack(bs)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if out.Version != in.Version || out.Kind != in.Kind ||
		out.DocKeyID != in.DocKeyID || out.SenderDeviceID != in.SenderDeviceID ||
		out.Sequence != in.Sequence {
		t.Fatalf("header mismatch: got %+v want %+v", out, in)
	}
	if !bytes.Equal(out.Nonce[:], in.Nonce[:]) {
		t.Fatalf("nonce mismatch")
	}
	if !bytes.Equal(out.Ciphertext, in.Ciphertext) {
		t.Fatalf("ciphertext mismatch: got %x want %x", out.Ciphertext, in.Ciphertext)
	}
	if !bytes.Equal(out.Signature[:], in.Signature[:]) {
		t.Fatalf("signature mismatch")
	}
}

func TestUnpackTooShort(t *testing.T) {
	if _, err := Unpack([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestUnpackBadCiphertextLen(t *testing.T) {
	bs := Pack(Frame{Ciphertext: []byte("abc")})
	// ciphertext_len is at offset 46..50 (header=30, nonce_remaining=16).
	bs[46] = 0xff
	bs[47] = 0xff
	bs[48] = 0xff
	bs[49] = 0xff
	if _, err := Unpack(bs); err == nil {
		t.Fatal("expected error for bogus ciphertext length")
	}
}
