// Wire envelope for collaborative-edit frames.
// See docs/superpowers/specs/2026-05-04-collab-edit-design.md §5 for the canonical layout.
package envelope

import (
	"encoding/binary"
	"errors"
)

// Kind values.
const (
	KindYjsUpdate        uint8 = 1
	KindYjsAwareness     uint8 = 2 // not persisted
	KindSnapshotAnnounce uint8 = 3
	KindOOOp             uint8 = 4 // v2
	KindOOLock           uint8 = 5 // v2
	KindOOCheckpointMeta uint8 = 6 // v2
)

// HeaderSize is the fixed-size prefix used as AAD.
const HeaderSize = 30

// Frame is the in-memory representation of a CollabFrame.
type Frame struct {
	Version        uint8
	Kind           uint8
	DocKeyID       uint32
	SenderDeviceID uint64
	Sequence       uint64
	Nonce          [24]byte
	Ciphertext     []byte
	Signature      [64]byte
}

// Header returns the first 30 bytes as a slice — used as AAD.
func (f Frame) Header() []byte {
	out := make([]byte, HeaderSize)
	out[0] = f.Version
	out[1] = f.Kind
	binary.LittleEndian.PutUint32(out[2:6], f.DocKeyID)
	binary.LittleEndian.PutUint64(out[6:14], f.SenderDeviceID)
	binary.LittleEndian.PutUint64(out[14:22], f.Sequence)
	copy(out[22:30], f.Nonce[:8])
	return out
}

// Pack serializes a Frame into the wire format.
// Layout: header(30) || nonce_remaining(16) || ciphertext_len(4 LE) || ciphertext || signature(64)
//
// Note: the first 8 bytes of the nonce are also embedded in the AAD-able header at offset 22.
// We store the full 24-byte nonce in the body so the wire format keeps a clean 30-byte AAD header.
func Pack(f Frame) []byte {
	clen := uint32(len(f.Ciphertext))
	out := make([]byte, 0, HeaderSize+16+4+len(f.Ciphertext)+64)
	out = append(out, f.Header()...)
	out = append(out, f.Nonce[8:]...)
	cl := make([]byte, 4)
	binary.LittleEndian.PutUint32(cl, clen)
	out = append(out, cl...)
	out = append(out, f.Ciphertext...)
	out = append(out, f.Signature[:]...)
	return out
}

// Unpack parses bytes into a Frame.
func Unpack(bs []byte) (Frame, error) {
	const minLen = HeaderSize + 16 + 4 + 64
	if len(bs) < minLen {
		return Frame{}, errors.New("envelope: too short")
	}
	var f Frame
	f.Version = bs[0]
	f.Kind = bs[1]
	f.DocKeyID = binary.LittleEndian.Uint32(bs[2:6])
	f.SenderDeviceID = binary.LittleEndian.Uint64(bs[6:14])
	f.Sequence = binary.LittleEndian.Uint64(bs[14:22])
	copy(f.Nonce[:8], bs[22:30])
	copy(f.Nonce[8:], bs[30:46])

	clen := binary.LittleEndian.Uint32(bs[46:50])
	if uint64(len(bs)) != uint64(50)+uint64(clen)+64 {
		return Frame{}, errors.New("envelope: bad ciphertext length")
	}
	f.Ciphertext = make([]byte, clen)
	copy(f.Ciphertext, bs[50:50+clen])
	copy(f.Signature[:], bs[50+clen:50+clen+64])
	return f, nil
}

// SignatureBody returns the bytes that get signed: everything except the trailing signature.
func SignatureBody(bs []byte) []byte {
	if len(bs) < 64 {
		return nil
	}
	return bs[:len(bs)-64]
}
