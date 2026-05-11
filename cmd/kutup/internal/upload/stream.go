// Package upload — streaming-encrypt-then-PATCH helpers for the CLI's tus
// path. The existing uploadSingleFile (cmd/upload.go) reads the whole file
// into RAM via os.ReadFile and would OOM on multi-GB inputs; this package
// gives us bounded-memory operation by iterating ciphertext chunks one
// PATCH at a time.
//
// Wire framing exactly matches the frontend / server: a 24-byte
// secretstream header followed by 5 MB plaintext chunks each producing
// 5MB+17B ciphertext via crypto_secretstream_xchacha20poly1305. The
// final chunk carries TagFinal so the decryptor stops cleanly.
package upload

import (
	"errors"
	"io"
	"os"

	"github.com/kutupbulut/kutup/cmd/kutup/internal/crypto"
)

// PlaintextChunkSize is the per-chunk plaintext read amount. Must match
// the frontend (5 * 1024 * 1024). Each chunk's ciphertext = this + 17B.
const PlaintextChunkSize = 5 * 1024 * 1024

// CipherSize returns the total ciphertext byte count for a plaintext of
// `plainBytes` bytes, given the secretstream framing kutup uses (24-byte
// header + 17B overhead per chunk). Callers pass this as `Upload-Length`
// when opening a tus session so the server can soft-reserve quota.
//
// Edge case: an empty plaintext returns just the header (24). The
// streaming encoder mirrors this so HEAD/PATCH/upload-len all agree.
func CipherSize(plainBytes int64) int64 {
	if plainBytes <= 0 {
		return int64(crypto.StreamHeaderBytes)
	}
	numChunks := (plainBytes + PlaintextChunkSize - 1) / PlaintextChunkSize
	return int64(crypto.StreamHeaderBytes) +
		plainBytes +
		int64(crypto.XChaCha20Poly1305IetfABYTES)*numChunks
}

// StreamEncryptor iterates ciphertext chunks for a tus upload. Each
// NextChunk() call returns the bytes the caller should ship as the next
// PATCH body. The first chunk includes the 24-byte secretstream header
// prepended; subsequent chunks are pure ciphertext. After the final
// chunk (which carries TagFinal under the hood), NextChunk returns
// io.EOF.
type StreamEncryptor struct {
	enc        crypto.Encryptor
	header     []byte
	src        *os.File
	plainTotal int64
	plainRead  int64

	buf        []byte // reusable plaintext buffer, PlaintextChunkSize
	sentHeader bool
	done       bool
}

// NewStreamEncryptor takes an opened file + the per-file key. The file
// position is assumed to be 0 (the constructor does not seek). `plainTotal`
// is the file's plaintext size — usually `fileInfo.Size()`. The caller is
// responsible for closing the file.
func NewStreamEncryptor(src *os.File, key []byte, plainTotal int64) (*StreamEncryptor, error) {
	enc, header, err := crypto.NewEncryptor(key)
	if err != nil {
		return nil, err
	}
	return &StreamEncryptor{
		enc:        enc,
		header:     header,
		src:        src,
		plainTotal: plainTotal,
		buf:        make([]byte, PlaintextChunkSize),
	}, nil
}

// Header returns the secretstream header without consuming a chunk. Only
// useful for tests; production callers should just iterate NextChunk()
// and let it prepend the header to the first chunk it returns.
func (s *StreamEncryptor) Header() []byte { return s.header }

// PlainRead returns the number of plaintext bytes consumed from the
// underlying file so far. Useful for progress reporting in plaintext
// units rather than the noisier ciphertext-byte count.
func (s *StreamEncryptor) PlainRead() int64 { return s.plainRead }

// NextChunk returns the next ciphertext chunk to ship. Returns io.EOF
// once the stream is done.
func (s *StreamEncryptor) NextChunk() ([]byte, error) {
	if s.done {
		return nil, io.EOF
	}

	remaining := s.plainTotal - s.plainRead

	// Empty-file edge: emit just the header on the only call, then EOF.
	if remaining <= 0 {
		if !s.sentHeader {
			s.sentHeader = true
			s.done = true
			out := make([]byte, len(s.header))
			copy(out, s.header)
			return out, nil
		}
		s.done = true
		return nil, io.EOF
	}

	// Read up to PlaintextChunkSize bytes — may read fewer on the last
	// chunk if the file size isn't a clean multiple.
	toRead := int64(PlaintextChunkSize)
	if toRead > remaining {
		toRead = remaining
	}
	n, err := io.ReadFull(s.src, s.buf[:toRead])
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	s.plainRead += int64(n)

	isLast := s.plainRead == s.plainTotal
	tag := byte(crypto.TagMessage)
	if isLast {
		tag = crypto.TagFinal
	}
	cipher, err := s.enc.Push(s.buf[:n], tag)
	if err != nil {
		return nil, err
	}

	out := cipher
	if !s.sentHeader {
		// First chunk: prepend secretstream header.
		out = make([]byte, 0, len(s.header)+len(cipher))
		out = append(out, s.header...)
		out = append(out, cipher...)
		s.sentHeader = true
	}
	if isLast {
		s.done = true
	}
	return out, nil
}
