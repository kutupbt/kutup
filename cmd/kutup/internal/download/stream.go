// Package download — streaming decrypt for the CLI's `kutup download`
// path. Mirrors what frontend/src/download/streamDownload.ts does in
// the browser: read a 24-byte secretstream header + N × (5 MB + 17 B)
// ciphertext chunks off the wire, decrypt each with the existing pure-
// Go Decryptor, and write plaintext to an io.Writer (typically a
// *os.File at the user's destination path).
//
// Drops the previous `io.ReadAll` + `crypto.DecryptStream(buffer)`
// pattern that buffered both ciphertext and plaintext in RAM — peak
// ~3× file size — and replaces it with bounded-memory iteration:
// one 5 MB chunk in flight at a time, GC'd between iterations.

package download

import (
	"errors"
	"fmt"
	"io"

	"github.com/kutupbulut/kutup/cmd/kutup/internal/crypto"
)

// Constants must match crypto/stream.go's encryption framing.
const (
	plainChunk   = 5 * 1024 * 1024 // 5 MiB plaintext per chunk
	headerBytes  = crypto.StreamHeaderBytes
	chunkOverhead = crypto.XChaCha20Poly1305IetfABYTES
	cipherChunk  = plainChunk + chunkOverhead
)

// Stream reads the encrypted stream from `src`, decrypts each
// 5 MB + 17 B chunk in turn, and writes the plaintext to `dst`.
// Returns the total plaintext bytes written.
//
// The progress callback (if non-nil) fires after every successful
// decrypt with the running plaintext count.
//
// Memory profile: one plaintext + one ciphertext chunk in flight
// (~10 MB total), regardless of input size.
//
// Errors:
//   - missing/short header → "stream header truncated"
//   - mid-stream cut       → "stream cut before FINAL chunk"
//   - MAC failure          → wrapped from crypto.Pull
func Stream(src io.Reader, key []byte, dst io.Writer, onProgress func(plainBytes int64)) (int64, error) {
	// 1. Pull the 24-byte secretstream header off the front.
	header := make([]byte, headerBytes)
	if _, err := io.ReadFull(src, header); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, fmt.Errorf("stream header truncated: %w", err)
		}
		return 0, fmt.Errorf("read header: %w", err)
	}

	dec, err := crypto.NewDecryptor(key, header)
	if err != nil {
		return 0, fmt.Errorf("init decryptor: %w", err)
	}

	// 2. Loop pulling cipherChunk-sized frames until EOF.
	//    The last chunk may be shorter — io.ReadFull returns
	//    ErrUnexpectedEOF on a partial read, which is fine here.
	buf := make([]byte, cipherChunk)
	var plainWritten int64
	for {
		n, rerr := io.ReadFull(src, buf)
		if n == 0 {
			if rerr == nil || errors.Is(rerr, io.EOF) {
				// Clean EOF without a trailing partial chunk means the
				// last full chunk we pulled was already FINAL. Already
				// validated below; if we reach here the only legitimate
				// way is the empty-file case (header alone, no chunks).
				return plainWritten, nil
			}
			return plainWritten, fmt.Errorf("read chunk: %w", rerr)
		}
		if rerr != nil && !errors.Is(rerr, io.ErrUnexpectedEOF) && !errors.Is(rerr, io.EOF) {
			return plainWritten, fmt.Errorf("read chunk: %w", rerr)
		}

		plain, tag, derr := dec.Pull(buf[:n])
		if derr != nil {
			return plainWritten, fmt.Errorf("decrypt chunk: %w", derr)
		}
		if _, werr := dst.Write(plain); werr != nil {
			return plainWritten, fmt.Errorf("write plaintext: %w", werr)
		}
		plainWritten += int64(len(plain))
		if onProgress != nil {
			onProgress(plainWritten)
		}

		isFinal := tag == crypto.TagFinal
		// A read short of cipherChunk means we've hit EOF on the wire.
		// If the secretstream tag wasn't FINAL the upstream cut us off.
		atEOF := errors.Is(rerr, io.ErrUnexpectedEOF) || errors.Is(rerr, io.EOF)
		if isFinal && atEOF {
			return plainWritten, nil
		}
		if atEOF && !isFinal {
			return plainWritten, errors.New("stream cut before FINAL chunk")
		}
		if isFinal && !atEOF {
			// FINAL tag but more bytes pending on the wire — server is
			// misbehaving. Surface, don't silently truncate.
			return plainWritten, errors.New("FINAL chunk seen but bytes remain on wire")
		}
	}
}
