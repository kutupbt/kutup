// Pure-Go implementation of libsodium's crypto_secretstream_xchacha20poly1305.
// Adapted from github.com/ente-io/ente/cli/internal/crypto (MIT License).
// Chunk size adjusted to 5 MB to match Kutup's frontend.
package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
)

const (
	TagMessage = 0
	TagPush    = 0x01
	TagRekey   = 0x02
	TagFinal   = TagPush | TagRekey

	StreamKeyBytes    = chacha20poly1305.KeySize
	StreamHeaderBytes = chacha20poly1305.NonceSizeX
	// XChaCha20Poly1305IetfABYTES = 16-byte MAC + 1-byte tag
	XChaCha20Poly1305IetfABYTES = 17

	// 5 MB plaintext chunk, matching the frontend
	streamChunkSize = 5 * 1024 * 1024

	cryptoCoreHchacha20InputBytes                  = 16
	cryptoSecretStreamXchacha20poly1305Counterbytes = 4
)

var (
	pad0         [16]byte
	errInvalidKey   = errors.New("invalid key")
	errInvalidInput = errors.New("invalid input")
	errCryptoFail   = errors.New("authentication failed")
)

type streamState struct {
	k     [StreamKeyBytes]byte
	nonce [chacha20poly1305.NonceSize]byte
	pad   [8]byte
}

func (s *streamState) reset() {
	for i := range s.nonce {
		s.nonce[i] = 0
	}
	s.nonce[0] = 1
}

// Encryptor pushes plaintext chunks into the stream.
type Encryptor interface {
	Push(m []byte, tag byte) ([]byte, error)
}

// Decryptor pulls and authenticates ciphertext chunks from the stream.
type Decryptor interface {
	Pull(m []byte) ([]byte, byte, error)
}

type encryptor struct{ streamState }
type decryptor struct{ streamState }

func NewStreamKey() []byte {
	k := make([]byte, chacha20poly1305.KeySize)
	_, _ = rand.Read(k)
	return k
}

func NewEncryptor(key []byte) (Encryptor, []byte, error) {
	if len(key) != StreamKeyBytes {
		return nil, nil, errInvalidKey
	}
	header := make([]byte, StreamHeaderBytes)
	if _, err := rand.Read(header); err != nil {
		return nil, nil, err
	}
	stream := &encryptor{}
	k, err := chacha20.HChaCha20(key, header[:16])
	if err != nil {
		return nil, nil, err
	}
	copy(stream.k[:], k)
	stream.reset()
	for i, b := range header[cryptoCoreHchacha20InputBytes:] {
		stream.nonce[i+cryptoSecretStreamXchacha20poly1305Counterbytes] = b
	}
	return stream, header, nil
}

func (s *encryptor) Push(plain []byte, tag byte) ([]byte, error) {
	var block [64]byte
	var slen [8]byte
	mlen := len(plain)
	out := make([]byte, mlen+XChaCha20Poly1305IetfABYTES)

	chacha, err := chacha20.NewUnauthenticatedCipher(s.k[:], s.nonce[:])
	if err != nil {
		return nil, err
	}
	chacha.XORKeyStream(block[:], block[:])

	var polyInit [32]byte
	copy(polyInit[:], block[:])
	poly := poly1305.New(&polyInit)

	memZero(block[:])
	block[0] = tag
	chacha.XORKeyStream(block[:], block[:])
	_, _ = poly.Write(block[:])
	out[0] = block[0]

	c := out[1:]
	chacha.XORKeyStream(c, plain)
	_, _ = poly.Write(c[:mlen])
	padlen := (0x10 - len(block) + mlen) & 0xf
	_, _ = poly.Write(pad0[:padlen])

	binary.LittleEndian.PutUint64(slen[:], 0)
	_, _ = poly.Write(slen[:])
	binary.LittleEndian.PutUint64(slen[:], uint64(len(block)+mlen))
	_, _ = poly.Write(slen[:])

	mac := c[mlen:]
	copy(mac, poly.Sum(nil))

	xorBuf(s.nonce[cryptoSecretStreamXchacha20poly1305Counterbytes:], mac)
	bufInc(s.nonce[:cryptoSecretStreamXchacha20poly1305Counterbytes])
	return out, nil
}

func NewDecryptor(key, header []byte) (Decryptor, error) {
	stream := &decryptor{}
	k, err := chacha20.HChaCha20(key, header[:16])
	if err != nil {
		return nil, err
	}
	copy(stream.k[:], k)
	stream.reset()
	copy(stream.nonce[cryptoSecretStreamXchacha20poly1305Counterbytes:],
		header[cryptoCoreHchacha20InputBytes:])
	return stream, nil
}

func (s *decryptor) Pull(cipher []byte) ([]byte, byte, error) {
	cipherLen := len(cipher)
	if cipherLen < XChaCha20Poly1305IetfABYTES {
		return nil, 0, errInvalidInput
	}
	mlen := cipherLen - XChaCha20Poly1305IetfABYTES

	var block [64]byte
	var slen [8]byte
	var poly1305State [32]byte

	chacha, err := chacha20.NewUnauthenticatedCipher(s.k[:], s.nonce[:])
	if err != nil {
		return nil, 0, err
	}
	chacha.XORKeyStream(block[:], block[:])

	copy(poly1305State[:], block[:])
	poly := poly1305.New(&poly1305State)

	memZero(block[:])
	block[0] = cipher[0]
	chacha.XORKeyStream(block[:], block[:])
	tag := block[0]
	block[0] = cipher[0]
	if _, err = poly.Write(block[:]); err != nil {
		return nil, 0, err
	}

	c := cipher[1:]
	if _, err = poly.Write(c[:mlen]); err != nil {
		return nil, 0, err
	}
	padLen := (0x10 - len(block) + mlen) & 0xf
	if _, err = poly.Write(pad0[:padLen]); err != nil {
		return nil, 0, err
	}

	binary.LittleEndian.PutUint64(slen[:], 0)
	if _, err = poly.Write(slen[:]); err != nil {
		return nil, 0, err
	}
	binary.LittleEndian.PutUint64(slen[:], uint64(len(block)+mlen))
	if _, err = poly.Write(slen[:]); err != nil {
		return nil, 0, err
	}

	mac := poly.Sum(nil)
	memZero(poly1305State[:])

	storedMac := c[mlen:]
	if !bytes.Equal(mac, storedMac) {
		memZero(mac)
		return nil, 0, errCryptoFail
	}

	m := make([]byte, mlen)
	chacha.XORKeyStream(m, c[:mlen])

	xorBuf(s.nonce[cryptoSecretStreamXchacha20poly1305Counterbytes:], mac)
	bufInc(s.nonce[:cryptoSecretStreamXchacha20poly1305Counterbytes])
	return m, tag, nil
}

// EncryptStream encrypts plaintext using secretstream with 5 MB chunks.
// Output format: [24-byte header][encrypted chunks...] — matches the frontend.
func EncryptStream(plaintext, key []byte) ([]byte, error) {
	enc, header, err := NewEncryptor(key)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(header)+len(plaintext)+((len(plaintext)/streamChunkSize)+1)*XChaCha20Poly1305IetfABYTES)
	out = append(out, header...)

	offset := 0
	for offset < len(plaintext) {
		end := offset + streamChunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		isLast := end == len(plaintext)
		tag := byte(TagMessage)
		if isLast {
			tag = TagFinal
		}
		chunk, err := enc.Push(plaintext[offset:end], tag)
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		offset = end
	}
	return out, nil
}

// DecryptStream decrypts a secretstream blob produced by EncryptStream or the frontend.
func DecryptStream(ciphertext, key []byte) ([]byte, error) {
	if len(ciphertext) < StreamHeaderBytes {
		return nil, errInvalidInput
	}
	header := ciphertext[:StreamHeaderBytes]
	dec, err := NewDecryptor(key, header)
	if err != nil {
		return nil, err
	}

	encChunkSize := streamChunkSize + XChaCha20Poly1305IetfABYTES
	out := make([]byte, 0, len(ciphertext)-StreamHeaderBytes)
	offset := StreamHeaderBytes

	for offset < len(ciphertext) {
		end := offset + encChunkSize
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		plain, tag, err := dec.Pull(ciphertext[offset:end])
		if err != nil {
			return nil, err
		}
		out = append(out, plain...)
		if tag == TagFinal {
			break
		}
		offset = end
	}
	return out, nil
}
