package crypto

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/nacl/box"
)

var errBoxOpen = errors.New("box: decryption failed")

// BoxSealBytes is the overhead added by SealAnonymous: 32-byte ephemeral public key + 16-byte MAC.
const BoxSealBytes = 48

// SealAnonymous encrypts message for recipientPublicKey using an ephemeral keypair.
// Compatible with libsodium crypto_box_seal (anonymous sender).
func SealAnonymous(message, recipientPublicKey []byte) ([]byte, error) {
	if len(recipientPublicKey) != 32 {
		return nil, errors.New("box: recipient public key must be 32 bytes")
	}
	var pub [32]byte
	copy(pub[:], recipientPublicKey)
	out, err := box.SealAnonymous(nil, message, &pub, rand.Reader)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// OpenAnonymous decrypts a sealed box using the recipient's keypair.
// Compatible with libsodium crypto_box_seal_open.
func OpenAnonymous(sealed, recipientPublicKey, recipientPrivateKey []byte) ([]byte, error) {
	if len(sealed) < BoxSealBytes {
		return nil, errBoxOpen
	}
	var pub, priv [32]byte
	copy(pub[:], recipientPublicKey)
	copy(priv[:], recipientPrivateKey)
	plain, ok := box.OpenAnonymous(nil, sealed, &pub, &priv)
	if !ok {
		return nil, errBoxOpen
	}
	return plain, nil
}
