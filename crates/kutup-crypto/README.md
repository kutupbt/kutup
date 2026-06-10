# kutup-crypto

Shared end-to-end-encryption primitives for kutup, in Rust. This crate is the
**Rust mirror** of [`frontend/src/crypto/`](../../frontend/src/crypto) (the
canonical libsodium-wrappers implementation) and the successor to the Go
packages [`cmd/kutup/internal/crypto/`](../../cmd/kutup/internal/crypto) and
[`backend/services/envelope/`](../../backend/services/envelope).

All three implementations **must stay byte-for-byte compatible on the wire.**

## Primitives

| Module | Construction | Backing crate | Used for |
|---|---|---|---|
| `kdf` | Argon2id (opslimit 3, memlimit 64 MiB, parallelism 1, 32-byte out) + HKDF-SHA256 | `dryoc`, `hkdf`+`sha2` | KEK / login key; per-file content key |
| `secretbox` | XSalsa20-Poly1305 | `dryoc` | master/private/collection/file keys, metadata |
| `sealedbox` | X25519 anonymous sealed box | `dryoc` | wrapping collection keys when sharing |
| `stream` | XChaCha20-Poly1305 secretstream, 5 MiB chunks | `dryoc` | file content |
| `asset` | XChaCha20-Poly1305-IETF AEAD | `chacha20poly1305` | whiteboard asset blobs |
| `envelope` | wire framing + Ed25519 signatures | `ed25519-dalek` | collab-edit frames |

## Verifying parity

Parity with the Go reference is enforced by cross-language vectors generated
from the **real Go packages** (true differential testing):

```sh
# Regenerate vectors after any crypto change:
go -C cmd/kutup run ./tools/genvectors > crates/kutup-crypto/tests/vectors/crypto.json
go -C backend   run ./tools/genvectors > crates/kutup-crypto/tests/vectors/envelope.json

# Check the Rust port reproduces / accepts them byte-for-byte:
cargo test -p kutup-crypto
```

The vectors pin Go-produced ciphertext (so the Rust decrypt direction is
verified) and, where the primitive is deterministic (KDF, HKDF, secretbox with a
fixed nonce, Ed25519 signing), also pin exact output so the Rust **encrypt**
direction is verified too.

## Notes / intentional deviations

- **Argon2id parallelism = 1.** libsodium's `crypto_pwhash` hard-codes one lane;
  the "4 threads" comment in `kdf.ts` is inaccurate (the Go code correctly uses
  `threads = 1`). `dryoc` matches libsodium, so all three agree — locked by the
  KDF vectors.
- **`envelope::verify` uses `verify_strict`**, rejecting non-canonical /
  small-order signatures. This is a security hardening over Go's
  `ed25519.Verify`; honest, canonical frames verify identically under both.
- The committed secretstream vectors are single-chunk (< 5 MiB) to keep the repo
  light; multi-chunk framing is covered by a Rust round-trip test
  (`stream_multichunk_roundtrip`).
