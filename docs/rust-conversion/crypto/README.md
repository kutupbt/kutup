# kutup-crypto (Phase 1 ✅)

The shared E2EE primitives crate — the Rust mirror of `frontend/src/crypto/` and the
successor to `cmd/kutup/internal/crypto/` + `backend/services/envelope/`. See also the
crate's own `crates/kutup-crypto/README.md`, and `../decisions.md` for the param /
wire-format facts that must never regress.

## Primitives

| Module | Construction | Backing crate |
|---|---|---|
| `kdf` | Argon2id (3 / 64 MiB / p=1 / 32 B) + HKDF-SHA256 | `dryoc`, `hkdf`+`sha2` |
| `secretbox` | XSalsa20-Poly1305 | `dryoc` |
| `sealedbox` | X25519 anonymous sealed box | `dryoc` |
| `stream` | XChaCha20-Poly1305 secretstream, 5 MiB chunks | `dryoc` |
| `asset` | XChaCha20-Poly1305-IETF AEAD | `chacha20poly1305` |
| `envelope` | collab-frame wire format + Ed25519 | `ed25519-dalek` |

## Module API surface

- `kdf::{derive_kek, derive_login_key, derive_content_key, derive_kek_b64, derive_login_key_b64}`
- `secretbox::{seal, seal_with_nonce, open, open_b64}`
- `sealedbox::{seal_anonymous, open_anonymous}`
- `stream::{StreamEncryptor, StreamDecryptor, encrypt_stream, decrypt_stream}` + consts
  (`CHUNK_SIZE`, `HEADER_BYTES`, `ABYTES`, `TAG_MESSAGE`, `TAG_FINAL`)
- `asset::{encrypt_asset, decrypt_asset}`
- `envelope::{Frame, sign, verify, kind::*}`

## Regenerate parity vectors after ANY crypto change

```sh
go -C cmd/kutup run ./tools/genvectors > crates/kutup-crypto/tests/vectors/crypto.json
go -C backend   run ./tools/genvectors > crates/kutup-crypto/tests/vectors/envelope.json
cargo test -p kutup-crypto
```

The generators (`cmd/kutup/tools/genvectors`, `backend/tools/genvectors`) use the **real
Go packages** as the oracle. Vectors pin Go-produced ciphertext (verifies the Rust
*decrypt* direction) and, where the primitive is deterministic (KDF, HKDF, secretbox with
a fixed nonce, Ed25519 signing), pin exact output too (verifies *encrypt*). The committed
secretstream vectors are single-chunk to keep the repo light; multi-chunk framing is
covered by a Rust round-trip test (`stream_multichunk_roundtrip`).
