# kutup-crypto (Phase 1 ✅)

> **Status:** conversion phase complete. Current ownership and test policy are
> documented in [`../../../crates/kutup-crypto/README.md`](../../../crates/kutup-crypto/README.md)
> and [`../../cryptographic-dependencies.md`](../../cryptographic-dependencies.md).
> Go paths below are historical parity references.

The canonical shared E2EE implementation used through Rust, WASM and UniFFI.
It succeeds `cmd/kutup/internal/crypto/` + `backend/services/envelope/`. See also the
crate's own `crates/kutup-crypto/README.md`, and `../decisions.md` for the param /
wire-format facts that must never regress.

## Current V1 primitives

| Module | Construction | Backing crate |
|---|---|---|
| `kdf` | Argon2id (3 / 64 MiB / p=1 / 32 B) + HKDF-SHA256 | `dryoc`, `hkdf`+`sha2` |
| `account_envelope` / `drive_envelope` | typed XChaCha20-Poly1305 | `chacha20poly1305` |
| `named_share` | authenticated X25519 HPKE + Ed25519 | `hpke-rs`, `ed25519-dalek` |
| `stream` | XChaCha20-Poly1305 secretstream, 5 MiB chunks | `dryoc` |
| `asset` | purpose-bound XChaCha20-Poly1305 | `chacha20poly1305` |
| `envelope` | XChaCha20-Poly1305 collab-frame format + Ed25519 | RustCrypto |
| `local_state` | profile-bound XChaCha20-Poly1305 | `chacha20poly1305` |

## Module API surface

- `kdf::{derive_account_protection_keys, derive_account_protection_keys_b64, derive_recovery_auth_proof}`
- `account_envelope`, `drive_envelope`, `drive_object`, `named_share` and `collection_epoch`
- `stream::{StreamEncryptor, StreamDecryptor, encrypt_stream, decrypt_stream}` + consts
  (`CHUNK_SIZE`, `HEADER_BYTES`, `ABYTES`, `TAG_MESSAGE`, `TAG_FINAL`)
- `asset::{encrypt_asset, decrypt_asset}`
- `envelope::{seal, open, inspect, verify_signature}`
- `local_state::{seal, open}`

## Verify canonical vectors after any crypto change

```sh
cargo test -p kutup-crypto
pnpm --dir frontend run build:crypto-wasm
node scripts/test-crypto-wasm.mjs
```

Rust is the canonical implementation. Checked-in deterministic vectors pin its
public formats and the browser runs those operations through the generated WASM
module. The committed secretstream vectors are single-chunk to keep the repo
light; multi-chunk framing is covered by `stream_multichunk_roundtrip`.
