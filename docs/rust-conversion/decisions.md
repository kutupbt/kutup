# Locked decisions & critical facts

## Library choices

| Area | Choice | Why |
|---|---|---|
| Crypto | **`dryoc`** (pure-Rust, libsodium-compatible) for pwhash / secretbox / box_seal / secretstream; **RustCrypto** (`hkdf`+`sha2`, `chacha20poly1305`, `ed25519-dalek`) for HKDF / IETF-AEAD / Ed25519 | In a crypto *port* the real risk is wire-format parity, not primitive strength. `dryoc` matches libsodium byte-for-byte in pure Rust (no C toolchain → static cross-compiles). |
| CLI HTTP | **`reqwest::blocking`** | Mirrors the Go client's synchronous control flow; no async coloring. |
| CLI store | **`redb`** (was BoltDB) + **`keyring`** (macOS/Windows only) | Pure-Rust embedded KV. The Linux keyring backend needs libdbus (C) → use the chmod-600 file fallback instead. |
| Server web | **Axum** + (later) **utoipa** | tokio/tower standard; utoipa replaces `swag` for OpenAPI. |
| Server DB | **`sqlx`** (postgres, rustls) | Async, compile-time-checked SQL; runs the existing migrations unchanged. |

## CRITICAL crypto facts (do not regress)

- **Argon2id parallelism = 1.** libsodium's `crypto_pwhash` hard-codes 1 lane. The
  "4 threads" comment in `frontend/src/crypto/kdf.ts` is **wrong**; the Go code uses
  `threads=1`; `dryoc` matches. Params: time/opslimit = 3, memory = 64 MiB (in **bytes**),
  keylen = 32. This is locked by a KDF vector — **never** change the param to "match" the
  comment.
- **secretstream**: XChaCha20-Poly1305, 5 MiB plaintext chunks, 24-byte header, 17-byte
  per-chunk overhead, `TAG_FINAL = 0x03`. Empty plaintext → header only, no final chunk
  (a quirk mirrored from the Go/TS reference).
- **secretbox** = XSalsa20-Poly1305 (keys, metadata). **sealed box** = X25519 anonymous
  (key sharing). **asset** = XChaCha20-Poly1305-IETF, AAD = `"kutup-asset/v1" || assetId`,
  key = `HKDF-SHA256(collectionMaster, salt "kutup/file-content/v1", info=fileId)`.
- **`envelope::verify` uses `verify_strict`** (ed25519-dalek) — rejects non-canonical /
  small-order signatures. Intentional hardening over Go's `ed25519.Verify`; honest,
  canonical frames verify identically under both.
- **The three crypto mirrors must stay in sync**: `frontend/src/crypto/` (canonical,
  libsodium-wrappers), `cmd/kutup/internal/crypto/` (Go), `crates/kutup-crypto/` (Rust).
  The CLI has **no** mnemonic (frontend-only). The collab envelope mirrors
  `backend/services/envelope/`.
