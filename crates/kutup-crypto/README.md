# kutup-crypto

Canonical end-to-end-encryption implementation for Kutup-owned account, Drive
and collaboration formats. Browser clients consume this crate through
`kutup-crypto-wasm`; the CLI and native clients call it directly. TypeScript
does not duplicate headers, parsers, KDF labels or AEAD constructions.

## Primitives

| Module | Construction | Backing crate | Used for |
|---|---|---|---|
| `kdf` | Argon2id + HKDF-SHA256 | `dryoc`, `hkdf`/`sha2` | account protection and purpose subkeys |
| `account_record` | `KUTPAR1`: per-record HKDF key and key commitment, XChaCha20-Poly1305 | primitives (`Kdf`, `Aead`) | every account-private record: password/recovery wraps, secrets under the master key, contact cards, mail names, identity pins |
| `identity` / `collection_epoch` | deterministic account keys and signed epoch chains | `ed25519-dalek`, `hkdf`/`sha2` | account authority and collection continuity |
| `account_roots` | random stored roots (account records under the master key) | primitives | the identity root, the Drive root (owned folder keys, link owner copies, the top-level name hash key), pseudonym and call-link roots, the object-id key |
| `drive_envelope` / `asset` | purpose-bound XChaCha20-Poly1305 | `chacha20poly1305` | Drive records, public links and whiteboard assets; the account's own folder and link keys under its Drive root (`seal_under_drive_root`) |
| `blocks` / `drive_blocks` / `chat_media_blocks` / `chat_backup_media_blocks` | 4 MiB XChaCha20-Poly1305 blocks bound to their index and revision, a sealed (Drive: signed) manifest of block hashes | primitives (`Kdf`, `Aead`, `mac`, `hash`), `ed25519-dalek` | Drive originals and versions, Chat attachments, Chat backup media |
| `named_share` | RFC 9180 X25519 HPKE + Ed25519 | `hpke-rs`, `ed25519-dalek` | authenticated local/federated collection shares |
| `envelope` | XChaCha20-Poly1305 + Ed25519 | RustCrypto, `ed25519-dalek` | canonical collaboration frames |
| `local_state` | profile-bound XChaCha20-Poly1305 | `chacha20poly1305` | CLI session cache |

## Verifying formats

Checked-in deterministic vectors pin every current Kutup-owned public format:

```sh
cargo test -p kutup-crypto
pnpm --dir frontend run build:crypto-wasm
node scripts/test-crypto-wasm.mjs
```

The Rust vector suite pins deterministic headers, KDF outputs, ciphertext and
signatures and tests strict negative cases. The WASM gate consumes the same
implementation rather than maintaining a second browser construction.

## Notes / intentional deviations

- **Argon2id parallelism = 1.** libsodium's `crypto_pwhash` hard-codes one lane;
  the "4 threads" comment in `kdf.ts` is inaccurate (the Go code correctly uses
  `threads = 1`). `dryoc` matches libsodium, so all three agree — locked by the
  KDF vectors.
- **`envelope::verify` uses `verify_strict`**, rejecting non-canonical /
  small-order signatures. This is a security hardening over Go's
  `ed25519.Verify`; honest, canonical frames verify identically under both.
- The committed block-format vectors (`blocks-v1.json`) are small objects to
  keep the repo light; multi-block objects are covered by the Rust round-trip
  and negative tests in `blocks.rs` and `drive_blocks.rs`.
