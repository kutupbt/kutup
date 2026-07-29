# Cryptographic dependency ownership

**Status:** normative for V1

Kutup uses one small primitive portfolio, but it does not use one universal
suite identifier or one key across features. Each protocol has a typed suite
registry, purpose-specific keys, and an independent migration boundary.

## Protocol libraries

| Dependency | V1 role | Dependency owns | Kutup owns |
|---|---|---|---|
| `libsignal-protocol` pinned to tag `v0.97.2` and its Cargo lock commit | Direct Chat, Note to Self, PQXDH, Triple Ratchet/SPQR, sealed-sender envelope and certificate primitives | Signal protocol state machines, wire parsing, ratchets and KEM negotiation | Account/device binding, storage transactions, federation, capabilities, abuse controls, padding policy and fail-closed UX |
| OpenMLS `0.8.1`, traits/basic-credential/memory-storage `0.5.0`, RustCrypto provider `0.5.1` | RFC 9420 private groups and the small broadcast administrator control group | MLS encoding, key schedule, TreeKEM, Commit/Welcome processing and epoch state | Manifest credential binding, authorization, multi-authority ordering, delivery, history, persistence and application policy |
| `hpke-rs` and `hpke-rs-rust-crypto` `0.6.1` | Named Drive share envelopes and anonymous MLS delivery | RFC 9180 context setup and KEM/KDF/AEAD operation | Suite selection, sender signature, account binding, `info`/AAD, limits and persistence |
| `dryoc` `0.7` | Argon2id-compatible password derivation and XChaCha secretstream-compatible Drive blobs | Primitive implementation | Parameters, typed formats, key hierarchy, chunk framing and failure policy |
| RustCrypto `chacha20poly1305` `0.10`, `ed25519-dalek` `2`, `hkdf` `0.12`, `sha2` `0.10` | Kutup-owned envelopes, signatures, hashing and derivation | Primitive implementation and strict key/signature parsing | Canonical encoding, domain separation, nonce generation, context binding and suite policy |
| `bip39` `2` | Human-readable encoding of 32 random recovery bytes | English word encoding and checksum | Entropy generation, key use and recovery UX |
| `bcrypt` `0.16` | Server-only verifier for the high-entropy login key | Password-hash implementation | Login rate limits, lockout, account-protection suite and client-side Argon2id |

The browser consumes the canonical `kutup-crypto` Rust implementation through
WASM. CLI and native clients call the same Rust code. A small browser
libsodium adapter is permitted only for a primitive that is reproducibly at
least ten times slower through Rust/WASM or cannot complete because of a
platform memory/runtime failure. Such an adapter never owns a header,
derivation label, parser, suite decision or persistent format.

Kutup does not fork or reimplement libsignal or OpenMLS. Their types do not
cross Kutup's public API boundary; Kutup-owned DTOs make dependency upgrades
explicit and testable.

## V1 primitive portfolio

- Password hardening: Argon2id, parallelism 1.
- Hash and derivation: SHA-256 and HKDF-SHA256.
- Public-key confidentiality: X25519, including RFC 9180 HPKE.
- Signatures: Ed25519.
- Kutup persistent AEAD: XChaCha20-Poly1305.
- Standards-constrained AEAD: ChaCha20-Poly1305 for HPKE and MLS suite
  `0x0003`.
- Large Drive blobs: `crypto_secretstream_xchacha20poly1305`, 5 MiB plaintext
  chunks and an authenticated final tag.

Algorithms used internally by libsignal are part of the pinned Direct Chat
suite and are not replaced for palette uniformity. Drive post-quantum wrapping
is a future suite: X-Wing remains an Internet-Draft and the available provider
path is experimental. V1 uses stable X25519 HPKE and reserves no implicit
downgrade.

## Updating a dependency

Every cryptographic dependency update requires:

1. an exact version/commit update and lockfile review;
2. upstream changelog, advisory and license review;
3. canonical-vector comparison and parser/fuzz runs;
4. full native, WASM, browser and two-server federation tests for affected
   suites;
5. a new suite code point if wire or persistent bytes change; and
6. documentation of create/read/migrate/reject policy after V1.

No provider failure may fall back to a different algorithm, exported HSM key,
unversioned format or less-protected suite.
