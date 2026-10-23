# Cryptographic dependency ownership

**Status:** normative for V1

Kutup uses one small primitive portfolio, but it does not use one universal
suite identifier or one key across features. Each protocol has a typed suite
registry, purpose-specific keys, and an independent migration boundary.

## Protocol libraries

| Dependency | V1 role | Dependency owns | Kutup owns |
|---|---|---|---|
| `libsignal-protocol` pinned to tag `v0.97.2` and its Cargo lock commit | Direct Chat, Note to Self, PQXDH, Triple Ratchet/SPQR, sealed-sender envelope and certificate primitives | Signal protocol state machines, wire parsing, ratchets and KEM negotiation | Account/device binding, storage transactions, federation, capabilities, abuse controls, padding policy and fail-closed UX |
| `hpke-rs` and `hpke-rs-rust-crypto` `0.6.1` | Named Drive share envelopes | RFC 9180 context setup and KEM/KDF/AEAD operation | Suite selection, sender signature, account binding, `info`/AAD, limits and persistence |
| `x-wing` `0.1.1` and `ml-kem` `0.3.3` (through `hpke-rs-rust-crypto`'s post-quantum KEMs) | The groups' anonymous route (`oblivious`): the X-Wing HPKE KEM, 0x647a | X-Wing key derivation from its seed, encapsulation and decapsulation (draft-connolly-cfrg-xwing-kem-06) | The one suite and its refusal of every other KEM, RFC 9458 framing, labels, padding, key config signing and pinning |
| `dryoc` `0.7` | Argon2id-compatible password derivation and XChaCha secretstream-compatible Drive and Chat-media blobs | Primitive implementation | Parameters, typed formats, key hierarchy, chunk framing and failure policy |
| RustCrypto `chacha20poly1305` `0.10`, `ed25519-dalek` `2`, `hkdf` `0.12`, `sha2` `0.10` | Kutup-owned envelopes, signatures, hashing and derivation | Primitive implementation and strict key/signature parsing | Canonical encoding, domain separation, nonce generation, context binding and suite policy |
| rPGP (`pgp`) `=0.21.0`, no default features (no bzip2) | OpenPGP for mail: address keys, encryption to and from Kutup users and outside PGP users, signatures (docs/plans/mail-address-keys.md) | OpenPGP packet parsing and serialization, key generation, SEIPD encryption, signatures | Address-key shape (v4 Ed25519 + Curve25519, preferences), master-key envelope and its address/fingerprint binding, signed key lists under the account authority, key lookup and trust, limits and UX. Audited: Radically Open Security (2024-12, fixes in CVE-2024-53856/53857), ETH analysis via Delta Chat (2024-03), Open Tech Fund (2019). Its RSA dependency carries the known Marvin timing issue, which needs an RSA *private* key: Kutup generates only Curve25519 keys and uses RSA solely for public operations with outside keys. GnuPG 2.4 interoperability is tested in both directions |
| `opaque-ke` `=4.0.1`, no default features (`ristretto255` only) | OPAQUE sign-in (docs/plans/opaque.md) | RFC 9807 OPAQUE: OPRF (via `voprf`), envelope, 3DH key exchange over ristretto255 | Suite 1 (OPRF ristretto255-SHA512, 3DH with SHA-512, the context `kutup/opaque/v1`, default identities), the KSF (Argon2id at the account-protection V1 cost through dryoc, so not the crate's `argon2` feature), randomness (dryoc), the credential identifier (the key binding), the export key → master-key KEK derivation, the sealed server setup, limits and lockout. Maintained by Meta (facebook/opaque-ke); used by WhatsApp's end-to-end encrypted backups. Vectors: `opaque-v1.json`, replayed from seeded randomness in Rust and checked in WASM |
| RustCrypto `aes` `0.8.4` and `cbc` `0.1.2` (the versions libsignal already brings), with `dryoc`'s X25519, `hkdf` and `hmac` | Linking a Chat device: Signal's `ProvisioningCipher` (`provisioning`, docs/plans/account-identity-key.md) | AES-256-CBC with PKCS#7 padding | The construction (X25519, HKDF-SHA256 with 32 zero bytes of salt and Kutup's info `Kutup Provisioning Message v1`, encrypt-then-MAC with HMAC-SHA256 checked first in constant time, version byte), refusal of a low-order key, the libsignal key encoding. Vectors: `provisioning-v1.json`, written by an independent node:crypto implementation (`scripts/provisioning-vectors.mjs`), with a case under Signal's own info string |
| `bip39` `2` | Human-readable encoding of 32 random recovery bytes | English word encoding and checksum | Entropy generation, key use and recovery UX |
| `bcrypt` `0.16` | Server-only verifier for the high-entropy recovery proof and the Pass PIN (passwords are OPAQUE records, `opaque-ke`) | Password-hash implementation | Recovery rate limits; the PIN's three tries per sign-in |

The browser consumes the canonical `kutup-crypto` Rust implementation through
WASM. CLI and native clients call the same Rust code. A small browser
libsodium adapter is permitted only for a primitive that is reproducibly at
least ten times slower through Rust/WASM or cannot complete because of a
platform memory/runtime failure. Such an adapter never owns a header,
derivation label, parser, suite decision or persistent format.

Generated Chat and Crypto WASM glue and binaries are served from directories
named for their content hash (`/crypto-wasm/<hash>/`, `/chat-wasm/<hash>/`),
which the bundle names. A new build is a new URL, so a page can never pair an
old Rust ABI or transport DTO with a new bundle, and the files are cached as
immutable like every other content-hashed web asset. They are still deployed
with their matching frontend and backend.

Kutup does not fork or reimplement libsignal. Its types do not
cross Kutup's public API boundary; Kutup-owned DTOs make dependency upgrades
explicit and testable.

## V1 primitive portfolio

- Password hardening: Argon2id, parallelism 1.
- Hash and derivation: SHA-256 and HKDF-SHA256.
- Public-key confidentiality: X25519, including RFC 9180 HPKE.
- Signatures: Ed25519.
- Kutup persistent AEAD: XChaCha20-Poly1305.
- Standards-constrained AEAD: ChaCha20-Poly1305 for HPKE.
- Large Drive and Chat-media blobs: `crypto_secretstream_xchacha20poly1305`,
  5 MiB plaintext chunks and an authenticated final tag, with independent typed
  headers and keys.

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
