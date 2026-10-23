# One primitive layer: build note (W2)

**Status:** build note for review, 2026-10-23 (second session). Implements W2
of [`wipe-unification.md`](wipe-unification.md), whose open question 1 is
settled: one suite table of whole tuples, with each format allowlisting its
suites. Nothing is built yet.

## 1. The module

`kutup_crypto::primitives` becomes the only code that names an algorithm. It
exposes operations by suite, never algorithm types:

```rust
pub enum Suite { V1 }                 // one row of the table (§2); #[non_exhaustive]

// Hash and MAC
pub fn hash(suite: Suite, data: &[u8]) -> Digest;          // 32 bytes for V1
pub struct Hasher;                                          // incremental (new/update/finish)
pub fn mac(suite: Suite, key: &[u8], data: &[&[u8]]) -> Tag;
pub fn mac_verify(suite: Suite, key: &[u8], data: &[&[u8]], tag: &[u8]) -> Result<()>;

// Key derivation; the label is always the caller's (W6 style)
pub fn kdf(suite: Suite, ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()>;
pub fn subkey(suite: Suite, root: &[u8], label: &[u8]) -> Key;  // "HMAC(root, label)"

// AEAD: lengths come from the suite
pub const fn nonce_len(suite: Suite) -> usize;  pub const fn tag_len(suite: Suite) -> usize;
pub fn seal(suite: Suite, key: &Key, aad: &[u8], pt: &[u8]) -> Vec<u8>;   // random nonce ‖ ct ‖ tag
pub fn seal_with_nonce(...); pub fn open(suite, key, aad, sealed) -> Result<Zeroizing<Vec<u8>>>;
pub struct Aead;    // `Aead::new(suite, key)` resolves the cipher once, for many blocks

// Signatures (strict verification), KEM / HPKE
pub struct SigningKey; pub struct VerifyingKey;   // sign / verify_strict, Ed25519 for V1
pub fn hpke_seal(suite, recipient_pk, info, aad, pt) / hpke_open(...);  // X-Wing HPKE for V1
pub fn kem_keypair_from_seed(suite, seed) -> (Pk, Sk);

// Randomness, comparison, passwords
pub fn random(out: &mut [u8]);          // getrandom, the one RNG
pub fn random_key() -> Key;
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool;
pub fn pwhash(params: &PwhashParams, password, salt, out) -> Result<()>;  // Argon2id, persisted params
```

- Keys are newtypes (`Key`, zeroized), so a wrong length is a type error.
- **No dynamic dispatch per call:** `Suite` is a small enum, and each
  operation matches it once. `Aead::new` resolves the cipher once for a
  stream of blocks (the block format), so per-block cost is unchanged.
  Measured against #321 §9 before the block format builds on it.
- **Secretstream** (5 MiB frames, libsodium-compatible) moves in as
  `primitives::legacy::secretstream`, unchanged, until the block format
  replaces it at the wipe. Then it is deleted.
- **Argon2id stays libsodium-compatible** (dryoc's `crypto_pwhash`, one lane,
  `OPSLIMIT 3`, `MEMLIMIT 64 MiB`, persisted per account). Only the call moves
  behind `pwhash`.

## 2. The suite table

| Suite | Hash | MAC / KDF | AEAD | Signature | Sealing to a key |
|---|---|---|---|---|---|
| V1 | SHA-256 | HMAC-SHA256 / HKDF-SHA256 | XChaCha20-Poly1305 | Ed25519 (strict) | HPKE base: X-Wing, HKDF-SHA256, ChaCha20-Poly1305 |
| future | … | … | … | Ed25519 + ML-DSA-65 | … |

- **Defined once**, in `primitives/suite.rs`: the row and its known-answer
  vectors (`tests/vectors/primitives-v1.json`, from RFC test vectors and an
  independent implementation for each operation).
- **Every format keeps its own wire suite id for now** and maps it to
  `Suite` through a per-format allowlist, checked on parse:

  ```rust
  // account_envelope.rs
  const SUITES: &[(u16, Suite)] = &[(2, Suite::V1)];
  ```

  The bytes on the wire don't change in this phase: Drive 1, account
  envelope 2, pins 3, contacts 2, photos 1 all map to `Suite::V1`. On the
  wipe branch, every Kutup header aligns to suite 1 (W1, the block format).
- **Layout version and suite stay separate:** the magic says the layout, the
  suite says the algorithms. The suite is in each format's AAD, as today.
- `docs/crypto-agility.md` is amended in the same PR: one table of whole
  tuples (never mixed), per-format allowlists, and the reasons the old "no
  universal suite" rule had, which the allowlists keep.

## 3. How existing code maps in

| Today | Becomes |
|---|---|
| `XChaCha20Poly1305::new` + `Payload` + own `NONCE_LEN`/`TAG_LEN` (22 files) | `seal` / `open` / `seal_with_nonce` |
| `Hkdf::<Sha256>` (24 files), `Hmac<Sha256>` (7) | `kdf`, `subkey`, `mac` |
| `sha2::Sha256` (31 files) | `hash`, `Hasher` |
| `dryoc::rng::copy_randombytes` (25), `OsRng`, `thread_rng` | `random`, `random_key` |
| `ed25519_dalek` (14 files) | `SigningKey` / `VerifyingKey` (strict) |
| `hpke_xwing::suite()` (7 users) | `hpke_seal` / `hpke_open` |
| `dryoc` pwhash, secretstream | `pwhash`, `legacy::secretstream` |
| server: `Sha256` tokens (36 files), `Hmac` subkeys (4 copies), 4 RNG styles, 3 `constant_time_eq` | `hash`, `subkey`, `random`, `ct_eq` |

**Adapters** stay outside the table, each one module with an `#[allow]` and
a comment naming its standard: OpenPGP (rPGP, Mail and Calendar invitations),
libsignal, Signal's provisioning cipher (AES-CBC, `provisioning.rs`), TLS
(rustls with aws-lc-rs), OPAQUE (opaque-ke), Web Push (RFC 8291/8292 in the
server), KeePass KDBX and the SSH agent (Pass), DKIM, WKD's SHA-1, coturn's
HMAC-SHA1, HS256 JWTs and TOTP.

## 4. Enforcement

- **Root `clippy.toml`:** `disallowed-types` and `disallowed-methods` for
  `chacha20poly1305::*`, `hkdf::Hkdf`, `hmac::Hmac`, `sha2::Sha256`/`Sha512`,
  `ed25519_dalek::SigningKey`/`VerifyingKey::verify`, `rand::thread_rng`,
  `rand::rngs::OsRng`, `dryoc::*`. Allowed with `#[allow]` only in
  `primitives` and the named adapters. A crate not yet moved carries a
  crate-level `#![allow(..)]` with a `// W2: moving` note, removed in its move
  PR, so the lint is on from the first PR and nothing new drifts.
- **`deny.toml` `[bans]`:** these crates with `wrappers` (kutup-crypto and the
  adapter crates), plus `ring` and `openssl` denied outright (ring is already
  unbuilt; this keeps it so).
- **ESLint:** `no-restricted-imports` for `libsodium-wrappers-sumo`, and
  `no-restricted-properties` for `crypto.subtle` / `crypto.getRandomValues`,
  outside `frontend/packages/crypto`. Today's uses move behind that package
  (secretstream until the block format, Chat's SHA-256 and the call HMAC
  through WASM or one WebCrypto wrapper, collab's Ed25519 through WASM).
- **The standalone roots** (chat-core, client-ffi, fuzz) get the same lint
  when chat-core's own crypto moves into kutup-crypto (wipe plan, code item 1).

## 5. Order (code-only, each merging to master on its own)

Every step is **byte-identical**: the existing vectors
(`crates/kutup-crypto/tests/vectors/*.json`, read by the Rust and the WASM
tests) prove nothing on the wire changed.

1. **The module, the table and its vectors**, the lint on, every crate
   allowed for now; `crypto-agility.md` amended. No call site moves.
2. **kutup-crypto, by operation:** randomness (one RNG first), then AEAD,
   then KDF/MAC, then hash, then signatures and HPKE. One PR, several
   commits, each green on the vectors.
3. **kutup-server:** token hashes, the four `subkey` copies, one RNG (drops
   rand 0.8, p256's `OsRng`), one `ct_eq`.
4. **kutup-cli:** the master key and recovery entropy from `random` (today
   `thread_rng`, `register.rs:61-65`), SHA-256 helpers.
5. **The frontend lint** and the moves behind `@kutup/crypto`.
6. **kutup-pass** (random only; KDBX and SSH stay adapters).
7. **deny `[bans]`** last, once nothing outside the wrappers uses the crates.

After that, **block format slices 1-2** build their framing on `Aead::new`
and `hash`, and the wipe branch sets every header's suite to 1.

## Not in this note

The wire-format realignment (wipe branch), chat-core's crypto (its own
item), and a second suite row (when ML-DSA is added).
