# One primitive layer: build note (W2)

**Status:** approved 2026-10-23; step 1 built (second session). Implements W2
of [`wipe-unification.md`](wipe-unification.md), whose open question 1 is
settled: one suite table of whole tuples, with each format allowlisting its
suites ([`../crypto-agility.md`](../crypto-agility.md), amended).

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

- **Defined once**, in `primitives/suite.rs` (`SuiteParams`), every
  parameter named: digest and tag lengths, HKDF's extract-then-expand with
  an empty salt as the zero key and the caller's `kutup/<area>/<purpose>/vN\0`
  as info, the AEAD's 32-byte key, 24-byte random nonce and 16-byte tag,
  Ed25519 with `verify_strict` (canonical S, no small-order A or R), HPKE's
  ids (KEM 0x647a, KDF 0x0001, AEAD 0x0003) and lengths, Argon2id as
  libsodium's one-lane `crypto_pwhash`, and the random source. A test checks
  the code does what the row says, so a V2 is a plain diff of one row.
- **Known answers** (`tests/vectors/primitives-v1.json`) are written by other
  implementations (`scripts/primitives-vectors.mjs`: OpenSSL through
  node:crypto, and libsodium), from the RFCs' own examples where they have
  them. HPKE opens a message sealed by hpke-rs on its libcrux backend: an
  independent X-Wing, ML-KEM and AEAD, but the same hpke-rs key schedule and
  framing, so HPKE's independence is partial (no second HPKE implementation
  with X-Wing exists yet to check against).
- **Tags compare only in constant time:** `Tag` has no `==`; it is checked
  with `mac_verify`, or its bytes with `ct_eq`.
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
  the AEADs (`XChaCha20Poly1305`, `ChaCha20Poly1305`, the generic
  `ChaChaPoly1305`), `hkdf::Hkdf`, `hmac::Hmac`, every `sha2` hash,
  `ed25519_dalek`'s keys and its non-strict `Verifier::verify`,
  `x25519_dalek`'s keys, `hpke_rs::Hpke`, every RNG (`rand`'s, `rand_core`'s,
  `getrandom`'s, dryoc's) and dryoc's secretstream, box, secretbox,
  generic hash, scalar multiplication and `crypto_pwhash`. dryoc's constants
  can't be named by clippy; the deny `[bans]` of the last step covers the
  crate. The server's two local `constant_time_eq` copies go in step 3
  (`ct_eq`). Allowed with `#[allow]` only in
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
4. **kutup-cli:** the master key and recovery entropy from
   `primitives::random_key` (today `thread_rng`, `register.rs:61-65`), with a
   test that they come from the one RNG; SHA-256 helpers.
5. **The frontend lint** and the moves behind `@kutup/crypto`.
6. **kutup-pass** (random only; KDBX and SSH stay adapters).
7. **deny `[bans]`** last, once nothing outside the wrappers uses the crates.

Step 3 notes: an object's stored SHA-256 that is also served as an RFC 9530
`Content-Digest` (Drive versions and uploads, Chat media, album thumbnails,
federation response bodies) goes through federation-proto's `ContentDigest`,
since the header names `sha-256` whatever the suite is; every other server
hash is the suite's. The server's RNG uses (rand 0.8, rand 0.9 for
libsignal, p256's `OsRng`) are all `primitives::Rng`/`random*` now, and the
server no longer depends on `rand`; `random_below` serves codes, digits and
jitter. kutup-chat-proto's group-route and MLS-control signers take
`primitives::SigningKey`, as the server hands them one; the rest of that
crate moves with chat-core.

Step 4 notes: the CLI's master key and recovery entropy are
`primitives::random_key()` (`register::account_secrets`), and the CLI no
longer depends on rand, sha2 or ed25519-dalek, so the lint leaves it no
other generator to name. Drive's `sha256`-named fields (version and file
uploads, whiteboard assets) are the suite's hash, as on the server; under V1
it is the same SHA-256 as the served `ContentDigest`, and a suite with
another hash renames those fields (a format change, not a silent swap).

Step 6 notes: kutup-pass draws its randomness from the one source: new key
files are `primitives::random_key()` (`generate_key_file` can no longer
fail), and RSA blinding in the SSH agent uses `primitives::Rng` in place of
its own getrandom wrapper. The crate no longer depends on getrandom or
rand_core; kutup-pass-wasm keeps getrandom's browser backend features, which
kutup-crypto's getrandom needs there. KeePass's and SSH's own hashes are
item-level adapters.

After that, **block format slices 1-2** build their framing on `Aead::new`
and `hash`, and the wipe branch sets every header's suite to 1.

## Lint exceptions

The crypto rules are in the root `clippy.toml` from step 1. Clippy reads a
crate's nearest `clippy.toml`, so a crate not yet moved carries its own,
which keeps only the workspace's other rules (the `reqwest` ones) and starts
with `# W2: moving`. A crate-level `#![allow]` would switch those off too.
Each move PR deletes its crate's file and strikes its row out;
`scripts/check-crypto-exceptions.py` (in `gate.sh static`) fails when the
files and the table differ, so none can be left behind. The gate runs clippy
on `fuzz` as on the other standalone roots.

| Crate | Moves in |
|---|---|
| ~~`crates/kutup-crypto`~~ | step 2: done |
| ~~`crates/kutup-crypto-wasm`~~ | step 2: done |
| ~~`crates/kutup-server`~~ | step 3: done |
| ~~`crates/kutup-cli`~~ | step 4: done |
| ~~`crates/kutup-pass`~~ | step 6: done (KDBX and the SSH agent are adapters) |
| ~~`crates/kutup-federation-proto`~~ | step 3: done |
| `crates/kutup-chat-proto` | with chat-core's crypto (wipe plan, code item 1) |
| `crates/kutup-chat-core`, `crates/kutup-client-ffi`, `fuzz` | with chat-core's crypto |

Every other `clippy.toml` (or `.clippy.toml`) must carry the root's rules
unchanged; one without the marker that drops a rule fails the check, as
does a marker file anywhere the table doesn't list.

`kutup_crypto::primitives` itself carries `#[allow]` for the rules, as do
the adapters once their crates move. An adapter's `#[allow]` sits on the
items that speak the standard (a `use`, a function, an `impl`), never on the
whole module, so Kutup's own formats inside an adapter's file stay linted.
Each rule has `allow-invalid`, as a crate without the dependency can't name
the type anyway.

The check also fails on any `clippy::disallowed_types` or
`clippy::disallowed_methods` in a Rust file this table doesn't list, and on
every other way to switch them off: an allow or expect of `clippy::style`,
`clippy::all` or `warnings` anywhere, a `[lints]` table allowing them in a
Cargo.toml, rustflags with `-A` or `--cap-lints` for them in a
`.cargo/config`, such a flag in a script or workflow, and `CLIPPY_CONF_DIR`. A new
adapter adds its row here, in the PR that adds it.

| File | Allowed for |
|---|---|
| `crates/kutup-crypto/src/lib.rs` | `primitives`, the one module that names algorithms |
| `crates/kutup-crypto/src/hpke_xwing.rs` | the HPKE backend behind `primitives::hpke_*` |
| `crates/kutup-crypto/src/mail_key.rs` | OpenPGP's SHA-256 key imprint (rPGP) |
| `crates/kutup-crypto/src/oblivious.rs` | Oblivious HTTP (RFC 9458): HPKE's context API and the response AEAD |
| `crates/kutup-crypto/src/opaque.rs` | OPAQUE's ciphersuite (RFC 9807) |
| `crates/kutup-crypto/src/pass_vault.rs` | KeePass's composite key (SHA-256 of the password) |
| `crates/kutup-crypto/src/provisioning.rs` | Signal's ProvisioningCipher |
| `crates/kutup-crypto/src/safety_number.rs` | Signal's safety number (iterated SHA-512) |
| `crates/kutup-crypto/src/stream.rs` | secretstream, until the block format replaces it |
| `crates/kutup-crypto/tests/vectors.rs` | reference implementations for the vectors |
| `crates/kutup-crypto/tests/chat_contact_list_vectors.rs` | reference implementations for the vectors |
| `crates/kutup-crypto/tests/chat_group_list_vectors.rs` | reference implementations for the vectors |
| `crates/kutup-server/src/tls.rs` | the `reqwest` rule: the one place a client is built |
| `crates/kutup-server/tests/common/mod.rs` | the `reqwest` rule, for the tests |
| `crates/kutup-cli/src/tls.rs` | the `reqwest` rule: the one place a client is built |
| `crates/kutup-federation-proto/src/http_signatures.rs` | RFC 9530's `sha-256` Content-Digest (`ContentDigest`) |
| `crates/kutup-server/src/calls.rs` | coturn's REST-API credential (HMAC-SHA1) |
| `crates/kutup-server/src/web_push_payload.rs` | RFC 8291 Web Push encryption (HKDF-SHA256) |
| `crates/kutup-server/src/web_push.rs` | RFC 8292's ES256 signature, checked in a test |
| `crates/kutup-pass/src/kdbx.rs` | KeePass's key file v2 check and composite key (SHA-256 of the password), in tests |
| `crates/kutup-pass/src/ssh.rs` | the SSH agent's signatures (RFC 8332's rsa-sha2-256/512) and OpenSSH's session binding |
| `crates/kutup-pass/tests/corpus.rs` | KeePass's composite key, the reference for KeePassXC's vaults |
| `crates/kutup-pass/tests/ssh.rs` | agent signatures checked as an SSH server checks them |

## Not in this note

The wire-format realignment (wipe branch), chat-core's crypto (its own
item), and a second suite row (when ML-DSA is added).
