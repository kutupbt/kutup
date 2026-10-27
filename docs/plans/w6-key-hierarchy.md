# W6: key-hierarchy fixes (build note)

Status: **proposed** (second session, 2026-10-27), for docs/plans/wipe-unification.md, W6. Branch `wipe/w6-key-hierarchy`, into `wipe-2`. Agreed with the third session: W6 defines the master-key generation once, and W1's `AccountRecordV1` reuses it. W6 builds the label registry; W1 and W5 slice 3 put their labels on it. This note settles what W6 in the plan leaves open.

## 1. Derived or stored, never both: the Drive X-Wing key

- **Today:** the Drive X-Wing seed is derived from the master key (`identity.rs`, `AccountIdentityKeysV1::derive`) and also stored as account-envelope purpose 3 (`DriveHpkePrivateKey`, column `users.drive_private_key_envelope`).
- **Change:** it is only derived. Purpose 3 goes from the registry: the number stays reserved and is refused on parse.
- **Server:** the column goes, along with the field in registration, sign-in, the identity-suite upgrade, admin reset and the account head.
- **Clients:** web, CLI and tests derive the key from the master key after sign-in, as they already derive the authority.
- **Identity suite 1** (before X-Wing) can't exist after the wipe. So its one-time upgrade goes too: `POST /api/account/identity-suite`, the CLI's step 5b, and the web's `identitySuite.ts` path. That code is the other writer of purpose 3. `identity_suite` stays a column, and the server accepts only 2 at registration.

## 2. The master-key generation

- **`kutup_crypto::account_envelope::MasterKeyGeneration(u32)`**: never 0. `MasterKeyGeneration::FIRST` = 1 is the only one until rotation is built ([account-identity-key.md](account-identity-key.md), "Device removal"). Exported for W1's `AccountRecordV1` header.
- **The account envelope gets it in its header**, a u32 big-endian after the reserved byte, authenticated as AEAD associated data with the rest of the header:
  - for purposes 1 and 2 (password and recovery wraps of the MK), the generation of the MK inside;
  - for every other purpose, the generation of the MK that sealed it.

  The magic becomes `KUTPAE2\0`. An envelope without the field is refused, and none survives the wipe.
- **Sealing takes the generation explicitly** (`seal`, `seal_object`, `seal_revision`, the base64 and WASM forms). A default would let a future rotation seal under the wrong one unnoticed. `inspect` (the authenticated header) shows it, so a future rotation reads it first to pick the master key that opens the envelope, and can tell old wraps from new. Opening is unchanged.
- **Clients** pass the account's current generation. Until rotation exists, that is one constant per client (`MASTER_KEY_GENERATION` in `@kutup/crypto/masterKeyGeneration`, passed by the TS wrappers that seal; `MasterKeyGeneration::FIRST` in Rust). A kept Pass key resealed for a copied vault keeps the generation of the envelope it came from, named so a search finds every place rotation will touch.
- **No server column yet.** Rotation, when it is built, adds the account's current generation to the account head (W1).

## 3. One label grammar, one registry

- **Grammar:** `kutup/<area>/<purpose>/v<N>\0`. Lowercase `a-z 0-9 -` segments, a trailing NUL, and nothing appended to a label without a length prefix or a separator that the label's own format fixes.
- **Registry:** `kutup-crypto/src/labels.rs` holds every label as a `pub const`, grouped by area, with one line saying what it separates. It is also the reviewer's index. Other crates use it from there: kutup-chat-proto, kutup-chat-core, kutup-group-send, kutup-server and kutup-cli all depend on kutup-crypto.
- **HKDF:** the salt is always the family label and the info always the purpose label, followed by the context, length-prefixed where it varies. No `None` salts (`store_cipher.rs`, `profile.rs`), no salts that are data (`sealed_sender.rs` salts with the recipient), and no label in both salt and info. One helper does it: `primitives::Kdf::labeled(family, ikm)` then `.expand(purpose, context, out)`.
- **Hash domains, signature contexts and AAD prefixes** take their labels from the same registry under the same grammar.
- **The renames change bytes.** They change every derived key and every pinned vector, which the wipe allows. Labels already in the grammar keep their text. Of the 188 label literals, 14 lack the NUL and about 30 mix `area-purpose` into one segment; those move to `area/purpose`.
- **Tests:**
  - a unit test lists `labels::ALL` and checks the grammar, uniqueness, and that no label is a prefix of another;
  - a static-gate check (`scripts/check-labels.sh`) refuses a `"kutup/` literal outside `labels.rs` in any crate's `src/`;
  - vectors are regenerated once (`crypto.json`, chat-core and proto vectors), with one commit saying so.
- **Not renamed:** strings that aren't cryptographic labels, such as the `kutup/<profile>` CLI keychain service name.

## 4. The legacy Argon2 derivation

The Argon2id account-protection derivation (`kdf::derive_account_protection_keys`, `AccountProtectionSuiteId`, and the WASM `deriveAccountProtectionKeys`) has no caller since OPAQUE, only its vectors. It goes, with its vectors and its row in docs/crypto-agility.md. The recovery proof (`derive_recovery_auth_proof`) stays.

## Migration and order

- **Migration `20261027160000`:** drops `users.drive_private_key_envelope` (down: adds it back, nullable).
- **Order:** one PR into `wipe-2`, in four commits (§4, §1, §2, §3).
- **Gates:** static, rust (with chat-core and client-ffi), web, the crypto and WASM vectors, and the account suite (registration, sign-in, recovery) in a lane stack built from the branch.

## Size and risk

- **Size:** about 2 days. §3 is most of it: it is mechanical but wide.
- **Risk:** low per item. The vector regeneration is the one place a mistake hides, so the label test and the static check are the guard. Every vector change sits in the one §3 commit.
