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
- **Sealing takes the generation explicitly** (`seal`, `seal_object`, `seal_revision`, the base64 and WASM forms). A default would let a future rotation seal under the wrong one unnoticed. `inspect` (and the WASM `inspectAccountEnvelope`) reads it from the header without opening the envelope, so a future rotation reads it first to pick the master key to try, and can tell old wraps from new. `inspect` authenticates nothing: the generation is AEAD associated data, so a forged one fails when the envelope opens. Opening is unchanged.
- **Clients** pass the account's current generation. Until rotation exists, that is one constant per client (`MASTER_KEY_GENERATION` in `@kutup/crypto/masterKeyGeneration`, passed by the TS wrappers that seal; `MasterKeyGeneration::FIRST` in Rust). A kept Pass key resealed for a copied vault keeps the generation of the envelope it came from, named so a search finds every place rotation will touch.
- **No server column yet.** Rotation, when it is built, adds the account's current generation to the account head (W1).

## 3. One label grammar, one registry

- **Grammar:** `kutup/<area>/<purpose>/v<N>\0`. Lowercase `a-z 0-9 -` segments, a trailing NUL, and nothing appended to a label without a length prefix or a separator that the label's own format fixes.
- **Registry:** `kutup-crypto/src/labels.rs` holds every label as a `pub const`, grouped by area, with one line saying what it separates. It is also the reviewer's index. Other crates use it from there: kutup-chat-proto, kutup-chat-core, kutup-group-send, kutup-server and kutup-cli all depend on kutup-crypto.
- **HKDF:** the salt is always a label from the registry (the family), and the info is the context (the purpose label, the object's own header, or both). There are no `None` or empty salts (`store_cipher.rs`, `profile.rs`, `drive_names.rs`, `opaque_login_state.rs`), and no data as salt (`sealed_sender.rs` salts with the recipient, `drive_names.rs` with the folder id): that data moves into the info, length-prefixed. Constructions a standard fixes keep their own salts, marked as adapters: OHTTP (RFC 9458), Web Push (RFC 8291), and Signal's provisioning cipher.
- **Hash domains, signature contexts and AAD prefixes** take their labels from the same registry under the same grammar.
- **The renames change bytes.** They change every derived key and every pinned vector, which the wipe allows. Labels already in the grammar keep their text. As built, the registry holds 180 labels:
  - 164 were `kutup/…` literals. Of those, 14 lacked the NUL. 20 moved into their area: `area-purpose` became `area/purpose` where the area already had labels, and two versions were fixed (`gateway-key/v2-xwing`, `call-link/v1/joined`);
  - 13 were in the old `kutup-…-vN` style (federation documents, Chat profile keys);
  - 3 are new family salts: `chat-store`, `chat-profile`, `drive/names`.
- **Tests:**
  - a unit test lists `labels::ALL` and checks the grammar, uniqueness, and that no label is a prefix of another;
  - a static-gate check (`scripts/check-labels.sh`) refuses a `"kutup/` or `"kutup-` literal (also `b"`, `br"`) outside `labels.rs` in any crate's `src/`, unless `scripts/check-labels.allow` names that file and literal as a non-label (a header, path, name or test fixture); an entry that no longer matches fails too. Labels the browser computes in TypeScript are registered too (marked so), and a `kutup/` literal in a frontend source must be one of them, NUL included;
  - vectors are regenerated once (`crypto.json`, chat-core and proto vectors), with one commit saying so.
- **Not renamed:** strings that aren't cryptographic labels, such as the `kutup/<profile>` CLI keychain service name.

## 4. The legacy Argon2 derivation

The Argon2id account-protection derivation (`kdf::derive_account_protection_keys`, `AccountProtectionSuiteId`, and the WASM `deriveAccountProtectionKeys`) has no caller since OPAQUE, only its vectors. It goes, with its vectors and its row in docs/crypto-agility.md. The recovery proof (`derive_recovery_auth_proof`) stays.

## Rotation checklist

When master-key rotation is built, every place that writes `MasterKeyGeneration::FIRST` (Rust) or `MASTER_KEY_GENERATION` (TypeScript) outside tests must take the account's current generation instead. Find them with `grep -rn 'MasterKeyGeneration::FIRST\|MASTER_KEY_GENERATION' crates frontend/packages frontend/apps`; as of W6 they are:

- **Master-key wraps (purposes 1 and 2):**
  - CLI `register.rs` (password and recovery wraps) and `login.rs` (the password wrap resealed at sign-in);
  - web `opaque.worker.ts` (`sealMasterKey`) and `accountEnvelope.ts` (`sealAccountEnvelope`).
- **Secrets sealed under the master key:**
  - mail address keys: `mail_key.rs` (`first_address_key`) and web `mailKey.ts` (generate, import, and `acceptMailForwarding`);
  - Pass kept keys: CLI `vaultsync.rs` and web `pass/src/vault/worker.ts` (`keepKey`). `kept::reseal` already keeps the generation of the envelope it opens, so a copied vault follows its source.
- **The server's fake recovery envelope** (`handlers/auth.rs`, `deterministic_fake_account_envelope`): an unknown name gets a stable fake so it looks like a real account. Once accounts can be past generation 1, the fake must carry a generation as plausible as a real one, or the header tells a fake from a real account.
- **The constant itself:** `@kutup/crypto/masterKeyGeneration` and its doc comment in `kutup-crypto-wasm` (`sealAccountEnvelope`).

The `inspect` that a rotation reads first to pick the master key returns the generation in Rust and in WASM (`inspectAccountEnvelope`).

## Migration and order

- **Migration `20261027160000`:** drops `users.drive_private_key_envelope` (down: adds it back, nullable).
- **Order:** one PR into `wipe-2`, in four commits (§4, §1, §2, §3).
- **Gates:** static, rust (with chat-core and client-ffi), web, the crypto and WASM vectors, and the account suite (registration, sign-in, recovery) in a lane stack built from the branch.

## Size and risk

- **Size:** about 2 days. §3 is most of it: it is mechanical but wide.
- **Risk:** low per item. The vector regeneration is the one place a mistake hides, so the label test and the static check are the guard. Every vector change sits in the one §3 commit.
