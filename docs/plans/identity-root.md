# The identity root and the stored account roots (build note)

Status: **proposed** (second session, 2026-11-13). Builds step 1 of
[identity-rotation.md](identity-rotation.md) §8 (approved 2026-11-12): the
account identity and four other long-lived roots become random secrets stored
as account records under the master key (MK), so an MK rotation changes
nothing a peer sees and moves no record ids. Branch `wipe/identity-root`, into
`wipe-2`.

## 1. Five new account-record purposes

Each holds one random 32-byte secret, sealed under the MK like every other
account record (header: suite, purpose, MK generation, key binding, object).
The plaintext is exactly the 32 bytes (`Length::Exact(32)`), and nothing else.
The purpose and the suite version it; a key record has no JSON and no `"v"`.

| # | Purpose | Object | What it roots |
|---|---|---|---|
| 22 | `IdentityRoot` | identity generation `id_gen`, u32 BE | authority, Drive X-Wing, Drive share-signing key |
| 23 | `DriveRoot` | Drive root generation, u32 BE | own collection keys, link owner copies (main's slice 3) |
| 24 | `GroupPseudonymRoot` | none | per-group pseudonyms |
| 25 | `CallLinkRoot` | none | call-link owner secrets and host tokens |
| 26 | `ObjectIdKey` | none | `hashed_object` ids |

- **All are immutable.** A new identity or Drive root is a new record at the
  next generation. The old one is kept, so old shares and signatures stay
  readable after an identity rotation (identity-rotation.md §4). The
  generation sits in the object, which the header authenticates, so a
  server can't relabel a record as another generation.
- **Which identity root is current:** the highest `id_gen` whose authority
  equals the account's registered authority (`users.account_authority_public_key`,
  and the manifest's). The client checks this and refuses a mismatch. The
  server keeps no pointer of its own.
- **Not rotated with the identity:** the pseudonym root, call-link root and
  object-id key never change (identity-rotation.md §5: "unchanged, since their
  roots are stored"), so they take no generation.

## 2. Derivations

- `identity::IdentityRoot`, `GroupPseudonymRoot`, `CallLinkRoot`,
  `ObjectIdKey` and `DriveRoot` are distinct zeroizing newtypes over
  `[u8; 32]`. An MK can't be passed where a root is expected; the types are
  the guard.
- **Identity:** `AccountIdentityKeysV1::derive(&IdentityRoot)`. The salt and
  infos are today's labels, and only the input key changes. The incarnation id
  stays the hash of the authority's public key: it now changes only at a reset
  or an identity rotation.
- **Pseudonyms:** `GroupPseudonymKey::derive(&GroupPseudonymRoot)`, with the
  same salt and info (group id ‖ join epoch).
- **Call links:** `owner_call_link_secret` and `owner_call_link_host_token`
  take `&CallLinkRoot` instead of the MK string.
- **Hashed objects:** `hashed_object(&ObjectIdKey, purpose, id)` =
  `HMAC(K_id, purpose ‖ id)` with the stored key as `K_id` directly. Its HKDF
  step and the `kutup/account-record/object-id/v1` label go, because the key
  is already random and single-purpose. Record ids then survive an MK
  rotation, and that step leaves W6's rotation checklist.
- **`AccountRoots`** bundles the five, plus `generate()` and two calls:
  `seal(mk, mk_gen, binding)` gives the five envelopes, and
  `open(mk, binding, envelopes)` checks that each purpose is there once
  (identity and Drive at their highest generation) and returns the roots.
- **Staying derived from the MK** (private to the account, cheap to rebuild,
  per identity-rotation.md §3): the account-head keys, the mail-search store
  key and name, revision-guard and local-chain-pin keys, the Chat store key
  and the manifest-pins key. An MK rotation re-keys those device-local
  stores; the rotation exercise (next slice) covers it. The Drive top-level
  hash key moves under the Drive root in main's slice 3.

## 3. Server

- **Table `account_roots`:**
  - columns: `user_id` (FK `users` ON DELETE CASCADE), `purpose smallint`
    (CHECK 22–26), `object bytea NOT NULL DEFAULT ''`, `envelope bytea`,
    `created_at`;
  - primary key `(user_id, purpose, object)`;
  - insert only: no UPDATE path. A rotation adds a generation, and an MK
    rotation re-wraps in one transaction (next slice);
  - each envelope is checked with `account_record::validate_for` against the
    account's key binding, its purpose and its object;
  - covered by the backups as ordinary data, and gone with the account
    (cascade).
- **Written by:**
  - registration (`RegisterRequest.accountRoots`) and an admin-created
    account's setup: exactly one record of each purpose, identity and Drive
    at generation 1, or `400`;
  - an account reset: the old rows are deleted and the new ones written in
    the reset's transaction, like the other keys it replaces.
- **Read by:**
  - every answer that hands out the MK envelope: the session answer (which
    also follows 2FA and setup completion) and the recovery answer. It gains
    `accountRoots`: base64 envelopes, newest generation first;
  - `GET /api/account/roots`, for a client that holds the MK but not the
    roots (a CLI profile, and the rotation exercise).
- The password change and recovery leave the roots alone: the MK doesn't
  change.
- **Migration** `20261111110000_account_roots` (main: please confirm it's
  free; I leave 20261109160000 to you).

## 4. Clients

- **WASM:**
  - `deriveAccountIdentityKeys(identityRootB64)`;
  - new `generateAccountRoots(mkB64, mkGen, binding)` → `{ roots, envelopes }`
    and `openAccountRoots(mkB64, binding, envelopes)` → `roots`;
  - the exports that take the MK only to derive one of these take the root
    instead: `signMailKeyList` the identity root, the pseudonym exports the
    pseudonym root, the call-link exports the call-link root, and the
    group/contact-list record ids the object-id key;
  - `driveTopLevelHashKey` stays until main's slice 3.
- **Web:**
  - `Session` gains `roots` (identity root and its generation, plus the other
    four), set at sign-in, sign-up, recovery and setup, and persisted exactly
    where `masterKey` is;
  - the 23 `deriveAccountIdentityKeys(masterKey)` callers pass
    `session.roots.identity`.
- **CLI:** the keyring profile stores the roots next to the MK. `register`,
  `login`, `recover`, account reset and the share, access, identity,
  collection, vault-sync and collab-device paths take them from the profile.
- **chat-core:**
  - `manifest.rs` and `identity_sync.rs` take the identity root;
  - `group.rs` takes the pseudonym root;
  - `call_link.rs` takes the call-link root;
  - `group_list` and `contact_list` take the object-id key next to the MK
    that seals their records;
  - the wasm and FFI entry points pass them through.

## 5. Vectors and tests

- **Vectors:**
  - identity vectors re-keyed from a fixed identity root (same formulas, new
    input);
  - account-record vectors for purposes 22–26;
  - pseudonym, call-link and hashed-object vectors from fixed roots;
  - all in one commit, saying so.
- **Unit tests:**
  - `AccountRoots` round trip;
  - a root sealed for one account or generation is refused for another;
  - an MK passed as a root doesn't compile (a doc test);
  - a new MK with the same identity root keeps the same incarnation. This
    replaces `a_new_master_key_is_a_new_incarnation`.
- **Live tests:**
  - registration stores five roots and sign-in returns them;
  - a registration missing one, or with one twice, is `400`;
  - a reset replaces them;
  - account deletion removes them.
- **Gates:** static, rust (with chat-core and client-ffi), web, the WASM
  vectors, and the account browser suite in the final full test.

## 6. Not in this slice

- **Next slice, the MK rotation exercise:** a new MK, roots re-wrapped at
  once, `mail_search.rs:114` taking the real generation, a plausible
  generation in the fake recovery envelope, and one live test.
- **Main's slice 3:** using the Drive root (collection keys, link owner
  copies, the top-level hash key). This slice only creates it, at
  registration.
- **After the wipe:** the identity rotation flow (UI, safety numbers,
  succession statement).
- **The `AccountRef` split:** the slice after the rotation exercise.

## Choices to confirm

1. **Generations as the record's object**, one record kept per generation,
   rather than one mutable record with the generation as its revision. Old
   roots must stay readable after a rotation; a mutable record would replace
   them.
2. **The object-id key used directly as the HMAC key**, dropping its HKDF
   label (it was there only to separate it from the MK).
3. **The Drive root created now**, at registration, though only main's
   slice 3 reads it, so that no account exists without one.
4. **Migration `20261111110000`.**

Size: about 3 days. Risk: wide but mechanical, like W6 §3. The newtypes make
any missed caller a compile error rather than a wrong key.
