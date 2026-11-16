# The master-key rotation exercise

Status: **approved** 2026-11-15 (second session's note; decisions below). This is identity-rotation.md
§8.4: the master-key (MK) rotation built end to end in Rust, with vectors and
one live test and no UI, so the formats are proven before the wipe freezes
them. The identity rotation gets a written walk-through only (§8). Branch
`wipe/mk-rotation`, on `wipe/identity-root` (#415), into `wipe-2`.

## 1. What a rotation is

A new random MK at `mk_gen + 1`, for a password or recovery phrase that was
exposed, an organization taking escrow, or routine. Nothing a peer sees
changes: the identity, Drive, pseudonym and call-link roots and the
object-id key are kept and only re-wrapped (identity-root.md). The old MK
stays readable to the account through a keyring record, so other records are
re-sealed lazily (identity-rotation.md §4).

One device rotates, in one server transaction:

1. **The password:** OPAQUE registered again for the same password, under a
   grant `for: masterKeyRotation` (a reauth, as a password change). The new
   password wrap (purpose 1) holds the new MK at `mk_gen + 1`.
2. **The recovery phrase:** a new phrase. Purpose 2 wraps the new MK under
   the new phrase's entropy, with the new recovery proof. The old phrase
   stops working, which is the point when it was exposed. Proton also makes
   a new recovery phrase when it makes new keys (`resetKeys.ts`). The CLI
   prints the phrase once, as `register` does.
3. **The roots,** re-wrapped at once: the five records sealed again under the
   new MK at `mk_gen + 1`, with the same root generations and plaintexts.
4. **The keyring:** a new record purpose 27, `MasterKeyKeyring`. It holds
   the old MK, its object is the old generation (u32 big-endian), and it is
   sealed under the new MK. Generation n+1 holds n, so one chain reaches
   every older MK.
5. **The account head:** the next head is sealed under the new MK (§3).
6. **The server** sets `users.master_key_generation = mk_gen + 1` and ends
   every other session. Those devices hold the old MK, and their writes would
   be refused anyway (§4). The rotation also goes into the security log, as a
   new kind `masterKeyRotated` (the CHECK is extended).

`POST /api/account/master-key/rotate` takes all of it, checks every header
(purpose, generation `current + 1`, binding, and the roots' generations
equal to the stored ones), and commits it in one transaction under the head
lock. A concurrent rotation or head write gets `409`.

## 2. Format gaps the exercise found (these need the wipe)

1. **The head's id key comes from the MK.** `HeadKeys` derives the key for
   value ids, writer ids and local names from the MK (`account_head.rs:77`),
   so a rotation would change every scope digest and every local name. The
   rotation head would then have to re-read every scope's index under the
   old keys and recompute it under the new ones, and each device's anchor
   would move to a new name. **Proposed:** derive that key from the object-id
   root instead, so heads are only sealed under the MK. The object-id root is
   stored, private to the account and kept by an MK rotation, the same reason
   identity-root moved record ids under it. The head vectors change.
2. **The Chat store key's wrap has no generation** (`chat_store.rs`: a
   version byte, a nonce and an AEAD under an MK-derived key). After a
   rotation, a device can't tell which MK it was wrapped under. **Proposed:**
   wrap it as an account record, purpose 28 `ChatStoreKey`, the way the mail
   search key already is (purpose 20). The generation is then in the header,
   and `inspect` picks the key. The SQLCipher and IndexedDB stores keep their
   data; only the 73-byte wrap changes.
3. **The manifest-pins key is derived from the MK with no generation**
   (`local_state.rs:35`, `KUTPLS1`). It is device-local in `localStorage`.
   **Proposed:** no format change. A reader tries the current MK and then the
   keyring's older ones, newest first (AEAD fails cleanly), and seals again
   under the current one. With one rotation the list is at most a few keys
   long. A pin list that opens under neither is lost, which is the case
   today too.

Item 1 and item 2 change bytes before the freeze; item 3 is code only.

## 3. Reading and checking across a rotation

- **Opening any account record:** `inspect` the header generation. When it
  is the current one, use the MK. When it is older, walk the keyring down to
  that generation. A record whose generation is newer than the account's is
  refused (a rolled-back MK). One function in kutup-crypto,
  `MasterKeys { current, older: BTreeMap<gen, MK> }`, built from the keyring
  records at sign-in, which the server returns with the roots. It replaces
  the bare `&[u8; 32]` wherever a record is opened. Sealing always uses
  `current`.
- **The head:** `HeadKeys` holds `MasterKeys`. A segment that crosses the
  rotation opens each head with the key its header names. The newest head
  must be sealed at the account's current generation. A client holding an
  older MK than the head's is told to sign in again, so a session that
  outlived a rotation can't go on.
- **Lazy re-sealing:** a listed write re-seals the record it writes at the
  current generation, which is what happens now. Nothing walks every record.
  The exercise's live test re-seals one record of each listed kind to prove
  the path.
- **Device-local stores** (local anchor 18, revision guard 19, mail search
  20, local chain pin 21, the Chat store key 28) open through `MasterKeys`
  and are sealed again under the current MK at their next write.

## 4. Server

- **Migration:** `users.master_key_generation integer NOT NULL DEFAULT 1
  CHECK (> 0)`; purposes 27 and 28 in the record-purpose CHECKs; the keyring
  in `account_roots`, whose purpose CHECK becomes 22–27 (its object is the
  generation, 4 bytes, as for the roots); `masterKeyRotation` in both
  grant-purpose CHECKs; `masterKeyRotated` in the security-event kind CHECK.
- **Sign-in** returns `masterKeyGeneration` and the keyring records with
  `accountRoots`, and so does `GET /api/account/roots`.
- **Writes** under an older key: every listed write carries the next account
  head, and the head lock now checks that head's generation against the
  account's (`409 masterKeyStale`); `register/finish` checks the password
  wrap's the same way. The rotation ends every other session, and every
  request checks its session row, so only a request already in flight could
  still write something unlisted under the old key, which stays readable
  through the keyring. (As built: the check is in the head path, not in each
  record's own header check.)
- **Recovery** (as built, changed from the note): the unauthenticated
  preflight returned the recovery envelope, whose header names the
  generation, so a rotated account would differ from the fixed fake answer.
  The preflight now gives only the key binding (a fake one for an unknown
  name), and `recover/grant` returns the envelope with the grant, after the
  proof. The fake envelope is gone.
- **Organizations:** a managed member's escrow holds the old MK. The
  rotation request carries the escrow re-sealed at the new generation, and
  the server swaps it in the same transaction, so admins never lose access.
  An admin's own copy of the organization key (purpose 7) is re-wrapped at
  once like the roots, because an admin with a stale copy can't serve
  access requests. Certificates are untouched, since the authority is kept.
  As built: the organization routes (O4) don't exist yet, so a rotation is
  refused (`409 organizationKeys`) while the account holds an escrow or a
  key copy; O4 adds the re-sealed escrow and copies to the request.
  `EscrowV1::seal` at the new generation is already the format.

## 5. Clients

- **Rust (kutup-crypto):** `MasterKeys`, `mk_rotation::prepare(...)`, which
  returns the request bodies above from the old `MasterKeys`, the roots, the
  new password's OPAQUE registration, a new phrase and the verified head,
  and the keyring codec. The fixed `FIRST` in non-test code (the W6
  checklist plus `mail_search.rs:114`, `local_chain_pin.rs:52`,
  `revision_guard.rs:42`, `account_head.rs:73`, chat-core's `profile.rs`,
  `call_link.rs`, `contact_list.rs`, `group_list.rs`, `identity_sync.rs`,
  kutup-pass `kept.rs`, CLI `vaultsync.rs`, `identity.rs`, `session.rs`,
  `login.rs`, `register.rs`) takes `MasterKeys::current()` instead.
- **CLI:** `kutup account rotate-master-key` (password, then prints the new
  phrase). It drives the live test. It is hidden from `--help` until the web
  can follow a rotated account (question 1).
- **Web:** sign-in keeps `masterKeyGeneration` and the keyring in the
  session (`SessionKeys` v6), and `MASTER_KEY_GENERATION` becomes the
  session's. The WASM record-open calls take the keyring. The web does not
  rotate.
- **chat-core / FFI:** the same `MasterKeys` through `NativeAccountKeys` and
  the WASM chat bindings.

## 6. Vectors and tests

- **kutup-crypto vectors:** a rotation from fixed keys (gen 1 → 2). They
  cover the keyring record; the five roots re-wrapped; a head chain that
  crosses the rotation and checks as `extends` on a device anchored before
  it; a gen-1 contact card that opens through the keyring; a gen-3 record
  refused by a gen-2 account; and the Chat store key record. The crypto WASM
  test opens them too.
- **Server tests:** the rotation transaction, including its conflicts, a
  stale write refused, the other sessions ended, the security-log row, and
  the escrow swap.
- **One live test** (`master_key_live` and `scripts/verify-mk-rotation.sh`, in the live backup gate):
  1. Register with the CLI, then write a contact card, a Pass vault secret, a
     mail address key and an identity pin.
  2. Rotate, then sign in again with the same password and read every record
     (through the keyring).
  3. Write one record of each kind, which re-seals it at gen 2.
  4. The old phrase is refused and the new phrase recovers.
  5. A second CLI profile signed in before the rotation is told to sign in
     again, and then follows the head across the rotation.
  6. A web sign-in reads the contact card.

## 7. Not in this slice

- A UI to rotate, and eager re-sealing of every record.
- The identity rotation flow (after the wipe).

## 8. Identity rotation: a written walk-through

For identity-rotation.md §5 (the identity rotation is built after the wipe).
Each checklist item, what changes, and whether the formats frozen now carry
it.

- **New roots.** All five get the next generation (records 22–26 keep every
  generation; their object is the generation), with a new MK and its keyring
  record: this exercise's path with `AccountRoots` regenerated instead of
  kept. Format: ready.
- **Account head.** It records identity, Drive and object-id generations
  (`AccountHeadV1`); the rotation head records the new ones, so a server
  serving an older root is `rootGenerationMismatch` everywhere. A new
  object-id root changes the head's id key: the rotation head must recompute
  every scope's digest from the verified indexes (old key for reading, new
  for writing) and each device's local state moves to its new name. Format:
  ready; code: a `HeadKeys` per object-id generation during the move.
- **Account manifest and pins.** New authority, a succession statement
  signed both ways, a new Drive key binding at the next `epoch` (the field
  exists). Pins must keep the highest epoch seen. Format: the succession
  statement is missing (a new manifest field before the freeze, or a new
  manifest version after it).
- **Collection epoch chains.** Each owned folder gets an epoch signed by the
  new authority; `collection_keyring::unlock` must accept older statements
  under an authority the manifest history lists. Format: ready (statements
  name their signer's key id); code: the history lookup.
- **Named shares, file shares, profile-key envelopes to the account.**
  Senders re-seal to the new X-Wing key when they next read the manifest; old
  ones open with the kept identity root of their generation. Format: ready
  (the envelopes name the recipient incarnation).
- **Block manifests.** The signer kind 2 names the incarnation, so old
  manifests verify against the authority of their incarnation. Format: main's
  Drive slice.
- **Chat.** A new libsignal identity is the existing reset flow; the backup
  binds `backup_incarnation_id`, not the account's. Group pseudonyms and call
  links: a new pseudonym root re-derives every pseudonym, so the account
  rejoins each group under the new one (the group list holds the groups);
  call links made under the old call-link root stay the old root's. Format:
  ready; code: the rejoin.
- **Organizations.** Certificates re-signed by another admin, the escrow
  re-sealed at the new generation, and releasing escrow is this rotation
  (identity-rotation.md §4). Format: ready.
- **Record ids.** A new object-id root moves every hashed id: each
  hashed-object record (contact cards' lists, chat lists, ledger, guards) is
  re-sealed under its new id and the old row deleted, purpose by purpose,
  through the server's normal write paths. Format: ready; code: a migration
  pass with progress kept on the device.

Missing before the freeze: the succession statement in the manifest. The rest
is code.

## 9. After smart's review (2026-11-16, as built)

- **The head names every generation in one map** (`AccountHeadV1.generations`:
  `mk`, `identity`, `drive`, `objectId`, `pseudonym`, `callLink`; at most 32
  entries; these six required, others allowed, so a later root is additive and
  a reader checks the ones it knows). `mk` is the current master key's
  generation, in the plaintext: the record header says which key sealed a
  head, not which key is current. Every check (`account_head::check`, at sign-in
  too) refuses a head whose map differs from the roots in use and the master
  key held, and a head sealed under another key than the one it names current.
  A rotation's head names the new key (`with_master_key`).
- **Recovery phrase, one wrap at a time.** The client makes the new phrase,
  shows it and has it confirmed (two of its words in the CLI) before it sends
  the rotation; the server swaps the recovery wrap and its verifier in the
  rotation's one transaction, so it never holds two.
- **A crashed rotation.** The rotation is one server transaction: the head
  naming the new key is stored in it, with everything else, or nothing is.
  Before the commit nothing changed and the device can rotate again (a new
  grant); after it, any device that signs in gets the new key through the
  password and the older one through the keyring. "The head's mk flips last"
  holds because there is no earlier step for it to follow.
- **What still derives from the master key** (labels.rs audited):
  - *Wrapped or sealed under it, moved by the rotation at once:* the password
    and recovery wraps (purposes 1, 2), the five roots (22–26), the keyring
    record (27).
  - *Account records under it, opened through the keyring, sealed again at
    their next write:* every other purpose (4–21, 28).
  - *Derived from it, private to a device and rebuildable:* the manifest-pins
    key (`MANIFEST_PINS_V1`/`MANIFEST_PINS_KEY_V1`, `local_state`) and Chat's
    local data key (`CHAT_STORE_V1`/`CHAT_LOCAL_V1`, `chat_store::LocalCipher`):
    both opened by trying each key newest first and sealed again under the
    current one.
  - *Derived from it, moved under the Drive root by main's Drive-root slice
    (which merges before this one):* the top-level name hash key
    (`DRIVE_NAMES_V1`/`DRIVE_TOP_LEVEL_NAMES_V1`), own collection keys and
    owner link key copies (Drive envelopes under the master key).
  - *No longer derived from it (moved to the object-id root here):* the head's
    id key (`ACCOUNT_HEAD_V1`/`ACCOUNT_HEAD_ID_KEY_V1`) and the mail-search
    database name (`MAIL_SEARCH_WRAP_V1`/`MAIL_SEARCH_LOCATOR_KEY_V1`).
  - *Not the master key:* the OPAQUE master-key KEK derives from the export
    key (`OPAQUE_MASTER_KEY_KEK_V1`).
  Nothing else moves with a rotation.
- **Escrow plaintext is versioned:** a version byte (1), then length-prefixed
  parts (u16 each): the master key, then the identity root. A third value (the
  keyring) is a new version, not a new organization suite.
- **Releasing escrow rotates the master key and all five roots**, each to its
  next generation (identity-rotation.md §4). Open decision, for the
  post-wipe flow (not built): rotating the pseudonym and call-link roots at a
  release is a visible leave-and-join in every group and a new call-link
  owner; not rotating them leaves the former admin able to link the member's
  group pseudonyms. The formats allow both.
- **Successions in the manifest** (`AccountManifestV3.successions`, newest
  last, at most 16): each entry names the account id, the previous authority
  and its identity-root generation, the new authority and its generation, and
  the hash of the last manifest the previous authority signed; the previous
  authority signs it under `ACCOUNT_SUCCESSION_BY_PREVIOUS_V1`, the new one
  under `ACCOUNT_SUCCESSION_BY_NEW_V1`. Readers verify each, that they chain
  authority to authority and generation to generation, and that the newest
  ends at the manifest's own authority; they never trust more because of
  them, and contacts still see a safety-number change. No writer adds one
  before the identity rotation flow exists. A manifest without any signs the
  same bytes as before the field existed. Vectors:
  `kutup-chat-proto/tests/vectors/account-succession-v1.json` (absent, two
  valid, a wrong signature).

## Decisions (2026-11-15, main session)

1. **Web reading is in this slice:** the session keeps the generation and the
   keyring, and the WASM opens take the keyring. A rotation after the wipe is
   proven to need no format change only if the web reads through it. There
   is no site-setting toggle, and the CLI command is not hidden.
2. **A new recovery phrase at every rotation,** as at registration: shown
   once, confirmed, and the old phrase stops working.
3. **Gap 1, agreed,** and the head also records the object-id root's
   generation next to the identity and Drive ones. A head of another
   object-id generation is `rootGenerationMismatch` too, because releasing
   escrow rotates the object-id root.
4. **Gap 2, agreed:** the Chat store key becomes purpose 28.
5. Gap 3 as described. **Numbers:** purposes 27 and 28; migration
   `20261111140000`. Main's Drive-root slice owns collection keys, link
   owner copies and `top_level_hash_key`, so this slice leaves them alone.

## Size

About 4–5 days with the web part, about 3 without it. The server
transaction and `MasterKeys` replacing `&[u8; 32]` across crates are most
of it.
