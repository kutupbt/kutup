# What to unify before the wipe

**Status:** audit and proposal, 2026-10-22, for the user's review. Nothing is
built. Read-only audit of origin/master `9ced6cf7`, PR #320
(`feat/chat-account-identity-client`) and the Drive block-format plan
([`drive-block-format.md`](drive-block-format.md), PR #321).

The user's request (2026-10-22): "if we wipe lets unify thing that needs to be
unified for better simpler elegant architecture like file format account
identity etc". Later, also: "unify cryptography, for example one modular secure
hash function, one modular symmetric enc function, so when needed I directly
change aes256 to aes512 for example or sha256 to something else."

The wipe already bundles:
- the Drive block format (#321);
- one Chat identity per account (#320,
  [`account-identity-key.md`](account-identity-key.md));
- removing the X25519 suite-1 upgrade path;
- the migration squash;
- removing MLS.

This note asks one question. Which parallel mechanisms do the same job in
different ways, and are cheap to merge only while there is no data to
migrate? It is ruthless about value: four deep changes are worth the wipe, and
most of the rest are code cleanups that can happen any time. A "Not unifying"
list names what must stay separate, and why.

Paths are relative to the repository root. `crypto/` means
`crates/kutup-crypto/src`, `srv/` means `crates/kutup-server/src`, `fe/` means
`frontend/packages`.

## Summary

**Recommended for the wipe**, in rank order:

| # | Item | Why it needs the wipe | Size |
|---|---|---|---|
| W1 | **One account-record envelope** (`AccountRecordV1`) for every account-private sealed value: about 12 hand-written formats become 1 | persistent format | M |
| W2 | **One primitive layer and one suite table** (crypto agility) | the suite ids in every header | M (formats) + L (call sites, code-only) |
| W3 | **One account-records service** (Signal's Storage Service): generic records under the account head, replacing the per-list tables and the private hash chains | persistent tables | L |
| W4 | **Calendar keys on account-level keys**, not mail address keys | persistent keys (the calendar is a week old) | M |
| W5 | **One device list per account**: collab device keys inside #320's manifest V2 | manifest format, device tables | M |
| W6 | **Key-hierarchy fixes**: derive-or-store, a master-key generation field, one label style | persistent labels and headers | S |
| W7 | **Permanent ids in the schema**: no username-keyed rows, and one account-id column name | persistent schema (squash) | S–M |

**Code-only, any time:** move chat-core's own crypto into kutup-crypto; drop
the Chat WASM from five apps; one sealed browser store; one settings and
rate-limit registry; one storage charge; one federation outbox; one cursor
format; generic push subscriptions; one system-mail builder; one signed-chain
verifier; frontend helper and boot cleanups. Two policy errors also need fixing
now: a wrong RSA advisory waiver, and the "no ring" claim.

**Not unifying:** OpenPGP for Mail; libsignal's formats; the libsignal identity
key (it stays random); TLS, OPAQUE, KDBX, SSH agent, TOTP, VAPID, DKIM and
WKD; the Drive shared-object envelope and the account-record envelope (two
families on purpose); the account head and the signed chains (a MAC versus
signatures a peer checks); the mail signed key list and the account manifest;
sessions and the federation transport, which are already one.

---

## W1. One account-record envelope

### Today

The account seals small private values under keys derived from the master key
(MK), each in its own hand-written format. Each one repeats the same
construction: XChaCha20-Poly1305, a 24-byte nonce, an HKDF subkey of the MK,
AAD over some mix of magic, suite, label, key binding, id and revision, and
padding to a bucket. Yet no two are the same:

| Value | Format | Where | Differences |
|---|---|---|---|
| Contact card | `KUTCC2` suite 2 | `crypto/contact_card.rs:43,309` | binding and UID in the AAD, not in the header |
| Mail folder, label and filter names | `KUTMN2` suite 2 | `crypto/mail_names.rs:36,106` | kind and id in the AAD |
| Identity pins | `KUTIP3` suite 3 | `crypto/identity_pins.rs:44,1006` | **no list id bound**; the docs still say `KUTIP2` |
| Chat group list entry | `KUTPGL1` | `crypto/chat_group_list.rs:34,230` | AAD hashes a header slice; a fixed 4032 B |
| Chat contact list entry | `KUTPCC1` | `crypto/chat_contact_list.rs:37` | a copy of the group list (135-line diff), 2048 B |
| Photos library | `KUTPPL1` | `crypto/photos_library.rs:28,121` | its own previous-digest chain and incarnation |
| Chat attachment ledger | `KUTPCL1` | `crypto/chat_attachment_ledger.rs:92,207` | its own previous-digest chain |
| Account head / local anchor | `KUTAH1` / `KUTAL1` | `crypto/account_head.rs:43,273,839` | own AAD style |
| Revision-guard seen record | none (48 B) | `crypto/revision_guard.rs:77` | **no magic or suite** |
| Mail search store-key wrap | `KUTMSW1` | `crypto/mail_search.rs:34` | |
| Joined meetings | none | `crates/kutup-chat-core/src/call_link.rs:444-528` | **constant AAD only**; binds no account or entry |
| Chat profile key, own copy | `kutup/chat-profile/wrap/v2` | chat-core `profile.rs` | hand-written HKDF and AEAD in chat-core |
| Pass vault secret | `AccountEnvelopeV1` purpose 6 | `crypto/account_envelope.rs` | already the generic one |

`AccountEnvelopeV1` (`KUTPAE1`) already is the right design. It has purposes,
each with a policy (does it name an object, how is its length padded, does it
carry a revision), and a server validator (`validate_for`). It is used only for
key wraps and Pass secrets. Everything else above reinvented it.

### What the references do

- **Signal** has one encryption for every record of the account's synced state:
  contacts, groups, the account record, call links and chat folders. Each
  record is a `StorageRecord` (`Signal-Desktop/protos/SignalStorage.proto:71`),
  sealed under `deriveStorageItemKey(recordIkm, id)`
  (`ts/Crypto.node.ts:248`). The record type is a field, not a new format.
- **Proton** seals every private value in one format (an OpenPGP message to the
  user or address key). Each app differs only in its plaintext.

### Proposal

Extend `AccountEnvelopeV1` into `AccountRecordV1`. It gets a new magic and
suite, and its purpose registry covers every row of the table above. The
header is the AAD:

```text
magic        8   "KUTPAR1\0"
suite        u16 (W2: the one suite table)
purpose      u16 closed registry: contactCard, mailName, identityPins,
                 chatGroup, chatContact, photosLibrary, attachmentLedger,
                 accountHead, revisionSeen, joinedMeeting, profileKeyWrap,
                 passVaultSecret, mailSearchKey, masterKeyWrap, ...
mk_gen       u32 generation of the master key that sealed it (W6)
binding      16  users.key_binding (the permanent random binding, never a name)
object       16  the record id (a UUID, or an HMAC of it for lists the server must not see)
revision     u64 for mutable purposes, 0 otherwise (policy-checked)
nonce        24
length       u32
```

- **Key:** `HKDF(MK-derived record root, info = suite ‖ purpose ‖ binding ‖
  object)`, so every record has its own AEAD key, as `AccountEnvelopeV1` and
  `DriveEnvelopeV1` already have.
- **Padding:** per purpose (`Exact`, `Fixed(n)`, `Bucket(256)`), applied once by
  the envelope, as today's policy table does.
- **The server** checks every write with one `validate_for(purpose, binding,
  object)`, and reads the revision from the header for its compare-and-swap
  (W3). It never reads a second field.
- **One vector file** (`account-record-v1.json`), with one refusal set per
  purpose, replaces about nine.
- **What is fixed along the way:** the pins' missing list id, the constant
  AAD of joined meetings, the guard record with no header, and chat-core's
  hand-written profile wrap.

**Needs the wipe:** yes. Every format listed is persistent.
**Value:** security (one audited construction; it closes the three binding
gaps), simplicity (one module and one validator instead of about 12) and
maintenance (a new list or setting is one purpose line).
**Size:** M. Each module keeps its plaintext codec and loses its envelope
code. Net deletion is likely over 2,000 lines.
**Risk:** low. It is the construction `AccountEnvelopeV1` already ships with
vectors. The main risk is mistakes in the bulk move, which the per-purpose
refusal vectors catch.
**Slice:** `wipe/account-record`, after W2's suite table. Dependencies: W2.

---

## W2. One primitive layer and one suite table (crypto agility)

The user's request was "one modular secure hash function, one modular
symmetric enc function", so that changing an algorithm is a single change.

### First, a correction

**AES-512 does not exist.** AES has 128-, 192- and 256-bit keys only. AES-256
and XChaCha20 (Kutup's AEAD, also with a 256-bit key) are already the strongest
standard choice. Against a quantum computer, Grover's search only halves the
effective strength, to about 128 bits, which stays out of reach. So Kutup's
symmetric layer needs no upgrade.

The swaps that may really come are these:
- **hash families:** SHA-256 → SHA-3 or BLAKE3, if SHA-2 is ever weakened;
- **KEMs:** already X-Wing (X25519 + ML-KEM-768) for Drive shares; the
  remaining X25519 paths move to ML-KEM hybrids ([`pq-shares.md`](pq-shares.md);
  Mail waits on rPGP, [`mail-pq-openpgp.md`](mail-pq-openpgp.md));
- **signatures:** Ed25519 → an Ed25519 + ML-DSA hybrid, for the authority, the
  manifest, the chains and collection epochs.

A suite registry is what turns each of those into a one-line change.

### Today (the inventory)

Algorithms are named directly almost everywhere:

- **kutup-crypto** (the intended single home):
  - `chacha20poly1305` in 24 files, HKDF in 27, HMAC in 6;
  - dryoc for secretstream (`stream.rs:14`), Argon2id (`kdf.rs:16`,
    `opaque.rs:28`) and random bytes (about 25 modules);
  - 27 `OsRng` uses alongside dryoc's RNG;
  - **no shared AEAD helper.** About 30 modules each build
    `XChaCha20Poly1305::new` + `Payload{aad}` + nonce + concat by hand, each
    with its own `NONCE_LEN`/`TAG_LEN`.
- **kutup-chat-core** does its own crypto in a separate Cargo root:
  - HKDF in 9 places, XChaCha in 9: `profile.rs:762,790,807,848`,
    `call_link.rs:224-493`, `invite_link.rs:91-158`,
    `db/store_cipher.rs:91-286`;
  - HMAC: `store_cipher.rs:100`;
  - HPKE called directly (`mls_engine/delivery.rs:10-12,233`; it goes away with MLS);
  - `x25519-dalek` declared and never used.
- **kutup-chat-proto:** HKDF in `sealed_sender.rs:19` and `mls/delivery.rs:522`;
  HMAC in `group_route.rs:650,683`; about 51 `hex(sha256(..))` key ids.
- **kutup-server:**
  - SHA-256: 71 calls in 36 files (token hashes, digests);
  - HMAC-SHA256: 13 calls in 8 files. The pattern "subkey = HMAC(root, label)"
    is written out 4 times (`auth_check.rs:254`, `middleware.rs:81`,
    `account_ids.rs:78`, `handlers/auth.rs:1890`);
  - HKDF: `chat_groups/keys.rs:56`;
  - RNG in four styles: rand 0.8 `thread_rng`, rand 0.8 `OsRng`, rand 0.9
    `OsRng`, p256's `OsRng`;
  - three `constant_time_eq` copies.
- **kutup-cli:** SHA-256 in 11 files. The master key and recovery entropy come
  from `thread_rng` (`register.rs:61-65`) and other keys from `OsRng`.
- **The browser:**
  - libsodium JS runs secretstream (12 calls), SHA-256 (20 calls, Chat),
    random bytes (master key and recovery entropy, `fe/crypto/src/index.ts:190`)
    and Ed25519 (`fe/collab/src/sign.ts:8,14`, `devices.ts:13`). The last one
    is outside the "only if 10× faster" rule in
    `docs/cryptographic-dependencies.md:26-29`;
  - WebCrypto SHA-256 in 10 places, and HMAC once (the group-call
    controller's participant tags; removed with MLS, back with slice 4's
    group calls).
- **Two implementations of one primitive:**
  - XChaCha: dryoc secretstream, RustCrypto and libsodium JS;
  - SHA-256: sha2, libsodium and WebCrypto;
  - Argon2: dryoc and rust-argon2;
  - RNG: dryoc, rand and getrandom.
  - In the lockfile: sha2 0.10/0.11, hmac 0.12/0.13, rand 0.8/0.9/0.10.
- **Suite ids are mostly cosmetic.** Most enums have one value, and many
  formats compare against a constant. The numbering is unaligned: Drive 1,
  AccountEnvelope 2, pins 3, contacts 2, photos 1.
- **Policy is not enforced.** `clippy.toml` restricts only `reqwest`, and
  `deny.toml` has no `[bans] deny` list.
- **Two policy errors** (fix at once, whatever is decided here):
  - `deny.toml:34-38` waives RUSTSEC-2023-0071 (RSA Marvin) because "no RSA
    private-key operation anywhere in Kutup". That is wrong:
    `crates/kutup-pass/src/ssh.rs:323-373` signs with `rsa::RsaPrivateKey`
    (the SSH agent).
  - `Cargo.toml:58-61` says "no ring anywhere", but `Cargo.lock` has ring
    0.17.14 through hickory-proto and rustls-webpki.

### Proposal

1. **`kutup_crypto::primitives` is the only module that names an algorithm.**
   It exposes operations, not algorithms:
   - `hash(suite, data)`, `Hasher`;
   - `mac(suite, key, data)` / `mac_verify`;
   - `kdf(suite, ikm, salt, info, len)`;
   - `aead_seal(suite, key, nonce, aad, pt)` / `aead_open`, with the
     nonce and tag lengths taken from the suite;
   - `sign` / `verify`;
   - `kem_encap` / `kem_decap`;
   - `random(len)` (one RNG, `getrandom`; dryoc's and rand's RNG go);
   - `ct_eq`;
   - a password KDF, `pwhash(params)`.

   The block framing ([`drive-block-format.md`](drive-block-format.md) §2) and
   the account record (W1) are built on these, not on RustCrypto types.
2. **One suite table.** A suite is a fixed tuple, listed once:

   | Suite | Hash | MAC/KDF | AEAD | Signature | KEM |
   |---|---|---|---|---|---|
   | 1 | SHA-256 | HMAC/HKDF-SHA256 | XChaCha20-Poly1305 | Ed25519 | X-Wing (X25519 + ML-KEM-768) |
   | (future 2) | SHA-256 | HKDF-SHA256 | XChaCha20-Poly1305 | Ed25519 + ML-DSA-65 | X-Wing |
   | (future 3) | SHA3-256 or BLAKE3 | … | … | … | … |

   - Every Kutup-owned header carries this suite id. At the wipe they all start
     at 1, aligned.
   - **Changing an algorithm** means adding a suite row with its vectors, and
     making it the default for new writes. Call sites do not change.
   - Readers keep older suites read-only until they are retired. At a wipe,
     old suites are simply dropped.
3. **Per-format allowlists keep what `docs/crypto-agility.md` asks for.** That
   doc says "Kutup will not define a universal `CryptoSuite`". Its reason is
   that one protocol must never be able to select or block another's
   cryptography, nor mix a KEM from one suite with a KDF from another. The
   table keeps that safe:
   - a suite is a whole tuple, never mixed;
   - each format declares the suites it accepts
     (`AccountRecordV1: [1]`, `DriveBlocks: [1]`, ...), checked on parse;
   - the suite sits in the AAD, so downgrading it fails the AEAD.

   The format's **layout version** (its magic) stays separate from the
   **suite**. A new field is a new magic; a new algorithm is a new suite.
   crypto-agility.md must be amended. That is an explicit decision for the
   user (open question 1).
4. **Purpose labels and domain separation stay at each call site**:
   `kutup/<area>/<purpose>/vN\0` (W6). The primitive layer never invents a label.
5. **Enforcement in CI:**
   - `clippy.toml` `disallowed-types` / `disallowed-methods` for `sha2::*`,
     `hmac::*`, `hkdf::*`, `chacha20poly1305::*`, `ed25519_dalek::SigningKey`,
     `rand::thread_rng`, `rand::rngs::OsRng` and `dryoc::*`, with
     `#[allow]` only in `primitives` and in the adapters (item 6);
   - `deny.toml` `[bans]` lists these crates with `wrappers` set to
     kutup-crypto (and the adapter crates), plus `ring` and `openssl` with their
     known transitive wrappers;
   - ESLint `no-restricted-imports` for `libsodium-wrappers-sumo`, and
     `no-restricted-properties` for `crypto.subtle`, outside `fe/crypto`.
     libsodium leaves the browser entirely once the block format replaces
     secretstream (#321).
6. **Where agility cannot apply.** Interoperable formats negotiate their own
   algorithms and stay behind adapters, outside the suite table:
   - OpenPGP (rPGP) for Mail, and Calendar's external invitations;
   - libsignal (Direct Chat, sealed sender);
   - TLS (rustls with aws-lc-rs, X25519MLKEM768);
   - Web Push (VAPID RFC 8292; RFC 8291 if payloads are ever added);
   - OPAQUE (opaque-ke, its own ciphersuite);
   - KeePass KDBX and the OpenSSH agent (Pass);
   - TOTP, DKIM, WKD's SHA-1, coturn's HMAC-SHA1 and HS256 JWT.

   Each adapter is one module with an `#[allow]` and a comment naming the
   standard.

**Needs the wipe:** the suite ids inside persistent headers do, so they are
set now, together with W1 and the block format. Moving the call sites is
code-only, and can start before the wipe: the primitives module first, then
crate by crate.
**Value:** maintenance and security. One place to review, the RNG unified, a
PQ signature swap becomes one row, and the lint stops new drift.
**Size:** M for the module, the table and the headers; L for moving every call
site (about 250 sites, mechanical).
**Risk:** low for the module. The real risk is a performance regression from
dynamic dispatch on block encryption. Dispatch once per object, not per call
(a `Suite` value resolves to concrete types), and benchmark against #321 §9.
**Slice:** `crypto/primitives` (code-only, first), then the header suite ids
inside `wipe/account-record` and `feat/drive-blocks`.

---

## W3. One account-records service (Signal's Storage Service)

### Today

There are seven per-app "sealed list" endpoints and tables. Each repeats list,
put(baseRevision, head) and delete(head), and all feed the account head
(`srv/account_heads.rs` `Scope` `:260`, one hard-coded SQL query per scope in
`values` `:320`):

| List | Server | Table |
|---|---|---|
| contacts | `handlers/contacts.rs` | `contacts` |
| mail names | `mail_folders.rs`, `mail_filters.rs` | `name_sealed` columns |
| pins | `identity.rs` | `identity_pins` (a single value) |
| Pass secrets | `pass.rs` | `pass_vault_secrets` |
| chat groups | `chat_group_list.rs` | `chat_group_list` |
| chat contacts | `chat_contact_list.rs` | `chat_contact_list` |
| calendars | `calendar.rs` | `calendar_members.revision` |

- The chat group and contact lists are copy-paste in kutup-crypto, the server
  (about 100 lines of difference over 300) and chat-core (two sync loops, each
  with its own random delays, due marks and flush; pins have a third).
- Three private values have **their own** rollback chains outside the head:
  - the Photos library (`KUTPPL1`, a previous digest);
  - the Chat attachment ledger (`KUTPCL1`, a previous digest plus a history
    table);
  - pins' rename anchors.
- **There are five CAS styles:**
  1. a sealed revision against `baseRevision`;
  2. the head's sequence + 1;
  3. a **plain body `revision`** (calendar members, `calendar.rs:418-470`,
     which breaks sealed-revisions.md's rule);
  4. a server-incremented revision (calendar events, Drive metadata);
  5. sequence + 1 plus a previous hash.
- **Gaps:**
  - contact groups have plaintext names, no revision and no head;
  - calendar events have no head;
  - the FFI client writes no head.
- On the web, five domain packages copy the same `xIndex()`/`listedX()`
  wrappers (`fe/contacts-core/src/api.ts:50`, `fe/calendar-core/src/api.ts:156`,
  `fe/mail-core/src/places.ts:40`, `fe/drive-core/src/identityPins.ts:240`,
  `apps/pass/src/drive/secrets.ts:55`).

### What the references do

Signal's Storage Service is one generic store for all synced account state:
contacts, groups, the account record, call links and chat folders.
- **A manifest** (`ManifestRecord`, `SignalStorage.proto:45`) holds a
  `version`, the `sourceDevice` and the list of typed record identifiers.
- **The records** are opaque, typed `StorageRecord`s.
- **Writes:** a client writes a new manifest version with its inserts and
  deletes, under compare-and-swap on that version.
- **The server** knows nothing about record types.

Kutup's account head is that manifest already, with the index HMAC'd and with
fork detection. The missing part is the generic record store under it.

### Proposal

- **One table:** `account_records (account_id, scope, record_id bytea(16),
  revision, sealed, change_xid)`. The record id is a UUID, or an HMAC of it
  where the server must not learn the id. The table carries the change-feed
  trigger ([`docs/sync-feeds.md`](../sync-feeds.md)), so caches sync
  incrementally.
- **One API:**
  - `GET /api/account/records/:scope` (cursor = the change feed);
  - `GET /api/account/records/:scope/:id`;
  - `POST /api/account/records` takes a batch of puts and deletes plus the
    next head, applied in one transaction. Each record is CAS-checked on the
    revision **read from its `AccountRecordV1` header**.
- **One client:** `AccountRecords<Scope>` in Rust (chat-core, CLI and FFI
  share it), wrapped once in TS. It replaces the five wrappers and the three
  sync loops.
- **Moved onto it:**
  - Chat groups, Chat contacts, pins, Pass secrets and the Photos library;
  - the attachment ledger. Its private chain goes; the head covers it;
  - joined meetings (now in a separate store) and the account's sealed settings;
  - the calendar list, with its member revision then sealed;
  - contact groups, which then gain a revision and the head.
- **Not moved:**
  - Contacts stay in their table: the server pages, searches and lists
    summaries, and counts contacts.
  - Mail names stay as columns on folder and label rows, which the server
    needs for message placement.

  Both keep `AccountRecordV1` and the head, so only their storage differs.
- **The scope registry** becomes data: one enum shared by the client and the
  server. Adding a scope no longer adds a SQL query to `values`.

**Needs the wipe:** yes. Tables and formats change, and three private chains go.
**Value:** high for simplicity and security. One rollback design for all
private state. It closes the gaps in contact groups and the calendar list, and
the unauthenticated calendar member revision. Calendar events stay out of the
head (open question 6).
**Size:** L. Server: about 1 new module, minus 5 handlers. chat-core: −2 loops.
Web: −5 wrappers.
**Risk:** medium. It touches every app's write path. Land it per scope behind
the integration branch, with the existing live tests per app.
**Slice:** `wipe/account-records`. Dependencies: W1. It is best landed after
#320 (the Chat contacts record carries the verified identity).

---

## W4. Calendar keys on account-level keys

### Today

Calendar E1 (#316 and before) follows Proton Calendar: each calendar has an
OpenPGP key whose passphrase is wrapped, once per member, to **that member's
mail address key** (`crypto/calendar.rs:1-17`). That has three costs:

1. **It binds a changeable value.** A rename or a removed address orphans the
   member's access. That breaks the standing rule
   ([`account-ids.md`](account-ids.md), "The rule"). The
   address key's binding is the one accepted exception, and it is accepted for
   Mail.
2. **It is not post-quantum,** and it waits on rPGP (the PQ plan). Drive shares
   and mail groups already use the account's X-Wing key.
3. **It is a second sharing model.** Mail groups wrap to the account-level
   Drive key (`crypto/mail_group.rs`); Calendar wraps to address keys.
   Revocation, members and epochs are written again in a third place.

Proton wraps calendar passphrases to address keys because, in Proton, the
address key is the only account key a peer can see. Kutup has an account-level
key that peers verify: the X-Wing Drive HPKE key, signed by the authority in
the manifest.

### Proposal

Choose one of these (open question 2):

- **(a) Minimal: wrap the calendar passphrase to the member's account X-Wing
  key.** Use the `NamedShareEnvelopeV1` construction with a new purpose,
  "calendar share", as mail groups already do. Events stay OpenPGP packets
  signed by address keys, as Proton does. This removes costs 1 and 2 for the
  key; event signatures remain address-bound and non-PQ.
- **(b) Full: a calendar is a Drive-style collection.** It gets an
  authority-signed epoch chain (`CollectionEpochStatementV1`), a key per epoch,
  members by named share and rotation on removal. Events are
  `DriveEnvelopeV1`-style records under the epoch key, signed by the author's
  share-signing key. External invitations stay `.ics` over Mail (OpenPGP).
  Everything is PQ now, there is
  one sharing model with Drive, and the member revision is authenticated.

**Recommendation: (a) for the wipe, at least.** (b) is cleaner, but it departs
from "copy Proton" more. It is the user's call, because the "follow references"
rule applies and Proton's choice here rests on a constraint Kutup does not have.

**Needs the wipe:** yes. Calendar keys and wraps are persistent, and the
calendar is a week old, so the cost of changing it only grows.
**Value:** security (no address binding, PQ) and simplicity (one share model).
**Size:** (a) S–M; (b) L.
**Risk:** (a) low, because it reuses a vetted envelope. (b) is medium.
**Slice:** `wipe/calendar-keys`, with the Calendar session. Dependencies: W1
for the calendar list record, and nothing else for (a).

---

## W5. One device list per account

Design note: [`one-device-list.md`](one-device-list.md) (approved 2026-10-25).

### Today

There are four device registries, each with its own lifecycle:
- `user_devices`;
- `chat_devices (user_id, device_id int)`;
- `chat_mls_devices`, which goes with MLS;
- `remote_collab_devices (domain, device_id)`, where **user_id is text**.

Collab devices are registered by authority-signed statements that are not
chained. Their freshness is a 30-day lease
(`crypto/device_registration.rs`; `srv/devices.rs:309,389,569`). Federated
revocations are a third, server-ordered counter (`collab_revocation_marks`).
Meanwhile #320 defines `AccountManifestV2`: an authority-signed, hash-chained
list of the account's devices, with their registration ids.

### What the references do

Signal has one device list per account: linked devices, each with a device id.
Every Signal feature (messages, calls, sync) uses that one list.

### Proposal

Make `AccountManifestV2` the account's **one device list**:
- each device entry gains an optional `collabKey` (its Ed25519 frame-signing key);
- the server keeps one `devices (account_id, device_id, …)` table, and the
  collab and Chat columns hang off it;
- "Linked devices" in Settings removes a device everywhere at once;
- collab's lease and revocation marks fold into manifest succession;
- federated peers verify collab senders against the manifest they already pin
  for Chat.

The cheap moment is **now, inside #320**, while V2 is being defined. A later V3
is possible without a wipe, because the chain allows a successor version. But
every client would then need both, and the four tables stay.

**Needs the wipe:** not strictly, but it is much cheaper with it, and with #320.
**Value:** security (one revocation that really revokes everything) and
simplicity.
**Size:** M.
**Risk:** scope creep into an approved, nearly finished PR. The alternative is
a follow-up PR on the same integration branch before the wipe. Open question 3.
**Slice:** #320 or `wipe/devices` right after it. Dependencies: #320 and the
MLS removal.

---

## W6. Key-hierarchy fixes

### Today

The hierarchy is sound and should stay as it is:
- **The MK** (random, 32 bytes) is the one root. It is wrapped by the password
  (`AccountEnvelopeV1` purpose 1, Argon2id-derived) and by the recovery secret
  (purpose 2).
- **HKDF from the MK** derives:
  - the authority (Ed25519), the Drive X-Wing key and the Drive share-signing
    key (`crypto/identity.rs:20-60`);
  - the head, record and pin keys;
  - group pseudonyms.
- **Random keys wrapped under the MK:**
  - the mail address keys, by the address-key purpose;
  - the Chat backup root;
  - the Pass vault secrets;
  - the libsignal identity, which is random and provisioned per #320. It is not
    derived and not in backups, as Signal does.
- **The OPAQUE export key** proves the password and unwraps.

This matches both references:
- **Proton:** a random user key; password-derived wrapping; per-address keys
  sealed under it (`WebClients/packages/shared/lib/keys/keyMigration.ts`); app
  keys (calendar, share and vault keys) wrapped to those keys.
- **Signal:** the AEP and master key are the root, with derived storage and
  backup keys. The ACI identity is random.

Four defects remain:
1. **Derived and also stored.** The Drive X-Wing private key is derivable from
   the MK and also stored as account-envelope purpose 3 (`DriveHpkePrivateKey`),
   with no check that the two agree. One of them should go.
2. **No MK generation in records.** Rotating the MK is a roadmap item
   ([`account-identity-key.md`](account-identity-key.md), "Device removal": a lost device keeps the MK). Every MK-derived record
   would then need re-encryption *at once*, because no header says which MK
   sealed it.
3. **Label style is inconsistent.** Some HKDF labels lack the trailing `\0`;
   some use a `None` salt while others put the label in the salt
   (`identity.rs` salt + info versus `drive_envelope.rs` salt-only).
4. **A legacy Argon2 kdf** is dead code, still exported to WASM.

### Proposal

1. **One rule: an account-level key is either derived and never stored, or
   random and stored, never both.**
   - Derived: the authority, the Drive keys and the MK subkeys.
   - Random: the libsignal identity, mail address keys, calendar and vault keys
     and the backup root.
   - Drop purpose 3. If a stored copy is ever needed for rotation, it becomes
     random and stored, and the derivation goes.
2. **Add `mk_gen` (u32)** to `AccountRecordV1` (W1) and to the account-envelope
   wraps. An MK rotation can then keep the old MK in a keyring sealed under the
   new one (as `file_keyring` and `collection_keyring` already do for files and
   folders) and re-seal lazily. No wipe is needed for the future rotation.
3. **One label grammar:** `kutup/<area>/<purpose>/v<N>\0`, the salt always the
   family label, the info always the context. Checked by a unit test that
   lists every label (a `labels.rs` registry, also a reviewer's index).
4. **Remove the legacy kdf export** (code-only).

**Needs the wipe:** items 1–3 change persistent bytes. Item 4 is code-only.
**Value:** rotation without a future wipe (high), and consistency.
**Size:** S.
**Risk:** low.
**Slice:** inside `wipe/account-record` (W1).

---

## W7. Permanent ids in the schema

### Today

- **A row keyed by a username:**
  `federated_outgoing_*shares.recipient_username` (text), against the
  account-ids rule.
- **Text ids:** `remote_collab_devices.user_id` and
  `federated_incoming_*shares.owner_account` are text, not
  `(server, account_id)` pairs.
- **Mixed names for the same concept:**
  - `user_id` (85 columns);
  - `owner_id` (calendars, and the MLS tables);
  - bare `owner` (Mail: a user *or* a mail group);
  - `*_account_id`, for remote accounts only.

  account-ids.md settled the name as `*_account_id`.
- **Fine as they are:** `mail_image_senders (user_id, address)` and
  `mail_auto_reply_sent (user_id, sender)` key external senders, which are just
  data.

### Proposal

At the squash:
- key the federated share tables by `(recipient_server, recipient_account_id)`;
- make the text ids typed pairs;
- **rename `user_id` → `account_id` everywhere**, in one mechanical commit
  against the new baseline (open question 4: this is the only cheap time,
  but it is cosmetic beyond consistency);
- keep Mail's `owner` (a user or a group) under a clear name, `mailbox_owner`.

**Needs the wipe:** the username key, yes. The renames are free only at the squash.
**Value:** the username key is a rule violation (security). The renames are
maintenance.
**Size:** S for the keys; M for the renames (mechanical, about 115 references
plus every query).
**Risk:** the renames touch every SQL statement. Do them as a separate commit,
with `sqlx prepare` and the full gate.
**Slice:** the migration squash PR.

---

## Code-only, any time

Ranked by value. None of these needs the wipe. Some are easier at the squash
because their tables only hold transient data.

1. **Move chat-core's own crypto into kutup-crypto.** That is
   `db/store_cipher.rs`, `call_link.rs`, `invite_link.rs`, `profile.rs` (whose
   `KUTPPE1` encoder sits in chat-core while the parser is in chat-proto) and
   the direct HPKE. It is the last large body of crypto outside the canonical
   crate, in a separate Cargo root whose versions drift. Pairs with W2. Size M.
2. **Drop the Chat WASM from Drive, Account, Maps, Photos and Office.** They
   load the 11 MB (3.35 MB gzip) Chat runtime only for profile-key operations
   (`fe/drive-core/src/people.ts:6,130,166`,
   `apps/account/src/features/settings/profile.ts:73,86`). Moving the profile
   module into kutup-crypto (item 1) removes it. This is the largest single
   web-performance win in the audit. Size S once item 1 is done.
3. **One sealed browser store.** Today there are four schemes
   (`fe/crypto/src/localState.ts`, chat-core `sealedStorage.ts` /
   `store_cipher.rs`, `revisionGuard.ts`, mail search `SealedStore`) and eight
   hand-written IndexedDB layers with copied `open/run/requestResult`
   (`apps/pass/src/sync/outbox.ts` ≈ `fe/files/src/upload/pendingUploads.ts`;
   `fe/files/src/mediaCache/indexedDbBackend.ts` ≈ `fe/chat-core/src/backup-store.ts`).
   - Make one `SealedIdb` in `fe/crypto`, on `KUTPLS1`, following
     docs/research/16 (Proton's model).
   - Seal the plaintext metadata that pending uploads and the media cache
     leave visible.

   Browser data is discarded at the wipe anyway, so format changes here are
   free whenever they land. Size M.
4. **One settings registry, rate limits included.**
   - Today: 81 registry limits, ad-hoc `site_settings` keys for chat_multi,
     capabilities and link joins, MLS limits hard-coded in
     `kutup-chat-proto/src/mls/delivery.rs:51-64`, 25 files with their own
     `SELECT value … parse` and 119 `const MAX_*` in the server.
   - One typed `NumericSetting` registry, read through one accessor, fed into
     the admin UI. This follows the standing "limits are site settings" rule.
   - Merge the three identical counter tables (`chat_anonymous_`,
     `chat_media_`, `chat_mls_rate_counters`) into one at the squash.
   - Size M.
5. **One storage charge.** There are 44 inline `UPDATE users SET
   storage_used_bytes` in 18 files, and identical `charge()` functions in
   `handlers/contacts.rs:192` and `handlers/calendar.rs:253`. Make one
   `storage_pool::charge(tx, owner, delta, app, kind)`, which also feeds the
   usage-by-app page. Size S–M.
6. **One federation outbox.**
   - Today: 8 outbox tables, 3 inbound-transaction tables, 4 sequence tables,
     3 replay mechanisms and about 5 retry loops, each with its own backoff.
     The transport itself is already one (`srv/federation/transport.rs`).
   - Make one `federation_outbox (kind, destination, sequence, payload,
     attempts, next_attempt_at)` with one worker.
   - The MLS removal deletes four of the tables. Do the rest at the squash
     (the queues are transient).
   - Size M.
7. **One cursor and page contract.** There are six or more cursor formats and
   about nine pairs of page-size constants, and contacts uses OFFSET. Make one
   opaque cursor type (the change feed's `xid.uuid` where a feed exists) and
   page sizes as site settings. Size M; do it per endpoint as touched.
8. **Generic push subscriptions** before Calendar and Mail need them.
   `chat_push_subscriptions` is keyed by the Chat device integer. Use
   `push_subscriptions (account_id, device_id uuid, apps)` on the W5 device id,
   with one VAPID key. Size S, after W5.
9. **One system-mail builder.** Four paths hand-build RFC 5322
   (`mail/notice.rs`, `handlers/mail_forwardings.rs:597`, `mail/auto_reply.rs`,
   `mail/forwarding.rs:788`). Make one builder that sets From, Date,
   Message-ID and Auto-Submitted. Size S.
10. **One signed-chain verifier.**
    - Today: the manifest V1/V2, the mail SKL, mail group key lists, the
      rename chain, collection epochs, the backup manifest, `GroupChangeV1`
      and the federation policy each write their own successor check
      ("sequence + 1, previous hash, first has none") and history page.
    - Make a generic `chain::check_successor<T: ChainLink>` and one history
      page contract. **Encodings stay as they are**: each is signed under its
      own domain, and that is correct.
    - Size M.
11. **Client-type list in one place.** It is in three SQL CHECKs plus the Rust
    `ClientType` enum (`srv/sessions.rs:38-110`), and has already drifted
    (android-/ios- types). At the squash, drop the CHECKs and let the Rust enum
    be the single source. Size S.
12. **Frontend boilerplate:**
    - about 14 hex, 20 base64 and 9 SHA-256-hex helpers, while
      `fe/crypto/src/base64.ts` exists;
    - 10 copies of `main.tsx`, `Boot.tsx`, `NotFoundPage` and the head banner;
    - 4 WASM loaders;
    - about 5 raw `fetch` calls with hand-built Bearer headers.

    Size S each.
13. **Docs and tests:**
    - `KUTIP2` → `KUTIP3` in sealed-revisions.md and v1-format-inventory.md;
    - the thumbnail label in drive-thumbnails.md;
    - the `KUTPCE1` magic collision (collection epoch versus Chat ledger
      entry, allowlisted in `tests/magics_unique.rs:12`). Remove it at the
      wipe, when W1 retires the ledger magic.
14. **Fix now:** the `deny.toml` RSA waiver and the "no ring" comment (W2).
15. **Raw keys used directly as AEAD keys** (DKIM keys, the OPAQUE setup, the
    forwarding parameter, live location and group avatars). Derive a purpose
    subkey through the primitive layer. Server-side secrets can be re-sealed
    with a migration, so this needs no wipe. The group avatar and joined
    meetings formats are persistent and go with W1/W3. Size S.

---

## Not unifying

- **OpenPGP for Mail.** It is interoperability with every other mail client.
  Address keys bind the address, the one accepted exception (Proton does the
  same). The mail signed key list stays separate from the account manifest: it
  is per address, it is published to outsiders (WKD and key lookups), and it
  is Proton's design. Mail keeps rPGP's algorithm negotiation; PQ waits on rPGP.
- **libsignal's formats and sessions,** sealed sender and the safety number.
  The **libsignal identity key stays random and provisioned**, not derived
  from the MK (#320 Q-a, as Signal): it speaks for the account in Chat and must
  be resettable without changing the MK.
- **MLS:** it is being removed, so nothing is built on it.
- **TLS, OPAQUE, KDBX, the SSH agent, TOTP, VAPID, DKIM, WKD SHA-1, coturn
  and JWT:** standards with their own negotiation, kept behind adapters (W2.6).
  Pass vaults stay KDBX, for KeePass compatibility.
- **The Drive shared-object envelope (`DriveEnvelopeV1`) and the account
  record (W1) stay two families.** Drive objects live under file, folder,
  album and link keys that other people hold, and bind epochs and parents.
  Account records live under the MK alone. Merging them would make one
  family's key schedule depend on the other's. Collab frames
  (`KUTPCF2`, signed per device, real time) also stay their own.
- **The block framing's three headers** (Drive, Chat attachment, backup media)
  stay separate over one shared framing, as #321 decides.
- **The account head and the signed chains stay two kinds.** The head is a
  MAC under the MK: only the account checks it, and any of its devices may
  write it. Manifests, epochs, SKLs and rename chains are signatures that
  peers verify. A MAC can't serve a peer, and signing the head adds nothing
  for the owner. Only the verifier code is shared (code-only item 10).
- **Collection epochs and the file-key chain stay separate.** One is signed
  and peer-verifiable; the other is unsigned, and holds because only key
  holders can forge it. They are different structures for different threats.
- **The change feed and the account head stay separate.** The feed keeps
  caches current, and the head proves freshness. W3 uses both: the feed as the
  cursor, the head as the check.
- **The mail-group storage pool:** a shared mailbox owns its quota, and that
  is a different owner, not a duplicate.
- **Already unified, so leave them:**
  - sessions (one `auth_sessions` table, with Proton-style forks per app
    origin);
  - the federation transport (one signed HTTP stack);
  - the TLS client builder;
  - the account head client core (`fe/session/src/accountHead.ts`);
  - the API client (one axios instance).

---

## Slices and order

```text
now (code-only)          crypto/primitives + lint + deny fixes      (W2 module)
                         chat-core crypto → kutup-crypto            (code 1, 2)
integration branch       feat/drive-blocks (#321 slices 3–7)
  (land together,        wipe/account-record   W1 + W6 + W2 headers
   just before the wipe) wipe/account-records  W3            needs W1
                         wipe/calendar-keys    W4 (a)        needs W1 (list record)
                         #320 or wipe/devices  W5            needs #320, MLS removal
                         squash                W7 + counters, outboxes, client-type CHECKs
after                    code-only items 3–13, in any order
```

- One integration branch for the whole wipe, or `feat/drive-blocks` widened
  to it, so master stays deployable without changing data until the release
  (as #321 §6 proposes).
- Each slice keeps its own vectors and its own live tests. The combined browser
  gate runs once on the integration branch, before the wipe.

## Open questions for the user

1. **Crypto agility:** amend `docs/crypto-agility.md` ("no universal
   CryptoSuite") to one suite table of whole tuples, with per-format
   allowlists (W2.3)? Or keep separate registries per purpose, still behind
   one `primitives` module? Either way, the primitives module and the lint
   happen.
2. **Calendar:** (a) wrap calendar keys to the account X-Wing key and keep
   OpenPGP events, or (b) model calendars as Drive-style collections, which
   departs further from Proton? The recommendation is (a) at least, now.
3. **Devices:** put collab device keys into #320's manifest V2 now, or in a
   separate PR before the wipe?
4. **Column names:** rename `user_id` → `account_id` across the schema at the
   squash (cosmetic, but the only cheap time)?
5. **W3's reach:** should Contacts move into the generic records table as
   well (giving up server-side listing order and counts), or keep its table
   with the shared envelope and head, as proposed?
6. **Drive metadata and calendar events in the head:** both are still out by
   earlier decision. Keep them out for this wipe? The block plan adds
   RevisionGuard for Drive metadata.
7. **MK rotation:** add the `mk_gen` field now (W6.2) even though rotation
   itself is not scheduled? The recommendation is yes; it costs 4 bytes.
