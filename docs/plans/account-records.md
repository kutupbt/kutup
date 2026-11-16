# W3: one account-records service

Status: **approved** 2026-11-16 (second session's note, main session's review; decisions at the end), for
docs/plans/wipe-unification.md W3. It follows Signal's Storage Service: one
generic store for the account's synced private state, with the account head as
its manifest. Branch `wipe/account-records`, on #417. It will be rebased onto
`wipe/integration` once that is green. Migrations from `20261111180000`;
record purposes from 31.

## 1. Today

The account head (`srv/account_heads.rs`) covers seven scopes. Each has its own
table, routes and compare-and-swap, and `values` has one hard-coded SQL query
per scope.

| List | Server | Storage | CAS | Head | Clients |
|---|---|---|---|---|---|
| contacts | `contacts.rs` | `contacts` (card, plaintext signed summary) | header rev vs `baseRevision`; delete: head only | yes | web |
| contact groups | `contacts.rs` | `contact_groups`, **name in plaintext** | none (last write wins) | **no** | web |
| mail names | `mail_folders.rs`, `mail_filters.rs` | `name_sealed` columns | header rev vs `baseNameRevision` | yes | web |
| identity pins | `identity.rs` | `identity_pins` (one row) | header rev vs base | yes | web, chat-core, CLI; FFI **without a head** |
| Pass secrets | `pass.rs` | `pass_vault_secrets` (no revision column) | header rev vs base; delete/forget: head only | yes | web, CLI |
| Chat groups | `chat_group_list.rs` | `chat_group_list` | header rev vs base | yes | chat-core (web transport); FFI none |
| Chat contacts | `chat_contact_list.rs` (a copy of the above) | `chat_contact_list` | the same | yes | the same |
| calendars | `calendar.rs` | `calendar_members.revision`, **plaintext from the body** | body revision vs base | yes | web |
| Photos library | `photos.rs` | `photos_library`, **its own chain** | rev+1 and previous digest | no | web |
| attachment ledger | `chat_media.rs` | entities + history + operations, **its own chain**, its own cursor | rev+1 and previous digest | no | web |
| joined meetings | `call_link_history.rs` | `chat_joined_meetings` | none (immutable) | no | web |

Four clients duplicate the index and write logic:
- the web, in five packages (`contacts-core`, `calendar-core`, `mail-core`,
  `drive-core`, `pass`) plus Chat's transport;
- chat-core, with two sync loops (groups and contacts, each with its own
  delays and due marks) plus the pins flush;
- the CLI (`account_head.rs`);
- the FFI, which writes pins without a head and has no lists.

Only `mail_messages` carries the change feed (`srv/change_feed.rs`).

## 2. Proposal

### 2.1 One store

- **Table `account_records`:**
  - `user_id`;
  - `scope smallint`;
  - `record_id bytea`: 16 bytes (a UUID) or 32 (an HMAC under the object-id
    root, `hashed_object`), as the scope says;
  - `revision bigint`: read from the record's header and stored for the index,
    never taken from a body;
  - `envelope bytea`, `created_at`;
  - `change_xid xid8` with the change-feed trigger, and
    `account_record_tombstones` for deletes, as `mail_messages` has
    (docs/sync-feeds.md).
  - Primary key `(user_id, scope, record_id)`.
- **The scope registry** is data, one Rust enum shared by the server and the
  clients (`kutup_crypto::account_records::Scope`). Each scope states:
  - its wire name and number;
  - its record purpose (which fixes the length, the object and mutability);
  - its record-id form;
  - its maximum count, an admin site setting (limits-are-site-settings);
  - whether it is in the head;
  - its server check, if any. Only Pass secrets has one: the vault file must
    be live and the caller's.

### 2.2 One API

- `GET /api/account/records/:scope?after=<cursor>`: a page of the change feed
  (records, tombstones and the next cursor), read in one snapshot together
  with the head that covers it.
- `GET /api/account/records/:scope/:id`.
- `POST /api/account/records` with `{ head, puts: [{ scope, id, baseRevision,
  envelope }], deletes: [{ scope, id, baseRevision }] }`.
  - It is applied in one transaction under the account lock, and the head
    advances last (`account_heads::advance`).
  - Every put and every delete is checked against its base revision, the
    deletes too, which closes today's gaps.
  - A put's new revision is its header's (`check_follows`). A record of an
    immutable purpose takes only `baseRevision` 0, and replaying the same
    bytes is a no-op.
  - A conflict answers `409 revision_conflict` with the current revision of
    each record that conflicted.
- `values` for the record scopes becomes one generic query on
  `account_records`. Contacts, mail names and calendars keep their own query
  (§2.4).

### 2.3 One client

- **`kutup_crypto::account_records`** holds the logic with no I/O:
  - the scope registry;
  - checking an index against a verified head;
  - building a batch and its next head from a verified index (on #417's
    `HeadKeys` and `MasterKeys`);
  - merging the feed into a local copy.

  Transport is a trait; the CLI, chat-core and the FFI implement it. The web
  reaches it through one WASM handle and one TS wrapper (`AccountRecords`) in
  `@kutup/session`, which replaces the five wrappers.
- **One sync loop in chat-core** for every scope it keeps: groups, contacts,
  pins. It has one due mark and one random delay, both site settings. Today's
  two loops and the pins flush go.
- **The FFI** writes through the same core, so its pins carry a head.

### 2.4 What moves, and what stays

Moves onto `account_records`:
- **Chat groups, Chat contacts, identity pins, Pass secrets:** the same
  envelopes, purposes 11, 12, 10 and 6.
- **The Photos library** (purpose 13), one record. Its private chain goes:
  the record stops being chained and its header revision is CAS'd under the
  head like any other. `previous_envelope_digest` leaves the format.
- **The Chat attachment ledger** (purpose 14), one record per entity. The
  history table, the private chain and the ledger's own cursor go; the change
  feed replaces them. The operation-id idempotency stays: a replayed batch is
  a no-op by revision.
- **Joined meetings** (purpose 15, immutable). The cap of 100 becomes the
  scope's maximum count; the oldest is deleted in the same batch.
- **Contact groups:** a new purpose 31, `ContactGroup`, whose plaintext
  follows the format-evolution rule (`v`, optional `min`, kept `extra`) and
  holds the name and colour. It gets a revision and the head. The plaintext
  `contact_groups.name` goes. The server still needs group ids to check a
  summary's `groups`; it reads them from the record ids.
- **A calendar's own settings:** a new purpose 32, `CalendarSettings`, one
  record per calendar the account belongs to, keyed by the calendar id. It
  holds the colour, the display flag and the default reminders, under the
  format-evolution rule, and replaces the plaintext `revision` and those
  columns of `calendar_members`. The member row keeps what the server needs:
  permissions and the passphrase key packet.

Stays:
- **Contacts:** the server pages, sorts, counts, autocompletes and charges
  them. They keep their table and their head scope, and their delete gains the
  base-revision check.
- **Mail names:** the server places messages with the folder and label rows,
  so the names stay columns there, under the head as today.
- **The Chat profile key wrap:** one field of the peer-facing profile row.
- **Calendar events:** outside the head (open question 6 of the parent
  plan).

### 2.5 Rollback protection

Every moved scope is covered by the head, so the three private chains go
(Photos, the ledger, and the ledger's local chain pins). The pins' rename
anchors stay: they chain a peer's renames, not the account's state. Local
chain pins (purpose 21) stay for anything left outside the head.

## 3. Slices (each its own commit, gated)

1. **Server:** the table, the trigger and tombstones, the registry, the three
   routes, generic `values`, and the batch CAS. The old routes stay until
   their clients move.
2. **The Rust core and the CLI** (pins, Pass secrets); the FFI's pins with a
   head.
3. **chat-core:** one loop for groups, contacts and pins; the web's Chat
   transport on the new API.
4. **The web wrapper** replaces the five; pins and Pass secrets move.
5. **Photos library and attachment ledger** move, and their chains go (format
   change).
6. **Contact groups and calendar settings** (new purposes 31 and 32) and joined
   meetings move. Then the old tables and routes go.

## 4. Size and risk

- **Size:** L, about six slices. Most of the work is client code; the server
  loses five handlers.
- **Risk:** medium. It touches every app's write path. Each slice keeps the
  app's live and browser tests, and moves one scope at a time behind the old
  routes until its clients are on the new one.

## Questions

1. **The attachment ledger's history:** does any client need an entity's
   older revisions, or only the newest? The web replays the history in cursor
   order to rebuild the newest state. **Proposed:** the newest only, with the
   feed for changes.
2. **Account sealed settings** (rollback-protection.md mentions them): there
   is nothing to move today. **Proposed:** no scope until a feature needs one;
   the registry makes adding it a row.
3. **Contact groups' plaintext name:** the server stops seeing group names.
   Nothing on the server uses them. **Proposed:** yes.

## Decisions (2026-11-16, main session)

1. **The ledger keeps the newest revision per entity only**, as Signal keeps
   only the latest record state.
2. **No sealed-settings scope** until a feature needs one.
3. **Contact group names leave the server's view.**
4. **Record ids are never a plaintext name or id:** every scope's id is
   `hashed_object` under the object-id root, or random. The registry states
   which, and the server refuses another length. (Pass secrets: see the open
   point below.)
5. **A page and its head come in one snapshot,** and a client applies a page
   only after it has verified that head against its anchor (the generations
   map included). The core refuses an unverified page; it has no path around
   that.
6. **No data migration** (the wipe). The last slice deletes the old tables and
   routes, with no shims.
7. **Calendar settings** are designed against W4 (`wipe/calendar-keys`
   fd213304: `calendar_members` lost `address_id` and `passphrase_key_packet`
   and gained `passphrase_share`).
8. **Order:** the build is based on `wipe/integration` once it is green. The
   server slice and the Rust core ship first, so the clients can follow in
   parallel.

9. **Pass secrets keep the Drive file id as their record id**, the one named
   exception to decision 4. The server already knows the id (a Drive row),
   and today's table is keyed by it. What it reveals is that this file is a
   vault the account holds a key for, the same as today. It keeps the
   server's check that the file is live and the caller's, and the key's
   removal when the file is deleted. Every other scope's id is
   `hashed_object` or random. The registry states the exception and why.
