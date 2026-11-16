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
  - `record_id text`, in the scope's id form, the same string the head's
    index names: base64url of `hashed_object` under the object-id root (43
    characters), a Drive file id (Pass, decision 9), or the one fixed id of a
    single-record scope (`pins`). The record's sealed object is the id's
    bytes, so a client opening a record under another id fails;
  - `revision bigint`: read from the record's header and stored for the index,
    never taken from a body;
  - `envelope bytea`, `created_at`;
  - `change_seq bigint`: the account's change counter (below), and
    `account_record_tombstones` for deletes, forgotten after a site-set
    number of days, past which an older cursor is told to start over, as
    docs/sync-feeds.md's floors do.
  - **Why a counter, not `change_xid`:** every write here holds the account
    lock, and the counter (`account_record_feeds.change_seq`) is bumped under
    it, so writes commit in counter order and any snapshot sees an exact
    prefix. The page and its head then always agree. A transaction-id cursor
    must stop below the oldest open transaction on the whole server, which
    would leave a committed write out of a page whose head already covers it.
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

- `GET /api/account/records/:scope?after=<seq>`: a page of the scope's
  changes after `after` (records and tombstones in counter order, at most a
  site-set number), the next cursor, `more`, and the account head, all from
  one snapshot. `after=0` (a new device) lists every record and is never
  told to start over; a cursor below the forgotten tombstones' floor is
  (`resync`).
- `GET /api/account/records/:scope/:id`.
- `POST /api/account/records` with `{ head, puts: [{ scope, id, baseRevision,
  envelope }], deletes: [{ scope, id, baseRevision }] }`.
  - It is applied in one transaction under the account lock, and the head
    advances last (`account_heads::advance`).
  - Every put and every delete is checked against its base revision, the
    deletes too, which closes today's gaps.
  - A put's new revision is its header's (`check_follows`). A record of an
    immutable purpose takes only `baseRevision` 0.
  - A retried batch that already landed fails its revision checks: the
    client reads again and finds its change there (Signal's model). No
    replay table.
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
  permissions and, after W4, the member's `passphrase_share`. The record id is
  `hashed_object` of the calendar id, so the server can't tie a settings
  record to its calendar.

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

A scope moves with **all** its clients in one slice: two clients of one
account writing it to two tables would disagree. Until a scope's slice, the
server's index for it reads the old table and the new one (the new one is
empty for it); the scope's slice deletes its old table, routes and handler.

1. **Server:** the tables, the counter feed, the registry, the three routes,
   the batch CAS, the index over both stores, settings.
2. **The Rust core:** `kutup_crypto::account_records` (index check against
   a verified head, the batch and its next head, the feed merge), the WASM
   handle and the TS wrapper. No scope moves yet.
3. **Pass secrets:** the CLI and the web.
4. **Identity pins:** the web (Drive and Chat), chat-core, the CLI and the
   FFI (whose pins then carry a head).
5. **Chat groups and contacts:** chat-core's one loop and the web's Chat
   transport.
6. **Photos library and attachment ledger** (their chains go; format
   change).
7. **Contact groups, calendar settings and joined meetings;** then the old
   index path goes.

After slice 2, slices 3 to 5 touch different clients and can be built in
parallel.

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
   server's check that the file is live and the caller's. (The server never
   removes a key with its file: a record removed by anyone but the account
   would break the head. As today, a key stays until its owner forgets it.)
   Every other scope's id is
   `hashed_object` or random. The registry states the exception and why.

### Deferred: the FFI's pins without a head (main session, 2026-11-16)

Slice 4 moves `kutup-client-ffi`'s pins to the records routes with today's
behaviour: read unverified, written without a head (an account that keeps
one refuses it with `head_required`). The FFI has no head manager yet, and
building one is the native-apps work: it is done together with
`start_client`'s head check (docs/roadmap.md, "Native iOS and Android
apps"), not as a half head manager here.
