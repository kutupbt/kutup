# Username renames

Status: v2, 2026-10-14. Reworked on the user's decisions (old names freed
after a hold, folded names, receive-only old addresses, deleted accounts'
names freed after the hold) and the main session's review of v1. For approval
by the main and third sessions. The crypto layer (`kutup_crypto::account_rename`,
`AccountRenameV1`, its WASM functions and vectors) and the pins that follow
renames (#193) are on `slate/renames`, not yet merged.

## What a rename is

- One account, one server, a new username. The key binding, the account
  authority, the incarnation, the OPAQUE record and every sealed value stay as
  they are: nothing is sealed to a name (docs/plans/account-identity.md).
- The proof is the account's rename chain: `AccountRenameV1` statements signed
  by the authority, numbered from 1, each starting where the last ended
  (`crates/kutup-crypto/src/account_rename.rs` on `slate/renames`).
  `verify_chain` refuses gaps, forks and time going backwards;
  `RenameChainView::extends` lets a verifier refuse a rollback.
- Statements about one relationship (named shares, profile key shares, MLS
  credentials) are not re-sealed: verifiers accept any address in the signer's
  verified chain (section 5).
- Moving an account to another server is a different thing, not this.

## How others do it (reference)

- **Proton** compares names in a folded form, lowercase without `.`, `_`, `-`
  (`canonicalizeEmail`, `CANONICALIZE_SCHEME.PROTON`,
  `WebClients/packages/shared/lib/helpers/email.ts`), so one person has one
  name in all its spellings. It never renames an address (an address is added,
  `packages/components/containers/addresses/EditInternalAddressModal.tsx`) and
  never gives a deleted one to anyone else
  (`containers/addresses/DeleteAddressPrompt.tsx`).
- **Gmail** delivers every dot variant of a local part to the one account.
- **Signal** holds an old username for its account, then frees it to anyone
  (`USERNAME_HOLD_DURATION`, `MAX_USERNAME_HOLDS`,
  `Signal-Server/service/src/main/java/org/whispersystems/textsecuregcm/storage/Accounts.java`;
  `RemoveExpiredUsernameHoldsCommand`).

**Kutup (the user's decisions, 2026-10-14):** one account per folded name, as
Proton and Gmail; old names are freed after a hold, as Signal, with a hold long
enough for a mail address (default 180 days, an admin setting); the old
address receives mail only, for a shorter window, then bounces until the name
is freed. A freed name taken by someone else is another incarnation with
another authority, so every pin of the old owner warns (#193).

## 1. Folded names

- **`fold(name)`** = the local part, lowercase, without `.`, `_` and `-`
  (Proton's scheme; usernames hold no `.` today, but mail to `name.123@`
  must find `name123`). One Rust function (`kutup_crypto::names::fold`, so
  clients and server agree), with vectors.
- **One account per folded name.** Availability (registration, renames, mail
  groups: one function, `names::available`) compares folded forms, across
  current and held names of accounts and every group address. `name_123` and
  `name123` cannot both exist. The account keeps the spelling it chose for
  display and its address.
- **Mail delivery** folds the recipient's local part: mail to any punctuation
  or case variant of a live address reaches it (section 4).
- **Sign-in accepts variants** through the folded lookup: `Name.123`,
  `name_123` and `name123` sign in to the same account. A typed variant never
  names another account, so this adds no confusion and spares a person who
  forgot where the underscore was.
- **OPAQUE's fake answer and the lockout use the folded form**, so variants
  share one bucket: `canonical_name` (`crates/kutup-server/src/handlers/auth.rs`
  on `slate/opaque-server`) returns the folded name, and
  `unknown_credential_identifier` and `auth_check::guard`'s `name:` key take
  it. This is a change to #198's code, made in the renames server PR, not in
  #198. Registration stores the chosen spelling and checks the folded one.

## 2. The rename flow

1. The client reauthenticates for a `rename` grant. Reauth identifies the
   account by its Bearer session, not by name (settled with the third session):
   `login/start` with `purpose: "reauth"` refuses a `name` (`400`), so a stale
   name fails nothing. The new purpose joins **both** CHECKs: `auth_grants.purpose`
   and `opaque_login_states.grant_for` (`20261013210000_opaque.up.sql`).
2. The client checks the name (`GET /api/user/rename/check`) and shows the
   warning, before the person confirms (en/tr in the Account app):
   > Your old address, `alice@kutup.dev`, will receive mail for **90 days**
   > and cannot send. After that it stops receiving, and after **180 days**
   > someone else can take the name. Update every service that uses the old
   > address now.
   (The numbers are the server's settings, from `GET /api/auth/settings`.)
3. The client builds, from the master key:
   - the `AccountRenameV1` statement: `sequence` = stored chain length + 1,
     `previous` = the current address, `current` = the new one;
   - a new `DriveKeyBindingV1` for the new address, same keys;
   - a mail address key and signed key list for the new address
     (`generateMailAddressKey`, `signMailKeyList` in `kutup-crypto-wasm`), or
     none when it takes back its own held name, whose row has them.
   - **Not the Chat manifest or profile:** the manifest is built only in Chat
     core and the profile key lives in Chat's store, so the Account app cannot
     make them. The Chat app re-publishes both on its next start, when
     `/user/me`'s address differs from its manifest's (section 4).
4. `POST /api/user/rename` (section 7). The server checks: the grant; setup
   done; not the break-glass account; the name's form and folded availability;
   the limits (section 8); the statement (`verify` against
   `users.account_authority_public_key`, incarnation, sequence = next,
   `previous` = the current address, `issued_at_ms` within 10 minutes and not
   before the last statement); `verify_chain` over the stored chain plus it;
   the re-issued binding against the new address.
5. **One transaction**, under the users row lock:
   - `account_names`: the new name `current`; the old one `held` with its
     windows (`receive_until` = now + `OLD_ADDRESS_RECEIVE_DAYS`, `free_at` =
     now + `NAME_HOLD_DAYS`), both from the settings at that moment;
   - `users.username` = the new name; `users.drive_key_binding` replaced;
   - append the statement to `account_renames`;
   - the new `mail_addresses` row (`state = 'active'`) with its keys, key list
     and a `mail_identities` row; it becomes the default sender. The old row
     becomes `receiving`: it takes mail, publishes keys, and sends nothing;
   - local rows naming the old address for display and lookup (section 5);
   - consume the grant; security event `rename` (old and new name);
   - queue the federation announce.
6. The session version covers the username (`crates/kutup-server/src/sessions.rs`,
   `live`), so every open app re-reads `/user/me`. No session ends. `/user/me`
   carries `renames: { sequence, digest }` (0 and none before a first rename),
   the device's anchor (section 6).

**No admin rename:** only the account's clients hold the authority.

## 3. Names over time

`account_names` holds every name in use or held, keyed by its **folded** form.

| State | What it means | Ends |
|---|---|---|
| `current` | the account's username | with a rename (→ `held`), account deletion (→ `held`, no live account) |
| `held` | still the account's (or a deleted account's): nobody else can take it; its address receives until `receive_until`, then bounces `5.1.1`; lookups answer `409 renamed` with the chain; sign-in by it gets the fake answer | at `free_at`: the row is deleted and the name is free |

- **Settings** (`site_settings`, editable in the admin dashboard; their first
  values from the environment):
  - `NAME_HOLD_DAYS`, default **180**: how long a left name stays the
    account's before anyone may take it.
  - `OLD_ADDRESS_RECEIVE_DAYS`, default **90**, at most `NAME_HOLD_DAYS`: how
    long the old address still receives. Two settings, because the user wants
    a stretch of bounces before reuse: a service still mailing the old address
    meets a bounce for months before the name could reach someone else.
  - A change applies to names held from then on; existing holds keep their
    dates (admins act on single names below).
- **The owner** may take a held name back while it is held (same account, same
  incarnation; a normal rename, its address row reused and made `active`
  again) or **drop** it (`DELETE /api/user/names/:name`, `rename` grant):
  receiving ends now; the name stays held until its `free_at`.
- **Admins**, per name: end receiving now; free now (audit-logged, and a
  security event on the account if it has one).
- **Account deletion:** every name of the account (current and held) becomes
  held with no live account (`user_id` null, the incarnation kept), its
  receiving ended at once (no one can read the mail), freed at
  `now + NAME_HOLD_DAYS`. Admins may free it sooner. Today a deleted account's
  name is free at once; this changes it.
- **Account reset** (a new incarnation): the current name stays current, now of
  the new incarnation; held names of the old incarnation stop receiving at
  once (`mail_addresses.state = 'closed'`: mail must not arrive under keys no
  one holds) and are freed on their own dates. The old chain stays published
  under the old incarnation.
- **A freed name** is free for anyone. Its old `mail_addresses` row is never
  deleted (its messages, keys, identities and key lists cascade from it, and
  the old owner's stored mail must stay readable): it becomes `freed`, keeps
  its keys for decrypting what it received, publishes nothing, receives
  nothing, and no longer holds the address (a partial unique index, section
  7). History stays in `account_renames`, which is public.
- **The sweep** (`jobs.rs`, hourly): closes rows past `receive_until`, frees
  names past `free_at`.

## 4. Sign-in, mail, Chat, federation

### Sign-in

- OPAQUE's credential identifier is the key binding, so **a rename needs no
  re-registration**.
- Login lookup is by the folded current name only. A held name, or a freed one
  not yet taken, is not found: OPAQUE's fake answer, keyed by the folded name.
  Recovery preflight and `recover/grant` by it are faked and refused the same
  way. That a name was renamed is no secret: the chain is public.
- **Lockout** stays keyed by the folded name and the client IP; a rename
  neither resets nor moves a window. The per-account ceiling
  (`account:<user id>`) carries across. After a name is freed and taken, its
  windows carry on to the new owner, as opaque.md says.

**Live test, "a held name gets the fake answer"** (deferred from the OPAQUE
review; `tests/renames_live.rs`):
1. Register `a…`; rename it to `b…`.
2. `login/start` with `a…`: `200`, the same shape and `credentialResponse`
   length as a random unknown name.
3. The same answer twice, and for `A…`, punctuation variants of `a…`, and
   `a…@<domain>`.
4. A full sign-in by `a…` with the right password: `401`.
5. `recover/preflight` by `a…`: stable, not the account's key binding;
   `recover/grant` with the right proof: `401`.
6. Sign-in by `b…` and by a punctuation variant of it: `200`, same key binding.
7. Five misses by a variant of `a…` from one client: `429` for every variant of
   `a…`; `b…` still signs in from that client.
8. Reauth from the account's session (no name): `200`; with a name: `400`.
9. Rename back to `a…` (the free undo): sign-in by `a…` works, `b…` is faked.

### Mail

- **Delivery** looks the recipient up by `fold(local part)` among
  `mail_addresses` in `active` or `receiving`: any variant reaches the one
  address. `closed` and unknown addresses bounce `550 5.1.1`.
- **The old address receives only**, until `receive_until`, encrypted to its
  own keys (still published, so senders can encrypt). It never sends: the
  composer and `POST /api/mail/send` refuse it as a sender (`403
  addressReceiveOnly`), and its `mail_identities` row is removed in the rename.
- **Published keys** (`GET /api/mail/keys`, `public_keys` in
  `crates/kutup-server/src/handlers/mail_keys.rs`; WKD
  `/.well-known/openpgpkey/hu/:hash`) are served only for `active` and
  `receiving` addresses, never `closed` or `freed`.
- **What senders see:** mail to the old address arrives while it receives,
  then bounces. Replies come from the new address. A Kutup sender's composer,
  looking up an address in a chain, shows "now alicia@kutup.dev" and offers to
  update the contact.
- `account_and_address` (`mail_keys.rs`) and any sender check that assumes one
  address per account read the account's `active` row instead.

### Chat

- Peers learn of it lazily: a lookup of the old address answers `409 renamed`
  with the chain list; Chat core verifies it against the pinned authority and
  moves the conversation and the pin (`kutup-chat-core::identity_sync`,
  `slate/renames`). Deliveries to a held name are routed to the account.
- **The manifest rule changes:** today a manifest's `account` may not change
  within an incarnation (`crates/kutup-server/src/handlers/chat.rs`). The next
  manifest may change it only to the account's current address, when it
  differs. Until the Chat app re-publishes, the manifest and profile served
  name an address of the verified chain, and Chat clients accept any address
  in the chain of the account they looked up.
- MLS groups keep the old address in credentials and `chat_mls_*` rows; nothing
  new is built on MLS, so nothing is re-issued: routing resolves held names,
  clients show the current name.

### Federation

- **Publish:** `GET /api/fed/accounts/:username/renames` (signed federation
  request) answers every chain that names it (a list, section 7: a reused name
  appears in several incarnations' chains).
- **Announce:** after the rename commits, `POST /api/fed/accounts/renames` to
  every peer with a verified federation identity, through an outbox with
  retries (the user agreed: a rename is public).
- **A receiver** checks: the origin is the chain's server; `version` is 1; the
  announce's `username` is the chain's last `current`; the chain verifies
  against the authority sent, and that authority matches one it stores for the
  incarnation where it has one; it extends what it has. It keeps at most
  50,000 chains per domain (`remote_account_renames`), refusing more (`429`).
- **It updates its own rows by incarnation only**, never by address: a reused
  name must not move a previous owner's rows (section 5).

## 5. Everything that stores a username or address

Keyed by user id (no change): `file_shares`, `collection_shares`,
`mail_group_members`, sessions, devices, `identity_pins`, `pass_*`,
`feedback`, `admin_audit_log.target_user_id`.

**Changed in the rename transaction** (home server):

| Where | On rename |
|---|---|
| `users.username` | the new name |
| `account_names` (new) | new `current`, old `held` |
| `account_renames` (new) | statement appended |
| `users.drive_key_binding` | re-signed for the new address |
| `mail_addresses` (+ keys, key lists, identities) | new `active` row; old row `receiving`, its identity removed |
| `drive_profile_keys.peer_account` | local rows whose `peer_incarnation_id` is this account's: the new address |

**Left as they are; held names resolve to the account:**

| Where | Why |
|---|---|
| Chat queues: `chat_mailbox.sender`, `chat_federation_outbox`, `chat_sealed_federation_outbox`, `chat_mls_federation_outbox`, `chat_media_federation_pull_grants` | drain in hours; held names routed |
| `chat_mls_*` addresses (`member_address`, `sender_address`, `owner_set`) | MLS state, frozen |
| `chat_call_link_seats.account`, `chat_call_link_knocks.account` | short-lived |
| `mail_messages.from_address`, `mail_auto_reply_sent.sender` | history |
| `contact_emails.address` (others' signed cards) | the Contacts app offers the update from a verified chain; never rewritten by the server |
| `mail_sender_rules.pattern`, `mail_image_senders.address` (others' rules) | their own rules |
| `admin_audit_log.payload.username`, `chat_mls_admin_audit_events.details` | an audit records the name at the time |
| named share and profile key share envelopes | valid while their address is in the signer's verified chain |

**Updated on a received announce, matched by incarnation only:**

| Where | Matched by |
|---|---|
| `federated_incoming_shares.owner_account`, `federated_incoming_file_shares.owner_account` | `owner_incarnation_id` |
| `federated_outgoing_shares.recipient_username`, `federated_outgoing_file_shares.recipient_username` | `recipient_incarnation_id` (exists, `20261013200000_remote_devices.up.sql`, not null) + `recipient_domain` |
| `drive_profile_keys.peer_account` | **new `peer_incarnation_id`**, filled from the verified envelope when a row is written; a row without one is never moved, only refreshed when its peer next writes |
| `remote_collab_devices.account` | `domain` + `incarnation_id` |

**Configuration and clients:**
- `ADMIN_ACCOUNT` names the break-glass account by username
  (`crates/kutup-server/src/config.rs`; `bootstrap_admin`, `main.rs`). That
  account cannot be renamed (`403 breakGlassAccount`), and `bootstrap_admin`
  treats a folded match in `account_names` as existing.
- CLI session `name`/`username` and the web session's `username` refresh from
  `/user/me` (the session-version change). Chat's local stores are keyed by
  server and user id. The collab hub's peer name changes on reconnect.

## 6. Rollback protection

**The rename chain is not an account-head scope.** It is public, signed by the
authority, checked by peers with no head key, and carries its own rollback
check (`extends`). The account's own devices keep their anchor in RevisionGuard
from `/user/me`'s `renames: { sequence, digest }`, fetch the chain only when the
sequence moved, and refuse a username that is not the current address of a
chain extending their anchor. The rename endpoint does not wait on the head's
compare-and-swap; the two PRs do not depend on each other.

## 7. Tables and endpoints

Migration `20261015000000_account_renames`:

```sql
CREATE TABLE account_names (
    folded         text PRIMARY KEY CHECK (folded ~ '^[a-z0-9]{1,32}$'),
    name           text NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9_-]{3,32}$'),
    user_id        uuid REFERENCES users(id) ON DELETE SET NULL,
    -- filled in the transaction that finishes setup (register, or
    -- complete-setup for an admin-made account); null until then
    incarnation_id char(64) CHECK (incarnation_id ~ '^[0-9a-f]{64}$'),
    state          text NOT NULL CHECK (state IN ('current', 'held')),
    receive_until  timestamptz,
    free_at        timestamptz,
    CHECK ((state = 'held') = (free_at IS NOT NULL)),
    CHECK (state = 'held' OR user_id IS NOT NULL)
);
CREATE UNIQUE INDEX account_names_one_current ON account_names (user_id)
    WHERE state = 'current';
CREATE INDEX account_names_free ON account_names (free_at) WHERE state = 'held';

CREATE TABLE account_renames (
    incarnation_id       char(64) NOT NULL,
    sequence             integer NOT NULL CHECK (sequence BETWEEN 1 AND 1000),
    user_id              uuid REFERENCES users(id) ON DELETE SET NULL,
    authority_public_key text NOT NULL,
    previous             text NOT NULL,   -- canonical username@server
    current              text NOT NULL,
    counted              boolean NOT NULL, -- false for the free undo
    statement            jsonb NOT NULL,  -- AccountRenameV1, as signed
    accepted_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (incarnation_id, sequence)
);
CREATE INDEX account_renames_previous ON account_renames (previous);
CREATE INDEX account_renames_current ON account_renames (current);

CREATE TABLE remote_account_renames (
    domain               text NOT NULL,
    incarnation_id       char(64) NOT NULL,
    authority_public_key text NOT NULL,
    sequence             integer NOT NULL,
    head_digest          bytea NOT NULL CHECK (octet_length(head_digest) = 32),
    current_username     text NOT NULL,
    chain                jsonb NOT NULL,
    updated_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (domain, incarnation_id)
);

CREATE TABLE rename_announce_outbox (
    destination     text NOT NULL,
    incarnation_id  char(64) NOT NULL,
    sequence        integer NOT NULL,
    attempts        integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error      text,
    PRIMARY KEY (destination, incarnation_id, sequence)
);

-- An address row outlives its name: never deleted (mail, keys, identities
-- and key lists cascade from it). Only live rows hold the address.
ALTER TABLE mail_addresses
    ADD COLUMN state text NOT NULL DEFAULT 'active'
        CHECK (state IN ('active', 'receiving', 'closed', 'freed')),
    ADD COLUMN folded text,              -- fold(local part) || '@' || domain
    ADD COLUMN receive_until timestamptz,
    DROP CONSTRAINT mail_addresses_address_key;
CREATE UNIQUE INDEX mail_addresses_live ON mail_addresses (folded)
    WHERE state <> 'freed';
ALTER TABLE drive_profile_keys ADD COLUMN peer_incarnation_id char(64)
    CHECK (peer_incarnation_id ~ '^[0-9a-f]{64}$');
-- From 20261013210000_opaque, replaced the same way: auth_grants.purpose and
-- opaque_login_states.grant_for gain 'rename'; account_security_events.kind
-- gains 'rename' and 'nameDropped', with old_name and new_name columns.
```

The users row lock and `(incarnation_id, sequence)` allow one rename at a time
per account. `account_names` is filled from `users` (the folded username); the
availability function also checks `mail_groups` and live `mail_addresses`.

**Endpoints** (new codes join the api.md table, which a server test enforces):

- `GET /api/user/rename/check?name=` → `{ "available": true, "takeBack": bool }`
  or `{ "available": false, "reason": "taken" | "held" | "reserved" |
  "invalid" }`; 30 per 15 minutes per account.
- `POST /api/user/rename`:
  ```json
  {
    "grant": "kg1_…",
    "rename": { "incarnationId": "…", "sequence": 1,
                "previous": "alice@kutup.dev", "current": "alicia@kutup.dev",
                "issuedAtMs": 1792000000000, "signature": "<base64>" },
    "driveKeyBinding": "<canonical base64>",
    "mailAddress": { "keys": [ … ], "keyList": { "data": "…", "signature": "…" } }
  }
  ```
  `mailAddress` is null only when taking back a held name. → `200 {
  "username", "address", "sequence", "oldAddressReceivesUntil",
  "oldNameFreeAt" }`. Errors: `400 renameInvalid`; `403 grantInvalid`;
  `403 breakGlassAccount`; `409 setupRequired`; `409 nameTaken`;
  `409 nameReserved`; `409 renameConflict` (re-read and re-sign);
  `409 tooManyHeldNames`; `429 renameTooSoon` with `retryAt`.
- `GET /api/user/names` → `[{ "name", "state", "receiveUntil", "freeAt" }]`.
- `DELETE /api/user/names/:name` (`{ "grant" }`) → `204`: receiving ends now.
- **Chain lookups return a list** (a reused name is in several chains), pinned
  now as version 1: `GET /api/users/renames/:address[?incarnationId=…]` and
  `GET /api/fed/accounts/:username/renames[?incarnationId=…]` →
  `{ "version": 1, "chains": [{ "incarnationId", "authorityPublicKey",
  "current", "state": "current" | "held" | "gone", "chain": [ … ] }] }`,
  newest first; `"chains": []` when no chain names it. (`AccountRenameV1` is
  `deny_unknown_fields`, so the version lives on the envelope, not the
  statement.)
- **Lookups of a held name** (identity, Drive identities, Chat
  manifest/keys/profile, federated Drive user, their `/api/fed/` twins) →
  `409 renamed` with that list. Delivery routes accept a held name and route
  it.
- `POST /api/fed/accounts/renames` → body `{ "version": 1, "username",
  "incarnationId", "authorityPublicKey", "chain" }` → `204`; `400` for a chain
  that does not verify or a username that is not its current; `409` for one
  that does not extend the cached one; `429` past the per-domain cap.
- `GET /api/user/security-events`: kinds `rename` and `nameDropped`, with
  `oldName` and `newName`.
- Admin: `GET /api/admin/users` gains `formerNames`; `POST
  /api/admin/names/:name/close` (end receiving) and `.../free` (free now) →
  `204`; the two settings in admin site settings. Audit actions `nameClose`,
  `nameFree`.
- `GET /api/auth/settings` gains `nameHoldDays` and `oldAddressReceiveDays`
  (for the warning).

**CLI:** `kutup account rename <name> [--yes] [--json]` (reauth by session,
shows the warning, signs with the same Rust code), `kutup account names
[--json]`, `kutup account names drop <name>`.

**Web:** Account app → Settings → Account → Username → Change, with the
warning; held names listed with their dates and Drop. en/tr.

## 8. Limits and abuse

- **One counted rename per 30 days.**
- **One free undo per counted rename:** going back to the name just left,
  within 7 days of that rename, is not counted, and restarts the 30-day clock.
  A second undo is a counted rename. So A→B→A→B is two counted renames 30 days
  apart, and the chain (at most 1,000) cannot be run up.
- **At most 5 held names that still receive** per account (`409
  tooManyHeldNames`). A dropped name stays held until freed but no longer
  counts, so dropping one makes room; squatting stays bounded by one rename
  per 30 days and the hold (decided 2026-10-15).
- Name checks: 30 per 15 minutes per account (registration already says
  whether a name is taken).
- A freed name can be taken by anyone; that is the user's choice. Pins warn on
  the new owner (#193), and the warning before a rename says when.

## 9. What the security event records

`rename`: when, the acting session (client, user agent; no IP), `old_name`,
`new_name`. `nameDropped`: the name. An admin's `nameClose` or `nameFree` of an
account's name is recorded on the account too, with the admin. Kept a year or
the newest 500. The full history is `account_renames`.

## 10. Merge order and tests

1. **#198 OPAQUE** (with #199).
2. **`slate/renames`** (crypto, pins, Safety Number V2; no migration):
   list-append conflicts in five files. Must land before the wipe (formats).
   `kutup_crypto::names::fold` and its vectors are added in step 4.
3. **The account-head server PR, #200** (`20261014100000_account_heads`).
4. **The renames server PR** (`20261015000000_account_renames`): above both,
   as it alters OPAQUE's tables and changes `canonical_name` to the folded
   form.

**Tests:**
- Live, `tests/renames_live.rs`: the flow; the held-name spec (section 4);
  folded availability (registration, rename, group) and variant sign-in; mail
  to a variant delivered; the old address receives, cannot send, then
  bounces, then is freed and taken by another account whose keys and chain
  are its own; take back and drop; the free undo once, then counted;
  `renameConflict`; `409 renamed` with a list from each lookup; break-glass
  refused; account reset closes held addresses; deletion holds then frees.
- Two-server federation: the announce updates rows by incarnation only (a
  reused name's previous owner's rows untouched); a forged, shorter or
  mismatched-username chain is refused.
- Browser: the rename dialog with its warning; Drive's banner says "formerly".

## Approval and build notes (2026-10-14)

Approved by the main and third sessions (v2). To carry into the build:
- **`fold` vectors** cover `.`, `_` and `-` at the edges and repeated (`a..b`,
  `_a`, `a-`, `a_-b`), case, and names that fold to the same form.
- **The stored username keeps the chosen spelling** (display, the address);
  uniqueness and every lookup use the folded form.
- **Sign-in by variant:** `login/start` folds before the lookup; the fake
  identifier and the lockout key take the folded name. Live test: `ada.l` and
  `adal` share one lockout bucket and one fake answer.
- **Mail delivery to variants** folds the local part only for this server's
  own domains; the SMTP recipient lookup (and Stalwart's directory query, if
  it resolves recipients itself) must use the same fold.
- **`version` is checked:** a chain lookup or announce with an unknown version
  is unverifiable: servers refuse it (`400`), clients treat it as unverified
  and warn, never guess.

## As built (R1, local; R2 brings federation)

R1 is everything on one server; R2 (migration `20261015010000`) adds the
publish endpoint, the announce and its outbox, `remote_account_renames`, and
announce-driven updates of other servers' rows. Where R1 differs from the plan
above:

- **Mail keys in the rename request, as planned** (after review): the new
  address's first key and key list are stored in the rename's transaction, so
  mail to it is never deferred. A name taken back keeps its own keys. The
  display name and signature move to the new address.
- **One resolver for every lookup by name:** `kutup_current_user(name)` (SQL)
  finds the account whose current name it is, in any spelling; nothing
  compares `users.username` directly (a server test greps for it). Lookups
  answer with the name as stored, the spelling signed data holds; a remote
  answer is accepted when its account folds to the name asked. Clients compare
  addresses folded (`kutup_crypto::identity_pins` does, vectors included),
  so `ada-l` finds the pin saved as `ada_l`. Any spelling of a held name
  answers `409 renamed` with the chains, never keys. Deliveries (Chat, MLS,
  media) reach held names, so nothing in flight is lost.
- **Receive-only is enforced at the sender:** mail is sent only from the
  account's `active` address (`403 addressReceiveOnly` should it have none);
  an auto-reply to mail at an old address goes from the current one. Delivery
  and key lookups check `receive_until` themselves, not only through the
  hourly sweep. Every read of `mail_addresses` filters by state: group
  members, administrators and group keys use the active address; a group or
  account found by address is found folded.
- **Taking a held name back** locks its row (the sweep or an administrator
  freeing it meanwhile waits, and a name gone meanwhile is a `409
  renameConflict`). It is taken back as it was spelled: its address, keys and
  key lists name that spelling, so another one is refused (`renameInvalid`,
  with the `spelling` the check also gives).
- **Key lookups** answer the address as stored and the account its newest key
  list names (an old address: the name it had then). Clients compare the
  address asked folded.
- **A message written as an old address** (sealed to that address's key for
  the sender's copy, such as one scheduled before the rename) is refused with
  `403 addressReceiveOnly`, not sent from the current address.
- **The sweep** runs every `NAME_SWEEP_SECONDS` (an hour; seconds on the test
  stack, where a live test watches it free a name).
- **Dropping a held name** is limited like a rename: one per 30 days
  (`429 dropTooSoon`).
- **The chain digest is stored** with each statement (`account_renames.digest`,
  from the verified chain), so `/user/me` answers the anchor without
  re-verifying.
- **Until R2,** `GET /api/users/renames/:address` answers an empty list for
  another server's address, and other servers learn of a rename lazily, from
  `409 renamed` at their next lookup.
- **Admin name actions** are recorded on the account as `nameClosed` and
  `nameFreed` (with the admin), besides the audit log.

## As built: web clients (slate/renames-web)

- **Account → Settings → Account → Username:** the rename dialog checks the
  name as it is typed (folded against the current one in Rust first), warns
  with `oldAddressReceiveDays` / `nameHoldDays`, and signs the statement, the
  re-issued Drive key binding and, when the check says `needsKey`, the new
  address's first key (`firstAddressKey`, mail-core). A take-back signs the
  returned `spelling`. A `renameConflict` (another device renamed meanwhile)
  is signed once more on the chain read again, with the same grant (the
  refused request stored nothing). Held names list their dates, with take
  back and stop receiving (a `rename` grant). Security events name the old
  and new name.
- **Mail:** the account is the `active` address; the earlier addresses' keys,
  each sealed for its own address, open the mail sent to them, and their
  public keys check the account's own signatures. Own addresses are compared
  folded (`isOwnAddress`). A `403 addressReceiveOnly` reads the account
  again so the next send goes from the current address.
- **Drive:** a lookup answering `409 renamed`, or a pinned local name not
  found, follows the chain of the pinned authority (`followRename`): the pin
  moves with its trust (`formerly` kept) and the status is `renamed { now }`.
  A pin found at a new address under an earlier name moves too (`ok` with
  `formerly`). An unknown `version`, `unavailable`, or a chain the pinned
  authority did not sign keeps the pin. Sharing to a left name offers the new
  address (`RecipientRenamed`; first use for someone never met).
- **Chat:** follows in its own PR (peer records keyed by a stable identity).

## As built (R2, federation)

Migration `20261015010000_account_renames_federation`; `crate::remote_renames`.

- **Feature header.** Renames are the account's, for Chat and Drive alike: requests go
  out under `chat.v2` when the peer admits it, else `drive.v1`, and are taken under
  whichever the signed request names, with that feature's admission policy. No new
  federation feature.
- **Announce.** In the rename's transaction, one outbox row per pinned peer not
  quarantined (`trust_state <> 'quarantined'`: "verified" in the trust table is the
  rare admin-verified state). A worker sends the whole chain every 30 seconds, with
  backoff to 6 hours, for 7 days; a peer without either feature, or one this server
  may not send to, is dropped at once (it learns at its next lookup).
- **Keeping chains** (`remote_account_renames`, one per domain and incarnation): kept
  when it verifies (the incarnation is the authority's hash, so no stored authority is
  needed), every address is on the domain that gave it, and it extends the one kept;
  a shorter one is a rollback and a different one a fork, neither kept. At most
  50,000 per domain. Every address a chain names is indexed folded.
- **Rows move by incarnation only** (incoming and outgoing federated shares, profile
  keys, collaboration devices). A peer can sign a chain for a fresh authority claiming
  one of its names; that is another incarnation and moves nothing (tested). A profile
  key whose new address already has one stays under the old address until the next
  key exchange replaces it (logged with its ids); the person sees the old address on
  that one key until then.
- **A peer's `409 renamed`** to Chat keys, manifests, history and profile lookups and
  the Drive user lookup is relayed to the client, its chains verified and kept (this
  closes an R1 gap: those answers were `502`). Chat's federated errors now carry their
  details, so the chains reach the asker at all.
- **Remote chain lookups** answer from what is kept when a chain is younger than a
  day; otherwise the peer is asked (per account 60 per 15 minutes, per peer 120 a
  minute, one fetch per address at a time). Unreachable with nothing kept:
  `unavailable: true`.
- **Tests:** `remote_renames::tests` (a chain kept only for its own server; kept,
  same, shorter, forked; rows by incarnation, the forged chain moving nothing) and the
  two-server gate's `renames` phase (B learns of A's rename, relays `409 renamed`,
  finds the new name; A's outbox empties and B keeps the chain).

