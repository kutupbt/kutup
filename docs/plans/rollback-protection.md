# Rollback protection across devices

Status: agreed 2026-10-13, before the wipe release, after OPAQUE, renames and
devices.
- Built: the crypto layer (`kutup_crypto::account_head`, its WASM functions and
  vectors), the server (head table, endpoints, every listed write carrying the
  next head), and the web clients for pins and Pass secrets (section 9).
- Next: contacts and mail names on the web, then Chat core and the CLI.

## What exists, and what it misses

Every mutable sealed value carries a revision in its authenticated header, and
the server does compare-and-swap writes (docs/plans/sealed-revisions.md). These
values are contact cards, mail names, the identity pin list, Pass vault secrets
and, with #179, the account's sealed settings. Each device keeps the highest
revision it has seen of each value (RevisionGuard).

That leaves three gaps, in order of how much they matter:

1. **Values this device never read.** The guard knows only values it has opened.
   - A contact first opened today, a vault this browser never unlocked, a mail
     label created on the phone: the server can hand any of them back at an
     older revision.
   - This covers most values on most devices, and it is the main hole.
2. **A device with no history** (a new browser, cleared site data, a private
   window, a fresh CLI profile) trusts whatever it reads first.
3. **Forks.** The server shows two devices two different, self-consistent
   histories. Neither device can tell on its own.

**No design closes gap 2 completely.** A device whose only link to the account
is the server and the password can only learn "the latest" from the server.
OPAQUE does not change this: the export key proves the password, not freshness.
The plan below closes gap 1, narrows gap 2 to the first read, and makes gap 3
visible as soon as the devices' histories meet.

## Design

### 1. The account head (`AccountHeadV1`, Rust-owned, with vectors)

One small value per account, sealed and authenticated by a key derived from
the master key (`HKDF(master key, "kutup/account-head/v1")`), so only the
account's own clients can make one:

```
AccountHeadV1 {
  incarnation,              the account's
  sequence,                 1, 2, 3, … one per change of any listed value
  previous,                 SHA-256 of the previous head (absent at 1)
  writer,                   HMAC(head key, device id): which device wrote it, unlinkable to the server
  scopes: [{ scope, count, digest }]   sorted by scope
}
```

- **What a scope is:** one kind of value: `pins`, `contacts`, `mailNames`,
  `passSecrets`, `chatGroups` (the account's group list,
  [`pairwise-groups.md`](pairwise-groups.md) §5), `settings`, and later ones.
- **What a scope's digest covers:** `digest = SHA-256` over the sorted list of
  `(HMAC(head key, value id), revision)` pairs of every value of the scope. A
  deleted value leaves the list. Value ids are HMAC'd, as RevisionGuard already
  does, so the head says nothing about which contacts exist.
- **Size:** a few hundred bytes, whatever the account holds.

### 2. Writing

Every write of a listed value also writes the next head, in the same request:
`{ …the value, baseRevision, head: { sequence, sealed } }`.
- The server stores both in one transaction, on two compare-and-swaps: the
  value's base revision and the head's sequence (`409 revision_conflict` or
  `409 head_conflict`). On a conflict the client reads again and redoes its
  edit, as today.
- **To compute the new digest,** the client needs the scope's current
  `(id, revision)` index. `GET /api/account/index/:scope` returns it: ids and
  revisions only, never content. That is about 50 KB for 1,000 contacts. The
  client checks it against the head before using it.
- **Deletes** write a head too, so a server cannot bring a deleted value back.

### 3. Reading

- The client reads the head first. It checks the seal and the incarnation, and
  that the sequence is not below the highest it has seen. That highest-seen is
  one RevisionGuard entry per account, so one number protects every value.
- **A scope's listing:** its `(id, revision)` pairs must hash to the head's
  digest, and their number must equal the count.
- **One value:** its sealed revision must equal the revision the verified
  index gives for it. A rolled-back contact, or a dropped or resurrected one,
  is refused, even if this device never saw it before. **That closes gap 1.**

### 4. Forks: devices notice each other

- Each head names the device that wrote it (`writer`, an HMAC) and links to
  the one before. A device remembers the sequence and hash of the last head it
  wrote itself.
- **On every read,** a device whose last own write was head n checks that the
  current head descends from it. The server returns the chain segment
  (`GET /api/account/heads?from=n`, at most what was written since). Every link
  must check out.
- **A device that cannot find its own write in the current chain** has been
  forked. It says so prominently: "Your data on this device and the server
  disagree; another device may have been shown a different history." It refuses
  to write until the user resolves it. **That makes gap 3 visible** the moment
  the two histories meet, which is any time both devices write. A server can
  keep two devices apart only by never letting one see the other's changes,
  and the user notices that in normal use.

### 5. New devices (gap 2, narrowed)

- **Linking from an existing device** (the QR flow Chat uses to add a device)
  carries the current head's sequence and hash. A linked device starts
  anchored.
- **Signing in with only the password** trusts the head it reads first, and
  checks against it from then on. If an older device of the account later
  writes, the fork check (4) catches a head that was rolled back for the
  newcomer. Its write would not descend from the newcomer's first head.
- **Account → Security** shows "Data state: #sequence, last changed by this
  device / another device, date", for anyone who wants to compare devices by
  hand. No new trust decision is asked of the user.

### 6. What it costs

- **Every listed write grows by one head (a few hundred bytes) and serializes
  on the head's sequence.** Two devices editing contacts at the same moment
  retry once each, as they already do for the pin list.
- **Contacts, the biggest scope, need its index at write time** (about 50 KB
  per 1,000 contacts), cached between writes and refreshed on a 409.
- **Bulk imports (CSV, vCard)** write one head per batch, not per value. The
  batch endpoint takes the values and one head.

### 7. Settled in review (main session, 2026-10-13)

- **Restores from a backup are legitimate rollbacks.** An operator restoring the
  database rolls every head back, so every device sees a head below its
  highest-seen, or a fork. The banner and the re-anchor action cover this in
  their text: "If your server was restored from a backup, recent changes may be
  lost. Review them, then continue." The self-hosting doc's restore section says
  users will see it. There is no server-signed "restore" bypass: the server is
  the party not trusted here.
- **Retention:** the chain keeps the last 1,000 heads. A device whose last own
  write fell out of that window (offline for months, or a busy account) cannot
  prove descent. That is a distinct outcome, "too old to verify", not a fork. It
  re-anchors with a non-blocking notice, like a first use, so long-idle CLIs get
  no false alarms.
- **Re-anchoring is one Rust function** (`account_head::reanchor`), used by web,
  Chat core and the CLI, and logged locally with the old and new head.
  - The CLI never accepts a fork silently: a fork exits with its own code (and
    a `--json` report).
  - Re-anchoring is the explicit `kutup account reanchor`.
- **Once a scope has a head:**
  - the server refuses a listed write without one (`409 head_required`);
  - clients refuse any value missing from the verified index.
  - The head starts at the first write after the update (trust on first use).
- **Drive metadata is out of this round, and account-level QR linking comes
  later** (a roadmap line; until then Chat's link is used where a device has
  one).

### 8. Settled in the crypto review (main session, 2026-10-14)

- **Too old means past the window.** `RETENTION` (1,000 heads) is a crate
  constant the server prunes by. A head shown without its chain is `tooOld`
  only when it is more than `RETENTION` past the anchor. Any smaller gap the
  server will not show is a fork, so a server cannot pass a fork off as too old.
- **Anything that does not hold together is a fork.** That covers a segment that
  starts elsewhere, is spliced, or does not reach the current head. It is
  blocking, never an error to retry. Only a head that does not open, or names
  another incarnation, is an error.
- **Re-anchoring runs the check itself** (`reanchor`). It re-anchors on `tooOld`
  always, and on `rollback` or `fork` only when the person confirmed it. The
  record carries the status the check found, not one a caller passes in.
- **Only a verified head counts.** `check` (for `fresh`, `current`, `extends`)
  and `reanchor` produce one, and so does `committed` (the device's own next
  head, once the server stored it). Indexes are checked, and next heads written,
  only against it. Anchors come from verified heads only.
- **Index checks** answer `matches` or `uncovered`. A difference is an error.
- **In the browser,** one `AccountHeadKeys` per signed-in account holds the keys
  and the verified head inside WASM. The master key crosses once, and is wiped.
- **Format durability:** the head is `deny_unknown_fields` under its suite byte.
  A new field in the head is a new suite, and older clients must update to read
  it (and so to write). That is accepted: scopes are already an open list, so a
  new kind of value never needs a new field.

### 9. The server, as built (settled with the main session, 2026-10-14)

- **The chain:** `account_heads (user_id, sequence, sealed, incarnation_id,
  written_at)`, primary key `(user_id, sequence)`, sealed heads up to 16 KiB
  (`MAX_SEALED_BYTES`); the newest `RETENTION` + 1 (1,001) kept, so a device
  anchored exactly `RETENTION` back still gets its whole segment, anchor
  included; pruned in the write. `crates/kutup-server/src/account_heads.rs`.
- **Every listed write first locks the account row** and checks, under the
  lock, that its session is still live. That orders the account's listed
  writes, and refuses one that began before a wipe (a wipe changes the
  incarnation and revokes every session in one transaction on that row; a
  session live under the lock is one of the current incarnation). The head
  stores the incarnation the server read there.
- **The compare-and-swap** runs last in each listed write's transaction: the
  new head's sequence (read with `account_head::inspect`) must be the current
  one plus one, else `409 head_conflict`, the whole write rolled back.
- **Starting the chain** is its own call, `POST /api/account/head`, with the
  first head and the `basis` an index answered with (a SHA-256 the server
  computes over every listed `(scope, id, revision)`). Under the lock the
  server recomputes it: a listed write without a head that landed between the
  client's read and its start moves it, and the start is refused, so a first
  head never leaves a value out. A listed write never starts the chain.
- **Before the chain starts** a listed write needs no head (trust on first
  use); after, `409 head_required`.
- **Reads:** `GET /api/account/head`; `GET /api/account/heads?from=n`, 200
  heads a page with `next` (`410 tooOld` only when `n` is more than
  `RETENTION` behind the newest, exactly the client's "too old", so a gap the
  server merely will not show is a fork); `GET /api/account/index/:scope`,
  which answers the head with the index, from one snapshot, so a write between
  two reads never looks like a rollback. An unknown scope is `404`, which the
  client treats as `Uncovered`. All three are limited per account (300 a
  minute).
- **Value ids per scope:** a contact's UID (client-chosen, unique per account, never changed); `folder:`, `label:` or `filter:`
  and the id for mail names; `pins`; a Pass secret's vault file id.

**Audit: every write to a listed value, and its head.**

| Write | Carries a head |
|---|---|
| Contact create, update, delete, delete many, import | yes (import and delete many: one per batch) |
| Mail folder, label, filter: create, rename, delete | yes |
| Mail folder delete (removes the folders inside it) | yes, with `removes`: every folder id it removes, compared in the transaction with what it does remove (`409 head_conflict` if they differ), since the server cannot read the head's digest |
| Mail folder parent, colour, position, folding; label colour, position; filter on/off, match, conditions, actions | no: not sealed, not rollback-protected; a head sent with one is `400` |
| Identity pin list put | yes |
| Pass vault secret keep, forget, forget many | yes |
| Group list entry put, delete (`chatGroups`) | yes |
| A vault's file purged | nothing: the secret is no longer deleted with it (its foreign key to `files` is gone); it stays listed, "unreachable but listed", until the owner's client forgets it, which it does on its next Pass write or unlock, all such under one head |
| Account deletion | everything goes, heads included |
| Account reset (an administrator's wipe) | the chain and every listed value sealed under the old keys go in the reset transaction: contacts, labels, filters, Pass secrets, identity pins, the group list. Custom folders keep their mail and lose their names (`name_sealed` null), left out of the index until their owner names them again from revision 0, under the new incarnation's first heads. So no verified head ever lists a value no key opens. |

**Not covered yet:** `settings` (with #179); Drive metadata (decided out of
this round).

**Tests:** `tests/account_heads_live.rs` (the start on its basis, refused
when a write moved it and when repeated; every kind of listed write with and
without its head; `head_conflict` with the current sequence; a head with an
unsealed change; the index with its head; a folder delete that names too
few; two starts at once, one wins; a wipe, then a start, a write and a read),
and `account_heads::tests` against a database: 1,005 heads, 1,001 kept; the
client's own `check` says `extends` at a gap of exactly `RETENTION` over the
paged segment, and `tooOld` at `RETENTION` + 1 where the server answers 410.

### 9. The clients (settled 2026-10-14)

**One device = one web origin.** Each app has its own IndexedDB, so each app
keeps its own anchor, writer tag and fork state. Chat core keeps one in its
store, and the CLI one per profile. Drive and Mail in one browser are two
writers, linked through the chain like any two devices.

**What a device keeps** is one sealed record, `LocalHeadStateV1`, the same
format for every client:
- its anchor, a random device id (hashed into its writer tag), and when the
  anchor last moved;
- a log of the last 20 events: started fresh, re-anchored, forgotten.

It is sealed under the head key, bound to the key binding and the
incarnation, and stored under an HMAC name of the incarnation. Two accounts in
one store, or one account before and after a reset, never share or compare
anchors. A record that does not open means the device starts fresh, which is
logged. The anchor moves only forward from a verified head. Another tab's
later anchor stays. Only a re-anchoring moves it back or sideways.

**One code path on the web**, `@kutup/session/accountHead`:
- `verifiedHead`: the head, its chain from the anchor (every page of it),
  then the check.
- `verifiedIndex(scope)`: one snapshot of the index and its head, checked. A
  scope the server keeps no index of (404) is uncovered.
  - Once covered, a value must open at exactly the revision the index lists.
  - A listing must be exactly the index's ids. Two reads that a write lands
    between are read again once.
- `listedWrite(scope, edit)`:
  - the edit is made on the verified index and sent with the next head;
  - the chain starts first on the index's `basis` when there is none;
  - it is redone up to five times when another device wrote first;
  - an edit with nothing to change sends nothing;
  - a write whose answer was lost is found in the index at its own revision
    and is never committed twice.
- While blocked, reads fall back to the device's own revision guard, and
  listed writes stop.

**Races are not attacks** (the #202 review):
- A verified head is a value its holder owns: WASM's `VerifiedAccountHead`,
  each with its own copy. A check elsewhere in the page cannot swap the head
  a write is building on. A write keeps the head it verified with its index,
  through edit, next head, send and commit, so its scope entry always matches
  its base, or the server refuses it and it is redone on the newer head.
- The chain is cut at the head being checked, so a head written since does
  not make it a fork.
- A rollback or fork is read once more before it blocks: another tab or
  device moving on between two reads is not one. A banner people learn to
  click away would protect nothing.
- A create keeps one UID for the whole form or dialog. Trying again after an
  answer that was lost finds the value made, and makes no second one.

**Blocked** (rollback or fork) shows `HeadStateBanner` under every app's
header. "Continue with the server's data" asks once more, then re-anchors and
logs it. A server with no head at all, while the device remembers one, is a
rollback too: continuing drops the anchor, and that is logged as forgotten.
Too old re-anchors with a quiet notice. Account → Security shows "Data state":
the sequence this app verified, whether this app wrote it, when it was seen
here (the head holds no time), and the app's log.

**Chat** keeps the synced identity pins as a listed value through the web
client, not a second anchor of its own:
- Chat core passes the revision it sealed with each write. The web Chat
  transport sends the write through `listedWrite('pins', …)`.
- On reads, the transport checks the revision the server names against the
  verified index, and Chat core checks the sealed revision against that one.
- A list the head does not vouch for, or an app blocked on another history,
  is not used. Chat keeps to its own pins, and the shell's banner says why.

The native transport (`kutup-client-ffi`) writes no head yet. On an account
with one, the server refuses its pin writes, which Chat takes as best effort.
It gets the same checks, in Rust, before a native app ships (docs/roadmap.md).

**The CLI** keeps the same `LocalHeadStateV1`, sealed, in the profile's data
directory (`account-head-<name>`), and a sealed revision guard
(`revisions.json`):
- The guard replaces the plaintext `identity-pins-revision`, and takes over
  its value once.
- Pins (`kutup identity`) and Pass vault secrets (`kutup pass keep`,
  `forget`, `ls`, `show-key`, and the keys sync and the ssh agent use) go
  through one `listed_write`.
- A rollback or fork stops listed writes with exit code 6.
- `kutup account state` shows where the device stands, and `kutup account
  reanchor` continues with the server's data after a confirmation (`--yes`
  for scripts), logged in the device's state.
- Too old re-anchors with a notice on stderr.
- **The state on disk** (the #205 review):
  - Every read and change of the state file and the guard is under the
    profile's lock (`account-head.lock`), re-read inside it. The anchor never
    moves back, except by a re-anchoring, which is checked against the anchor
    it was decided on.
  - Writes go to a temporary file of their own, are synced, renamed over the
    file, and the directory is synced.
  - A state that does not open is kept aside (`….corrupt-<ms>`), with a
    warning. The fresh state records why it started over, and the first
    anchor's log entry says so (`startedOver` in `kutup account state`).
  - The old plaintext revision file goes only after the guard holds its value.

**Writes to the local store** count only once IndexedDB commits them. A
request's success comes first, and a page closed in between would lose an
anchor or a re-anchoring.

## Is it needed before the wipe?

**No format of existing values changes.** The head is a new object, and no value
gets a new field. So this can land after the wipe:
- **On a list with no head yet,** the first device to write after the update
  creates one from the current state. That moment is trust on first use, as a
  fresh device's is today.
- **No second wipe:** nothing breaks or needs migrating.

Before the wipe, it would only spare the first-write TOFU moment on the beta
accounts. **The user put it on the pre-wipe list**, sequenced after OPAQUE,
renames and devices.

## Split and size

- **Crypto:** `account_head` (head format, key, digest, chain check, vectors),
  plus the web RevisionGuard and Chat-core and CLI integration. About 2.5 days.
- **Server:**
  - the `account_heads` table (the chain, with the last 1,000 kept);
  - the head compare-and-swap in each listed write endpoint (contacts, mail
    names, pins, Pass secrets, settings, contact batches);
  - the index and heads endpoints.
  About 2 days.
- **Tests:**
  - vectors;
  - live: a rolled-back contact the device never read is refused; a dropped
    value is refused; a fork between two clients is detected at the next write;
  - browser: the fork banner.

## Decided questions

1. Drive metadata is out of this round: Drive has its own versioned objects.
2. A fork blocks writes, with a re-anchor action whose text covers a restore
   from a backup (section 7).
3. Account-level QR linking for web and CLI comes later (roadmap). Until then,
   a device with Chat's link uses it.
