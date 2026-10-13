# Rollback protection across devices

Status: agreed 2026-10-13, before the wipe release, after OPAQUE, renames and
devices. The crypto layer (`kutup_crypto::account_head`, its WASM functions
and vectors) is built. The server's head table and endpoints, and the
clients' use of the head, follow.

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
  `passSecrets`, `settings`, and later ones.
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
