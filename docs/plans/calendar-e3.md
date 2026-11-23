# Calendar E3: sharing, links and busy/free

Status: approved by the main session 2026-11-17 with the recommended answers to Q-1 to Q-5 (see "Decisions"). Plan by the third session. Phase E3 of
[`calendar.md`](calendar.md), on its decisions D-1 to D-4 and the W4 key
model (a calendar's passphrase shared on account keys,
`CalendarShareEnvelopeV1`). Built on `post-wipe/calendar-e3` (E3a–E3e; see
"as built" under §6). Code starts from `wipe/final`
once it is green, and merges after the wipe.

Copies Proton's web client (`WebClients`, read 2026-11-17):
`packages/shared/lib/calendar/sharing/shareProton/shareProton.ts`,
`sharing/shareUrl/shareUrl.ts`, `calendar/permissions.ts`,
`api/calendars.ts` (members, invitations, `urls`, `busy-schedule`),
`interfaces/calendar/{Link,Api}.ts`,
`components/containers/calendar/calendarModal/BusySlotsCheckbox.tsx`,
`applications/calendar/src/app/store/busySlots`. Where Kutup differs, the
section says why; the open questions are **Q-n** at the end.

## What Proton does

- **Members.**
  - Permission bits are `SUPER_OWNER, OWNER, ADMIN, READ_MEMBER_LIST, WRITE,
    READ, AVAILABILITY`, already Kutup's constants in
    `handlers/calendar.rs`.
  - The share dialog offers two presets: **Edit** (`WRITE + READ +
    AVAILABILITY`) and **See all event details** (`READ + AVAILABILITY`).
    `LIMITED` (`AVAILABILITY`) is used for links.
  - At most 49 members per calendar. Only the owner shares; a member can't
    re-share.
- **Invitations.**
  - The owner wraps the passphrase's session key to the invitee's address
    key and signs it (context `calendar.sharing.invite`).
  - The invitation is pending, with an `ExpirationTime`.
  - The invitee verifies the signature against the sender's pinned keys,
    then signs the passphrase with their own key and accepts. They can also
    reject. The owner can see and revoke pending invitations.
- **Removing a member.** The member row is deleted. No key is rotated (no
  client code does it).
- **Links** (5 per calendar).
  - **Full:** the passphrase XOR a random `PassphraseKey`, which travels in
    the URL's query (`…/url/{id}/calendar.ics?CacheKey=…&PassphraseKey=…`).
    The server decrypts on each fetch and serves ICS.
  - **Limited:** busy blocks only, with no key.
  - **Every link:** a `CacheKey` (only its salted hash is stored; the key
    itself is encrypted to the calendar key, so members can rebuild the URL)
    and an optional purpose encrypted to the calendar key. A link can be
    deleted.
- **Busy/free.**
  - "Show others when I'm busy" is a per-calendar toggle, plus a default in
    the settings.
  - Only users in the same organization can see it.
  - `GET /calendar/v1/{email}/busy-schedule?Start&End&Timezone&Type` answers
    busy blocks from the readable times, never details.
  - The app shows them when you add participants to an event, not in the
    month view.

## Kutup's design

### 1. Members and invitations

- **Who and what.** Only the owner shares. The two presets are Proton's;
  the server keeps the bits. The limit is an admin setting
  (`calendar.members_per_calendar`, default 49).
- **Inviting.**
  - The owner's client finds the person with Drive's flow
    (`lookupAddress`, then `confirmRecipient`): pins by the typed address,
    and a warning on a changed identity.
  - It then seals the passphrase of every live key generation (§2) with
    `calendar::seal_passphrase` to that account's verified HPKE key, signed
    with the owner's account signing key.
  - `POST /api/v1/calendar/calendars/{id}/invitations {account, incarnation,
    permissions, shares[]}`. The server checks every envelope's binding:
    calendar, generation, owner, member and incarnation.
- **The invitee's side.**
  - `GET /api/v1/calendar/invitations` lists pending invitations, and the
    Calendar app shows them in the sidebar ("Shared with you").
  - Accepting runs `open_passphrase`, which refuses a share the owner's key
    didn't sign. The owner's signing key is checked against the pins, as
    Drive does: warn, and accept only after the person confirms.
  - The invitee then writes a `calendarSettings` record (colour, display)
    and posts `…/invitations/{id}/accept`. Declining is
    `…/invitations/{id}/decline`.
  - Unlike Proton, there is no second signature: the envelope already binds
    the member and the calendar.
- **Expiry.** An invitation expires after an admin setting
  (`calendar.invitation_days`, default 7) and is swept.
- **What the owner manages.** The owner lists members and pending
  invitations, changes a member's preset, revokes an invitation, or removes
  a member.
- **Leaving.** A member can leave (`DELETE …/members/me`).
- **Telling the member.** Removal, leaving and deleting the calendar leave
  the member a tombstone (calendar id, reason, time) that the client reads
  once. The client then drops its `calendarSettings` record. This closes
  calendar.md's L4: a server that hides a calendar without a tombstone shows
  up as a record whose calendar is missing.
- **Events by members.** Members with `WRITE` write events. Each part is
  signed by the author's address key, and the server already checks this.
  The owner pays storage, as in E1.
- **Alarms** (from the E2b-2 review):
  - an `AVAILABILITY`-only member gets no alarms;
  - a change of preset queues an alarm recompute;
  - removal deletes the member's alarms, reminders and recompute requests.
- **Notices.** "Calendar shared with you" is shown in the app only. A Mail
  message comes in E4, with invitations.

### 2. Removing a member rotates the key (generations)

calendar.md §1 decided to rotate on removal, beyond Proton. How:

- **A list of keys, not one key.** `calendar_keys (calendar, generation,
  public_key, fingerprint, locked_secret_key)` replaces the key columns on
  `calendars`, as Proton's `keys/all` list does.
- **Shares per generation.** `calendar_member_shares (calendar, user,
  generation, share)` holds a member's share of each generation's
  passphrase.
- **What the owner's client does on removal, in one request:**
  - makes generation n+1 (a new key and passphrase);
  - seals the new passphrase to each remaining member;
  - re-seals the calendar's name to the new key;
  - re-seals each link's passphrase copy (§3);
  - posts `POST …/keys/rotate {removeMember, generation, key, shares[],
    metadata, links[]}`.
- **What changes for events.** New and edited events must wrap to the
  newest key: `check_sealed_shape` against it. Old events keep their key
  packets and are read with their own generation's key, so nothing is
  re-encrypted.
- **What the removed member keeps.** The old passphrases, so the events it
  could already read. It can't read anything written after removal. A
  member added later gets every generation, to read the history.
- **Why not re-wrap every event's key packets to one new key:** that means
  up to 25,000 events × 2 packets opened and rewritten by the owner's
  browser on every removal. Proton's key list avoids it.
- **Size:** generations are capped by an admin setting
  (`calendar.key_generations`, default 50).

### 3. Links (D-2)

Three kinds, at most `calendar.links_per_calendar` (default 5). Each has an
optional purpose sealed to the calendar key, as Proton's. Only the owner
makes or deletes links.

1. **Full, key in the fragment (the default).**
   - The URL is `https://calendar.<domain>/l/{linkId}#<secret>`.
   - The server stores, per live generation, that generation's passphrase
     sealed under a key derived from the 32-byte link secret (HKDF, label
     `kutup/calendar/link-passphrase/v1` in `labels.rs`; AEAD in
     `kutup-crypto`). This differs from Proton's XOR, so no pad is reused
     across generations.
   - The owner keeps the secret, sealed to its own account key (see "Review
     fixes" 1: it was first sealed under the newest passphrase, which every
     member holds). That lets the owner show the URL again and seal the new
     passphrase for the link on rotation.
   - The page fetches `GET /api/v1/calendar/links/{id}/events?start&end` (no
     account; rate limited per IP and per link) with the keys and sealed
     passphrases. It opens them in WASM and shows a read-only calendar.
   - The server never decrypts anything.
2. **Full, key in the query (for other calendar apps).**
   - Proton's kind: `…/api/v1/calendar/links/{id}/calendar.ics?key=<secret>`.
   - The server opens the passphrase, decrypts while serving, and builds
     ICS (`kutup-crypto` on the server).
   - The UI warns: "The server reads this calendar each time it is fetched."
   - This path's query must never be logged. nginx logs it without the
     query, the server's request log redacts it, and there is a test for
     both.
3. **Busy only.**
   - `…/l/{id}` and `…/calendar.ics` with no key, served from the readable
     columns: start, end, all-day, `TRANSP`, `STATUS`.
   - Each busy block becomes a `VEVENT` with `SUMMARY:Busy`, as Proton's
     limited link. Transparent and cancelled events are left out.

On rotation, the owner re-seals each full link's copy to the new generation.
Busy-only links need nothing.

### 4. Busy/free

- **Setting.** "Show others when I'm busy" per calendar. It is a readable
  member column (`share_busy`), because the server answers from it. A
  default for new calendars lives in the calendar settings record.
- **Who may ask:** Q-3.
- **API.** `GET /api/v1/calendar/busy?address=&start&end`:
  - the server resolves the address;
  - it unions the calendars that share busy times;
  - it expands recurrences with E2's rule engine;
  - it answers `[{start, end, fullDay}]` in UTC.
- **Limits** (admin settings): window `calendar.busy_window_days` (default 31),
  and a rate limit in the registry.
- **What a limited (`AVAILABILITY`) member sees:** the calendar's busy
  blocks in the grid, drawn as Proton's `PartDayBusyEvent` /
  `FullDayBusyEvent`. That is the same `events` route answering busy blocks
  instead of events, rather than today's 403.
- **Seeing another person's busy times:** Q-4.

### 5. Numbers and checks

- **Migration:** none after the wipe. The main session decided on 2026-11-18 that E3's tables (and E4's) go into the W7 baseline before the wipe, in their final names and types, coordinated with the second session; see calendar-e4.md, "Decisions". What follows lists those tables.
  - Adds `calendar_keys`, `calendar_member_shares`, `calendar_invitations`,
    `calendar_member_tombstones` and `calendar_links`, plus the
    `share_busy` column.
  - Moves the key columns off `calendars`; the server makes generation 1
    from them.
  - No data migration is needed: it is a fresh table after the wipe.
- **Other numbers:**
  - specs 201–206 (renumbered 2026-11-18: the Sieve editor holds 200);
  - one new label (`kutup/calendar/link/v1`), with the `ALL` array length
    updated;
  - no new account-record purpose or scope (it reuses `calendarSettings`,
    purpose 32).
- **Everything else:**
  - every limit above is a site setting, keyed `calendar.<snake_case>` (W7
    §7). The JSON that `/api/v1/auth/settings` publishes keeps camelCase fields
    (`calendar.queryLinksAllowed`), which is what the app reads;
  - all strings are in en.json and tr.json;
  - all crypto is in Rust/WASM, with vectors for the link envelope and the
    generation lists.
- **Tests:**
  - until the full test is over: static, rust, web and unit checks only;
  - live and browser specs once main says the full test is over.

### 6. Slices

| Slice | Delivers |
|---|---|
| E3a | Crypto: key generations, the link envelope, vectors (Rust and WASM) |
| E3b | Server: invitations, members, presets, leave, tombstones, generations and rotation, alarm rules |
| E3c | App: Share dialog, "Shared with you", accept with the identity check, member list, removal with rotation |
| E3d | Links: fragment, query and busy-only; the public view; logging redaction |
| E3e | Busy/free: the setting, the API, the limited member's grid, and Q-4's UI |

**E3a as built** (`feat/calendar-e3`, no schema):

- `kutup_crypto::calendar_link`: `LinkSecret` (32 bytes, base64url in the
  URL), `seal_link_passphrase` / `open_link_passphrase`
  (`version ‖ nonce ‖ XChaCha20-Poly1305`, with the key from HKDF over
  (calendar id, link id, generation), and the same context as associated
  data); since the review, `seal_owner_link_secret` /
  `open_owner_link_secret` and `link_access_proof`.
- `calendar::event_key_id` (the generation an event needs),
  `UnlockedCalendarKey::key_id`, `next_key_generation`. Member shares per
  generation reuse `seal_passphrase` / `open_passphrase`, which already
  bind the generation.
- WASM (`crypto-calendar` only): `shareCalendarPassphrase`,
  `unlockSharedCalendar`, `calendarEventKeyId`, `UnlockedCalendar.keyId`,
  `rotateCalendar` (new key, own and member shares, metadata, each link's
  new copies, all in one result for one request), `createCalendarLink`,
  `calendarLinkUrlSecret`, `calendarLinkAccessProof`, `openCalendarLink`.
- Vectors: `calendar-sharing-v1.json` (a generation-2 member share,
  refused shares, and the link envelopes with fixed nonces, so their bytes
  are exact), run in Rust and in `scripts/test-crypto-wasm.mjs`.
- No account-record purposes or scopes are needed.

**E3c and E3d's dialog, as built before E3b** (`feat/calendar-e3`). The UI
talks to the server through one module,
`frontend/apps/calendar/src/features/sharing/client.ts`, tested against a
stand-in server. These are the shapes E3b serves (post-W7 names); if E3b
differs, only that module changes.

- **Calendar rows** (`GET /api/v1/calendar/calendars`) gain:
  - `owner {accountId, address, incarnationId, signingPublicKey}` on a
    calendar someone else owns;
  - `keys [{keyGeneration, publicKey, fingerprint, lockedSecretKey,
    passphraseShare}]`, every live generation with the caller's share.

  The old single-key fields stay for now. A shared calendar opens only
  after the app's owner check (Drive's pins) passes. An owner whose
  identity changed is listed apart, to confirm, and the calendar stays
  closed.
- `GET …/calendars/{id}/keys` → `{keys: [...]}`, as above, for the caller.
- `GET …/calendars/{id}/members` → `{members: [{accountId, address,
  permissions, addedAt}], invitations: [{id, accountId, address,
  permissions, state: pending|declined, createdAt, expiresAt}]}`.
- `POST …/calendars/{id}/invitations {accountId, incarnationId,
  permissions, shares: [{keyGeneration, share}]}`. There is one share per
  live generation, sealed to the account the pins confirm.
- `PATCH …/calendars/{id}/members/{accountId} {permissions}`;
  `DELETE …/calendars/{id}/invitations/{invitationId}`;
  `DELETE …/calendars/{id}/members/me`.
- `POST …/calendars/{id}/keys/rotate {removeAccountId, fromKeyGeneration,
  keyGeneration, publicKey, lockedSecretKey, ownShare, memberShares:
  [{accountId, share}], metadata, links: [{id, passphrase, secret}]}`.
  - Pending invitees get the new generation too. **E3b requirement:** the
    server stores their shares beside the members' (an invitation holds a
    share of every live generation). An accept then hands the member every
    generation, including ones made while the invitation was pending.
  - It is refused (409) when `fromKeyGeneration` is not the newest.
- `GET /api/v1/calendar/invitations` → `{invitations: [{id, calendarId, owner,
  permissions, metadata, keys, createdAt, expiresAt}]}`;
  `POST …/invitations/{id}/accept` and `…/decline`. The member files its
  `calendarSettings` record before the accept.
- `GET …/calendars/{id}/links` → `{links: [{id, kind: full|query|busy,
  secret: {keyGeneration, sealed} | null, createdAt}]}`.
- `POST …/calendars/{id}/links {id, kind, secret?, passphrases?:
  [{keyGeneration, sealed}]}` answers the row.
- `DELETE …/calendars/{id}/links/{linkId}`.
- **Site settings in `/api/v1/auth/settings`:** `calendar {queryLinksAllowed,
  membersPerCalendar, linksPerCalendar}`.
- **A link's optional purpose:** `purpose` (a sealed triple, like the name)
  on `POST …/links` and on the link rows.
  - It is sealed to the calendar key with `sealLinkPurpose`, bound to the
    calendar and the link, and signed by the owner's address key: the
    server holds the calendar's public key, so without the signature it
    could write one.
  - `openLinkPurpose` opens it with whichever generation sealed it.
  - At most 100 characters; only the owner is shown it.
- **The public link page** (`/l/{id}#secret`) sits outside the session's
  boot, so it needs no sign-in and never forks the account app. It talks to
  the server through `frontend/apps/calendar/src/features/public/publicClient.ts`,
  with `fetch` and no credentials, never the session's client (no refresh,
  no sign-in redirect, no instance-id reconciliation that could clear
  anything on this origin). Routes:
  - `GET /api/v1/calendar/links/{id}` → `{calendarId, kind, metadata?, keys?:
    [{keyGeneration, fingerprint, lockedSecretKey, passphrase}]}`. A full
    link carries the sealed name and each generation's link-sealed
    passphrase; a busy link carries neither; 404 or 410 means gone;
  - `GET …/links/{id}/events?start&end[&afterStart&afterId]` →
    `{events: [{id, event, startUtc, endUtc, fullDay}], next}`;
  - `GET …/links/{id}/busy?start&end` → `{busy: [{startUtc, endUtc,
    fullDay}]}`.

  The page can't check the owner's signatures (no account to look their
  keys up), so nothing on it shows as verified. It is a week's agenda in
  the viewer's own time zone.
- **Busy/free (E3e):**
  - `shareBusy` on the calendar row, set through the existing `PUT
    …/calendars/{id}` with the member's defaults;
  - `GET /api/v1/calendar/busy?address&start&end` → `{busy: [{startUtc,
    endUtc, fullDay}]}` (camelCase UTC, as event rows), its window at most
    `calendar.busy_window_days` from the published settings;
  - the client merges overlaps;
  - the participant row stays with E4 (Q-4).
  - No member is limited to busy times in E3 (the presets give `READ`), so
    the limited member's grid waits for a preset that needs it.
  - The default for new calendars (a calendar settings record field) is not
    built.

**E3b as built** (`post-wipe/calendar-e3`, 2026-11-23; no migration, the
tables are the W7 baseline's):

- **Pending invitees' shares (decided 2026-11-23):** an invitation's shares
  live in `calendar_member_shares`, keyed by calendar, account and
  generation, beside the members'. That table has no foreign key to
  `calendar_members`, so a share can belong to an invitation; a rotation
  gives pending invitees the new generation like members, an accept turns
  the invitation into a member row without moving a share, and a decline,
  revoke or expiry drops them.
- Routes as above (`docs/api.md`, "Sharing" and "Links"), in
  `handlers/calendar_sharing.rs` and `handlers/calendar_links.rs`; busy
  blocks in `calendar_busy.rs`. Every envelope is checked against its
  binding and the owner's signature; the rotation is one transaction, and
  an event sync re-checks the newest generation under the calendar's lock
  (`409 keyRotated`).
- Settings (Server settings → Calendar): `calendar.members_per_calendar`
  (49) and `calendar.links_per_calendar` (5), both per account (they limit
  the owner); `calendar.query_links_allowed` (1; a whole-number setting, 0
  or 1, as the registry has no switch type); `calendar.invitation_days`
  (7); `calendar.busy_window_days` (31); `calendar.key_generations` (1000: a
  rotation past it is refused, nothing is pruned).
- Rate limits: `calendar.rate.busy` (per account) and, for the public link
  routes, `calendar.rate.link_fetches` (per address) and
  `calendar.rate.link_fetches_per_link` (a new `link` subject).
- Public links follow the site's and the owner's public-sharing switch
  (`drive.public_sharing`, A11), as Drive's links do.
- A busy link's feed covers a month back to a year ahead.
- Tombstones: `GET /calendar/tombstones` and `DELETE …/{calendarId}`; the
  app drops a listed tombstone's settings record when it lists calendars.
- Logging: the server's request span and nginx's `kutup` log format leave
  a calendar link's query out; unit tests check both.
- Tests: `crates/kutup-server/tests/calendar_sharing_live.rs` (in the live
  backup gate), browser specs 201–206.

**Review fixes** (2026-11-23, after an independent security review of
`post-wipe/calendar-e3`; migration `20261204000000_calendar_link_proofs`):

1. **A link's secret is the owner's alone.** It was sealed under the
   newest generation's passphrase, which every member holds: with an old
   copy and a removed member's old passphrase, every later generation
   opened through the link's passphrase copies. It is now a
   `CalendarLinkSecretEnvelopeV1` from the owner to itself (HPKE to the
   owner's account key, signed, bound to the link; label
   `kutup/calendar/link-secret-hpke/v1`), checked by the server against
   the owner's binding. A rotation carries a link over with the new
   generation's passphrase only.
2. **Query links off stops existing ones**: the feed answers `410
   queryLinksOff`, and a query link has no page and serves no events.
3. **nginx's error log** (which prints whole request lines on an upstream
   error or a refused request) is off for `/api/v1/calendar/links/`, in a
   location of its own with `limit_req_log_level info`.
4. **A link's id alone opens nothing.** A keyed link's page shows an access
   proof (HKDF of the secret over the link id, label
   `kutup/calendar/link-access/v1`, checked-in vector) in
   `X-Kutup-Link-Proof`; the server keeps its SHA-256 and serves the keys
   and events only with it (without it, only the kind). The query feed
   checks its key against the same hash before opening anything. Busy
   blocks come from a busy link only.
5. **Busy times are the owner's**: answered from calendars the person owns;
   `shareBusy` on a calendar someone else owns is `403 notOwner`, and the
   switch shows only to the owner.
6. **Generations**: `calendar.key_generations` defaults to 1000; at the cap a
   removal is `409 keyGenerationLimit` with a message saying so, and the
   owner's app compacts a calendar before it gets there ("Compaction"
   below).
7. **Inactive accounts** are left out of a rotation (and of the member
   list); what they held of the calendar goes, with a pending invitation.
8. **Busy blocks merge** (overlapping and touching), in answers and feeds.
9. **The query feed** opens only the events of a month back to a year
   ahead; the link fetch limits are 30 a minute per address and 60 per
   link.
10. **Lock order**: a calendar's change locks the calendar row first.
11. **Joining again** after leaving: a fresh accept clears this browser's
   replay guard for the calendar (`RevisionGuard.reset`).

Trade-offs decided (stricter than Proton):

- **T1, rotation due.** Leaving, a revoked invitation its invitee had read,
  a declined one read first, and one that expired after it was read mark
  the calendar `rotation_due`. When the owner's app next loads the calendar
  it asks the pins about everyone who would get the new key, without
  recording anyone: only when every one is on the owner's roster (below)
  and verified or pinned before does it rotate unasked (the removal's code,
  nobody removed). Otherwise (no roster, someone not on it, as a removed
  member the server brought back would be; someone first met; a changed
  identity), or when the rotation fails, the calendar's row says
  "Key change pending — review", which opens a dialog naming each
  recipient with what the pins say before the owner confirms.
- **T2, links on removal.** The remove dialog lists the keyed links with
  "Also replace links" checked by default: the rotation request names them
  (`removeLinks`), so they go in the same transaction as the new key and
  nothing is lost if it fails; they are made again after under fresh
  secrets, and the owner is shown the new addresses, or told which links
  were removed and couldn't be made again.
- **T3, recipients.** The remove dialog lists who gets the new key, each
  with what the pins say (verified, as before, first time, changed, not
  signed, someone else now), so an account the server slipped in shows.

**Roster.** The server says who a calendar's members and invitees are,
and a pin only says someone was met before, anywhere in Drive. So the
owner keeps its own roster of who it gave the key to, in its sealed
`calendarSettings` record (synced across its devices, out of the server's
reach): a keyed tag per account (the first 6 bytes of `hashed_object` of
the calendar id and the account id, 8 base64url characters, concatenated;
`CalendarSettingsV1::roster`, an optional field older readers keep). A new
calendar starts with an empty one; an invitation adds its invitee, a
revoked one comes off, and every rotation writes it as exactly who gets the
new key before the key changes (the removed member and anyone who left are
off it; not written, no key change). A calendar from before the roster, or
whose roster outgrew the 511-byte record (about 55 people), has none, and
every due key change goes to review.

**Compaction.** Each removal or due rotation adds a key generation. The
owner's app compacts a calendar when it holds 90% of
`calendar.key_generations`, and the calendar dialog offers it by hand
("Tidy up old keys") while there is more than one; Administration's
overview counts calendars at 90% or more.

1. `GET …/events/stale` lists, a batch at a time, the events whose key
   packets aren't to the newest key.
2. The owner's client opens each one's two key packets with the older
   generation's key and seals the same session keys to the newest key
   (`UnlockedCalendarKey::rewrap_key_packet`): the parts and their
   signatures stay byte for byte, and no author has to sign again.
3. `POST …/events/rewrap` takes them, each from the revision it was read
   at (`409 revisionConflict` otherwise, read again next round), checks
   that the packets are to the newest key (`notNewestKey`), and bumps the
   revision; link labels sealed under older keys go the same way.
4. `POST …/keys/prune` drops the older generations, with their member
   shares and link copies, in one transaction, after checking that no
   event and no link label names one (`409 generationInUse`; a packet that
   doesn't parse counts as naming one). The newest is never pruned.

The server can't check that a rewrapped packet carries the same session
key: only the owner rewraps, and a wrong one breaks only that owner's own
event. A removed member never held the newest key, so moving old events to
it gives nothing away.

Threat notes:

- **T5, the link page's origin.** `/l/{id}` is served by the Calendar app
  on `calendar.<domain>`, beside the signed-in app, as Drive's public pages
  are on Drive's origin. It reads no session, sends no credentials and
  writes nothing on the origin, and its secret stays in the fragment; a
  script injected into the origin could read both, as it could in Drive.
  Kept as Drive does.
- A query link gives the server the calendar on each fetch, by design;
  the access and error logs leave the key out, and the administrators can
  turn such links off (existing ones stop).
- A removed member keeps the passphrases it had, so the events it could
  read; nothing written after. Its copies of keyed links' addresses stop
  working when the links are replaced (T2).

Each slice is its own PR from its own worktree (`feat/calendar-e3a…`),
opened after the wipe.

## Questions

- **Q-1. Rotation by generations (§2).**
  - Recommended: keep old keys as a list, as Proton does.
  - Alternative: re-wrap every event to one new key, which is heavier.
- **Q-2. Members on other servers.**
  - Recommended: E3 shares with accounts on the same server only.
  - Federated calendars (events living on the owner's server, read through
    federation) come as their own phase after E5. Drive's federation
    covers files, not calendar queries.
- **Q-3. Who may see your busy times.**
  - Proton: only your organization.
  - Recommended: Proton's rule, with the toggle on by default for calendars
    of organization members and off otherwise. Without an organization,
    nobody can ask.
  - Wider options: anyone on the server, or your contacts.
- **Q-4. Where you see other people's busy times.**
  - Proton shows them only when participants are added to an event, which
    in Kutup comes with E4.
  - Recommended: build the API and the setting in E3, and the participant
    row (Proton's `BusyParticipantRow`) in E4.
  - Alternative: a small "Show availability of…" picker in E3.
- **Q-5. The fragment link's envelope.**
  - Recommended: an AEAD under a key derived per generation, instead of
    Proton's XOR, which would reuse one pad across generations.

## Decisions (the main session, 2026-11-17)

- **Q-1 to Q-5:** the recommended answers. Key generations; same server
  only in E3, federated calendars later; Proton's organization-only rule for
  busy times; the API and setting in E3, the participant row with E4; an AEAD
  per generation for the fragment link.
- **Event writes:** the server refuses an event write wrapped to anything
  but the newest generation, so a removed member's stale client can't keep
  writing under the old key. There is a test for it.
- **The query-key link:**
  - it says plainly in the UI (en and tr) that the server sees the calendar
    in plaintext on each fetch;
  - it is off by default in the link dialog;
  - it is an admin site setting (`calendar.query_links_allowed`, default
    allowed, as Proton);
  - the redaction test stays.
- **Busy-only ICS:** times only, from the readable columns. It reveals
  nothing the server can't already see: no counts or fields beyond the
  blocks themselves.
- **Removal is rotation in one request:** one transaction. A crash
  halfway leaves the old generation valid and current, never half-rotated.
  The new generation becomes current only when every share, the metadata and
  the links are written, and the member is removed in that same commit.
