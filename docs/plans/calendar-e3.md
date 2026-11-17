# Calendar E3: sharing, links and busy/free

Status: approved by the main session 2026-11-17 with the recommended answers to Q-1 to Q-5 (see "Decisions"). Plan by the third session. Phase E3 of
[`calendar.md`](calendar.md), on its decisions D-1 to D-4 and the W4 key
model (a calendar's passphrase shared on account keys,
`CalendarShareEnvelopeV1`). Nothing is built. Code starts from `wipe/final`
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
  (`calendarMembersPerCalendar`, default 49).
- **Inviting.**
  - The owner's client finds the person with Drive's flow
    (`lookupAddress`, then `confirmRecipient`): pins by the typed address,
    and a warning on a changed identity.
  - It then seals the passphrase of every live key generation (§2) with
    `calendar::seal_passphrase` to that account's verified HPKE key, signed
    with the owner's account signing key.
  - `POST /api/calendar/calendars/{id}/invitations {account, incarnation,
    permissions, shares[]}`. The server checks every envelope's binding:
    calendar, generation, owner, member and incarnation.
- **The invitee's side.**
  - `GET /api/calendar/invitations` lists pending invitations, and the
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
  (`calendarInvitationDays`, default 7) and is swept.
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
  (`calendarKeyGenerations`, default 50).

### 3. Links (D-2)

Three kinds, at most `calendarLinksPerCalendar` (default 5). Each has an
optional purpose sealed to the calendar key, as Proton's. Only the owner
makes or deletes links.

1. **Full, key in the fragment (the default).**
   - The URL is `https://calendar.<domain>/l/{linkId}#<secret>`.
   - The server stores, per live generation, that generation's passphrase
     sealed under a key derived from the 32-byte link secret (HKDF, label
     `kutup/calendar/link/v1` in `labels.rs`; AEAD in `kutup-crypto`). This
     differs from Proton's XOR, so no pad is reused across generations.
   - The owner's own copy of the secret is sealed to the calendar key, as
     Proton seals its `CacheKey`. That lets the owner show the URL again and
     re-seal it on rotation.
   - The page fetches `GET /api/calendar/links/{id}/events?start&end` (no
     account; rate limited per IP and per link) with the keys and sealed
     passphrases. It opens them in WASM and shows a read-only calendar.
   - The server never decrypts anything.
2. **Full, key in the query (for other calendar apps).**
   - Proton's kind: `…/api/calendar/links/{id}/calendar.ics?key=<secret>`.
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
- **API.** `GET /api/calendar/busy?address=&start&end`:
  - the server resolves the address;
  - it unions the calendars that share busy times;
  - it expands recurrences with E2's rule engine;
  - it answers `[{start, end, fullDay}]` in UTC.
- **Limits** (admin settings): window `calendarBusyWindowDays` (default 31),
  and a rate limit in the registry.
- **What a limited (`AVAILABILITY`) member sees:** the calendar's busy
  blocks in the grid, drawn as Proton's `PartDayBusyEvent` /
  `FullDayBusyEvent`. That is the same `events` route answering busy blocks
  instead of events, rather than today's 403.
- **Seeing another person's busy times:** Q-4.

### 5. Numbers and checks

- **Migration:** one, at 20261201000000 or later.
  - Adds `calendar_keys`, `calendar_member_shares`, `calendar_invitations`,
    `calendar_member_tombstones` and `calendar_links`, plus the
    `share_busy` column.
  - Moves the key columns off `calendars`; the server makes generation 1
    from them.
  - No data migration is needed: it is a fresh table after the wipe.
- **Other numbers:**
  - specs 200–206;
  - one new label (`kutup/calendar/link/v1`), with the `ALL` array length
    updated;
  - no new account-record purpose or scope (it reuses `calendarSettings`,
    purpose 32).
- **Everything else:**
  - every limit above is a site setting;
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
  - it is an admin site setting (`calendarQueryLinksAllowed`, default
    allowed, as Proton);
  - the redaction test stays.
- **Busy-only ICS:** times only, from the readable columns. It reveals
  nothing the server can't already see: no counts or fields beyond the
  blocks themselves.
- **Removal is rotation in one request:** one transaction. A crash
  halfway leaves the old generation valid and current, never half-rotated.
  The new generation becomes current only when every share, the metadata and
  the links are written, and the member is removed in that same commit.
