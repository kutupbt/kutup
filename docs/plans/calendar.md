# Calendar

Status: decided (the user, 2026-10-21; see Decisions), settled from Proton Calendar's
code in WebClients (`applications/calendar`, `packages/shared/lib/calendar`,
`packages/activation`), for the user's decisions. Follows
[research 17](../research/17-mail-calendar-contacts.md) "Calendar" and the
decisions there (Proton's readable split, invitations over Mail, no CalDAV).
Every path below is WebClients'; `psl` is `packages/shared/lib`.

## What Proton does

**Keys.**
- Each calendar has its own OpenPGP key (Curve25519, `calendarKeys.ts:25-40`),
  locked by a random 32-byte passphrase of its own (`:17-20`).
- The passphrase is one encrypted data packet, signed with the owner's address
  key, and one key packet per member, wrapped to that member's address key
  (`CalendarPassphrase { MemberPassphrases }`, `CalendarKey.ts:20-64`). Sharing
  wraps one more key packet; no event is re-encrypted.
- A key can be reset (a new key: old events become unreadable,
  `resetCalendarKeys.ts`) or reactivated once the address keys are recovered
  (`reactivateCalendarKeys.ts`). No client code rotates a calendar's key when a
  member is removed.

**Events, split by what the server may read** (`psl/calendar/constants.ts:315-347`,
`veventHelper.ts:296-330`):

| Part | Fields | Protection |
| --- | --- | --- |
| shared, signed | UID, DTSTART, DTEND (with TZID), RRULE, EXDATE, RECURRENCE-ID, ORGANIZER, SEQUENCE | readable, signed |
| shared, encrypted | title, description, location, conference URL, everything else | encrypted and signed |
| calendar, signed | STATUS, TRANSP | readable, signed |
| calendar, encrypted | comment | encrypted and signed |
| attendees | the attendee list | encrypted and signed; readable per attendee: a token (SHA-1 of UID and email), PARTSTAT, an optional comment |

- Two session keys per event (shared and calendar), wrapped to the calendar
  key; each part signed by the author's address key (`serialize.ts`,
  `encrypt.ts:44-64`).
- Readable beside them: start and end times and zones, all-day, RRULE, UID,
  RECURRENCE-ID, EXDATEs (`CalendarEventMetadata`, `Event.ts:84-94`), the
  event's colour and its **reminders** (`Notifications`, `formatData.ts:56-60`).
- So Proton's server knows **when** every event is, how it repeats and when
  to remind; it never knows **what** it is or **who** is invited by name.

**Sharing.** Members by permission bits (`SUPER_OWNER, OWNER, ADMIN,
READ_MEMBER_LIST, WRITE, READ, AVAILABILITY`; presets edit, full view,
limited), 49 per calendar. The owner wraps the passphrase's session key to
the invitee's address key, signed (`calendar.sharing.invite`); the invitee
verifies, signs and accepts. Calendar names, descriptions and colours are
readable.

**Share links** (5 per calendar): full (the passphrase XOR a random key) or
limited (busy blocks only). The key is in the **query string**
(`…/calendar.ics?CacheKey=…&PassphraseKey=…`, `shareUrl.ts:117-139`), so
Proton's server decrypts the calendar on each fetch and serves an ICS any
calendar app can subscribe to.

**Invitations over mail (iTIP/iMIP).** `invite.ics` (`METHOD:REQUEST`,
`REPLY`, `CANCEL`, RFC 5546) attached and sent with each recipient's sending
preferences (`useSendIcs.ts`). Between Proton users, the event's shared session
key goes in the invitation (`x-pm-session-key`) and the server adds the event
to the attendee's calendar at once (`AddedProtonAttendees`), linked to the
organizer's so edits reach them. A reply updates the organizer's PARTSTAT by
the attendee's token (`inviteApi.ts:921-935`). Outside people get plain ICS;
`icsSurgery/` repairs what others send.

**Reminders.** Device (notification) or email, relative triggers, readable.
The **server** expands recurrences and lists the occurrences due
(`GET /calendar/v1/{id}/alarms`, `Alarm.ts`); the web app fires local
notifications from it; email reminders are sent by the server.

**Add calendar from URL.** The server validates and then fetches the feed
periodically, encrypting events to the calendar's public key; the URL is
readable; statuses for size, HTTP failures, "not synced" after 12 hours
(`Subscription.ts`, `subscribe/helpers.ts`).

**Imports.** `.ics` import in the browser (15,000 events, 10 MB). Google and
Outlook through Easy Switch: OAuth through Proton's server, which keeps the
token, fetches from Google's API and encrypts to the calendar's public key.

**Also:** holiday calendars (a directory of Proton-owned calendars whose
passphrase is published), busy/free of other users from the readable times
(per calendar, opt-in), video-call links (Zoom created server-side, Proton
Meet with an encrypted title), and **no CalDAV** anywhere.

**Limits:** calendars 3 / 25 / 50 / 150 by plan, 10 reminders per event,
100 attendees, 49 members, 5 links, title 255, description 3000, location
255, COUNT ≤ 49 (499 for invitations), dates 1970–2037.

## Proposal for Kutup

Copy Proton, as the standing rule asks, except where Kutup can do as well
with less trust in the server (marked **D-n** for the user's decision).

**1. Keys.** As Proton: a calendar key per calendar (rPGP in `kutup-crypto`,
as Mail's address keys; post-quantum once Mail's keys are,
[`mail-pq-openpgp.md`](mail-pq-openpgp.md)), a random passphrase, one data
packet and a key packet per member wrapped to their address key, signed. Reset
and reactivation as Proton's. On a member's removal the passphrase and key are
rotated (Proton shows none; Kutup does it, so a removed member can't read new
events with a key it kept).

**2. Events.** Proton's split exactly: what is readable is what the server
needs for reminders, busy/free, the time-window queries and invitations. The
same parts, two session keys, the author's signature. The Rust core
(`kutup-crypto` `calendar_event`) owns the format, with vectors.

**3. Calendars and members.** Owner, admin, edit, full view and limited
(busy only); invitations signed and accepted as Proton's. Names, descriptions
and colours readable as Proton's. **D-1:** encrypt the calendar's name and
description too (Kutup's Drive and Photos encrypt names); recommended, since
the server needs neither.

**4. Share links.** **D-2:**
- (a) Proton's: the key in the query, the server decrypts on fetch, any
  calendar app can subscribe; or
- (b) the key in the fragment: only Kutup's own web view opens it, nothing
  is decrypted by the server, and other apps can't subscribe.
- Decided: offer both, the default being (b), and (a) labelled "for
  other calendar apps (the server reads it while serving)".
- Limited (busy only) links need no key, as Proton's.

**5. Invitations.** As Proton's, through Kutup Mail: `invite.ics` for
outside people, the session key and an instant add between Kutup users
(across servers too, as a Mail message), replies by attendee token,
`icsSurgery`-style repair of what others send, the invitation widget in Mail.

**6. Reminders.** As Proton's: readable triggers, the server expands
recurrences (the `rrule` crate) and sends **web push** (Chat's) and
**email** reminders; the browser shows notifications while open.

**7. Add calendar from URL** (asked by the user). As Proton's: the server
fetches the feed (it is someone else's public feed; Kutup's server is just a
client of it), encrypts the events to the calendar's key and refreshes it; the
URL is readable; statuses as Proton's. Feeds count against the account's
storage. This is also how a Google calendar appears beside Kutup's, read-only
(Google's "secret address in iCal format"), the "Gmail calendars in one view"
the user asked for.

**8. Import from Google** (asked by the user). **D-3:**
- (a) Proton's: the server runs the OAuth, keeps the token, fetches and
  encrypts; or
- (b) the browser runs the OAuth (PKCE) and reads Google's Calendar API
  itself, encrypting before upload: no Google token or event ever on Kutup's
  server.
- Decided (b); either needs a Google OAuth client registered by the
  operator (and Google's verification for the calendar scope), so it is off
  on a server without one.
- `.ics` import and export in the browser as Proton's (limits as settings).

**9. Busy/free** of other Kutup users from the readable times, per calendar
opt-in, as Proton's; across servers through federation (a signed request
answering only busy blocks).

**10. Chat meetings.** An event can carry a Kutup meeting link (created
through Chat's call links, its title encrypted as Proton Meet's), replacing
today's `.ics` download in Chat; recurring meetings come from here.

**11. Not now:** holiday calendars (**D-4**: a later phase), Zoom and other
outside video links (a link pasted into the event works without them).

**12. Limits.** All administrators' settings, per account where it fits:
calendars per account (25), members per calendar (49), links per calendar
(5), reminders per event (10), attendees (100), import size (15,000 events,
10 MB), feeds per account and their refresh interval (12 hours) and size,
plus Proton's field lengths. Events and feeds count against the account's
one storage pool.

**13. The app.** `calendar.<domain>`: day, week, month and agenda views, the
event editor (recurrence, reminders, attendees, video link), calendars and
sharing, links, import and export, settings; the invitation and reminder
widgets in Mail. English and Turkish.

## Phases

| Phase | Delivers |
| --- | --- |
| E1 | Calendar keys and events in `kutup-crypto` (vectors), the server's calendars, members and events (time-window queries), the app with personal calendars |
| E2 | Recurrence and exceptions, reminders (web push, email), `.ics` import and export |
| E3 | Sharing (members, links per D-2), busy/free |
| E4 | Invitations over Mail (outside and Kutup-to-Kutup), the Mail widgets |
| E5 | Add calendar from URL, import from Google (per D-3), Chat meetings in events |

## Decisions (the user, 2026-10-21)

- **D-1: calendar names and descriptions are encrypted** (to the calendar's
  key), unlike Proton's: the server needs neither. Colours stay readable.
- **D-2: both kinds of share link, the fragment kind by default.** Its key is
  in the URL's fragment, so the server never decrypts; only Kutup's web view
  opens it. Proton's kind (the key in the query, the server decrypts on each
  fetch) is optional, for subscribing from other calendar apps, and the UI
  warns plainly that the server reads the calendar while serving it.
  Busy-only links need no key.
- **D-3: Google import runs in the browser** (OAuth with PKCE, Google's
  Calendar API, events encrypted before upload): no Google token or event
  ever reaches Kutup's server. It needs a Google OAuth client the operator
  registers (and Google's verification for the calendar scope);
  self-hosting.md documents the registration, and the import is off where
  none is configured.
- **D-4: holiday calendars come later**, in a phase after E5.
- **Confirmed:** event times, time zones, all-day, recurrence, exceptions
  and reminders stay readable by the server, as Proton's (needed for
  reminders, busy/free and time-window queries); titles, descriptions,
  locations, attendees and comments are encrypted and signed.
- Phases E1 to E5 as above; building starts after the rate limits (#299).

## E1: build note (second session, 2026-10-21)

Built: crypto and server in #307, the app in its follow-up (PR (b)). The view
settings are kept per device in E1 (`kutup-calendar-prefs`); the account-wide
settings come with reminders in E2.

For review before code. E1 delivers personal calendars end to end: keys,
calendars, single events (no recurrence, reminders or sharing yet, but the
formats and tables carry them so E2–E4 add no migration of data). Copied from
Proton (`packages/shared/lib/calendar`, `interfaces/calendar/{Api,Event}.ts`)
except where marked.

**Crypto (`kutup-crypto` `calendar`, feature `mail`, rPGP as Mail).**
- *Calendar key:* the same shape as a Mail address key (v4, Ed25519 primary,
  Curve25519 ECDH subkey, AES-256), its secret armored and **locked with a
  passphrase** (iterated S2K, AES-256; Mail's export path). Post-quantum when
  Mail's address keys move (`mail-pq-openpgp.md`), as Proton.
- *Passphrase:* 32 random bytes. Stored as Proton's `CalendarPassphrase`: one
  data packet (SEIPD under a session key) and one key packet per member
  (PKESK to that member's primary address key), plus the owner's detached
  signature over the passphrase. A member verifies the signature against the
  owner's address keys (`mail-core` key lists) before using it.
- *Calendar metadata (D-1):* name and description, as one JSON object, signed
  and encrypted to the calendar key (`encrypt_split` with the calendar key as
  recipient: key packet and data packet stored apart). Colour is the
  member's, readable.
- *Events:* Proton's parts, each a VCALENDAR text with one VEVENT holding only
  its part's properties (Proton's field lists above), types
  `signed` / `encrypted-and-signed`:
  - shared signed: `uid, dtstamp, dtstart, dtend, recurrence-id, rrule,
    exdate, organizer, sequence`;
  - shared encrypted: `uid, dtstamp, created, description, summary, location`
    (and the conference URL later);
  - calendar signed: `uid, dtstamp, exdate, status, transp`;
  - calendar encrypted: `uid, dtstamp, comment`;
  - attendees (E4): encrypted.
  Two session keys, shared and calendar, each a key packet to the calendar
  key; every part signed (detached) by the author's address key. **The Rust
  core owns the parts' text**: it builds them from typed fields and parses
  them strictly (the properties of its part, nothing else, RFC 5545 escaping,
  `DTSTART;TZID=` or `VALUE=DATE` or UTC), so the server and every client
  read one format.
- *New rPGP functions:* encrypt a data packet with a given session key,
  wrap a session key to a public key (a new key packet: sharing in E3 and
  invitations in E4 reuse it), and open a key packet to its session key with
  the calendar key. Mail has none of these today; they live in `mail_key.rs`
  beside `encrypt_split`.
- *WASM and JS:* `frontend/packages/crypto/src/calendar.ts`, the calendar
  secret held inside WASM as Mail's address keys are: the browser passes the
  locked key and the passphrase (opened with the member's address key) on
  each call.
- *Vectors:* `calendar-key-v1.json`, `calendar-event-v1.json` (fixed keys
  and ciphertexts that must open; refused cases: a part with a property of
  another part, a bad signature, a wrong key packet), run in Rust and WASM.

**Server.**
- Tables (one migration, above master and open PRs when built):
  - `calendars`: id, owner, key (armored public key; the locked secret),
    passphrase data packet and owner's signature, metadata key packet and
    data packet, created/updated;
  - `calendar_members`: calendar, user, address id the key packet is to,
    permissions (Proton's bit flags; E1 writes the owner only), passphrase key
    packet, colour, display flag;
  - `calendar_events`: id, calendar, uid, author address, the parts (type,
    data, signature) and the two key packets, and the readable columns the
    server derives: `start_utc`, `end_utc`, `start_tz`, `end_tz`, `full_day`,
    `rrule` (text), `recurrence_id`, `exdates`, `range_end_utc` (the last
    instant any occurrence can reach; open for an endless rule), sequence,
    status, transp, created/modified;
  - indexes on (calendar, start_utc, range_end_utc) and (calendar, uid,
    recurrence_id).
- *Readable fields come from the signed part* (Proton: the API takes only
  the parts): the server parses the shared signed part with the Rust core,
  checks the author's detached signature against the author's current address
  keys (key list), and converts DTSTART/DTEND with their TZID to UTC (a time
  zone database: `jiff` with its bundled, pinned tzdb). Unknown TZIDs are refused (clients map Windows
  and other aliases first, as Proton's `getSupportedTimezone`).
- *Routes* (`/api/calendar/...`, Proton's shapes renamed to Kutup's style):
  `GET/POST calendars`, `PUT/DELETE calendars/{id}` (metadata, colour,
  display), `GET calendars/{id}/events?start&end` (events whose
  [start_utc, range_end_utc) meets the window; paged), `POST
  calendars/{id}/events/sync` (Proton's batch of create/update/delete, each
  checked alone, at most 10 a request), `GET calendars/{id}/events/{eventId}`.
  E1 refuses `rrule`, `recurrence-id` and `exdate` (E2 lifts it).
- *Limits* (administrators' settings, per account where they count per
  account): calendars per account (25), events per calendar (25,000), part
  sizes (title 255, description 3,000, location 255 characters; each part
  ≤ 64 KiB), sync batch (10); a rate limit per account on writes in the
  registry (#302).
- *Storage:* every event's bytes and each calendar's keys and metadata count
  against the owner's one pool (`storage_pool::lock`), refunded on delete;
  the reconcile job and the usage page get a Calendar line.
- *Account reset and deletion* remove the account's calendars (members'
  rows with them).
- *Rollback:* Proton keeps no index for events. Kutup adds the `calendars`
  scope to the account head (the list of calendar ids and their metadata
  revisions), as Contacts does, so a server can't hide or replay a calendar;
  events per calendar get no head index in E1 (a later item if wanted).

**The app (`calendar.<domain>`, dev port 5183).**
- Every file the new-app checklist names (sessions' client type, origins,
  fork, vite, nginx/hosts script, Dockerfile, deploy, compose files, CI SANs,
  e2e fixtures, app switchers, launcher, storage page, feedback app list), and
  a `calendar-core` package (API, keys, parts through WASM, time zones).
- Views: month and week (and day), today, a mini-month to move; the event
  editor (title, all-day, start and end with time zone, location,
  description, calendar); the calendars sidebar (create, rename, colour,
  show/hide, delete with its events). Times shown in the browser's zone or the
  one the person picks (settings: zone, week start, 12/24 h). Time-zone maths
  through `Intl` with a small tested helper (Proton's approach), no extra
  library.
- The first open makes a "My calendar" with the person's primary address
  key; an account without a Mail address key gets one first (Mail's
  `addFirstAddressKey`).
- en and tr; e2e specs (create a calendar, an event across a time zone,
  edit, move, delete; a second device reads them).

**The browser runtime and its budget (the main session, 2026-10-21).**
Calendars and the bundled time zone database add about 805 KB raw, 230 KB
gzipped, to the crypto WASM. So `kutup-crypto-wasm` is built twice from the
one crate: `crypto` for every app, and `crypto-calendar` (its `calendar`
feature) which the Calendar app, and Mail once invitations need it (E4),
load **instead of** `crypto`, never both. Every WASM runtime has a gzipped
size budget (`frontend/wasm-budgets.json`, about 5% above its size when
set), checked in the web gate (`scripts/check-wasm-size.mjs`): crypto
1.78 MB, crypto-calendar 2.02 MB. The WASM vectors run on both builds, and
the plain one must carry no calendar function.

**Not in E1:** recurrence, reminders, import/export (E2), sharing and links
and busy/free (E3), invitations (E4), URL feeds, Google import, meetings
(E5), holidays (later).

**Answers (the main session, 2026-10-21).**
1. The `calendars` account-head scope is added: rollback protection like the
   other listed scopes, a deliberate addition beyond Proton.
2. Time zones through **jiff with its bundled tzdb** (`jiff-tzdb`), pinned,
   so every server and the WASM client convert identically whatever the
   host's zoneinfo. A tzdb update is a dependency bump (a new `jiff-tzdb`
   release), reviewed and gated like any other.
3. Two PRs: (a) crypto, proto and server with live tests; (b) the app. No
   UI affordance ships before its backend.
- The rPGP additions get vectors, cross-checked against a Proton calendar
  event where the references hold one (OpenPGP.js / go-crypto test data),
  and pass `cargo deny`.

**Security review (the main session, 2026-10-21), fixed in #307 before any
data exists.**
- H1: a client seals events and metadata only through the calendar key it
  unlocked (`UnlockedCalendarKey`, whose public key is derived from the
  secret), never to a public key the server hands it; the WASM has no
  seal-to-a-key function.
- M3: the sealed metadata names its calendar id and the key's fingerprint,
  and opens only under both, so the server can't move one calendar's name
  onto another.
- L6: a locked key is taken only in the form this code writes (AES-256,
  iterated and salted S2K, a bounded count).
- M1, L1: the events page cursor is the client's `(afterStart, afterId)`;
  the window is half-open.
- L2: events carry a revision; an update names its `baseRevision`, and
  `SEQUENCE` never goes down.
- L3: the member's permissions are checked again inside each change's
  transaction. L7: the author columns are indexed.
- The window and page sizes are site settings (`calendarWindowDays`,
  `calendarEventsPage`).

**Recorded for later.**
- M2 (post-quantum): calendar keys follow Mail's keys to PQ OpenPGP
  ([`mail-pq-openpgp.md`](mail-pq-openpgp.md)). `calendars.suite` (1 =
  the current Ed25519/X25519 key) is in the schema now, so a PQ suite is a
  new value with its own read and migrate policy, never a format change.
- L4: deleting a calendar removes the members' rows without their account
  heads naming the change. E1 has owners only; E3 (sharing) makes the delete
  tell each member's client, which then drops the calendar from its head.

## E2: build note (second session, 2026-10-21)

Recurrence and exceptions, reminders, `.ics` import and export, following
Proton's web client (`packages/shared/lib/calendar`, `applications/calendar`)
unless marked **Q-n** (the main session's answers, 2026-10-21, are in
place). Three PRs, as E1: (a) the Rust
core, (b) the server, (c) the app.

**1. Recurrence: Proton's subset, in the Rust core.**
- `RRULE` with `FREQ` DAILY, WEEKLY, MONTHLY or YEARLY only, and only
  Proton's parts per frequency (`rrule.ts:83-142`): `INTERVAL`, `COUNT`,
  `UNTIL`, `WKST`; WEEKLY `BYDAY`; MONTHLY one `BYMONTHDAY`, or one `BYDAY`
  with `BYSETPOS` in {-1, 1, 2, 3, 4} (also written `2TU`); YEARLY one
  `BYMONTH` with one `BYMONTHDAY`, or `BYYEARDAY`. `COUNT` and `UNTIL`
  never together; `DTSTART` is the first occurrence; at least one
  occurrence. `RDATE`, `EXRULE`, `BYWEEKNO`, `BYHOUR` and lists in monthly
  or yearly rules are refused, as Proton refuses them (they are kept as
  unsupported, read-only, on import; see 5).
- `UNTIL` is normalised as Proton's (`getSupportedUntil`): before `DTSTART`
  becomes `DTSTART`; all-day a `DATE`; timed 23:59:59 of that day in
  `DTSTART`'s zone, as UTC. `WKST` is kept only when not MO and meaningful.
- The canonical form of E1 already carries `RRULE` and `EXDATE` in the
  shared and calendar signed parts; E2 lifts E1's refusal and parses them
  strictly (a rebuild must match byte for byte).
- **The expander is Kutup's, on jiff**, not the `rrule` crate the plan
  named: `rrule` brings `chrono` and `chrono-tz`, a second time zone
  database that could disagree with `jiff-tzdb`, and Proton's subset is
  small. As Proton's (`recurring.ts`): the rule runs on the wall clock in
  `DTSTART`'s zone and each occurrence converts with that zone, so 09:00
  stays 09:00 across DST; a gap moves forward, an overlap takes the earlier
  instant (jiff's `compatible`); the end is start + duration in the start
  zone; all-day durations count days. `EXDATE` matches by local start.
  Vectors cross-checked against ical.js runs of the same rules (the
  references' test data), and a fuzz target for the parser and expander.
- The same code runs in the server (below) and in WASM (`crypto-calendar`;
  its size budget is raised only with the measured growth).

**2. Exceptions, as Proton's (`containers/calendar/recurrence`).**
- One occurrence changed: a child event with the same UID and
  `RECURRENCE-ID` = the occurrence's local start (`DATE` for all-day), no
  `RRULE` or `EXDATE`. Deleted: an `EXDATE` on the parent, and the child
  deleted if any.
- This and following: the series is cut (`COUNT` reduced, or `UNTIL` the
  previous day 23:59:59 in its zone; the `RRULE` removed when nothing is
  left), the later children deleted, and a new series created with Proton's
  UID `<uid>_R<yyyymmdd>[T<hhmmss>]@<domain>` (an older `_R` suffix
  replaced), `SEQUENCE` 0.
- All occurrences: the parent changed and the children deleted, with
  Proton's three choices when the start moved (keep single changes, keep the
  original date with the new time, use the new date).
- `SEQUENCE` as Proton's (`sequence.ts`): +1 unless the times, all-day and
  rule are unchanged or the new rule is a subset of the old; a child's is at
  least its parent's.
- Each change is one sync change, applied alone, as Proton's. The server
  checks a child's parent exists in the calendar (same UID, no
  `RECURRENCE-ID`, an `RRULE`) and that the `RECURRENCE-ID` is one of its
  occurrences; the unique (calendar, UID, RECURRENCE-ID) index already
  holds one child per occurrence. **Q-1 (answered: as Proton's):** a "this
  and following" edit is three changes (delete the later children, cut the
  parent, create the new series), each applied alone. The app plans all
  three before sending and retries what hasn't landed, and every step is
  idempotent: an event's id is drawn by the client (a UUID v4, as calendar
  ids in E1), so a create retried with the same id and content answers the
  stored event instead of a second one; the cut names its `baseRevision`,
  so a retry after it landed is a `revision_conflict` the app reads as done
  (it checks the stored rule) and never cuts twice; a delete of an event
  already gone is done. The series shows as pending until all three have
  landed.

**3. The window and range end.** `range_end_utc` (E1's column, NULL for
endless) becomes the last occurrence's end, computed by the server from the
signed `DTSTART`, `DTEND`, `RRULE` and `EXDATE` with the expander, so the
window query of E1 is unchanged. Clients expand the series in the window
from the opened event and check the server's `startUtc` and range end
against their own, as E1 checks the start.

**4. Reminders.**
- As Proton's: `{ type: email | device, trigger }` relative to the start
  only (`-PT15M`), readable by the server, never in the encrypted parts.
  They belong to the member, not the event (each member of a shared
  calendar in E3 has their own): a table `calendar_event_reminders (event,
  user, reminders jsonb)`, absent meaning the calendar's defaults, sent
  beside the event in a sync change (`reminders`). Proton's bounds:
  triggers up to 999 weeks, 6999 days, 999 hours or 9999 minutes before;
  at the start for timed events, up to a day after for all-day ones
  (`VALARM`s otherwise are dropped on import).
- Defaults per member and calendar, as Proton's calendar settings
  (`DefaultPartDayNotifications`, `DefaultFullDayNotifications`,
  `DefaultEventDuration`): timed 15 minutes before, all-day 15 hours before
  (09:00 the day before), device and email. On the member row, under its
  revision and the account head like colour and display.
- **The server expands and fires.** A table `calendar_alarms (user, event,
  occurrence, fire_at, action)` holds each member's next alarm per event
  and reminder, recomputed when the event or its reminders change and after
  one fires; a job (`jobs.rs`) every minute takes the due ones (`FOR UPDATE
  SKIP LOCKED`, so several servers never fire one twice) and skips any more
  than the site setting's lateness (Proton: one minute for the web).
  `GET /api/calendar/alarms?start=&end=` lists a member's alarms in a
  window (pages by fire time), as Proton's `/alarms`, for the open app.
- **Device:** the open app fires its own notifications from `/alarms`
  (Proton's: two days ahead, refetched before the end, one timer for the
  next). When no tab is open the server sends a **web push** through
  Chat's `web_push.rs` (its VAPID key, allowlisted push services, a
  subscription per browser now also for the Calendar app). **Q-2
  (answered):** Chat's pushes are empty; a reminder push carries, encrypted
  to the browser (RFC 8291), only the start time and the event id, never
  the title (the server can't read it), so the notification reads "An
  event starts at 09:30", and opening it opens the event. The service
  worker never holds calendar keys.
- **Email:** a message the server writes to the member's own Kutup address,
  delivered through Mail's inbound path (so it is encrypted at rest to the
  address key like any mail) saying only "You have an event at <time>" and
  a link to the event: never the title, description or location, which the
  server can't read. Only for accounts with a Mail
  address; the editor hides the email type otherwise.

**5. Import (`.ics`, in the browser).**
- As Proton's: `.ics`, `.ical`, `.icalendar`, `.ifb`; up to 10 MB and
  15,000 components (site settings); errors as Proton's (empty, not a
  calendar, no events, too many, corrupted; a non-`PUBLISH` method warns).
- A lenient parser in the Rust core (folded lines, bad line endings, the
  repairs Proton's `icsSurgery` makes) that rebuilds each event by
  Proton's whitelist: UID (made when missing), DTSTAMP, DTSTART, DTEND
  (`DURATION` turned into `DTEND`, a zero-length one dropped), SEQUENCE
  (mod 2^31), SUMMARY, LOCATION, DESCRIPTION (Proton's lengths), EXDATE,
  RECURRENCE-ID, RRULE, VALARMs (10 at most, `AUDIO` as device).
  `ORGANIZER`/`ATTENDEE` dropped on `PUBLISH`; `VTODO`, `VJOURNAL` and
  `VFREEBUSY` refused; an unsupported rule or `RECURRENCE-ID` with `RRULE`
  is reported per event and not imported, as Proton's.
- Time zones: `VTIMEZONE` blocks ignored; a `TZID` mapped as Proton's
  `getSupportedTimezone` (IANA, then `(UTC+x) Name`, then the Windows
  names table, then a substring), floating times in `X-WR-TIMEZONE` or the
  person's zone.
- Events go in batches of `calendarSyncBatch`, parents before children,
  each with its own reminders (imported events take no defaults). **Q-3
  (answered: as Proton's `Overwrite:1`):** a UID already in the calendar
  is overwritten, unless the imported `SEQUENCE` is lower than the stored
  one: that event is refused (`sequenceBehind`, as E1's updates) and listed
  as skipped in the import's report.

**6. Export.** All events of a calendar (paged by id), opened in the
browser, written by the Rust core as one `VCALENDAR` (`VERSION:2.0`,
`METHOD:PUBLISH`, `CALSCALE:GREGORIAN`, `X-WR-CALNAME`, `X-WR-CALDESC`,
`X-WR-TIMEZONE`) with a `VTIMEZONE` for each zone used, built from the
bundled tzdb's transitions over the events' years; reminders as `VALARM`s;
the colour not exported; the file `<name>-yyyy-MM-dd.ics`.

**7. Settings.** Proton's calendar user settings that apply in E2 (week
length, week numbers, default calendar, the primary zone and its
auto-detect, a secondary zone, the default view) move from the app's local
`prefs.ts` to the account's synced UI preferences (`ui_preferences.rs`),
so every device shows the same; week start stays the account's.

**8. Limits (site settings, per account where it fits).** Reminders per
event (10) and per calendar's defaults (5), the largest `COUNT` (49; 499
for invitations in E4), import size and components (10 MB, 15,000), how
late a reminder may still fire (1 minute), the alarms page (100). The rule
grammar (which `RRULE` parts) and the 1970–2037 date range are the format,
as Proton's, not limits.

**9. The app.** The editor's repeat control (Proton's: none, daily,
weekly, monthly on the day or the nth weekday, yearly, custom with interval,
weekdays and an end by date or count), the "this / this and following /
all" choice for edits and deletes, reminders with defaults, import (a file,
a calendar, a report) and export from the calendar's menu, the settings
above, notification permission asked when the first device reminder is
saved. English and Turkish; e2e specs for a weekly series across DST, an
exception, a cut series, a reminder fired (a short trigger with the test
stack's lateness), import of a Google export and export round-trip.

**Not in E2:** sharing and busy/free (E3), invitations and their wider
rule set (E4), feeds and Google import (E5).
