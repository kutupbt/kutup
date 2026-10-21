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
  zone database: `jiff` with its bundled tzdb, or `chrono-tz`; whichever the
  dependency policy passes). Unknown TZIDs are refused (clients map Windows
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

**Not in E1:** recurrence, reminders, import/export (E2), sharing and links
and busy/free (E3), invitations (E4), URL feeds, Google import, meetings
(E5), holidays (later).

**Questions for the reviewer.**
1. The `calendars` account-head scope beyond Proton (recommended).
2. The time zone crate: `jiff` (newer, bundled tzdb, one crate) or
   `chrono-tz` (widely used, compiled-in tzdb).
3. E1 as one PR (crypto + server + app, about Contacts' size) or two (crypto
   and server first, then the app).
