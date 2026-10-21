# Calendar

Status: proposal (second session, 2026-10-21), settled from Proton Calendar's
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
- Recommended: offer both, the default being (b), and (a) labelled "for
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
- Recommended (b); either needs a Google OAuth client registered by the
  operator (and Google's verification for the calendar scope), so it is off
  on a server without one.
- `.ics` import and export in the browser as Proton's (limits as settings).

**9. Busy/free** of other Kutup users from the readable times, per calendar
opt-in, as Proton's; across servers through federation (a signed request
answering only busy blocks).

**10. Chat meetings.** An event can carry a Kutup meeting link (created
through Chat's call links, its title encrypted as Proton Meet's), replacing
today's `.ics` download in Chat; recurring meetings come from here.

**11. Not now:** holiday calendars (**D-4**: later, or not), Zoom and other
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

## Decisions for the user

- **D-1** Encrypt calendar names and descriptions (recommended) or keep them
  readable as Proton's.
- **D-2** Share links: both kinds, fragment by default (recommended); or
  Proton's only.
- **D-3** Import from Google: in the browser (recommended) or server-side as
  Proton's.
- **D-4** Holiday calendars: later, or not at all.
- Confirm: event times, recurrence and reminders readable by the server as
  Proton's (research 17 decided so; needed for reminders and busy/free).
