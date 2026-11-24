# Calendar E4: invitations over Mail

Status: approved by the main session 2026-11-18 with the recommended answers to Q-1 to Q-6 (see "Decisions"). Plan by the third session. Built 2026-11-24 on `feat/calendar-e4`: see "As built" at the end for what was built, what differs from the plan and why, and what is left.
Phase E4 of [`calendar.md`](calendar.md) (decision 5: as Proton's, through
Kutup Mail). Builds on E2 (the recurrence engine), E3 (members, busy times;
`calendar-e3.md`) and L7 (sealed mail headers; `server-personal-data.md`). The
names are W7's (`accountId`, `/api/calendar/…`, `calendar.*` settings).
Questions are **Q-n** at the end.

## What Proton does

Paths are in `kutup-references/WebClients`.

**Methods** (`packages/shared/lib/calendar/constants.ts`, `vcalHelper.ts`):
- REQUEST, REPLY and CANCEL work fully.
- A missing METHOD means PUBLISH, which is offered as an import ("Add to
  Calendar").
- COUNTER and REFRESH are shown ("proposed a new time", "asked for the
  latest updates") but not acted on: "Event rescheduling / refreshing is not
  supported for the moment". A COUNTER that carries a PARTSTAT is applied like
  a REPLY.
- ADD is "not supported for the moment".
- DECLINECOUNTER is refused, and Proton never sends COUNTER, REFRESH or
  DECLINECOUNTER.
- Direction is checked: REPLY, COUNTER and REFRESH only reach an organizer;
  REQUEST, CANCEL, ADD and DECLINECOUNTER only reach an attendee. Anything
  else is "Invalid method".

**The Mail widget** (`applications/mail/src/app/components/message/extrasHeader/components/ExtraEvents.tsx`,
`calendar/ExtraEvent*.tsx`; logic in `helpers/calendar/invite.ts`,
`inviteApi.ts`, `summary.ts`):
- one widget per `.ics` on a message;
- states:
  - new invitation;
  - updated ("This event has been updated.");
  - out of date ("This invitation is out of date…");
  - cancelled;
  - already answered ("You already accepted…");
  - a reply received ("X accepted your invitation", "…to one occurrence");
  - a reply out of date, or for an event that no longer exists;
  - "This response doesn't match your invitation details";
  - party crasher ("Your email address is not in the original participants
    list"; Proton invitations are blocked, outside ones let you answer);
  - "You cannot reply from the invited address";
  - disabled calendars;
  - in progress or ended;
- errors with "Try again" (`icsInvitationErrorMessage.ts`);
- actions: "Attending? Yes / Maybe / No", "Change my answer"
  (`CalendarInviteButtons.tsx`), "Add to Calendar" for PUBLISH, "Open in
  Calendar", and "Add participant" for an organizer who receives a reply from
  a party crasher.

**Parsing** (`invite.ts`, `icsSurgery/vevent.ts`):
- only the first VEVENT is used, and a non-Gregorian CALSCALE is refused;
- an invitation without a UID is refused (PUBLISH gets a hashed one);
- a missing DTSTAMP takes the message time;
- a missing ORGANIZER is guessed from the headers;
- UID and SEQUENCE outside the VEVENT are accepted;
- outdated means a lower SEQUENCE, or an older DTSTAMP (attendee side) or
  UpdateTime (organizer side);
- an update that raised the SEQUENCE resets the attendee's answer; other
  changes keep it;
- RECURRENCE-ID makes a single edit of an occurrence that exists;
- CANCEL marks the event cancelled, or adds an EXDATE for one occurrence;
- on the organizer side, an answer to a single occurrence is not applied:
  "we only support answers to all events of a series".

**Replies** (`useSendIcs.ts`, `mailIntegration/invite.ts`):
- the reply ICS:
  - METHOD:REPLY;
  - a cut-down VEVENT (uid, dtstart, dtend, sequence, recurrence-id,
    organizer, rrule, location, summary, comment, dtstamp, exdate);
  - only your own ATTENDEE, with PARTSTAT;
- the email:
  - sent to the organizer only, as `invite.ics` with type
    `text/calendar; method=REPLY`;
  - a plain-text body ("X accepted your invitation to T", with an optional
    "NOTE:");
  - subject `Re: <subject>` from Mail, or "Re: Invitation for an event
    starting on …" from Calendar;
  - encrypted as the recipient's sending preferences say.

**The organizer** (`applications/calendar/.../eventModal/rows/RowParticipants.tsx`,
`BusyParticipantRow.tsx`, `eventActions/inviteActions.ts`, `sequence.ts`):
- the participants row:
  - "Add participants";
  - "Show busy times" / "Hide busy times", and "Availability unknown";
  - "Make this participant optional";
  - at most 10 people's busy times shown;
- invitations are never sent from a shared calendar;
- what is sent when:
  - a new event with attendees: REQUEST to all ("You are invited to T");
  - a change to the title, description, location, times or RRULE: an update
    to all ("This event was updated. Here's what changed:");
  - attendees added: REQUEST to them only;
  - attendees removed: CANCEL to them only;
  - the event deleted: CANCEL to all, SEQUENCE + 1;
- SEQUENCE + 1 only when the times, all-day or the RRULE change, beyond a
  subset of the old rule;
- recipients with send-preference errors are dropped.

**Storage** (`formatData.ts`, `attendees.ts`):
- the attendee list (`uid, attendee`, partstat stripped) is an encrypted,
  signed part under the shared session key;
- beside it, readable rows `Attendees[{Token, Status, UpdateTime, Comment}]`;
- the token is `SHA1(uid ‖ canonical email)`, stored in clear and never in
  outgoing ICS;
- an outside REPLY is applied by the organizer's Mail client: it matches the
  token, then `PUT …/attendees/{id} {Status, UpdateTime = DTSTAMP}`.

**Between Proton users:**
- the invitation carries `X-PM-SHARED-EVENT-ID` and `X-PM-SESSION-KEY`;
- the organizer's save sends `AddedProtonAttendees[{Email,
  AddressKeyPacket}]` (the shared session key wrapped to the attendee's
  address key), and the server adds the event to the attendee's calendar at
  once;
- the attendee's answer is written to the server first (`updateAttendeePartstat`),
  then mailed with `X-PM-PROTON-REPLY`;
- the organizer's widget skips such replies, since the server already holds
  the answer.

**Limits:**
- 100 attendees (or the mail recipient limit);
- COUNT ≤ 499 for invitations;
- busy times for 10 people.

**One message for everyone:** the same plain-text email and `invite.ics`,
encrypted per recipient. There is no HTML template. PRODID is
`-//Proton AG//<client> <version>//EN`.

## What Kutup already has

- **Mail** hides `.ics` attachments from list rows (`attachments.ts:47-53`). It
  has no invitation widget, no ICS preview and no "add to calendar".
- **No general ICS parser.** `calendar_event.rs` builds and parses each part
  strictly (one canonical form, exactly one VEVENT). Its `KNOWN` list already
  has ATTENDEE, so an incoming ATTENDEE can't be kept as an "other" line: it
  needs a part.
- **ORGANIZER and SEQUENCE are modelled** (`SharedSigned`); attendees are
  not. The server refuses an event with an organizer: "invitations come later
  (E4)" (`handlers/calendar.rs:1001`).
- **The recurrence engine:**
  - `Series::occurrence_at` finds a RECURRENCE-ID's occurrence;
  - `occurs_at_all` and `occurrences_between` cover the rest;
  - `SharedSigned::series()` builds a series from an event.
- **Sending from Calendar works today.** `mail-core`'s `sendDraft(account,
  draft, parts, pinned)` builds the MIME, seals it for Kutup recipients,
  sends PGP/MIME to outside recipients with a key and plaintext otherwise
  (signed with Sign), and is already called outside the composer
  (`spamUnsubscribe.ts:111`). The Calendar app already depends on
  `mail-core`.
- **L7:** subject, addresses, Message-ID and attachment names and types are
  sealed. The server keeps keyed hashes for threading. Filters and
  auto-reply see the plaintext only at delivery.
- **E3:**
  - members and same-server rules;
  - the busy client (`GET /api/calendar/busy`, overlaps merged, its window a
    setting) and the "Show others when I'm busy" toggle;
  - the participant row was left for E4.
- **Contacts:** `useContactEmailSearch` and `ContactSuggestInput` (Mail, Drive
  and Chat use them).

## Kutup's design

### 1. Methods: Proton's set

- **REQUEST, REPLY, CANCEL:** in full.
- **PUBLISH:** "Add to Calendar", using E2's import rules.
- **COUNTER and REFRESH:** shown, with Proton's "not supported for the
  moment". A COUNTER carrying a PARTSTAT is applied as a REPLY.
- **ADD:** shown as not supported.
- **DECLINECOUNTER:** refused as invalid.
- **Direction checked:** as Proton's.

Kutup sends REQUEST, REPLY and CANCEL only. Counter-proposals (Q-1) wait,
as at Proton.

### 2. ICS in Rust: `kutup_crypto::calendar_itip`

One module, used by the Calendar and Mail apps through WASM, so the server
and every client read invitations alike.

- **Reading (lenient, as `icsSurgery`):**
  - the VCALENDAR with METHOD and CALSCALE, the first VEVENT, VTIMEZONE
    blocks, and VALARM (dropped);
  - ORGANIZER and ATTENDEE with their parameters (CN, PARTSTAT, ROLE, RSVP,
    X-PM-*);
  - folding, escaping, and the common faults Proton repairs: UID or SEQUENCE
    outside the VEVENT, no DTSTAMP, a floating time made to the sender's
    zone, Windows zone names mapped to IANA, a bare date-time DTEND;
  - the result is typed: `Invitation {method, vevent: EventFieldsV1,
    organizer, attendees[{email, cn, partstat, role, rsvp}], other}`, or
    one of Proton's error kinds (invalid ICS, invalid method, unsupported,
    invalid response, missing UID, missing attendee);
  - recurrence through E2's rule engine, refused past COUNT 499 for
    invitations.
- **Writing (one canonical form):**
  - METHOD:REQUEST, REPLY or CANCEL;
  - the VTIMEZONEs the event uses, from the bundled database;
  - PRODID `-//Kutup//Calendar <release>//EN`;
  - for REPLY, Proton's cut-down VEVENT with only the sender's ATTENDEE;
  - for CANCEL, SEQUENCE + 1 and STATUS:CANCELLED;
  - never a token or anything sealed.
- **Vectors:** real invitations from Google, Outlook (with Windows zones),
  Apple, Proton and Fastmail, checked in as files and expected readings, plus
  every error kind. Rust tests, and a WASM check.

### 3. Attendees on the event

A new event part, and readable attendee rows.

- **The attendee part** (`AttendeesEncrypted`, as calendar.md's table):
  - holds each attendee's ATTENDEE line (email, CN, role, RSVP; no PARTSTAT);
  - encrypted under the shared session key and signed by the organizer's
    address key;
  - the shared signed part already carries ORGANIZER and SEQUENCE.
- **The token: keyed, unlike Proton's.**
  - Proton's `SHA1(uid ‖ email)` is in clear beside a readable UID, so a
    server can confirm a guessed email.
  - Kutup's token is `HMAC-SHA256(HKDF(shared session key,
    "kutup/calendar/attendee-token/v1"), uid ‖ canonical email)`.
  - Every client that can read the event computes it: the organizer, and
    attendees who were given the session key. The server only stores and
    compares it.
- **The answer: sealed** (Q-3). Each attendee row holds `{token, answer,
  updatedAt}`. `answer` is the PARTSTAT and an optional note, sealed under
  the shared session key. A Kutup attendee writes it themselves; an outside
  REPLY is written by the organizer's client.
  - Proton keeps Status readable. The server has no use for it (it runs no
    logic on answers), and the note is a person's words. Only `updatedAt`
    stays readable, so a stale answer can be refused.
- **Limits** (admin settings):
  - `calendar.attendees_per_event` (default 100, at most the site's mail
    recipient limit);
  - `calendar.invitation_count_max` (default 499).

### 4. The organizer (Calendar app)

- **A participants row in the event editor**, Proton's `RowParticipants`:
  - suggestions from Contacts (`ContactSuggestInput`);
  - optional or required per person ("Make this participant optional");
  - remove;
  - "Self invitation not allowed".
- **Busy times on the row**, Proton's `BusyParticipantRow`, through E3's busy
  client:
  - "Show busy times" / "Hide busy times";
  - "Availability unknown" when the answer is not accessible. **E3's busy
    route gains `accessible: boolean`**, as Proton's `IsDataAccessible`;
  - drawn in the grid as busy blocks;
  - at most 10 people shown (an admin setting, `calendar.busy_shown_max`).
- **Only in the account's own calendars**, as Proton's: no invitations from
  a calendar shared with you.
- **On save, the client sends Proton's messages:**
  - REQUEST on create, an update on a data change, REQUEST to people added,
    CANCEL to people removed, CANCEL to all on delete;
  - SEQUENCE + 1 under Proton's rule.

  All of them go through `sendDraft`:
  - from the account's own address (or the shared mailbox the calendar's
    address is);
  - the body is Proton's plain-text template, en and tr, in the organizer's
    language;
  - `invite.ics` as an attachment of type `text/calendar; method=…;
    charset=utf-8`. `mime.ts`'s `attachmentPart` takes a type with
    parameters (one small change);
  - each recipient's encryption is Mail's: Kutup, PGP or plain.
- **A save that sends is one action:**
  - the event is saved first, then the messages go;
  - a message that fails is listed on the event ("not sent to …: Send again")
    rather than lost, as Proton's error banner;
  - the Sent folder keeps a copy, as Mail does.
- **Answers:**
  - the event view lists each attendee and their answer (opened from the
    sealed rows), with Proton's "Optional" mark;
  - answers to a single occurrence are not applied, with Proton's message.

### 5. The attendee (Mail widget)

`ExtraEvent`-style widgets above a message's body, one per `text/calendar`
part (and per `.ics` attachment).

- **Reading:** the ICS is read with `calendar_itip`. Mail loads the calendar
  runtime only for a message that has one (Q-4), which keeps Mail's own WASM
  as it is.
- **States:** Proton's list in §"What Proton does", with its strings
  translated:
  - new, updated, out of date;
  - cancelled;
  - already answered;
  - party crasher (outside invitations can still be answered, Kutup ones
    can't);
  - not from an address you can reply from;
  - in progress or ended;
  - errors with Try again.
- **Matching:** the invitation is checked against the stored event by UID,
  SEQUENCE and DTSTAMP (outdated, from the future), as Proton's.
- **Actions:**
  - "Attending? Yes / Maybe / No", "Change my answer", an optional note;
  - "Open in Calendar";
  - "Add to Calendar" for PUBLISH.
- **Where a received event goes:**
  - into the account's default calendar (a choice of calendar when it has
    several, as Proton's);
  - stored as the attendee's own copy (§6);
  - an update replaces it, keeping or resetting the answer by Proton's rule;
  - CANCEL marks it cancelled, or EXDATEs one occurrence.
- **Replies:** Proton's REPLY:
  - to the organizer only, `Re: <subject>`, through `sendDraft`, encrypted by
    Mail's rules;
  - for a Kutup organizer on this server, the answer row is written first,
    then the mail goes with an `X-Kutup-Reply` marker (Proton's
    `X-PM-PROTON-REPLY`).
- **The organizer's side of the widget:** a REPLY from outside is applied by
  the organizer's client:
  - it computes the token from the sender and the stored UID;
  - it writes the sealed answer, with `updatedAt` from the reply's DTSTAMP;
  - an older one is refused;
  - a party crasher gets Proton's "is not in the participants list" and an
    "Add participant" button;
  - a marked Kutup reply only shows the answer the server already holds.

### 6. Between Kutup users: the event appears at once

Proton's `AddedProtonAttendees`. Mail stays the record, and the server makes
it immediate.

- **On save,** for each attendee on this server (looked up through Mail's
  address keys, with Drive's pins), the organizer's client wraps the event's
  shared session key to that attendee's address key, using the rPGP
  key-packet wrap calendar.md planned for E4. That gives `invitees[{accountId,
  addressId, keyPacket}]`.
- **Shared events, split from the calendar copies** (Q-2), as Proton's
  SharedEvents and CalendarEvents:
  - the shared parts and the attendee part are one row, owned by the
    organizer's event (`sharedEventId`);
  - each calendar that holds the event (the organizer's, and each Kutup
    attendee's once they add it) has its own row: the calendar key packet
    and the calendar parts (its own status, transparency and comment).
  - So an organizer's change reaches every Kutup attendee's calendar without
    any of them opening a mail, and cancellations too.
- **The attendee's client:**
  - lists `GET /api/calendar/invitations/events` (new invitations by address
    key packet);
  - opens the shared parts with its address key and shows the event in the
    calendar marked "Invitation";
  - on an answer (or "Add to calendar") it wraps the session key to its own
    calendar key and posts its calendar row;
  - the Mail widget then shows "already in your calendar".
- **Kutup users on other servers:** the Mail message only (decision 5: "as a
  Mail message"). The invitation is end-to-end encrypted by Mail. The
  attendee's client adds the event from the ICS, as for an outside
  invitation, and replies the same way. There is no cross-server auto-add;
  federation stays as it is.
- **Members versus attendees:** an attendee is not a member of the
  organizer's calendar. They see only the events they are invited to.

### 7. Privacy

- **Readable to the server:** the shared signed part (as now: times, UID,
  ORGANIZER, SEQUENCE), the number of attendees, their keyed tokens,
  `updatedAt`, and which Kutup accounts were invited.
- **Sealed:** names, emails and answers.
- **Outside recipients** get what any iMIP recipient gets, and are encrypted
  only with a known key, as Mail sends.
- **The ICS never carries** a token or Kutup's key material. The session key
  goes only in key packets to Kutup address keys, never in the ICS (unlike
  Proton's `X-PM-SESSION-KEY`, which outside recipients also receive).

## Server and schema needs

To follow E3b, in one migration (`20261201…` or later, above E3b's):

1. **The shared event split** (Q-2):
   - `calendar_shared_events` (id, uid, organizer address and account,
     shared key packets per calendar, the shared signed and encrypted parts
     and their signatures, the attendee part, sequence, times, rrule,
     range end);
   - `calendar_events` keeps the per-calendar part (calendar key packet,
     calendar signed and encrypted, revision) and gains `shared_event_id`.
   - The existing columns move: before the wipe this is a schema change with
     no data to move; after it, a data migration.
   - **Best done in the W7 window, with E3b**, so no data migration is ever
     needed. The main session decides.
2. **`calendar_event_attendees`** (shared_event_id, token bytea(32), answer
   bytea NULL, updated_at, optional, PRIMARY KEY (shared_event_id, token)).
3. **`calendar_event_invitees`** (shared_event_id, account_id, address_id,
   key_packet, created_at): a Kutup attendee's way in, removed when they are
   removed or the event is deleted.
4. **Routes:**
   - `POST …/events/sync` accepts an organizer, the attendee part,
     `attendees[{token, optional}]` and `invitees[...]`. The 400 "invitations
     come later (E4)" goes;
   - `PUT /api/calendar/shared-events/{id}/attendees/{token} {answer,
     updatedAt}`, by the organizer (for outside replies) or by the invitee
     whose token it is (the server checks the invitee row's account);
   - `GET /api/calendar/invitations/events` (the caller's invitee rows, with
     the shared parts);
   - `POST /api/calendar/calendars/{id}/events/adopt {sharedEventId,
     calendarKeyPacket, calendar parts}`;
   - E3's busy route gains `accessible`.
5. **Settings:** `calendar.attendees_per_event`, `calendar.invitation_count_max`,
   `calendar.busy_shown_max` (W7 §7: dotted namespace, snake_case segments; the
   published JSON fields stay camelCase), and the rate limit `calendar.rate.busy`.
6. **Quota:** the shared event counts against the organizer; each adopted
   calendar row (small) against its calendar's owner.
7. **Labels:** `kutup/calendar/attendee-token/v1`.
8. **Account-record purposes and scopes:** none.
9. **Mail server:** no change. `text/calendar` is an attachment type L7
   already seals.

## Slices

| Slice | Delivers |
|---|---|
| E4a | `calendar_itip` read and write, the attendee part, the keyed token, key-packet wrap; vectors (Rust, WASM) |
| E4b | Server: the shared-event split, attendee and invitee tables, the routes above, the settings |
| E4c | Calendar: the participants row with busy times, sending REQUEST/updates/CANCEL, the answers in the event view |
| E4d | Mail: the invitation widget (attendee and organizer sides), replies, PUBLISH import |
| E4e | Kutup-to-Kutup: invitees, the invitations list, adopting into a calendar |

**Browser specs:** 220–225 (the third session's block is 200–239; the Sieve editor holds 200, E3 201–206, Pass 207–217).

**Tests:**
- static, rust, web and unit checks until the full test is over;
- the mail gate (Stalwart) for an outside round trip: a REQUEST to the sink
  and a REPLY back;
- the two-server gate for Kutup users across servers (Mail only).

## Questions

- **Q-1. Counter-proposals.** Proton shows COUNTER and doesn't act on it.
  Recommended: the same (shown, not supported, its PARTSTAT applied). A
  "propose a new time" flow waits for later, as at Proton.
- **Q-2. The shared-event split.** Proton's model: one shared row, a calendar
  row per calendar. It makes edits and cancellations reach Kutup attendees at
  once.
  - Recommended, in the W7 window beside E3b, so it is a schema change and
    never a data migration.
  - The alternative (the attendee keeps a copy, refreshed from each update
    mail) needs no split. But updates then wait for the attendee's Mail, and
    answers have two homes.
- **Q-3. Sealed answers.** Proton keeps PARTSTAT readable. Recommended:
  sealed under the shared session key (the server does nothing with it), with
  `updatedAt` readable to refuse a stale one.
- **Q-4. Mail's WASM.** Mail reads invitations with `calendar_itip` and the
  time zone database, which live in the crypto-calendar build. Recommended:
  load that runtime lazily, only for a message with a calendar part, so
  Mail's `crypto` build (97.8% of its budget) doesn't grow.
- **Q-5. Keyed token.** Recommended over Proton's clear SHA-1, which lets
  the server confirm a guessed email against a readable UID. It costs
  nothing: everyone who needs the token holds the session key.
- **Q-6. Where an invitation lands.** Recommended: the default calendar,
  with a choice when the account has several (Proton). Shared calendars and
  calendars shared with you are not offered.

## Decisions (the main session, 2026-11-18)

- **Q-1, Q-3 to Q-6:** the recommended answers. Counter-proposals are shown
  and not supported; answers are sealed; Mail loads the calendar runtime
  lazily; the token is keyed; an invitation lands in the default calendar,
  or a chosen one.
- **Q-2:** the shared-event split, **in the W7 baseline before the wipe**.
  This is the user's standing rule: whatever only gets costly once real data
  exists is done before the wipe.
  - When W7's groups 2–4 have landed, one commit against the baseline adds
    the tables in their final names and types:
    - E3's key generations, member shares, invitations, tombstones and
      links;
    - E4's `calendar_shared_events` split, attendees and invitees.
  - It is coordinated with the second session first, since the baseline is
    theirs.
  - The server code and UI merge after the wipe. The post-wipe PRs add code,
    and migrations only for what is new by then.
- **Specs:** 220–225 (above).

## As built (2026-11-24, `feat/calendar-e4`)

Built on `feat/calendar-ics` (#443: `kutup_crypto::calendar_ics` and the
lazily loaded calendar-ics runtime), with recurrence (#439) and the
popovers (#441) from master.

### What each slice holds

| Slice | Built |
|---|---|
| E4a | `calendar_ics::itip` (read and write), the attendee part (`calendar_event::AttendeesPart`), keyed tokens, sealed answers, the invitee key packet and adopting (`calendar_invitation`); Rust tests, fixtures (`tests/ics/itip/`), vectors (`calendar-invitation-v1.json`), WASM checks in both runtimes |
| E4b | One additive migration (`20261210000000_calendar_invitations`), the sync's `invitation`, the answer, invitations and adopt routes, the invitation settings, `accessible` on busy times, the five settings; live tests (`calendar_invitations_live.rs`) |
| E4c | The participants row with busy times, Proton's messages on save and delete through `sendDraft`, "Send again", the answers in the event view |
| E4d | Mail's widget: attendee and organizer sides, replies, PUBLISH "Add to Calendar", the applied-on-view updates, cancellations and outside replies |
| E4e | Kutup invitees, the invitations list, adopting into the default calendar ("Add to calendar and mark as pending"), answering from the Calendar event view |

Parity items the parity list flagged for E4, built: an attendee deleting an
invitation declines it first (Proton's `getAttendeeDeleteSingleEditActions`);
"Send in" (the language invitations and replies go in) and "Add to calendar
and mark as pending" (Proton's `InviteLocale` and `AutoImportInvite`), both
kept on the account (`calendar_invite_settings`), shown in Calendar's
settings.

### Where the code went

- **Rust, keyless** (`kutup_crypto::calendar_ics::itip`, in the
  calendar-ics runtime, which holds no key): the reader reuses the import's
  whitelist rebuild with the UID kept (`Context::keep_uid`); the writer
  reuses the export's `VTIMEZONE`s. Kutup sends REQUEST, REPLY and CANCEL
  only; the writer refuses anything else.
- **Rust, keyed** (`kutup_crypto::calendar_invitation`, in crypto-calendar):
  everything that needs the shared session key or a key: tokens, the
  attendee part, answers, the invitee key packet, adopting, and the server's
  check of an adopted row. `UnlockedCalendarKey` gained `seal_event_keeping`
  (an invitation's change keeps its session keys, which attendees' copies
  and tokens hold) and `open_event_by` (an adopted copy's shared parts are
  the organizer's, its calendar parts the attendee's).
- **Mail's runtimes (Q-4):** Mail keeps loading `crypto`. A message with a
  calendar part loads `calendar-ics` (to read it) and `crypto-calendar`
  beside `crypto` (to open and write calendars), the latter through
  `getCalendarCryptoWasm` (`@kutup/crypto/rustWasm`): the two instances
  share no state, every call takes its keys. Mail's build copies both
  runtimes; neither is fetched for a message without an invitation.
- **The schema:** the baseline had the split, the attendee and invitee
  tables. Building showed three things missing, added in one additive
  migration: the invitee row names its attendee's token (so the server
  lets a Kutup attendee write their own answer row only; it goes with the
  attendee row), an event row names its own author (an adopted copy's
  calendar parts are the attendee's), and the account's invitation settings.

### Server rules (who may write what)

- An event with an ORGANIZER carries its whole attendee list on every
  create and update (`invitation`), and only such an event does
  (`invitationMismatch`). Only the calendar's owner invites
  (`notOwnCalendar`): never from a calendar shared with you (Proton's).
- **Kutup invitees** only on the organizer's own event: ORGANIZER must be
  the signing address (`organizerNotAuthor`). An event whose ORGANIZER is
  someone else is an attendee's own copy of an outside invitation: kept with
  its attendee list, reaching no one. Each invitee is an active address on
  this server (not the organizer's own account), its key packet to one of
  that address's keys (`inviteeKey`), and one of the rows.
- **Updates in place:** `rewrite` updates the shared row and the home row
  instead of deleting and re-inserting them (which cascaded to every
  attendee row, answer and copy). An invitation is changed by its organizer
  only (`notOrganizer`).
- **Answers:** by the owner of the event's home calendar (an outside reply)
  or by the invitee whose token the row is; anyone else gets 404. A time
  older than the stored one is `409 answerStale`; one more than a day ahead
  is refused. `resetAnswers` (the client's, when SEQUENCE went up) clears
  them all.
- **Copies:** adopted by an invitee into a calendar they own, its key
  packets to its newest key, its calendar parts signed by their address,
  their EXDATEs occurrences of the series; one per account. Removing an
  attendee, or deleting the event, deletes their copies and gives each
  owner back what it held; every copy's alarms follow the organizer's
  changes.
- **Spam limit:** an account holds at most `calendar.invitations_per_account`
  invitee rows; past it, a new invitation comes by mail only.

### What the clients verify (trust)

- The **organizer shown** is ORGANIZER only when it is the address whose
  checked keys verified the shared parts (`CalendarEvent.organizer`); an
  outside invitation's organizer is the ICS's word, as at Proton.
- **Attendees** come from the attendee part, signed by the organizer and
  bound to the UID, never from the server's rows. Each row is matched by
  the token the client derives itself; a row with another token is ignored.
- An **answer** counts only when it opens for its row (the token and the
  shared event id are inside the sealed answer) and was signed by a key the
  client looked up itself: the organizer's, or a Kutup attendee's own. An
  answer signed by another attendee's key would still verify (the client
  passes all of them together); the server lets an invitee write only their
  own row.
- A **Kutup invitation** is opened with the account's own address key, its
  shared parts and attendee part checked against the organizer's keys, and
  listed (or auto-added) only when all of that verifies and ORGANIZER is
  the signing address.
- An **outside REPLY** is applied only when its ATTENDEE is the message's
  sender (the address it was delivered from and the From inside agree),
  for an event this account organizes, and for an attendee on its list.
  `X-KUTUP-REPLY` (Proton's `X-PM-PROTON-REPLY`) grants nothing: it only
  skips applying a reply whose answer the server already holds.
- The **ICS** never carries a token, a key or anyone else's answer; names
  and notes are written without line breaks or quotes (no property
  injection).

### What the server sees (§7, as built)

Readable: the shared signed part (times, UID, ORGANIZER, SEQUENCE), the
number of attendees, each one's keyed token and optional flag, when each
last answered, which accounts and addresses of this server were invited
(and their tokens), which calendars adopted the event, and the account's
"Send in" language and auto-add switch. Sealed: names, addresses and
answers (with their notes). The answer's signature is inside its sealed
blob. An invitee's key packet is OpenPGP to the address key (not
post-quantum, as Mail's address keys).

### Proton behaviours copied, and where Kutup differs

Copied: the methods and their direction rule; the reader's repairs (UID and
SEQUENCE outside the VEVENT, DTSTAMP from the message, ORGANIZER from the
sender, attendees written as URLs read by `EMAIL`); the widget's states and
strings; the reply's cut-down VEVENT, `Re: <subject>`, plain text,
`invite.ics` as `text/calendar; method=…`; one message for all; REQUEST on
create, an update to those kept when the data changed, REQUEST to those
added, CANCEL to those removed, CANCEL to all on delete with SEQUENCE + 1;
SEQUENCE + 1 when the times or the rule change, and the answers asked again
then; outside replies applied by the organizer's client; Kutup invitations
at once (`AddedProtonAttendees`); updates and cancellations of an outside
invitation applied when the widget is shown; "Send in"; "Add to calendar and
mark as pending"; an attendee's delete declining; busy times beside the
participants with "Availability unknown"; at most 100 attendees, 10 busy
rows, COUNT 499.

Differs:
- The token is keyed and the answers sealed (Q-3, Q-5); the session key is
  never in the ICS.
- SEQUENCE goes up on any change of the rule, not only past a subset of the
  old one (Proton's `getIsRruleSubset`).
- A cancelled invitation's copy is deleted with the organizer's event
  (Kutup attendees) instead of kept and marked cancelled; an outside one is
  marked cancelled, as Proton.
- An invitation's series is changed and deleted as a whole: the "this
  event / this and future" choice is not offered for one, and participants
  can't be set on a changed occurrence.
- A party crasher can't answer from the widget (Proton lets an outside one
  add themselves).
- Busy times show as a line under each participant ("Busy at this time" and
  the day's blocks), not as blocks drawn on the grid.
- The invitation language setting offers English and Turkish (the app's).

### Left for later (roadmap)

- Busy blocks drawn on the grid while planning; changing one occurrence of
  an invitation (Proton's single-edit invitations); counter-proposals
  (Q-1, as at Proton); a party crasher adding themselves; inviting from a
  shared mailbox's address.
- The mail gate's stack has no browser, and the browser stack no inbound
  SMTP: an outside round trip is covered by the reader and writer's tests
  (Google, Outlook, Apple, Fastmail and Proton files) and the reply logic,
  not by a browser spec.

### Tests

- Rust: `calendar_ics::itip::tests` (fixtures and refusals),
  `calendar_invitation::tests`, `calendar_event` (the attendee part's one
  form), `tests/calendar_invitation_vectors.rs`.
- WASM: `scripts/test-calendar-ics-wasm.mjs` (the reader on the fixtures,
  the writer against the vectors) and `scripts/test-crypto-wasm.mjs` (the
  vectors open; what the browser seals opens alike; an adopted copy).
- Server: `crates/kutup-server/tests/calendar_invitations_live.rs`.
- Browser: 220 (calendar: Kutup invite, answer, update, cancel), 221 (mail:
  the widget's answer and the organizer's reply).
