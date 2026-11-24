# Calendar: Proton Calendar parity

**Status:** the gap list, 2026-11-24. The goal for Calendar is Proton
Calendar's feature set (the standing rule: copy Proton where it does it
right, [`calendar.md`](calendar.md)). This lists every user-facing feature
of Proton Calendar's web client, where Kutup Calendar stands, and the order
to close the gaps. Each slice gets its own plan before it is built (the
phases E1–E5 are in [`calendar.md`](calendar.md), E3 in
[`calendar-e3.md`](calendar-e3.md), E4 in `calendar-e4.md` on
`docs/calendar-e4`, approved 2026-11-18); keep this list current as they
land.

Read from `WebClients` (`kutup-references/WebClients`, 2026-11-24). Paths
in the Proton column are shortened: `cal/` is
`applications/calendar/src/app/`, `pcc/` is
`packages/components/containers/calendar/`, `psl/` is
`packages/shared/lib/`. Kutup read from the code on master (592ced04, with
E1, E2's core, server and reminders, and E3 merged), not from the plans:
what the website really does end to end. Paths in the Kutup column are under
`frontend/apps/calendar/src/` unless they start with `crates/` or
`frontend/`.

**Key:** ✅ works end to end · 🟡 partial or in progress (what is missing
is said) · ❌ missing · ➖ not for Kutup (Proton lacks it, or decided
against; not counted). "Planned" names the phase or plan that covers a gap;
"not planned" means no Kutup plan covers it yet.

**Summary** (rows per area, 2026-11-24):

| Area | ✅ | 🟡 | ❌ |
|---|---|---|---|
| Views and navigation | 4 | 1 | 9 |
| Creating and moving on the grid | 6 | 0 | 4 |
| The event editor | 5 | 2 | 3 |
| Recurrence | 0 | 3 | 2 |
| Reminders and notifications | 6 | 0 | 0 |
| Time zones | 1 | 2 | 2 |
| Calendars | 6 | 0 | 3 |
| Settings | 0 | 1 | 4 |
| Sharing: members and links | 11 | 0 | 2 |
| Busy/free | 2 | 0 | 2 |
| Invitations | 0 | 0 | 10 |
| Import, export and other calendars | 0 | 2 | 3 |
| Video calls | 0 | 0 | 1 |
| Search and shortcuts | 1 | 0 | 2 |
| Booking pages | 0 | 0 | 1 |
| Other apps and platforms | 2 | 1 | 2 |
| **All** | **44** | **12** | **50** |

## Views and navigation

| Feature | Proton | Kutup | Notes / where |
|---|---|---|---|
| Day, week and month views | `cal/components/ViewSelector.tsx` | ✅ | `features/CalendarPage.tsx`; the view and date in the address bar (`?view=&date=`) |
| Today, previous, next; the range as the title | `cal/components/DateCursorButtons.tsx`, `cal/containers/calendar/getTitleDateString.ts` | ✅ | `features/format.ts` |
| Current-time line; the grid scrolled to now | `cal/components/calendar/TimeGrid.tsx` | ✅ | `features/TimeGrid.tsx`, refreshed every 30 seconds |
| Overlapping events side by side | `cal/components/calendar/layout.ts` | ✅ | `features/placement.ts` (`columns`) |
| Mini month navigator in the sidebar | `packages/components/components/miniCalendar/LocalizedMiniCalendar.tsx` | ❌ | listed in calendar.md's UX parity table; not planned |
| Custom range (days or weeks dragged on the mini calendar) | `VIEWS.CUSTOM`, `ViewSelector.tsx` "Custom" | ❌ | with the mini calendar; not planned |
| A day header opens that day | `handleClickDateWeekView` in `InteractiveCalendarView.tsx` | ❌ | UX parity table; not planned |
| "+N more" in the month opens the day's events | `cal/components/events/MorePopoverEvent.tsx` | 🟡 | a count only (`CalendarPage.tsx`); UX parity table |
| Week numbers | `pcc/settings/CalendarLayoutSection.tsx` "Show week numbers" | ❌ | planned: E2 settings (calendar.md E2 §7) |
| Default view | `pcc/settings/ViewPreferenceSelector.tsx` | ❌ | always opens in week; planned: E2 §7 |
| Agenda (list) view | `VIEWS.AGENDA` (commented out in `ViewSelector.tsx`; search results are the only list) | ❌ | Kutup's own aim (calendar.md §13), not Proton's; comes nearly free with search |
| Print the shown range | `cal/containers/calendar/CalendarContainerView.tsx` (`only-print`: the zone and the shown calendars above the grid) | ❌ | no print styles; not planned |
| Today's date in the tab's icon | `cal/hooks/useCalendarFavicon.ts` | ❌ | not planned |
| Collapse the sidebar | `cal/containers/calendar/CalendarSidebarCollapsedButton.tsx` | ❌ | the shared `AppShell` sidebar is fixed on wide screens; not planned |
| Year view | `VIEWS.YEAR` (commented out) | ➖ | Proton doesn't offer it |

## Creating and moving on the grid

| Feature | Proton | Kutup | Notes / where |
|---|---|---|---|
| Click for a 30-minute event, drag to create | `cal/components/calendar/interactions/timeGridMouseHandler.ts` | ✅ | `features/gridInteraction.ts`, `features/TimeGrid.tsx`; Proton's 30-minute snap and 20 px threshold |
| Drag on the day grid (all-day row, month) for all-day events | `interactions/dayGridMouseHandler.ts` | ✅ | `features/DaySpan.ts` |
| Drag an event to move it (across days) | as above | ✅ | `features/moves.ts`; the editor opens with the new times |
| Resize by the bottom edge | only booking ranges | ✅ | beyond Proton (calendar.md "Calendar UX parity") |
| Touch (long press) and keyboard paths on the grid | none | ✅ | beyond Proton: `features/press.ts`, slots as cells, Alt+arrows move |
| Escape cancels a drag | none | ✅ | beyond Proton |
| Quick-create popover (title, Save, More options) | `cal/components/eventModal/CreateEventPopover.tsx` | ❌ | the full editor opens; UX parity table |
| Event peek popover (details, Edit, Delete) | `cal/components/events/EventPopover.tsx`, `PopoverEventContent.tsx` | ❌ | a click opens the editor; UX parity table |
| Duplicate an event | `cal/components/events/eventPopoverButtons/EventPopoverButtons.tsx` "Duplicate event" | ❌ | not planned |
| A repeating event moved or resized asks "this / this and future / all" | `cal/containers/calendar/confirmationModals/SelectRecurringType.tsx`, `eventActions/getRecurringSaveType.ts` | ❌ | planned: E2 app (calendar.md E2 §9) |

## The event editor

| Feature | Proton | Kutup | Notes / where |
|---|---|---|---|
| Title, all day, start and end, location, description, calendar | `cal/components/eventModal/EventForm.tsx`, `rows/` | ✅ | `features/EventDialog.tsx`; every field encrypted and signed |
| Notifications per event, the calendar's defaults until edited | `pcc/notifications/` | ✅ | `features/reminders/ReminderList.tsx` |
| Delete, with a confirmation | `confirmationModals/DeleteConfirmModal.tsx` | ✅ | |
| Edited on another device first: told, not overwritten | (sync errors) | ✅ | `events.changedElsewhere`, revision checks |
| Signature check | `getEventInformation.ts` (verification status) | ✅ | "Not verified" on an event whose signature fails |
| Start and end time zones apart | `rows/DateTimeRow.tsx` "Show time zones" | 🟡 | one zone for both start and end |
| Repeat | `inputs/FrequencyInput.tsx`, `CustomFrequencyModal.tsx`, `rows/RepeatEveryRow.tsx`, `RepeatOnRow.tsx`, `EndsRow.tsx` | 🟡 | no control yet (the editor writes `rrule: null`); see Recurrence |
| Participants | `rows/RowParticipants.tsx`, `inputs/ParticipantsInput.tsx` | ❌ | planned: E4c |
| Colour per event | `inputs/EventColorSelect.tsx` "Custom event colors" | ❌ | events take their calendar's colour; not planned |
| Links in the description and location clickable | `cal/hooks/useUrlifyString.tsx` | ❌ | the event is shown only in its editor's fields; comes with the peek popover |

## Recurrence

| Feature | Proton | Kutup | Notes / where |
|---|---|---|---|
| Proton's rule subset (daily to yearly, interval, count or until, weekdays, monthly by day or nth weekday) | `psl/calendar/recurrence/rrule.ts` | 🟡 | the Rust core parses, normalises and expands it (`crates/kutup-crypto/src/calendar_recurrence.rs`, vectors, fuzzing) and the server takes it (range end, `handlers/calendar.rs`); no app control. Planned: E2 app (calendar.md E2 §9) |
| Occurrences shown in the views | `psl/calendar/recurrence/recurring.ts` | ❌ | `features/placement.ts` places an event's first start only; planned: E2 app |
| Change or delete one occurrence | `cal/containers/calendar/recurrence/updateSingleRecurrence.ts`, `deleteSingleRecurrence.ts` | 🟡 | the server checks a child against its parent's occurrences (RECURRENCE-ID, EXDATE); no app path. Planned: E2 app |
| This and future occurrences | `recurrence/createFutureRecurrence.ts`, `deleteFutureRecurrence.ts` | 🟡 | the server side as above (idempotent steps, calendar.md E2 §2); no app path. Planned: E2 app |
| All occurrences, with Proton's three choices when the start moved | `eventActions/getRecurringUpdateAllPossibilities.ts`, `confirmationModals/editRecurring/` | ❌ | planned: E2 app |

## Reminders and notifications

| Feature | Proton | Kutup | Notes / where |
|---|---|---|---|
| Notifications in an open tab | `cal/containers/alarms/AlarmWatcher.tsx` | ✅ | `features/reminders/AlarmWatcher.tsx`, `alarmChain.ts`; Proton's texts and one-minute cutoff |
| Email reminders | server (`Alarm.ts`) | ✅ | `crates/kutup-server/src/calendar_alarms.rs`: the time only, never the title |
| Reminders with Calendar closed (web push) | none | ✅ | beyond Proton: `features/reminders/push.ts`, the shared service worker |
| Picker: minutes to weeks before, at the start; all-day on the day or before at a time | `pcc/notifications/` | ✅ | `features/reminders/triggers.ts` |
| Defaults per calendar, timed and all-day | `pcc/settings/CalendarEventDefaultsSection.tsx` | ✅ | `features/CalendarDialog.tsx` |
| Asking for permission (banner) | `NotificationManagerInjector.tsx` | ✅ | `NotificationBanner` in `app/CalendarShell.tsx`, and `NotificationSettings.tsx` |

## Time zones

| Feature | Proton | Kutup | Notes / where |
|---|---|---|---|
| Correct across DST; all-day and floating times | `psl/date/timezone.ts` | ✅ | jiff with the bundled tzdb (`features/dst.test.ts`) |
| Primary zone | `pcc/settings/PrimaryTimezoneSection.tsx` | 🟡 | the account has one (`PUT /api/v1/calendar/settings`, reminders use it), but a device may choose its own (`features/prefs.ts`); planned: E2 §7 |
| Auto-detect the zone, offer to update on a change | `pcc/settings/AutoDetectPrimaryTimezoneSection.tsx`, `cal/containers/settings/AskUpdateTimezoneModal.tsx` | ❌ | E2 §7 names auto-detect; the "Time zone changed — Update" question isn't planned |
| Secondary zone column | `pcc/settings/SecondaryTimezoneSection.tsx`, `ShowSecondaryTimezoneToggle.tsx` | ❌ | planned: E2 §7 |
| Per-event zones (start and end apart) | `rows/DateTimeRow.tsx` | 🟡 | one zone per event (the editor row above) |

## Calendars

| Feature | Proton | Kutup | Notes / where |
|---|---|---|---|
| Create, rename, recolour, describe, delete | `pcc/calendarModal/personalCalendarModal/PersonalCalendarModal.tsx`, `pcc/settings/CalendarDeleteSection.tsx` | ✅ | `features/CalendarDialog.tsx`; names and descriptions encrypted (D-1, beyond Proton) |
| A first calendar made on the first open | `cal/containers/setup/CalendarSetupContainer.tsx` | ✅ | `useFirstCalendar` in `app/CalendarShell.tsx` |
| Show or hide a calendar, kept on every device | `cal/containers/calendar/CalendarSidebarListItem.tsx` | ✅ | `display` in the account's `calendarSettings` |
| Leave a calendar shared with you | `CalendarDeleteSection.tsx` "Leave calendar?" | ✅ | `sharing.leave` |
| Calendars per account limit | `CalendarLimitReachedModal.tsx` | ✅ | an administrators' setting |
| Old key generations tidied up | none | ✅ | beyond Proton (E3's rotation): `calendars.keys.compact` |
| Key reset and reactivation after a password reset | `cal/containers/setup/CalendarResetSection.tsx`, `CalendarReactivateSection.tsx` | ➖ | not needed: the passphrase is on the account key (W4), which a recovery keeps |
| Default calendar | `pcc/settings/MyCalendarsSection.tsx` "Default calendar updated" | ❌ | new events go to the first calendar; planned: E2 §7 |
| Default event duration per calendar (30, 60, 90, 120) | `PersonalCalendarModal.tsx` "Event duration" | ❌ | fixed 30 minutes; planned: E2 (calendar.md E2 §4, `DefaultEventDuration`) |
| The address a calendar sends invitations from | `PersonalCalendarModal.tsx` "Email address" | ❌ | comes with E4 (from the account's address or the calendar's shared mailbox) |

## Settings

| Feature | Proton | Kutup | Notes / where |
|---|---|---|---|
| Week start, clock (12/24 h) | `pcc/settings/WeekStartSelector.tsx`, account time format | 🟡 | `features/SettingsDialog.tsx`, kept on this device; planned: E2 §7 moves them to the account |
| Invitation language ("Send in") | `pcc/settings/InviteLocaleSelector.tsx`, `CalendarInvitationsSection.tsx` | ❌ | E4 sends in the organizer's language, with no setting |
| "Add to calendar and mark as pending" for received invitations | `CalendarInvitationsSection.tsx` | ❌ | E4 §6 adds Kutup invitations on this server at once, with no setting; outside invitations wait for an answer |
| Auto-add video links to invitations | `CalendarInvitationsSection.tsx` "Auto-add Meet links" | ❌ | with E5's Chat meetings |
| "Show others when I'm busy" default for new calendars | `CalendarEventDefaultsSection.tsx` | ❌ | left out of E3 on purpose (roadmap); not planned |
| Keyboard shortcuts on or off | `pcc/settings/CalendarOtherPreferencesSection.tsx` | ➖ | Kutup's are always on and never in a field or dialog (calendar.md UX parity) |
| Quick settings drawer | `cal/components/drawer/CalendarQuickSettings.tsx` | ➖ | the Settings dialog holds the same |

## Sharing: members and links

| Feature | Proton | Kutup | Notes / where |
|---|---|---|---|
| Share with people: Edit, See all event details | `pcc/shareProton/`, `psl/calendar/sharing/shareProton/shareProton.ts` | ✅ | `features/sharing/ShareCalendarDialog.tsx` (E3c) |
| Pending invitations; join or decline | `cal/containers/calendar/ShareCalendarInvitationModal.tsx` | ✅ | `features/sharing/SharedWithYou.tsx` |
| The sender's identity checked before joining | signature against pinned keys | ✅ | identity pins: changed, unsigned, someone else (`sharing.invitations.doubt`) |
| Revoke a pending invitation, delete a declined one | `pcc/settings/CalendarMemberAndInvitationList.tsx` | ✅ | |
| Change what a member can do | `CalendarMemberRow.tsx` | ✅ | `sharing.presetChanged` |
| Remove a member; a new key for the rest | removal only, no rotation | ✅ | beyond Proton: rotation in one request, links replaced if asked (calendar-e3.md §2) |
| 49 members per calendar | `MAX_CALENDAR_MEMBERS` | ✅ | an administrators' setting |
| Full-detail links | `pcc/shareURL/`, `sharing/shareUrl/shareUrl.ts` | ✅ | the key in the fragment by default (D-2); Proton's query kind for other calendar apps, off by default and warned (E3d) |
| Busy-only links | `shareURL/` (limited) | ✅ | `features/sharing/LinksPanel.tsx` |
| A label per link, copy, delete; 5 per calendar | `shareURL/` | ✅ | |
| A web page for a link | ICS only | ✅ | beyond Proton: `features/public/PublicCalendarPage.tsx` |
| Members with busy times only (`AVAILABILITY` alone) | `psl/calendar/permissions.ts` | ❌ | left out of E3 on purpose (roadmap): no preset gives it |
| Members on other servers | one service | ❌ | planned: after E5 (calendar-e3.md Q-2) |

## Busy/free

| Feature | Proton | Kutup | Notes / where |
|---|---|---|---|
| "Show others when I'm busy" per calendar | `pcc/calendarModal/BusySlotsCheckbox.tsx` | ✅ | `busy.share` (E3e) |
| Only the organization may ask; times only | `busy-schedule` API | ✅ | `crates/kutup-server/src/calendar_busy.rs` |
| Others' busy times beside an event's participants | `cal/components/eventModal/rows/BusyParticipantRow.tsx`, `cal/hooks/useBusySlots.ts` | ❌ | planned: E4c (calendar-e3.md Q-4) |
| Their busy blocks drawn on the grid while planning | `cal/store/busySlots` | ❌ | planned: E4c |

## Invitations

All planned in E4 (`calendar-e4.md`, slices E4a–E4e) unless said.

| Feature | Proton | Kutup | Notes / where |
|---|---|---|---|
| Participants from Contacts, optional or required | `rows/RowParticipants.tsx`, `ParticipantRow.tsx` | ❌ | E4c |
| Invitations, updates and cancellations by mail (iMIP REQUEST, CANCEL) | `psl/calendar/mailIntegration/invite.ts`, `useSendIcs.ts` | ❌ | E4c, through Mail's `sendDraft` |
| Send failures listed with "Send again" | `confirmationModals/SendWithErrorsConfirmationModal.tsx` | ❌ | E4c |
| The organizer sees each answer | `cal/components/events/AttendeeStatusIcon.tsx`, `ParticipantDropdown.tsx` | ❌ | E4c, answers sealed (beyond Proton) |
| The Mail widget: Yes / Maybe / No, a note, change the answer, its states | `applications/mail/.../extrasHeader/components/ExtraEvents.tsx`, `pcc/RsvpSection/` | ❌ | E4d |
| Outside replies applied; "not in the participants list" with Add | `ExtraEvents.tsx` | ❌ | E4d |
| "Add to Calendar" for a published event (PUBLISH) in Mail | `ExtraEvents.tsx` | ❌ | E4d |
| Kutup attendees get the event at once, and its updates | `AddedProtonAttendees` | ❌ | E4e (the shared-event split is in the wipe-2 schema) |
| Answer from Calendar's event view | `cal/components/events/RsvpSection.tsx` | ❌ | E4e (an invitation shown in the calendar, answered there) |
| An attendee deleting the event declines it | `eventActions/getAttendeeDeleteSingleEditActions.ts`, `getDeleteEventActions.ts` | ❌ | not in E4's text |
| Counter-proposals | shown, "not supported for the moment" | ➖ | E4 Q-1: as Proton |

## Import, export and other calendars

| Feature | Proton | Kutup | Notes / where |
|---|---|---|---|
| `.ics` import (a file, a calendar, a report) | `pcc/importModal/` | 🟡 | in progress (`feat/calendar-ics`); plan calendar.md E2 §5 |
| `.ics` export | `pcc/exportModal/`, `pcc/settings/CalendarExportSection.tsx` | 🟡 | in progress (`feat/calendar-ics`); plan E2 §6 |
| Import from Google (and Outlook) | `packages/activation` (Easy Switch, OAuth through Proton's server) | ❌ | planned: E5, Google only, in the browser (D-3); Outlook not planned |
| Add calendar from URL (subscribed feeds, statuses) | `pcc/calendarModal/subscribedCalendarModal/`, `pcc/settings/OtherCalendarsSection.tsx` | ❌ | planned: E5 |
| Holiday calendars | `pcc/calendarModal/holidaysCalendarModal/` | ❌ | planned: after E5 (D-4) |
| CalDAV | none | ➖ | as Proton ([`../research/06-webdav-support.md`](../research/06-webdav-support.md)) |

## Video calls

| Feature | Proton | Kutup | Notes / where |
|---|---|---|---|
| A meeting link in the event (Proton Meet, title encrypted) | `rows/RowVideoConference.tsx` | ❌ | planned: E5, Chat's call links (calendar.md §10) |
| Zoom links made from the event | `RowVideoConference.tsx` "Add Zoom meeting" | ➖ | not now (calendar.md §11): a pasted link works |

## Search and shortcuts

| Feature | Proton | Kutup | Notes / where |
|---|---|---|---|
| N, T, 1 2 3, ← → | `cal/hooks/useCalendarHotkeys.ts` | ✅ | `features/CalendarPage.tsx` |
| Search events (`/`): an encrypted index in the browser, results by date | `cal/containers/calendar/search/`, `cal/containers/EncryptedSearchLibraryProvider.tsx` | ❌ | UX parity table; not planned |
| Shortcuts list (`?`) and the quick actions menu (Meta+K) | `pcc/shortcutsModal/CalendarShortcutsModal.tsx`, `CalendarShortcutsAndCommander.tsx` | ❌ | UX parity table; not planned |

## Booking pages

| Feature | Proton | Kutup | Notes / where |
|---|---|---|---|
| Booking pages: weekly and one-off ranges, a public page where others pick a slot, the booking added to the calendar | `cal/containers/bookings/` (`BookingSidebar.tsx`, `BookingsPageManagement.tsx`, `DisplayRecurringRanges.tsx`), `cal/containers/calendar/sidebar/Bookings.tsx` | ❌ | not planned |

## Other apps and platforms

| Feature | Proton | Kutup | Notes / where |
|---|---|---|---|
| English and Turkish | many languages | ✅ | `locales/en.json`, `tr.json` |
| Reminder and link pages only open Calendar's own pages | — | ✅ | the service worker's checks (calendar.md E2b-3) |
| Narrow screens | "Week and month views only apply to desktop" (`CalendarLayoutSection.tsx`) | 🟡 | the sidebar becomes a sheet (`frontend/packages/ui/src/components/app-shell.tsx`); the week and month grids are not adapted |
| Calendar beside Mail and Drive (side panel) | `cal/helpers/drawer.ts`, `VIEWS.MAIL`, `VIEWS.DRIVE` | ❌ | not planned |
| Open an event from Mail | `cal/hooks/useOpenEventsFromMail.tsx` | ❌ | planned: E4d ("Open in Calendar") |
| Offline | none | ➖ | as Proton; [`../research/16-browser-storage-architecture.md`](../research/16-browser-storage-architecture.md) if ever |
| Native apps | iOS, Android | ➖ | deferred ([`../mobile-build.md`](../mobile-build.md)) |

## Gaps in priority order

What people hit first, then what blocks moving from Proton or Google:

1. **Recurrence in the app** (E2 §9): the repeat control, occurrences in the
   views, and "this / this and future / all" for edits, moves and deletes.
   The core and server are done; without the app a weekly meeting can't be
   entered.
2. **`.ics` import and export** (in progress, E2 §5–6).
3. **The event peek and quick-create popovers**, with Duplicate and
   clickable links: every click now opens the full editor.
4. **Settings on the account** (E2 §7): default calendar, default duration,
   default view, week numbers, secondary zone, the zone's auto-detect and
   "Time zone changed — Update".
5. **Invitations** (E4a–E4e), with an attendee's delete declining, the
   invitation language and the "add as pending" setting.
6. **Search** (`/`) on an index in the browser, as Proton's encrypted
   search, and the agenda list it gives.
7. **Mini calendar** with the custom range, day headers opening the day,
   "+N more" opening the day.
8. **Feeds from a URL and Google import** (E5), then **meeting links**
   (E5, with auto-add).
9. **Shortcuts list (`?`) and Meta+K**, printing, today's date in the
   tab's icon, a collapsible sidebar, narrow-screen views.
10. **Colour per event**, separate start and end zones.
11. **Busy-only members**, a busy default for new calendars, members on
    other servers (after E5).
12. **Holiday calendars** (after E5, D-4).
13. **Booking pages** (Proton's newest; its own plan when taken up).
14. **Calendar beside Mail and Drive** (a side panel in the other apps).

## Out of scope / decided not to do

| Item | Why | Decision |
|---|---|---|
| CalDAV | Proton has none; Kutup serves no DAV | [`calendar.md`](calendar.md); the no-DAV rule |
| Zoom links made from the event | an outside service holding the meeting; a pasted link works | calendar.md §11 |
| Google import through the server | the token and events would reach Kutup's server | D-3: in the browser |
| Keyboard shortcuts behind a setting | Kutup's never fire in a field or dialog | calendar.md "Calendar UX parity" |
| Year view, offline | Proton has neither | — |
| Counter-proposals acted on | Proton shows them only | E4 Q-1 |
