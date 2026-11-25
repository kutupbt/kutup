// The `.ics` runtime (crates/kutup-calendar-ics-wasm, docs/plans/calendar.md
// E2c) against the Rust core's fixtures: a Google export read as the Rust
// tests read it, the refusals, Outlook's Windows zones and Apple's line
// ends, and an export that reads back as it was. Run after
// `pnpm -C frontend build:calendar-ics-wasm`.
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const dir = `${root}frontend/wasm/calendar-ics-wasm`
const ics = await import(`${dir}/kutup_calendar_ics_wasm.js`)
await ics.default({ module_or_path: await readFile(`${dir}/kutup_calendar_ics_wasm_bg.wasm`) })
const fixture = (name) => readFile(`${root}crates/kutup-crypto/tests/ics/${name}.ics`, 'utf8')

const options = { primaryZone: 'Europe/Istanbul', maxBytes: 10 * 1024 * 1024, maxEvents: 15000, maxCount: 49, maxReminders: 10, now: '2026-11-24T10:00:00Z' }
const google = await fixture('google')
const { read } = ics.calendarImportIcs(google, options)
assert.equal(read.method, 'PUBLISH')
assert.equal(read.events.length, 4)
assert.deepEqual(read.errors.map((e) => e.kind), ['rruleUnsupported'])
const sync = read.events.find((e) => e.fields.summary === 'Team sync')
assert.equal(sync.fields.rrule, 'FREQ=WEEKLY;UNTIL=20261221T205959Z;BYDAY=MO')
assert.deepEqual(sync.fields.exdates, [{ zoned: { local: '2026-11-16T10:00:00', tzid: 'Europe/Istanbul' } }])
assert.deepEqual(sync.reminders, [{ type: 'email', trigger: '-P1D' }, { type: 'device', trigger: '-PT10M' }])
assert.equal(read.events.at(-1).fields.recurrenceId.zoned.local, '2026-11-09T10:00:00')
assert.equal(read.events.at(-1).fields.sequence, 2)

const outlook = ics.calendarImportIcs(await fixture('outlook'), options).read
assert.equal(outlook.events.find((e) => e.fields.summary === 'Monthly review').fields.start.zoned.tzid, 'Europe/Berlin')
assert.deepEqual(outlook.errors.map((e) => e.kind), ['tzidUnsupported'])
const apple = ics.calendarImportIcs(await fixture('apple'), options).read
assert.equal(apple.events.find((e) => e.fields.summary === 'Concert').fields.start.zoned.tzid, 'Europe/Istanbul')
assert.deepEqual(apple.errors.map((e) => [e.component, e.kind]), [['vtodo', 'todoFormat']])

assert.deepEqual(ics.calendarImportIcs('', options), { refused: 'fileEmpty' })
assert.deepEqual(ics.calendarImportIcs(google, { ...options, maxBytes: 10 }), { refused: 'fileTooBig' })
assert.deepEqual(ics.calendarImportIcs('BEGIN:VCARD\r\nEND:VCARD', options), { refused: 'invalidCalendar' })
assert.throws(() => ics.calendarImportIcs(google, { ...options, primaryZone: 'Nowhere/Else' }))

const text = ics.calendarExportIcs({
  name: 'Work',
  description: null,
  zone: 'Europe/Istanbul',
  release: '0.0.0-dev',
  untitled: '(no title)',
  email: 'me@kutup.example',
  events: read.events.map(({ fields, reminders }) => ({ fields, reminders })),
})
assert.ok(text.startsWith('BEGIN:VCALENDAR\r\nPRODID:-//Kutup//Calendar 0.0.0-dev//EN\r\n'))
assert.ok(text.includes('BEGIN:VTIMEZONE\r\nTZID:Europe/Istanbul\r\n'))
const again = ics.calendarImportIcs(text, options).read
assert.deepEqual(again.errors, [])
assert.deepEqual(again.events, read.events)
assert.throws(() => ics.calendarExportIcs({ name: 'x', description: null, zone: 'Nowhere/Else', release: '1', untitled: '-', email: null, events: [] }))

// Invitations (docs/plans/calendar-e4.md §2): Proton's fixtures read as the
// Rust tests read them, a refusal, and the writer's one form (the vectors'
// text, byte for byte).
const itip = (name) => readFile(`${root}crates/kutup-crypto/tests/ics/itip/${name}.ics`, 'utf8')
const inviteOptions = { primaryZone: 'Europe/Istanbul', maxBytes: 1024 * 1024, maxCount: 499, maxAttendees: 100, now: '2026-11-24T10:00:00Z', messageDate: '2026-11-20T08:00:00Z', sender: 'zeynep@fastmail.example' }
const appleInvite = ics.calendarReadInvitation(await itip('apple-single-edit'), inviteOptions).read
assert.equal(appleInvite.method, 'REQUEST')
assert.equal(appleInvite.fields.uid, 'BA3017ED-889A-4BCB-B9CB-11CE30586021')
assert.deepEqual(appleInvite.fields.recurrenceId, { zoned: { local: '2022-09-15T09:00:00', tzid: 'Europe/Vilnius' } })
assert.deepEqual(appleInvite.organizer, { email: 'agmailone@gmail.com', name: 'testKrt' })
assert.equal(appleInvite.attendees[1].partstat, 'accepted')
const outlookInvite = ics.calendarReadInvitation(await itip('outlook-request'), inviteOptions).read
assert.equal(outlookInvite.fields.start.zoned.tzid, 'Europe/Berlin')
const cancel = ics.calendarReadInvitation(await itip('fastmail-cancel'), inviteOptions).read
assert.equal(cancel.fields.sequence, 3)
assert.equal(cancel.fields.dtstamp, '2026-11-20T08:00:00Z')
assert.deepEqual(ics.calendarReadInvitation('', inviteOptions), { refused: { error: 'noComponent', reason: null, method: null } })
const refusedReply = ics.calendarReadInvitation('BEGIN:VCALENDAR\r\nMETHOD:REPLY\r\nBEGIN:VEVENT\r\nUID:x\r\nDTSTART:20270101T100000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n', inviteOptions)
assert.deepEqual(refusedReply, { refused: { error: 'invitationInvalid', reason: 'missingAttendee', method: 'REPLY' } })
const iv = JSON.parse(await readFile(`${root}crates/kutup-crypto/tests/vectors/calendar-invitation-v1.json`, 'utf8'))
assert.equal(ics.calendarWriteInvitation(iv.write.input), iv.write.text)
const back = ics.calendarReadInvitation(iv.write.text, inviteOptions).read
assert.equal(back.fields.uid, iv.write.input.fields.uid)
assert.equal(back.attendees.length, 2)
assert.throws(() => ics.calendarWriteInvitation({ ...iv.write.input, method: 'PUBLISH' }))

console.log('calendar-ics WASM checks passed')
