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

console.log('calendar-ics WASM checks passed')
