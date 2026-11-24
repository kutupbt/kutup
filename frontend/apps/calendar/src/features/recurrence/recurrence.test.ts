// @vitest-environment node
import { describe, expect, it, vi } from 'vitest'

// The real rules and expansion: the Rust crate's, through its browser build.
vi.mock('@kutup/crypto/rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([import('node:fs/promises'), import('../../../../../wasm/crypto-calendar-wasm/kutup_crypto_wasm.js')])
  const wasm = await readFile(new URL('../../../../../wasm/crypto-calendar-wasm/kutup_crypto_wasm_bg.wasm', import.meta.url))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: () => Promise.resolve(module) }
})

const { followStart, modelOf, onceModel, pickPreset, presetOf, ruleOf } = await import('./frequency')
const { choicesFor, cutBefore, futureUid, planDelete, planSave, seriesContext } = await import('./actions')
const { instancesOf, placeAll } = await import('../placement')
type CalendarEvent = import('@kutup/calendar-core/api').CalendarEvent
type EventFields = import('@kutup/crypto/calendar').EventFields
type CalendarTime = import('@kutup/crypto/calendar').CalendarTime

const BERLIN = 'Europe/Berlin'
const zoned = (local: string, tzid = BERLIN): CalendarTime => ({ zoned: { local, tzid } })

let ids = 0
/** An event as opened, its server times its first occurrence's (as `timesOf` gives them). */
async function event(fields: Partial<EventFields> & Pick<EventFields, 'start' | 'end'>): Promise<CalendarEvent> {
  const { timesOf } = await import('@kutup/calendar-core/api')
  const full: EventFields = {
    uid: 'series@kutup.test',
    dtstamp: '2026-10-01T08:00:00Z',
    created: '2026-10-01T08:00:00Z',
    recurrenceId: null,
    rrule: null,
    exdates: [],
    organizer: null,
    sequence: 0,
    summary: 'Standup',
    description: null,
    location: null,
    status: 'confirmed',
    transp: 'opaque',
    comment: null,
    other: [],
    ...fields,
  }
  ids++
  return { id: `00000000-0000-4000-8000-${String(ids).padStart(12, '0')}`, calendarId: 'cal', fields: full, ...(await timesOf(full)), revision: 1, reminders: null, verified: true }
}

describe('the repeat choice (Proton’s frequency model)', () => {
  it('writes the presets as Proton does', async () => {
    const start = zoned('2026-10-13T09:00:00')
    const once = onceModel('2026-10-13')
    expect(await ruleOf(once, start, '2026-10-13', 1)).toBeNull()
    expect(await ruleOf(pickPreset(once, 'daily', '2026-10-13', 1), start, '2026-10-13', 1)).toBe('FREQ=DAILY')
    expect(await ruleOf(pickPreset(once, 'weekly', '2026-10-13', 1), start, '2026-10-13', 1)).toBe('FREQ=WEEKLY')
    expect(await ruleOf(pickPreset(once, 'workdays', '2026-10-13', 1), start, '2026-10-13', 1)).toBe('FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR')
    // 13 October 2026 is the second Tuesday.
    expect(await ruleOf(pickPreset(once, 'monthly:onNthDay', '2026-10-13', 1), start, '2026-10-13', 1)).toBe('FREQ=MONTHLY;BYSETPOS=2;BYDAY=TU')
    expect(await ruleOf(pickPreset(once, 'monthly:onMonthDay', '2026-10-13', 1), start, '2026-10-13', 1)).toBe('FREQ=MONTHLY')
    expect(await ruleOf(pickPreset(once, 'yearly', '2026-10-13', 1), start, '2026-10-13', 1)).toBe('FREQ=YEARLY')
  })

  it('offers the last weekday only on the last one, and never a fifth', async () => {
    // 27 October 2026 is the fourth and last Tuesday; 29 October the fifth Thursday.
    const last = pickPreset(onceModel('2026-10-27'), 'monthly:onLastDay', '2026-10-27', 1)
    expect(await ruleOf(last, zoned('2026-10-27T09:00:00'), '2026-10-27', 1)).toBe('FREQ=MONTHLY;BYSETPOS=-1;BYDAY=TU')
    const moved = followStart({ ...last, monthly: 'onNthDay' }, '2026-10-27', '2026-10-29')
    expect(moved.monthly).toBe('onLastDay')
    expect(followStart(last, '2026-10-27', '2026-10-20').monthly).toBe('onNthDay')
  })

  it('ends a timed series at the end of its last day in its zone, as UTC', async () => {
    const model = { ...pickPreset(onceModel('2026-10-13'), 'daily', '2026-10-13', 1), type: 'custom' as const, ends: { type: 'until' as const, count: 2, until: '2026-10-31' } }
    // 23:59:59 CET (UTC+1) on 31 October.
    expect(await ruleOf(model, zoned('2026-10-13T09:00:00'), '2026-10-13', 1)).toBe('FREQ=DAILY;UNTIL=20261031T225959Z')
    const read = await modelOf('FREQ=DAILY;UNTIL=20261031T225959Z', zoned('2026-10-13T09:00:00'), '2026-10-13')
    expect(read).toMatchObject({ type: 'custom', ends: { type: 'until', until: '2026-10-31' } })
  })

  it('reads a stored rule back into the same choice', async () => {
    const start = zoned('2026-10-12T09:00:00')
    for (const text of ['FREQ=WEEKLY', 'FREQ=WEEKLY;COUNT=5;INTERVAL=2', 'FREQ=WEEKLY;BYDAY=MO,WE;WKST=SU', 'FREQ=MONTHLY;BYSETPOS=2;BYDAY=MO']) {
      const model = await modelOf(text, start, '2026-10-12')
      expect(model.type).not.toBe('other')
      expect(await ruleOf(model, start, '2026-10-12', 1, text)).toBe(text)
    }
    expect(presetOf(await modelOf('FREQ=WEEKLY', start, '2026-10-12'), '2026-10-12', 1)).toBe('weekly')
    // A rule the editor doesn't make is kept as it is.
    const other = await modelOf('FREQ=YEARLY;BYYEARDAY=100', zoned('2026-04-10T09:00:00'), '2026-04-10')
    expect(other).toMatchObject({ type: 'other', text: 'FREQ=YEARLY;BYYEARDAY=100' })
  })
})

describe('every occurrence in the shown days', () => {
  it('keeps 09:00 in Berlin across the change of offset, and hides the changed one', async () => {
    const series = await event({ start: zoned('2026-10-19T09:00:00'), end: zoned('2026-10-19T10:00:00'), rrule: 'FREQ=WEEKLY' })
    const placed = await placeAll([series], () => '#000', BERLIN, '2026-10-18T22:00:00Z', '2026-11-08T23:00:00Z')
    expect(placed.map((p) => p.start)).toEqual(['2026-10-19T09:00:00', '2026-10-26T09:00:00', '2026-11-02T09:00:00'])
    expect(placed.map((p) => p.instance?.startUtc)).toEqual(['2026-10-19T07:00:00Z', '2026-10-26T08:00:00Z', '2026-11-02T08:00:00Z'])
    // The 26 October one moved to the 28th.
    const child = await event({ start: zoned('2026-10-28T11:00:00'), end: zoned('2026-10-28T12:00:00'), recurrenceId: zoned('2026-10-26T09:00:00'), summary: 'Moved' })
    const withChild = await placeAll([series, child], () => '#000', BERLIN, '2026-10-18T22:00:00Z', '2026-11-08T23:00:00Z')
    expect(withChild.map((p) => [p.start, p.event.fields.summary])).toEqual([
      ['2026-10-19T09:00:00', 'Standup'],
      ['2026-11-02T09:00:00', 'Standup'],
      ['2026-10-28T11:00:00', 'Moved'],
    ])
    // Seen from New York, the same instants.
    const ny = await placeAll([series], () => '#000', 'America/New_York', '2026-10-18T22:00:00Z', '2026-11-08T23:00:00Z')
    expect(ny.map((p) => p.start)).toEqual(['2026-10-19T03:00:00', '2026-10-26T04:00:00', '2026-11-02T03:00:00'])
  })

  it('skips the months without a 31st and the EXDATEs', async () => {
    const series = await event({ start: { date: '2026-01-31' }, end: { date: '2026-02-01' }, rrule: 'FREQ=MONTHLY;COUNT=6', exdates: [{ date: '2026-05-31' }] })
    const found = await instancesOf(series, '2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z')
    // January, March, May, July, August, October: six by COUNT, May removed.
    expect(found.map((o) => [o.start, o.number])).toEqual([
      [{ date: '2026-01-31' }, 1],
      [{ date: '2026-03-31' }, 2],
      [{ date: '2026-07-31' }, 4],
      [{ date: '2026-08-31' }, 5],
      [{ date: '2026-10-31' }, 6],
    ])
  })

  it('draws a long series from the window, not from its start', async () => {
    const series = await event({ start: zoned('1990-01-01T08:00:00'), end: zoned('1990-01-01T08:30:00'), rrule: 'FREQ=DAILY' })
    const found = await instancesOf(series, '2030-06-01T00:00:00Z', '2030-06-03T00:00:00Z')
    expect(found.map((o) => o.start)).toEqual([zoned('2030-06-01T08:00:00'), zoned('2030-06-02T08:00:00')])
  })
})

describe('this event, this and future events, all events (Proton’s)', () => {
  const form = (start: string, end: string, rrule: string | null, summary = 'Standup') => ({
    start: zoned(start),
    end: zoned(end),
    rrule,
    summary,
    description: null,
    location: null,
  })

  it('changes one occurrence as an event of its own, and deletes one by EXDATE', async () => {
    const series = await event({ start: zoned('2026-10-19T09:00:00'), end: zoned('2026-10-19T10:00:00'), rrule: 'FREQ=WEEKLY;COUNT=5' })
    const [, second] = await instancesOf(series, '2026-10-01T00:00:00Z', '2026-12-01T00:00:00Z')
    const context = (await seriesContext([series], series, second))!
    expect(await choicesFor(context)).toEqual(['single', 'future', 'all'])
    const [create] = await planSave('single', context, form('2026-10-26T11:00:00', '2026-10-26T12:00:00', 'FREQ=WEEKLY;COUNT=5'), undefined)
    expect(create).toMatchObject({ kind: 'create', fields: { uid: series.fields.uid, recurrenceId: zoned('2026-10-26T09:00:00'), rrule: null, sequence: 1 } })
    const [exdate] = await planDelete('single', context)
    expect(exdate).toMatchObject({ kind: 'update', fields: { exdates: [zoned('2026-10-26T09:00:00')] } })
  })

  it('a changed occurrence deleted goes, and the series excludes it', async () => {
    const series = await event({ start: zoned('2026-10-19T09:00:00'), end: zoned('2026-10-19T10:00:00'), rrule: 'FREQ=WEEKLY;COUNT=5' })
    const child = await event({ start: zoned('2026-10-27T09:00:00'), end: zoned('2026-10-27T10:00:00'), recurrenceId: zoned('2026-10-26T09:00:00') })
    const context = (await seriesContext([series, child], child, null))!
    expect(context.occurrence).toMatchObject({ startUtc: '2026-10-26T08:00:00Z', number: 2 })
    const steps = await planDelete('single', context)
    expect(steps.map((s) => s.kind)).toEqual(['delete', 'update'])
    expect(steps[0]).toMatchObject({ event: { id: child.id } })
  })

  it('splits the series for this and future events: UNTIL the day before, a new UID', async () => {
    const series = await event({ start: zoned('2026-10-19T09:00:00'), end: zoned('2026-10-19T10:00:00'), rrule: 'FREQ=WEEKLY', exdates: [zoned('2026-11-09T09:00:00')] })
    const later = (await instancesOf(series, '2026-11-01T00:00:00Z', '2026-11-03T00:00:00Z'))[0]
    const child = await event({ start: zoned('2026-11-16T10:00:00'), end: zoned('2026-11-16T11:00:00'), recurrenceId: zoned('2026-11-16T09:00:00') })
    const context = (await seriesContext([series, child], series, later))!
    const steps = await planSave('future', context, form('2026-11-02T10:00:00', '2026-11-02T11:00:00', 'FREQ=WEEKLY', 'Later standup'), undefined)
    expect(steps.map((s) => s.kind)).toEqual(['delete', 'update', 'create'])
    // 1 November 23:59:59 CET.
    expect(steps[1]).toMatchObject({ kind: 'update', fields: { rrule: 'FREQ=WEEKLY;UNTIL=20261101T225959Z', exdates: [], sequence: 1 } })
    expect(steps[2]).toMatchObject({
      kind: 'create',
      fields: { uid: 'series_R20261102T090000@kutup.test', rrule: 'FREQ=WEEKLY', recurrenceId: null, sequence: 0, summary: 'Later standup' },
    })
  })

  it('counts a COUNT series on from the occurrence', async () => {
    const series = await event({ start: zoned('2026-10-19T09:00:00'), end: zoned('2026-10-19T10:00:00'), rrule: 'FREQ=WEEKLY;COUNT=5' })
    const third = (await instancesOf(series, '2026-11-01T00:00:00Z', '2026-11-03T00:00:00Z'))[0]
    expect(third.number).toBe(3)
    expect((await cutBefore(series, third)).rrule).toBe('FREQ=WEEKLY;COUNT=2')
    const context = (await seriesContext([series], series, third))!
    const steps = await planSave('future', context, form('2026-11-02T09:00:00', '2026-11-02T10:00:00', 'FREQ=WEEKLY;COUNT=5', 'Renamed'), undefined)
    expect(steps.at(-1)).toMatchObject({ kind: 'create', fields: { rrule: 'FREQ=WEEKLY;COUNT=3' } })
  })

  it('moves all events to a new time on their own days, and keeps changes when only the title changes', async () => {
    const series = await event({ start: zoned('2026-10-19T09:00:00'), end: zoned('2026-10-19T10:00:00'), rrule: 'FREQ=WEEKLY', exdates: [zoned('2026-10-26T09:00:00')] })
    const child = await event({ start: zoned('2026-11-03T09:00:00'), end: zoned('2026-11-03T10:00:00'), recurrenceId: zoned('2026-11-02T09:00:00') })
    const third = (await instancesOf(series, '2026-11-09T00:00:00Z', '2026-11-10T00:00:00Z'))[0]
    const context = (await seriesContext([series, child], series, third))!
    const moved = await planSave('all', context, form('2026-11-09T14:00:00', '2026-11-09T15:30:00', 'FREQ=WEEKLY'), undefined)
    expect(moved.map((s) => s.kind)).toEqual(['delete', 'update'])
    expect(moved[1]).toMatchObject({ fields: { start: zoned('2026-10-19T14:00:00'), end: zoned('2026-10-19T15:30:00'), exdates: [], sequence: 1 } })
    const renamed = await planSave('all', context, form('2026-11-09T09:00:00', '2026-11-09T10:00:00', 'FREQ=WEEKLY', 'Daily sync'), undefined)
    expect(renamed.map((s) => s.kind)).toEqual(['update', 'update'])
    expect(renamed[0]).toMatchObject({ fields: { start: zoned('2026-10-19T09:00:00'), exdates: [zoned('2026-10-26T09:00:00')], summary: 'Daily sync', sequence: 0 } })
    expect(renamed[1]).toMatchObject({ event: { id: child.id }, fields: { summary: 'Daily sync' } })
  })

  it('deletes all events, the changed ones first; the first occurrence offers no "future"', async () => {
    const series = await event({ start: zoned('2026-10-19T09:00:00'), end: zoned('2026-10-19T10:00:00'), rrule: 'FREQ=WEEKLY' })
    const child = await event({ start: zoned('2026-10-27T09:00:00'), end: zoned('2026-10-27T10:00:00'), recurrenceId: zoned('2026-10-26T09:00:00') })
    const context = (await seriesContext([series, child], series, null))!
    expect(await choicesFor(context)).toEqual(['single', 'all'])
    expect((await planDelete('all', context)).map((s) => (s.kind === 'delete' ? s.event.id : s.kind))).toEqual([child.id, series.id])
  })

  it('names the new series as Proton does, an older split replaced', () => {
    expect(futureUid('abc@kutup.test', { date: '2026-11-02' })).toBe('abc_R20261102@kutup.test')
    expect(futureUid('abc_R20261019T090000@kutup.test', zoned('2026-11-02T09:00:00'))).toBe('abc_R20261102T090000@kutup.test')
  })
})
