import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { MailAccount } from '@kutup/mail-core/api'
import type { Session } from '@kutup/session/store'
import type { Calendar, EventRow } from './api'

// The import's batches and the export's pages (docs/plans/calendar.md, E2
// §5–6). The `.ics` reading and writing are Rust's (its tests and the WASM
// check); here the sealing is a stand-in and the server a script.

const sealed = vi.hoisted(() => ({ fail: new Set<string>() }))
vi.mock('@kutup/crypto/calendar', () => ({
  sealCalendarEvent: (_key: unknown, _author: unknown, fields: { uid: string }) => {
    if (sealed.fail.has(fields.uid)) throw new Error('cannot seal')
    return { sealed: fields.uid }
  },
  importIcs: vi.fn(),
  exportIcs: (input: unknown) => Promise.resolve(JSON.stringify(input)),
}))
vi.mock('./api', () => ({
  beforeEventWrite: () => Promise.resolve(),
  activeAddressId: () => Promise.resolve('a1'),
  openEvent: (_account: unknown, _calendar: unknown, row: EventRow & { broken?: boolean; own?: unknown }) =>
    row.broken
      ? Promise.reject(new Error('does not open'))
      : Promise.resolve({ fields: { uid: row.uid }, fullDay: row.fullDay, reminders: row.reminders }),
}))
vi.mock('@kutup/session/apps', () => ({ loadServerSettings: () => Promise.resolve({ calendar: { syncBatch: 2, importMaxBytes: 1000 } }) }))
vi.mock('@kutup/session/release', () => ({ RELEASE: '2026.1124.0' }))

const server = vi.hoisted(() => ({
  posts: [] as { url: string; body: { changes: { create: { event: { sealed: string }; overwrite: boolean; reminders: unknown[] } }[] } }[],
  answer: (_body: unknown): unknown => null,
  pages: new Map<string | undefined, { events: unknown[]; next: string | null }>(),
}))
vi.mock('@kutup/session/client', () => ({
  default: {
    post: (url: string, body: never) => {
      server.posts.push({ url, body })
      return server.answer(body)
    },
    get: (_url: string, config: { params: { afterId?: string } }) => Promise.resolve({ data: server.pages.get(config.params.afterId) }),
  },
}))

const { checkIcsFile, exportCalendar, exportFileName, IcsFileRefused, importEvents, loadImportLimits } = await import('./ics')

const session = {} as Session
const account = { address: 'ada@kutup.test', key: {} } as unknown as MailAccount
const calendar = {
  id: 'c1',
  name: 'Work',
  description: '',
  unlocked: {},
  defaultReminders: { timed: [{ type: 'device', trigger: '-PT15M' }], allDay: [{ type: 'email', trigger: '-PT15H' }] },
} as unknown as Calendar
const event = (uid: string) => ({ fields: { uid } as never, reminders: [{ type: 'device' as const, trigger: '-PT5M' }], id: uid })

beforeEach(() => {
  server.posts = []
  sealed.fail.clear()
  server.answer = (body) => Promise.resolve({ data: { results: (body as { changes: unknown[] }).changes.map(() => ({ status: 200, code: null, error: null })) } })
})

describe('the import', () => {
  it('takes the site limits, Proton’s where the server names none', async () => {
    expect(await loadImportLimits()).toEqual({ maxBytes: 1000, maxEvents: 15000, syncBatch: 2, maxCount: 49, maxReminders: 10 })
  })

  it('refuses files by type and size before reading them', async () => {
    const limits = await loadImportLimits()
    const file = (name: string, size: number) => new File(['x'.repeat(size)], name)
    expect(checkIcsFile(file('work.ICS', 10), limits).name).toBe('work.ICS')
    expect(checkIcsFile(file('a.ifb', 10), limits).name).toBe('a.ifb')
    const reason = (f?: File) => {
      try {
        checkIcsFile(f, limits)
      } catch (error) {
        return error instanceof IcsFileRefused ? error.reason : 'other'
      }
    }
    expect(reason(undefined)).toBe('noFileSelected')
    expect(reason(file('notes.txt', 10))).toBe('noIcsFile')
    expect(reason(file('big.ics', 1001))).toBe('fileTooBig')
  })

  it('sends batches of the site’s sync, each event overwriting, with its own reminders', async () => {
    const seen: number[] = []
    const done = await importEvents(session, account, calendar, ['a', 'b', 'c'].map(event), await loadImportLimits(), (p) => seen.push(p.imported))
    expect(server.posts.map((post) => post.body.changes.map((c) => c.create.event.sealed))).toEqual([['a', 'b'], ['c']])
    expect(server.posts[0]?.body.changes[0]?.create.overwrite).toBe(true)
    expect(server.posts[0]?.body.changes[0]?.create.reminders).toEqual([{ type: 'device', trigger: '-PT5M' }])
    expect(done).toEqual({ encrypted: 3, imported: 3, errors: [] })
    expect(seen.at(-1)).toBe(3)
  })

  it('reports what the server refuses and what doesn’t seal, by name', async () => {
    sealed.fail.add('b')
    server.answer = () =>
      Promise.resolve({
        data: {
          results: [
            { status: 409, code: 'sequenceBehind', error: 'behind' },
            { status: 400, code: 'parentMissing', error: 'no series' },
          ],
        },
      })
    const done = await importEvents(session, account, calendar, ['a', 'b', 'c'].map(event), { ...(await loadImportLimits()), syncBatch: 3 }, () => undefined)
    expect(done.imported).toBe(0)
    expect(done.errors).toEqual([
      { id: 'b', kind: 'encryptionError' },
      { id: 'a', kind: 'sequenceBehind' },
      { id: 'c', kind: 'parentEventMissing' },
    ])
  })

  it('waits out the rate limit and sends the batch again', async () => {
    let first = true
    server.answer = (body) => {
      if (first) {
        first = false
        return Promise.reject(Object.assign(new Error('rate limited'), { response: { status: 429, headers: { 'retry-after': '0.01' } } }))
      }
      return Promise.resolve({ data: { results: (body as { changes: unknown[] }).changes.map(() => ({ status: 200 })) } })
    }
    const done = await importEvents(session, account, calendar, [event('a')], await loadImportLimits(), () => undefined)
    expect(server.posts).toHaveLength(2)
    expect(done.imported).toBe(1)
  })
})

describe('the export', () => {
  it('opens every page of events, with this member’s reminders or the calendar’s defaults', async () => {
    const row = (uid: string, extra: Record<string, unknown> = {}) => ({ uid, fullDay: false, reminders: null, startUtc: '2026-11-02T07:00:00Z', endUtc: '2026-11-02T08:00:00Z', rangeEndUtc: '2026-11-02T08:00:00Z', ...extra })
    server.pages.set(undefined, { events: [row('a'), row('b', { fullDay: true })], next: 'id-b' })
    server.pages.set('id-b', { events: [row('c', { reminders: [] }), row('d', { broken: true, rangeEndUtc: null })], next: null })
    const result = await exportCalendar(account, calendar, 'Europe/Istanbul', '(no title)')
    const written = JSON.parse(result.text) as { events: { fields: { uid: string }; reminders: unknown[] }[]; email: string; release: string }
    expect(written.events.map((e) => [e.fields.uid, e.reminders])).toEqual([
      ['a', calendar.defaultReminders.timed],
      ['b', calendar.defaultReminders.allDay],
      ['c', []],
    ])
    expect(written.email).toBe('ada@kutup.test')
    expect(written.release).toBe('2026.1124.0')
    expect(result.exported).toBe(3)
    expect(result.errors).toEqual([{ startUtc: '2026-11-02T07:00:00Z', fullDay: false, repeats: true }])
  })

  it('names the file as Proton’s', () => {
    expect(exportFileName('Work', '2026-11-24')).toBe('Work-2026-11-24.ics')
    expect(exportFileName('a/b: c', '2026-11-24')).toBe('a_b_ c-2026-11-24.ics')
    expect(exportFileName('  ', '2026-11-24')).toBe('calendar-2026-11-24.ics')
  })
})
