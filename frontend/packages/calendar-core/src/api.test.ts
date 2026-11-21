import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { MailAccount } from '@kutup/mail-core/api'
import type { Session } from '@kutup/session/store'

// The calendars under the account head (docs/plans/rollback-protection.md):
// each listed with its settings record (docs/plans/account-records.md). The
// crypto is Rust's (vectors there); here a calendar's key is a stand-in
// whose metadata opens only under the id it names, and a settings record a
// stand-in that opens only under its own id.

vi.mock('@kutup/crypto/calendar', () => ({
  unlockCalendar: (_account: unknown, lock: { passphraseShare: string }) =>
    Promise.resolve({
      fingerprint: lock.passphraseShare,
      openMetadata: (metadata: { dataPacket: string; signature: string }, calendarId: string) => {
        if (metadata.dataPacket !== calendarId) throw new Error('another calendar')
        return { name: `name of ${calendarId}`, description: '', verified: metadata.signature === 'owner' }
      },
      free: () => undefined,
    }),
  createCalendar: () =>
    Promise.resolve({ publicKey: 'P', lockedSecretKey: 'L', fingerprint: 'f', passphraseShare: 'f', metadata: { keyPacket: 'k', dataPacket: 'd', signature: 's' } }),
  localToUtc: () => Promise.resolve(''),
  sealCalendarEvent: () => ({}),
  sealCalendarMetadata: () => ({}),
}))
vi.mock('@kutup/mail-core/api', () => ({ useMailAccount: vi.fn() }))
vi.mock('@kutup/crypto/scopeRecords', () => ({
  scopeRecordId: (_key: unknown, scope: string, plain: Uint8Array) => Promise.resolve(`${scope}:${Array.from(plain, (b) => b.toString(16).padStart(2, '0')).join('')}`),
  sealScopeRecord: (_keys: unknown, _binding: string, _scope: string, id: string, revision: number, value: unknown) =>
    Promise.resolve(JSON.stringify({ id, revision, value })),
  openScopeRecord: (_keys: unknown, _binding: string, _scope: string, id: string, sealed: string) => {
    const opened = JSON.parse(sealed) as { id: string; revision: number; value: unknown }
    if (opened.id !== id) return Promise.reject(new Error('another record'))
    return Promise.resolve({ value: opened.value, revision: opened.revision })
  },
}))
vi.mock('@kutup/session/devices', () => ({ ownAccount: () => Promise.resolve('aci:u1@kutup.test') }))

const http = vi.hoisted(() => ({
  rows: [] as unknown[],
  get: vi.fn(),
  post: vi.fn(),
  put: vi.fn(),
  delete: vi.fn(),
}))
vi.mock('@kutup/session/client', () => ({
  default: {
    get: (url: string) => {
      http.get(url)
      if (url.endsWith('/events')) return Promise.resolve({ data: { events: [], next: { afterStart: '2026-10-29T09:00:00Z', afterId: 'e1' } } })
      if (url === '/mail/addresses') return Promise.resolve({ data: [{ id: 'a1', address: 'ada@kutup.test', state: 'active' }] })
      return Promise.resolve({ data: { calendars: http.rows } })
    },
    post: (url: string, body: unknown) => http.post(url, body) as Promise<unknown>,
    put: (url: string, body: unknown) => http.put(url, body) as Promise<unknown>,
    delete: (url: string, body: unknown) => http.delete(url, body) as Promise<unknown>,
  },
}))

// The head, its rules kept small (its own tests: @kutup/session): the
// settings scope's verified records. A blocked head refuses reads and
// writes of it, as `records` and `recordsWrite` do.
const head = vi.hoisted(() => ({ records: new Map<string, { revision: number; envelope: string }>(), blocked: false }))
vi.mock('@kutup/session/accountHead', async () => {
  const actual = await vi.importActual<typeof import('@kutup/session/accountHead')>('@kutup/session/accountHead')
  const { ScopeRecords } = await vi.importActual<typeof import('@kutup/session/accountRecords')>('@kutup/session/accountRecords')
  const copy = () => {
    const records = new ScopeRecords('calendarSettings')
    for (const [id, record] of head.records) records.records.set(id, record)
    return records
  }
  const client = {
    verifiedHead: () => (head.blocked ? Promise.reject(new actual.HeadBlockedError('fork')) : Promise.resolve()),
    records: () => (head.blocked ? Promise.reject(new actual.HeadBlockedError('fork')) : Promise.resolve(copy())),
    recordsWrite: async <T,>(_s: string, edit: (copy: InstanceType<typeof ScopeRecords>) => Promise<{ puts: { id: string; revision: number; envelope: string }[]; deletes: string[]; done: T } | null>) => {
      if (head.blocked) throw new actual.HeadBlockedError('fork')
      const change = await edit(copy())
      if (!change) return undefined
      for (const put of change.puts) head.records.set(put.id, { revision: put.revision, envelope: put.envelope })
      for (const id of change.deletes) head.records.delete(id)
      return change.done
    },
  }
  return { ...actual, accountHead: () => Promise.resolve(client) }
})

import { OlderThanSeenError, resetRevisionGuardsForTesting } from '@kutup/crypto/revisionGuard'
import type { EventFields } from '@kutup/crypto/calendar'
import { HeadBlockedError } from '@kutup/session/accountHead'
import {
  CalendarChangedError,
  createCalendar,
  deleteCalendar,
  deleteEvent,
  loadCalendars,
  loadEvents,
  openEvent,
  saveEvent,
  updateCalendar,
  type Calendar,
  type EventRow,
} from './api'
import { testRoots } from '@kutup/crypto/accountRoots.testing'

const session = { accountId: 'u1', sessionId: 's1', masterKey: new Uint8Array(32), roots: testRoots(0) } as unknown as Session
const account = {
  key: { masterKeyBase64: 'm', binding: 'b', address: 'ada@kutup.test', envelope: 'e', fingerprint: 'k' },
  olderKeys: [],
  ownPublicKeys: ['A'],
  publicKey: 'A',
  isOwnAddress: () => true,
} as unknown as MailAccount

let fingerprints = 0
/** Calendar ids as UUIDs (the settings record id hashes their bytes). */
const uuid = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`
const settingsOf = (n: number) => `calendarSettings:${uuid(n).replace(/-/g, '')}`
/** The settings record of calendar `n`, at `revision`, as the head vouches for it. */
function settings(n: number, revision: number, value: Record<string, unknown> = { color: '#1da583', display: true }) {
  head.records.set(settingsOf(n), { revision, envelope: JSON.stringify({ id: settingsOf(n), revision, value }) })
}
/** Calendar `n` as the server lists it; its metadata names `metadataId`, signed by `signer`. */
function row(n: number, { metadataId = uuid(n), signer = 'owner', listed = 'own', ownerId = 'u1' } = {}) {
  const fingerprint = `fp${++fingerprints}`
  return {
    id: uuid(n),
    ownerAccountId: ownerId,
    publicKey: 'P',
    fingerprint: listed === 'own' ? fingerprint : listed,
    lockedSecretKey: 'L',
    keyGeneration: 1,
    passphraseShare: fingerprint,
    metadata: { keyPacket: 'k', dataPacket: metadataId, signature: signer },
    permissions: 127,
    defaultReminders: { timed: [], allDay: [] },
    createdAt: '',
    updatedAt: '',
  }
}

beforeEach(() => {
  resetRevisionGuardsForTesting()
  http.rows = []
  for (const fn of [http.get, http.post, http.delete, http.put]) fn.mockReset()
  head.records.clear()
  head.blocked = false
})

describe('reading the calendars', () => {
  it('opens the calendars with their own settings', async () => {
    http.rows = [row(1), row(2)]
    settings(1, 1)
    settings(2, 3, { color: '#8080ff', display: false, order: 2 })
    const { calendars, unreadable } = await loadCalendars(session, account)
    expect(calendars.map((c) => [c.name, c.color, c.display, c.revision])).toEqual([
      [`name of ${uuid(1)}`, '#1da583', true, 1],
      [`name of ${uuid(2)}`, '#8080ff', false, 3],
    ])
    expect(calendars[1].settingsRest).toEqual({ order: 2 })
    expect(unreadable).toBe(0)
  })

  it('counts a calendar listed without its settings, or with another\'s, as unreadable', async () => {
    http.rows = [row(1), row(2)]
    settings(1, 1)
    head.records.set(settingsOf(2), head.records.get(settingsOf(1))!)
    const { calendars, unreadable } = await loadCalendars(session, account)
    expect(calendars.map((c) => c.id)).toEqual([uuid(1)])
    expect(unreadable).toBe(1)
  })

  it('never shows a name its owner did not sign, nor one moved from another calendar', async () => {
    http.rows = [row(1, { signer: 'someone' }), row(2, { metadataId: uuid(1) }), row(3)]
    for (const n of [1, 2, 3]) settings(n, 1)
    const { calendars, unreadable } = await loadCalendars(session, account)
    expect(calendars.map((c) => c.id)).toEqual([uuid(3)])
    expect(unreadable).toBe(2)
  })

  it('opens no calendar of another account (sharing comes in E3)', async () => {
    http.rows = [row(1, { ownerId: 'u2' })]
    settings(1, 1)
    const { calendars, unreadable } = await loadCalendars(session, account)
    expect(calendars).toHaveLength(0)
    expect(unreadable).toBe(1)
  })

  it('refuses a key that is not the one listed', async () => {
    http.rows = [row(1, { listed: 'another' })]
    settings(1, 1)
    const { calendars, unreadable } = await loadCalendars(session, account)
    expect(calendars).toHaveLength(0)
    expect(unreadable).toBe(1)
  })

  it('reads on while the app is blocked, as every listed scope does (the banner says why)', async () => {
    http.rows = [row(1)]
    head.blocked = true
    const { calendars } = await loadCalendars(session, account)
    expect(calendars).toHaveLength(1)
    expect(calendars[0].revision).toBe(0)
  })

  it('refuses settings rolled back below what this browser saw', async () => {
    http.rows = [row(1)]
    settings(1, 3)
    await loadCalendars(session, account)
    settings(1, 2)
    await expect(loadCalendars(session, account)).rejects.toBeInstanceOf(OlderThanSeenError)
  })

  it('refuses a calendar brought back after this browser deleted it, blocked or not', async () => {
    http.rows = [row(1)]
    settings(1, 1)
    const { calendars } = await loadCalendars(session, account)
    http.delete.mockResolvedValue({ data: {} })
    await deleteCalendar(session, calendars[0])
    expect(head.records.size).toBe(0)
    settings(1, 1)
    await expect(loadCalendars(session, account)).rejects.toBeInstanceOf(OlderThanSeenError)
    head.blocked = true
    await expect(loadCalendars(session, account)).rejects.toBeInstanceOf(OlderThanSeenError)
  })
})

describe('writing calendars', () => {
  it('files the settings before the create, and removes them when it fails', async () => {
    http.post.mockResolvedValue({ data: {} })
    const id = await createCalendar(session, account, 'Ev', '#8080ff')
    expect(http.post).toHaveBeenCalledWith('/calendar/calendars', expect.objectContaining({ id, passphraseShare: 'f' }))
    expect(http.post.mock.calls[0][1]).not.toHaveProperty('head')
    expect(http.post.mock.calls[0][1]).not.toHaveProperty('color')
    const filed = head.records.get(`calendarSettings:${id.replace(/-/g, '')}`)
    expect(JSON.parse(filed!.envelope).value).toEqual({ color: '#8080ff', display: true })
    http.post.mockRejectedValueOnce(new Error('calendarLimit'))
    await expect(createCalendar(session, account, 'Ev', '#8080ff')).rejects.toThrow('calendarLimit')
    expect(head.records.size).toBe(1)
  })

  it('changes colour and visibility in the record, a newer client\'s fields kept, and refuses a stale one', async () => {
    http.rows = [row(1)]
    settings(1, 1, { color: '#1da583', display: true, order: 2 })
    const [calendar] = (await loadCalendars(session, account)).calendars
    await updateCalendar(session, account, calendar, { display: false })
    expect(http.put).not.toHaveBeenCalled()
    const stored = head.records.get(settingsOf(1))!
    expect(stored.revision).toBe(2)
    expect(JSON.parse(stored.envelope).value).toEqual({ order: 2, color: '#1da583', display: false })
    // Made from revision 1, which another device has moved on from.
    await expect(updateCalendar(session, account, calendar, { color: '#8080ff' })).rejects.toBeInstanceOf(CalendarChangedError)
  })

  it('writes nothing while the app is blocked: calendars or events', async () => {
    head.blocked = true
    await expect(createCalendar(session, account, 'Ev', '#8080ff')).rejects.toBeInstanceOf(HeadBlockedError)
    const calendar = { id: uuid(1), revision: 1, settingsId: settingsOf(1) } as Calendar
    await expect(saveEvent(session, account, calendar, fields({ date: '2026-10-29' }, null))).rejects.toBeInstanceOf(HeadBlockedError)
    await expect(deleteEvent(session, account, calendar, { id: 'e1', revision: 1 })).rejects.toBeInstanceOf(HeadBlockedError)
    expect(http.post).not.toHaveBeenCalled()
  })
})

function fields(start: EventFields['start'], end: EventFields['end']): EventFields {
  return {
    uid: 'u@kutup.test',
    dtstamp: '2026-10-21T08:00:00Z',
    created: null,
    start,
    end,
    recurrenceId: null,
    rrule: null,
    organizer: null,
    summary: 'Lunch',
    description: null,
    location: null,
    status: null,
    transp: null,
    comment: null,
  }
}

/** A calendar whose key opens every event as `opened`, signed. */
function calendarOpening(opened: EventFields): Calendar {
  return { id: 'c1', revision: 1, unlocked: { openEvent: () => ({ fields: opened, verified: true }) } } as unknown as Calendar
}

function eventRow(startUtc: string, endUtc: string, fullDay: boolean): EventRow {
  return { id: 'e1', calendarId: 'c1', uid: 'u@kutup.test', authorAddress: 'ada@kutup.test', event: {} as EventRow['event'], startUtc, endUtc, fullDay, rangeEndUtc: endUtc, sequence: 0, revision: 1, modifiedAt: '', reminders: null }
}

describe('opening events', () => {
  it('draws the times from the signed fields, and the server agreeing verifies them', async () => {
    const signed = fields({ utc: '2026-10-29T09:00:00Z' }, { utc: '2026-10-29T10:00:00Z' })
    const event = await openEvent(account, calendarOpening(signed), eventRow('2026-10-29T09:00:00Z', '2026-10-29T10:00:00Z', false))
    expect(event).toMatchObject({ startUtc: '2026-10-29T09:00:00Z', endUtc: '2026-10-29T10:00:00Z', fullDay: false, verified: true })
  })

  it('never takes a length or all-day from the server: a differing one is unverified', async () => {
    const signed = fields({ utc: '2026-10-29T09:00:00Z' }, { utc: '2026-10-29T10:00:00Z' })
    const longer = await openEvent(account, calendarOpening(signed), eventRow('2026-10-29T09:00:00Z', '2026-10-29T18:00:00Z', false))
    expect(longer).toMatchObject({ endUtc: '2026-10-29T10:00:00Z', verified: false })
    const allDay = await openEvent(account, calendarOpening(signed), eventRow('2026-10-29T09:00:00Z', '2026-10-29T10:00:00Z', true))
    expect(allDay).toMatchObject({ fullDay: false, verified: false })
  })

  it('reads a missing end as RFC 5545 does: a date lasts a day, a time has no length', async () => {
    const day = await openEvent(account, calendarOpening(fields({ date: '2026-10-31' }, null)), eventRow('2026-10-31T00:00:00Z', '2026-11-01T00:00:00Z', true))
    expect(day).toMatchObject({ endUtc: '2026-11-01T00:00:00Z', fullDay: true, verified: true })
    const moment = await openEvent(account, calendarOpening(fields({ utc: '2026-10-29T09:00:00Z' }, null)), eventRow('2026-10-29T09:00:00Z', '2026-10-29T09:00:00Z', false))
    expect(moment).toMatchObject({ endUtc: '2026-10-29T09:00:00Z', verified: true })
  })
})

describe('reading events', () => {
  it('refuses a server that hands the same page again', async () => {
    const calendar = calendarOpening(fields({ date: '2026-10-29' }, null))
    await expect(loadEvents(account, calendar, '2026-10-26T00:00:00Z', '2026-11-02T00:00:00Z')).rejects.toThrow('repeats a page')
    expect(http.get).toHaveBeenCalledTimes(2)
  })
})
