import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { MailAccount } from '@kutup/mail-core/api'
import type { Session } from '@kutup/session/store'

// The calendars under the account head (docs/plans/rollback-protection.md).
// The crypto is Rust's (vectors there); here a calendar's key is a stand-in
// whose metadata opens only under the id it names.

vi.mock('@kutup/crypto/calendar', () => ({
  unlockCalendar: (_key: unknown, passphrase: { keyPacket: string }) =>
    Promise.resolve({
      fingerprint: passphrase.keyPacket,
      openMetadata: (metadata: { dataPacket: string; signature: string }, calendarId: string) => {
        if (metadata.dataPacket !== calendarId) throw new Error('another calendar')
        return { name: `name of ${calendarId}`, description: '', verified: metadata.signature === 'owner' }
      },
      free: () => undefined,
    }),
  createCalendar: () =>
    Promise.resolve({ publicKey: 'P', lockedSecretKey: 'L', fingerprint: 'f', passphrase: { dataPacket: 'd', signature: 's', keyPacket: 'f' }, metadata: { keyPacket: 'k', dataPacket: 'd', signature: 's' } }),
  localToUtc: () => Promise.resolve(''),
  sealCalendarEvent: () => ({}),
  sealCalendarMetadata: () => ({}),
}))
vi.mock('@kutup/mail-core/api', () => ({ useMailAccount: vi.fn() }))

const http = vi.hoisted(() => ({
  rows: [] as unknown[],
  get: vi.fn(),
  post: vi.fn(),
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
    delete: (url: string, body: unknown) => http.delete(url, body) as Promise<unknown>,
  },
}))

// The head, its rules kept small (its own tests: @kutup/session). A blocked
// head refuses listed writes, as `listedWrite` does.
const head = vi.hoisted(() => ({ index: (): [string, number][] => [], covered: false, blocked: false }))
vi.mock('@kutup/session/accountHead', async () => {
  const actual = await vi.importActual<typeof import('@kutup/session/accountHead')>('@kutup/session/accountHead')
  const index = () => new actual.VerifiedIndex('calendars', head.covered, head.index(), null)
  const client = {
    verifiedHead: () => (head.blocked ? Promise.reject(new actual.HeadBlockedError('fork')) : Promise.resolve()),
    verifiedIndex: () => (head.blocked ? Promise.reject(new actual.HeadBlockedError('fork')) : Promise.resolve(index())),
    listedWrite: async <T,>(_s: string, edit: (i: InstanceType<typeof actual.VerifiedIndex>) => Promise<{ send: (h: string) => Promise<T> } | null>) => {
      if (head.blocked) throw new actual.HeadBlockedError('fork')
      const change = await edit(index())
      return change ? change.send('head-1') : undefined
    },
  }
  return { ...actual, accountHead: () => Promise.resolve(client) }
})

import { OlderThanSeenError, resetRevisionGuardsForTesting } from '@kutup/crypto/revisionGuard'
import type { EventFields } from '@kutup/crypto/calendar'
import { HeadBlockedError, NotInVerifiedIndexError } from '@kutup/session/accountHead'
import { createCalendar, deleteCalendar, deleteEvent, loadCalendars, loadEvents, openEvent, saveEvent, type Calendar, type EventRow } from './api'

const session = { userId: 'u1', sessionId: 's1', masterKey: new Uint8Array(32) } as unknown as Session
const account = {
  key: { masterKeyBase64: 'm', binding: 'b', address: 'ada@kutup.test', envelope: 'e', fingerprint: 'k' },
  olderKeys: [],
  ownPublicKeys: ['A'],
  publicKey: 'A',
  isOwnAddress: () => true,
} as unknown as MailAccount

let fingerprints = 0
/** A calendar as the server lists it; its metadata names `metadataId`, signed by `signer`. */
function row(id: string, revision: number, { metadataId = id, signer = 'owner', listed = 'own' } = {}) {
  const fingerprint = `fp${++fingerprints}`
  return {
    id,
    ownerAddress: 'ada@kutup.test',
    publicKey: 'P',
    fingerprint: listed === 'own' ? fingerprint : listed,
    lockedSecretKey: 'L',
    passphrase: { dataPacket: 'd', signature: 's', keyPacket: fingerprint },
    addressId: 'a1',
    metadata: { keyPacket: 'k', dataPacket: metadataId, signature: signer },
    permissions: 127,
    color: '#8080ff',
    display: true,
    revision,
    createdAt: '',
    updatedAt: '',
  }
}

beforeEach(() => {
  resetRevisionGuardsForTesting()
  http.rows = []
  for (const fn of [http.get, http.post, http.delete]) fn.mockReset()
  Object.assign(head, { index: () => [], covered: false, blocked: false })
})

describe('reading the calendars', () => {
  it('opens the calendars the head vouches for', async () => {
    http.rows = [row('c1', 1), row('c2', 3)]
    head.covered = true
    head.index = () => [['c1', 1], ['c2', 3]]
    const { calendars, unreadable } = await loadCalendars(session, account)
    expect(calendars.map((c) => c.name)).toEqual(['name of c1', 'name of c2'])
    expect(unreadable).toBe(0)
  })

  it('refuses a list with a calendar dropped, after reading again once', async () => {
    http.rows = [row('c1', 1)]
    head.covered = true
    head.index = () => [['c1', 1], ['c2', 3]]
    await expect(loadCalendars(session, account)).rejects.toBeInstanceOf(NotInVerifiedIndexError)
    expect(http.get).toHaveBeenCalledTimes(2)
  })

  it('never shows a name its owner did not sign, nor one moved from another calendar', async () => {
    http.rows = [row('c1', 1, { signer: 'someone' }), row('c2', 1, { metadataId: 'c1' }), row('c3', 1)]
    const { calendars, unreadable } = await loadCalendars(session, account)
    expect(calendars.map((c) => c.id)).toEqual(['c3'])
    expect(unreadable).toBe(2)
  })

  it('refuses a key that is not the one listed', async () => {
    http.rows = [row('c1', 1, { listed: 'another' })]
    const { calendars, unreadable } = await loadCalendars(session, account)
    expect(calendars).toHaveLength(0)
    expect(unreadable).toBe(1)
  })

  it('reads on while the app is blocked, as every listed scope does (the banner says why)', async () => {
    http.rows = [row('c1', 1)]
    head.blocked = true
    expect((await loadCalendars(session, account)).calendars).toHaveLength(1)
  })

  it('refuses a calendar rolled back below what this browser saw, blocked or not', async () => {
    http.rows = [row('c1', 3)]
    await loadCalendars(session, account)
    head.blocked = true
    http.rows = [row('c1', 2)]
    await expect(loadCalendars(session, account)).rejects.toBeInstanceOf(OlderThanSeenError)
    expect(http.get).toHaveBeenCalledTimes(3)
  })

  it('refuses a calendar brought back after this browser deleted it', async () => {
    http.rows = [row('c1', 1)]
    const { calendars } = await loadCalendars(session, account)
    http.delete.mockResolvedValue({ data: {} })
    head.covered = true
    head.index = () => [['c1', 1]]
    await deleteCalendar(session, calendars[0])
    head.blocked = true
    await expect(loadCalendars(session, account)).rejects.toBeInstanceOf(OlderThanSeenError)
  })
})

describe('writing calendars', () => {
  it('creates a calendar under the id the head names', async () => {
    http.post.mockResolvedValue({ data: {} })
    const id = await createCalendar(session, account, 'Ev', '#8080ff')
    expect(http.post).toHaveBeenCalledWith('/calendar/calendars', expect.objectContaining({ id, head: 'head-1', addressId: 'a1' }))
  })

  it('writes nothing while the app is blocked: calendars or events', async () => {
    head.blocked = true
    await expect(createCalendar(session, account, 'Ev', '#8080ff')).rejects.toBeInstanceOf(HeadBlockedError)
    const calendar = { id: 'c1', revision: 1 } as Calendar
    await expect(deleteCalendar(session, calendar)).rejects.toBeInstanceOf(HeadBlockedError)
    await expect(saveEvent(session, account, calendar, fields({ date: '2026-10-29' }, null))).rejects.toBeInstanceOf(HeadBlockedError)
    await expect(deleteEvent(session, account, calendar, { id: 'e1', revision: 1 })).rejects.toBeInstanceOf(HeadBlockedError)
    expect(http.post).not.toHaveBeenCalled()
    expect(http.delete).not.toHaveBeenCalled()
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
  return { id: 'e1', calendarId: 'c1', uid: 'u@kutup.test', authorAddress: 'ada@kutup.test', event: {} as EventRow['event'], startUtc, endUtc, fullDay, rangeEndUtc: endUtc, sequence: 0, revision: 1, modifiedAt: '' }
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
