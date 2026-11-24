import { beforeEach, describe, expect, it, vi } from 'vitest'

// The public link's routes, answered by a stand-in `fetch`; the keys stand
// in too (Rust's vectors cover the link envelope).

const crypto = vi.hoisted(() => ({ opened: [] as unknown[], freed: 0 }))
vi.mock('@kutup/crypto/calendar', () => ({
  openCalendarLink: (secret: string, calendarId: string, linkId: string, lock: { keyGeneration: number; sealedPassphrase: string }) => {
    if (secret !== 'SECRET') return Promise.reject(new Error('not this link’s key'))
    crypto.opened.push({ calendarId, linkId, ...lock })
    return Promise.resolve({
      keyId: `kid-${lock.keyGeneration}`,
      fingerprint: `fp${lock.keyGeneration}`,
      openMetadata: (_m: unknown, id: string, signers: string[]) => ({ name: `name of ${id}`, description: '', verified: signers.length > 0 }),
      openEvent: (event: { summary: string }) => ({ fields: { summary: event.summary, start: { utc: '2026-11-20T09:00:00Z' }, end: { utc: '2026-11-20T10:00:00Z' } }, verified: true }),
      free: () => {
        crypto.freed++
      },
    })
  },
  calendarEventKeyId: (event: { kid: string }) => Promise.resolve(event.kid),
  calendarLinkAccessProof: (secret: string, linkId: string) => Promise.resolve(`proof(${secret},${linkId})`),
}))
vi.mock('@kutup/calendar-core/api', () => ({
  timesOf: () => Promise.resolve({ startUtc: '2026-11-20T09:00:00Z', endUtc: '2026-11-20T10:00:00Z', fullDay: false }),
  plainEventParts: (id: string) => ({ sharedEventId: id, home: true, organizer: null, attendees: null, attendeesVerified: false, tokens: [], attendeeRows: [], sequence: 0 }),
}))
vi.mock('@kutup/session/apiBase', () => ({ resolveApiBase: () => Promise.resolve('/api/v1') }))

const http = vi.hoisted(() => ({ routes: new Map<string, { status: number; body: unknown }[]>(), calls: [] as { url: string; init: RequestInit }[] }))
vi.stubGlobal(
  'fetch',
  vi.fn((url: string, init: RequestInit) => {
    http.calls.push({ url, init })
    const path = url.split('?')[0]
    const queue = http.routes.get(path) ?? []
    const answer = queue.length > 1 ? queue.shift()! : (queue[0] ?? { status: 404, body: {} })
    return Promise.resolve({ ok: answer.status < 300, status: answer.status, json: () => Promise.resolve(answer.body) })
  }),
)

const { LinkKeyMissing, LinkNotFound, closePublicCalendar, loadBusyBlocks, loadPublicEvents, loadPublicLink, openPublicCalendar } = await import('./publicClient')

const key = (g: number, fingerprint = `fp${g}`) => ({ keyGeneration: g, fingerprint, lockedSecretKey: 'L', passphrase: `pp${g}` })
const fullLink = { calendarId: 'cal', kind: 'full' as const, metadata: { keyPacket: 'k', dataPacket: 'd', signature: 's' }, keys: [key(2), key(1)] }

beforeEach(() => {
  http.routes = new Map()
  http.calls = []
  crypto.opened = []
  crypto.freed = 0
})

describe('a full link', () => {
  it('asks the server with no credentials and the link’s access proof, and opens every generation from the URL’s secret', async () => {
    http.routes.set('/api/v1/calendar/links/l1', [{ status: 200, body: fullLink }])
    const link = await loadPublicLink('l1', 'SECRET')
    expect(http.calls[0].init.credentials).toBe('omit')
    expect((http.calls[0].init.headers as Record<string, string>)['X-Kutup-Link-Proof']).toBe('proof(SECRET,l1)')
    const calendar = await openPublicCalendar('l1', link, 'SECRET')
    expect(crypto.opened).toEqual([
      { calendarId: 'cal', linkId: 'l1', keyGeneration: 1, sealedPassphrase: 'pp1', lockedSecretKey: 'L' },
      { calendarId: 'cal', linkId: 'l1', keyGeneration: 2, sealedPassphrase: 'pp2', lockedSecretKey: 'L' },
    ])
    expect(calendar.name).toBe('name of cal')
    closePublicCalendar(calendar)
    expect(crypto.freed).toBe(2)
  })

  it('refuses without the key, with another key, and a key that is not the one listed (freeing what it opened)', async () => {
    await expect(openPublicCalendar('l1', fullLink, '')).rejects.toBeInstanceOf(LinkKeyMissing)
    // Asked without its proof, the server tells only the kind: the key is missing.
    await expect(openPublicCalendar('l1', { kind: 'full' }, 'SECRET')).rejects.toBeInstanceOf(LinkKeyMissing)
    http.routes.set('/api/v1/calendar/links/l1', [{ status: 200, body: { kind: 'full' } }])
    await loadPublicLink('l1')
    expect((http.calls.at(-1)!.init.headers as Record<string, string>)['X-Kutup-Link-Proof']).toBeUndefined()
    await expect(openPublicCalendar('l1', fullLink, 'OTHER')).rejects.toThrow()
    await expect(openPublicCalendar('l1', { ...fullLink, keys: [key(1), key(2, 'another')] }, 'SECRET')).rejects.toThrow('not the one listed')
    expect(crypto.freed).toBe(2)
  })

  it('says a deleted link is gone', async () => {
    http.routes.set('/api/v1/calendar/links/gone', [{ status: 410, body: {} }])
    await expect(loadPublicLink('gone')).rejects.toBeInstanceOf(LinkNotFound)
  })

  it('opens each event with its own generation, never as verified, and counts what it can’t open', async () => {
    const calendar = await openPublicCalendar('l1', fullLink, 'SECRET')
    http.routes.set('/api/v1/calendar/links/l1/events', [
      { status: 200, body: { events: [{ id: 'e1', event: { kid: 'kid-1', summary: 'Old' } }, { id: 'e2', event: { kid: 'kid-9', summary: 'X' } }], next: { afterStart: 'a', afterId: 'e2' } } },
      { status: 200, body: { events: [{ id: 'e3', event: { kid: 'kid-2', summary: 'New' } }], next: null } },
    ])
    const { events, unreadable } = await loadPublicEvents('l1', calendar, '2026-11-16T00:00:00Z', '2026-11-23T00:00:00Z', 'P')
    expect((http.calls.at(-1)!.init.headers as Record<string, string>)['X-Kutup-Link-Proof']).toBe('P')
    expect(events.map((e) => [e.id, e.fields.summary, e.verified])).toEqual([
      ['e1', 'Old', false],
      ['e3', 'New', false],
    ])
    expect(unreadable).toBe(1)
    expect(http.calls.at(-1)!.url).toContain('afterId=e2')
  })

  it('refuses a server that hands the same page again', async () => {
    const calendar = await openPublicCalendar('l1', fullLink, 'SECRET')
    http.routes.set('/api/v1/calendar/links/l1/events', [{ status: 200, body: { events: [], next: { afterStart: 'a', afterId: 'x' } } }])
    await expect(loadPublicEvents('l1', calendar, '2026-11-16T00:00:00Z', '2026-11-23T00:00:00Z', 'P')).rejects.toThrow('repeats a page')
  })
})

describe('a busy link', () => {
  it('answers times only', async () => {
    http.routes.set('/api/v1/calendar/links/b1/busy', [{ status: 200, body: { busy: [{ startUtc: 's', endUtc: 'e', fullDay: false }] } }])
    expect(await loadBusyBlocks('b1', '2026-11-16T00:00:00Z', '2026-11-23T00:00:00Z')).toEqual([{ startUtc: 's', endUtc: 'e', fullDay: false }])
    expect(http.calls[0].url).toBe('/api/v1/calendar/links/b1/busy?start=2026-11-16T00%3A00%3A00Z&end=2026-11-23T00%3A00%3A00Z')
  })
})
