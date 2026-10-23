// @vitest-environment node
import { readFileSync } from 'node:fs'
import { webcrypto } from 'node:crypto'
import { runInNewContext } from 'node:vm'
import { describe, expect, it, vi } from 'vitest'

// The calendar's service worker (public/push-sw.js), run against a fake
// worker global: what a reminder push shows, and what a click opens.

const SOURCE = readFileSync(new URL('../../../public/push-sw.js', import.meta.url), 'utf8')
const ACCOUNT = '3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70'
/** The server's `account` for this subscription secret ([1; 16]) and account (its Rust test pins it too). */
const ACCOUNT_TAG = 'bOzkrVOAPAcr6dlqCNiyod'

const E1 = '11111111-2222-4333-8444-555555555555'
const E2 = '66666666-7777-4888-9999-aaaaaaaaaaaa'

type Handler = (event: { waitUntil: (p: Promise<unknown>) => void; data?: { json: () => unknown }; notification?: unknown }) => void

type Shown = { tag: string; title?: string; body?: string; icon?: string; data?: unknown }

function worker(shown: Shown[] = [], windows: unknown[] = []) {
  const handlers: Record<string, Handler> = {}
  const showNotification = vi.fn((title: string, options: { body: string; tag: string; data: { url: string }; silent?: boolean }) => {
    shown.push({ tag: options.tag, title, body: options.body })
    return Promise.resolve({ title, options })
  })
  const openWindow = vi.fn(() => Promise.resolve(null))
  const query = new URLSearchParams({
    title: 'Kutup Calendar',
    at: 'Event at {{time}}',
    today: 'Event today',
    on: 'Event on {{date}}',
    onAt: 'Event on {{date}} at {{time}}',
    zone: 'Europe/Istanbul',
    lang: 'en-GB',
    hour12: 'false',
    account: ACCOUNT,
  })
  const self = {
    location: { href: `https://calendar.kutup.test/push-sw.js?${query}` },
    addEventListener: (name: string, handler: Handler) => {
      handlers[name] = handler
    },
    skipWaiting: () => undefined,
    clients: { claim: () => Promise.resolve(), matchAll: () => Promise.resolve(windows), openWindow },
    registration: {
      getNotifications: ({ tag }: { tag: string }) => Promise.resolve(shown.filter((n) => n.tag === tag)),
      showNotification,
      pushManager: { getSubscription: () => Promise.resolve({ getKey: () => new Uint8Array(16).fill(1).buffer }) },
    },
  }
  // The worker's own globals: `self`, Web Crypto, and what JavaScript has.
  runInNewContext(SOURCE, { self, crypto: webcrypto, URL, URLSearchParams, TextEncoder, btoa, Intl })
  const fire = async (name: string, event: Partial<Parameters<Handler>[0]>) => {
    let done: Promise<unknown> = Promise.resolve()
    handlers[name]({
      waitUntil: (p) => {
        done = p
      },
      ...event,
    })
    await done
  }
  return { fire, showNotification, openWindow }
}

const push = (payload: unknown) => ({ data: { json: () => payload } })
const FIRE = '2029-12-31T09:00:00Z'

describe('the calendar’s service worker', () => {
  it('shows when, never what, tagged per alarm as the open app tags it, opening the event', async () => {
    const { fire, showNotification } = worker()
    const start = new Date(Date.now() + 3 * 3600_000)
    start.setUTCSeconds(0, 0)
    await fire('push', push({ eventId: E1, startUtc: start.toISOString(), fireAt: FIRE, allDay: false, account: ACCOUNT_TAG }))
    const [title, options] = showNotification.mock.calls[0]
    expect(title).toBe('Kutup Calendar')
    expect(options.body).toMatch(/^Event (at|on) /)
    expect(options.tag).toBe(`kutup-calendar:${E1}:${start.getTime()}:${Date.parse(FIRE)}`)
    expect(options.silent).toBe(false)
    expect(options.data.url).toBe(`/?event=${E1}`)
  })

  it('with Calendar open: shows the app’s one again silently, or one of its own silently', async () => {
    const start = '2030-01-01T09:00:00Z'
    const tag = `kutup-calendar:${E1}:${Date.parse(start)}:${Date.parse(FIRE)}`
    const again = worker([{ tag, title: 'Calendar reminder', body: 'Toplantı starts at 9:30' }], [{}])
    await again.fire('push', push({ eventId: E1, startUtc: start, fireAt: FIRE, allDay: false, account: ACCOUNT_TAG }))
    expect(again.showNotification.mock.calls[0][0]).toBe('Calendar reminder')
    expect(again.showNotification.mock.calls[0][1]).toMatchObject({ body: 'Toplantı starts at 9:30', tag, silent: true })

    const first = worker([], [{}])
    await first.fire('push', push({ eventId: E1, startUtc: start, fireAt: FIRE, allDay: false, account: ACCOUNT_TAG }))
    expect(first.showNotification.mock.calls[0][1].silent).toBe(true)
  })

  it('opens the start page for another account’s reminder', async () => {
    const other = worker()
    await other.fire('push', push({ eventId: E2, startUtc: '2030-01-01T00:00:00Z', fireAt: FIRE, allDay: true, account: 'someoneElsesTag0000000' }))
    expect(other.showNotification.mock.calls[0][1].data.url).toBe('/')
    expect(other.showNotification.mock.calls[0][1].body).toBe('Event on Tuesday 1 January')
  })

  it('ignores a push that isn’t a reminder: no event id, no real times, not JSON', async () => {
    const { fire, showNotification } = worker()
    await fire('push', push({ nonsense: true }))
    await fire('push', push({ eventId: '../../x', startUtc: '2030-01-01T09:00:00Z', fireAt: FIRE }))
    await fire('push', push({ eventId: E1, startUtc: 'soon', fireAt: FIRE }))
    await fire('push', { data: { json: () => { throw new Error('not JSON') } } })
    expect(showNotification).not.toHaveBeenCalled()
  })

  it('opens the event a click names, and nothing but Calendar’s own pages', async () => {
    const { fire, openWindow } = worker()
    await fire('notificationclick', { notification: { close: () => undefined, data: { url: `/?event=${E1}` } } })
    expect(openWindow).toHaveBeenLastCalledWith(`/?event=${E1}`)
    await fire('notificationclick', { notification: { close: () => undefined, data: { url: '/api/user/me' } } })
    expect(openWindow).toHaveBeenLastCalledWith('/')
  })
})
