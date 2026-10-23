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

type Handler = (event: { waitUntil: (p: Promise<unknown>) => void; data?: { json: () => unknown }; notification?: unknown }) => void

function worker(shown: { tag: string }[] = []) {
  const handlers: Record<string, Handler> = {}
  const showNotification = vi.fn((title: string, options: { body: string; tag: string; data: { url: string } }) => {
    shown.push({ tag: options.tag })
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
    clients: { claim: () => Promise.resolve(), matchAll: () => Promise.resolve([] as unknown[]), openWindow },
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

describe('the calendar’s service worker', () => {
  it('shows when, never what, tagged as the open app tags it, opening the event', async () => {
    const { fire, showNotification } = worker()
    const start = new Date(Date.now() + 3 * 3600_000)
    start.setUTCSeconds(0, 0)
    await fire('push', push({ eventId: 'e1', startUtc: start.toISOString(), allDay: false, account: ACCOUNT_TAG }))
    const [title, options] = showNotification.mock.calls[0]
    expect(title).toBe('Kutup Calendar')
    expect(options.body).toMatch(/^Event (at|on) /)
    expect(options.tag).toBe(`kutup-calendar:e1:${start.getTime()}`)
    expect(options.data.url).toBe('/?event=e1')
  })

  it('stays quiet for one the open app showed, and opens the start page for another account’s', async () => {
    const start = '2030-01-01T09:00:00Z'
    const shown = [{ tag: `kutup-calendar:e1:${Date.parse(start)}` }]
    const quiet = worker(shown)
    await quiet.fire('push', push({ eventId: 'e1', startUtc: start, allDay: false, account: ACCOUNT_TAG }))
    expect(quiet.showNotification).not.toHaveBeenCalled()

    const other = worker()
    await other.fire('push', push({ eventId: 'e2', startUtc: start, allDay: true, account: 'someoneElsesTag0000000' }))
    expect(other.showNotification.mock.calls[0][1].data.url).toBe('/')
    expect(other.showNotification.mock.calls[0][1].body).toBe('Event on Tuesday 1 January')
  })

  it('ignores a push that isn’t a reminder', async () => {
    const { fire, showNotification } = worker()
    await fire('push', push({ nonsense: true }))
    await fire('push', { data: { json: () => { throw new Error('not JSON') } } })
    expect(showNotification).not.toHaveBeenCalled()
  })

  it('opens the event a click names', async () => {
    const { fire, openWindow } = worker()
    await fire('notificationclick', { notification: { close: () => undefined, data: { url: '/?event=e1' } } })
    expect(openWindow).toHaveBeenCalledWith('/?event=e1')
  })
})
