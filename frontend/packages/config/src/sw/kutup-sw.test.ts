// @vitest-environment node
import { readFileSync } from 'node:fs'
import { runInNewContext } from 'node:vm'
import { describe, expect, it, vi } from 'vitest'
import { STREAM_ANSWER_HARD_MAX_BYTES, STREAM_PROTOCOL_VERSION } from '../../../files/src/blockReader/protocol'

// Kutup's service worker (kutup-sw.js) run against a fake worker global:
// its stateless stream route (docs/plans/drive-block-format.md §4) and that
// everything else goes to the network untouched. Calendar's push is tested
// beside Calendar (apps/calendar/src/features/reminders/push-sw.test.ts).

const SOURCE = readFileSync(new URL('./kutup-sw.js', import.meta.url), 'utf8')
const ORIGIN = 'https://drive.kutup.test'
const STREAM = 'AAAAAAAAAAAAAAAAAAAAAA'

type Handler = (event: unknown) => void

interface Asked {
  type: string
  v: number
  accepts: number[]
  streamId: string
  range: unknown
}

/** The worker, its internals, and a page that answers each request with `reply`. */
function worker(reply: ((asked: Asked) => unknown) | null = null, query = '') {
  const handlers: Record<string, Handler> = {}
  const asked: Asked[] = []
  const client = {
    postMessage: (message: Asked, [port]: MessagePort[]) => {
      asked.push(message)
      const answer = reply?.(message)
      if (answer !== undefined) {
        const transfer = answer && typeof answer === 'object' && 'bytes' in answer ? [(answer as { bytes: ArrayBuffer }).bytes] : []
        port.postMessage(answer, transfer as Transferable[])
      }
    },
  }
  const self = {
    location: { href: `${ORIGIN}/kutup-sw.js${query}`, origin: ORIGIN },
    addEventListener: (name: string, handler: Handler) => {
      handlers[name] = handler
    },
    skipWaiting: vi.fn(),
    clients: { claim: vi.fn(() => Promise.resolve()), get: vi.fn((id: string) => Promise.resolve(id === 'page' ? client : undefined)) },
  }
  const internals = runInNewContext(`${SOURCE}\n;({ parseRange, streamHeaders, mediaType, STREAM_PROTOCOL, STREAM_ACCEPTS, ANSWER_MAX_BYTES })`, {
    self,
    URL,
    URLSearchParams,
    Response,
    MessageChannel,
    setTimeout,
    clearTimeout,
  }) as {
    parseRange: (header: string) => unknown
    streamHeaders: (extra?: Record<string, string>) => Record<string, string>
    mediaType: (type: unknown) => string
    STREAM_PROTOCOL: number
    STREAM_ACCEPTS: number[]
    ANSWER_MAX_BYTES: number
  }
  /** Fires a fetch: the response it answers with, or null when it leaves it to the network. */
  const fetch = (
    path: string,
    { range, destination = 'video', clientId = 'page', method = 'GET' }: { range?: string; destination?: string; clientId?: string; method?: string } = {},
  ): Promise<Response | null> => {
    let answered: Promise<Response | null> = Promise.resolve(null)
    handlers.fetch({
      request: { url: `${ORIGIN}${path}`, method, destination, headers: new Headers(range ? { Range: range } : {}) },
      clientId,
      respondWith: (response: Promise<Response> | Response) => {
        answered = Promise.resolve(response)
      },
    })
    return answered
  }
  return { internals, fetch, asked, self, handlers }
}

function bytes(length: number, from = 0): ArrayBuffer {
  return Uint8Array.from({ length }, (_, i) => (from + i) & 0xff).buffer
}

const SECURITY = {
  'content-security-policy': "default-src 'none'; sandbox",
  'x-content-type-options': 'nosniff',
  'cross-origin-resource-policy': 'same-origin',
  'accept-ranges': 'bytes',
}

function expectSecurityHeaders(response: Response) {
  for (const [name, value] of Object.entries(SECURITY)) expect(response.headers.get(name), name).toBe(value)
}

describe('the service worker', () => {
  it('speaks the page’s stream protocol and caps answers at the largest response setting', () => {
    const { internals } = worker()
    expect(internals.STREAM_PROTOCOL).toBe(STREAM_PROTOCOL_VERSION)
    expect(internals.STREAM_ACCEPTS).toContain(STREAM_PROTOCOL_VERSION)
    expect(internals.ANSWER_MAX_BYTES).toBe(STREAM_ANSWER_HARD_MAX_BYTES)
  })

  it('takes over at once and claims the open pages', () => {
    const { handlers, self } = worker()
    handlers.install({})
    expect(self.skipWaiting).toHaveBeenCalled()
    const waited: Promise<unknown>[] = []
    handlers.activate({ waitUntil: (p: Promise<unknown>) => waited.push(p) })
    expect(self.clients.claim).toHaveBeenCalled()
    expect(waited).toHaveLength(1)
  })

  it('parses one byte range: a-b, a-, -k; anything else is refused', () => {
    const { parseRange } = worker().internals
    expect(parseRange('bytes=0-1')).toEqual({ start: 0, end: 1 })
    expect(parseRange('bytes=100-')).toEqual({ start: 100, end: null })
    expect(parseRange('bytes=-500')).toEqual({ suffix: 500 })
    expect(parseRange(' bytes = 5 - 6 ')).toEqual({ start: 5, end: 6 })
    for (const bad of ['bytes=0-1,4-5', 'items=0-1', 'bytes=5-4', 'bytes=-', 'bytes=-0', 'bytes=a-b', 'bytes=0-99999999999999999999', 'bytes', '']) {
      expect(parseRange(bad), bad).toBeNull()
    }
  })

  it('serves audio and video as themselves and anything else as bytes', () => {
    const { mediaType } = worker().internals
    expect(mediaType('video/mp4')).toBe('video/mp4')
    expect(mediaType('Audio/MPEG; charset=x')).toBe('audio/mpeg')
    for (const other of ['text/html', 'image/svg+xml', 'application/javascript', 'video/../text/html', '', undefined]) {
      expect(mediaType(other), String(other)).toBe('application/octet-stream')
    }
  })

  it('puts the security headers on every response', () => {
    const headers = worker().internals.streamHeaders({ 'Content-Length': '3' })
    expect(headers['Content-Security-Policy']).toBe("default-src 'none'; sandbox")
    expect(headers['X-Content-Type-Options']).toBe('nosniff')
    expect(headers['Cross-Origin-Resource-Policy']).toBe('same-origin')
    expect(headers['Content-Length']).toBe('3')
  })

  it('leaves every request outside /sw/ to the network', async () => {
    const { fetch } = worker()
    expect(await fetch('/')).toBeNull()
    expect(await fetch('/api/files/x/download', { range: 'bytes=0-1' })).toBeNull()
    expect(await fetch('/assets/index.js')).toBeNull()
    expect(await fetch('/kutup-sw.js')).toBeNull()
    expect((await fetch('/sw/other'))?.status).toBe(404)
  })

  it('answers 206 with exactly the bytes the page gave, capped by the page at its block', async () => {
    const page = worker(() => ({ v: 1, kind: 'bytes', start: 0, total: 10_000_000, mimeType: 'video/mp4', bytes: bytes(2) }))
    const response = (await page.fetch(`/sw/stream/${STREAM}`, { range: 'bytes=0-1' }))!
    expect(page.asked[0]).toEqual({ type: 'get_stream_chunk', v: 1, accepts: [1], streamId: STREAM, range: { start: 0, end: 1 } })
    expect(response.status).toBe(206)
    expectSecurityHeaders(response)
    expect(response.headers.get('content-range')).toBe('bytes 0-1/10000000')
    expect(response.headers.get('content-length')).toBe('2')
    expect(response.headers.get('content-type')).toBe('video/mp4')
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(new Uint8Array([0, 1]))
  })

  it('serves a suffix range from the end the page knows', async () => {
    const page = worker(() => ({ v: 1, kind: 'bytes', start: 990, total: 1000, mimeType: 'text/html', bytes: bytes(10) }))
    const response = (await page.fetch(`/sw/stream/${STREAM}`, { range: 'bytes=-10' }))!
    expect(page.asked[0].range).toEqual({ suffix: 10 })
    expect(response.status).toBe(206)
    expect(response.headers.get('content-range')).toBe('bytes 990-999/1000')
    // Not a media type: served as bytes, never as a page.
    expect(response.headers.get('content-type')).toBe('application/octet-stream')
  })

  it('answers 416 with the total when the range has no bytes', async () => {
    const past = worker(() => ({ v: 1, kind: 'unsatisfiable', total: 1000 }))
    const response = (await past.fetch(`/sw/stream/${STREAM}`, { range: 'bytes=5000-' }))!
    expect(response.status).toBe(416)
    expectSecurityHeaders(response)
    expect(response.headers.get('content-range')).toBe('bytes */1000')
    const empty = worker(() => ({ v: 1, kind: 'bytes', start: 0, total: 0, mimeType: 'video/mp4', bytes: bytes(0) }))
    expect((await empty.fetch(`/sw/stream/${STREAM}`, { range: 'bytes=0-' }))!.headers.get('content-range')).toBe('bytes */0')
  })

  it('refuses what isn’t a player asking a page for one of its streams', async () => {
    const page = worker(() => ({ v: 1, kind: 'bytes', start: 0, total: 10, mimeType: 'video/mp4', bytes: bytes(10) }))
    const status = async (path: string, init: Parameters<typeof page.fetch>[1]) => (await page.fetch(path, init))!.status
    expect(await status(`/sw/stream/${STREAM}`, { range: 'bytes=0-', destination: 'document' })).toBe(403)
    expect(await status(`/sw/stream/${STREAM}`, { range: 'bytes=0-', destination: '' })).toBe(403)
    expect(await status(`/sw/stream/${STREAM}`, { destination: 'video' })).toBe(400)
    expect(await status(`/sw/stream/${STREAM}`, { range: 'bytes=0-1,5-6' })).toBe(416)
    expect(await status('/sw/stream/short', { range: 'bytes=0-' })).toBe(404)
    // A navigation, or a page that went: no client, nothing served.
    expect(await status(`/sw/stream/${STREAM}`, { range: 'bytes=0-', clientId: '' })).toBe(404)
    expect(await status(`/sw/stream/${STREAM}`, { range: 'bytes=0-', clientId: 'gone' })).toBe(404)
    expect(page.asked).toHaveLength(0)
    const response = (await page.fetch(`/sw/stream/${STREAM}`, { range: 'bytes=0-', destination: 'document' }))!
    expectSecurityHeaders(response)
    expect(response.headers.get('content-length')).toBe('0')
  })

  it('refuses an answer that isn’t the range asked', async () => {
    const answer = (reply: unknown, range: string) => worker(() => reply).fetch(`/sw/stream/${STREAM}`, { range })
    // Another start, past the end asked, past the total, over the cap.
    expect((await answer({ v: 1, kind: 'bytes', start: 1, total: 10, mimeType: 'video/mp4', bytes: bytes(2) }, 'bytes=0-1'))!.status).toBe(502)
    expect((await answer({ v: 1, kind: 'bytes', start: 0, total: 10, mimeType: 'video/mp4', bytes: bytes(3) }, 'bytes=0-1'))!.status).toBe(502)
    expect((await answer({ v: 1, kind: 'bytes', start: 8, total: 10, mimeType: 'video/mp4', bytes: bytes(3) }, 'bytes=8-'))!.status).toBe(502)
    expect((await answer({ v: 1, kind: 'bytes', start: 5, total: 10, mimeType: 'video/mp4', bytes: bytes(5) }, 'bytes=-4'))!.status).toBe(502)
    const cap = STREAM_ANSWER_HARD_MAX_BYTES
    expect((await answer({ v: 1, kind: 'bytes', start: 0, total: cap * 2, mimeType: 'video/mp4', bytes: bytes(cap + 1) }, 'bytes=0-'))!.status).toBe(502)
    expect((await answer({ v: 1, kind: 'error', message: 'a block failed' }, 'bytes=0-'))!.status).toBe(502)
    expect((await answer('nonsense', 'bytes=0-'))!.status).toBe(502)
  })

  it('answers 503 when the page and the worker share no protocol version', async () => {
    const newer = worker(() => ({ v: 2, kind: 'bytes', start: 0, total: 10, mimeType: 'video/mp4', bytes: bytes(10) }))
    const response = (await newer.fetch(`/sw/stream/${STREAM}`, { range: 'bytes=0-' }))!
    expect(response.status).toBe(503)
    expectSecurityHeaders(response)
    const refused = worker(() => ({ v: 9, kind: 'version' }))
    expect((await refused.fetch(`/sw/stream/${STREAM}`, { range: 'bytes=0-' }))!.status).toBe(503)
  })

  it('gives up on a page that never answers, after its timeout', async () => {
    vi.useFakeTimers()
    try {
      const silent = worker(() => undefined)
      let answered: Promise<Response> | null = null
      silent.handlers.fetch({
        request: { url: `${ORIGIN}/sw/stream/${STREAM}`, method: 'GET', destination: 'video', headers: new Headers({ Range: 'bytes=0-' }) },
        clientId: 'page',
        respondWith: (response: Promise<Response>) => {
          answered = response
        },
      })
      await vi.advanceTimersByTimeAsync(189_000)
      expect(silent.asked).toHaveLength(1)
      await vi.advanceTimersByTimeAsync(1_000)
      expect((await answered!).status).toBe(504)
    } finally {
      vi.useRealTimers()
    }
  })

  it('handles push only when the registration names it', async () => {
    const shown = vi.fn(() => Promise.resolve())
    const quiet = worker()
    Object.assign(quiet.self, { registration: { showNotification: shown } })
    const waited: Promise<unknown>[] = []
    quiet.handlers.push({ waitUntil: (p: Promise<unknown>) => waited.push(p) })
    expect(waited).toHaveLength(0)

    const chat = worker(null, '?push=chat&title=Kutup%20Sohbet&body=Yeni')
    Object.assign(chat.self.clients, { matchAll: () => Promise.resolve([]) })
    Object.assign(chat.self, { registration: { showNotification: shown } })
    const chatWaits: Promise<unknown>[] = []
    chat.handlers.push({ waitUntil: (p: Promise<unknown>) => chatWaits.push(p) })
    await Promise.all(chatWaits)
    expect(shown).toHaveBeenCalledWith('Kutup Sohbet', expect.objectContaining({ body: 'Yeni', tag: 'kutup-chat' }))
  })
})
