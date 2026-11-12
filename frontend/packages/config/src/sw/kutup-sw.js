// Kutup's one service worker, served at /kutup-sw.js (scope /) by every app
// that streams media or takes Web Push: Drive, Photos, Chat and Calendar.
// The shared Vite plugin (../../vite.ts `kutupServiceWorker`) copies this
// file into those apps' builds as it is: a plain script with no imports,
// free of app code. An app opts into a feature by what it registers:
//
// - Push, when the registration URL names one (`?push=chat&…` or
//   `?push=calendar&…`), its words in the URL in the language of the page
//   that registered it (docs/chat-notifications.md, docs/plans/calendar.md).
// - Streaming (docs/plans/drive-block-format.md §4), always: GET
//   /sw/stream/{streamId} from a <video> or <audio> answers one Range from
//   the page that asked. The worker holds no state and no keys: for each
//   request it asks that page (clients.get(event.clientId)) over a fresh
//   MessageChannel for the bytes, which the page's block reader Worker has
//   verified, and answers 206 with at most one block. A worker stopped or
//   replaced between two requests loses nothing.
//
// Every request outside /sw/ goes to the network untouched (no respondWith).

/* The stream protocol (`@kutup/files` blockReader/protocol.ts). `accepts`
   keeps the previous version for one release after a change. */
const STREAM_PROTOCOL = 1
const STREAM_ACCEPTS = [1]
/** How long one answer may take: a block fetched and verified over a slow line. */
const CHUNK_TIMEOUT_MS = 190_000
/** The most bytes one answer carries: the largest `drive.stream.response_max_bytes`. */
const ANSWER_MAX_BYTES = 16 * 1024 * 1024
/** 128 random bits or more, base64url. */
const STREAM_ID = /^[A-Za-z0-9_-]{22,86}$/

/** The types a stream may be served as; anything else is application/octet-stream. */
const MEDIA_TYPES = new Set([
  'video/mp4',
  'video/webm',
  'video/ogg',
  'video/quicktime',
  'video/x-matroska',
  'video/mp2t',
  'audio/mpeg',
  'audio/mp4',
  'audio/x-m4a',
  'audio/aac',
  'audio/ogg',
  'audio/opus',
  'audio/webm',
  'audio/flac',
  'audio/x-flac',
  'audio/wav',
  'audio/wave',
  'audio/x-wav',
])

const params = new URL(self.location.href).searchParams
const PUSH = params.get('push')

self.addEventListener('install', () => self.skipWaiting())
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()))

// ---------------------------------------------------------------------------
// Streaming
// ---------------------------------------------------------------------------

/** A served type: one of the media types, else application/octet-stream. */
function mediaType(type) {
  const base = typeof type === 'string' ? type.split(';')[0].trim().toLowerCase() : ''
  return MEDIA_TYPES.has(base) ? base : 'application/octet-stream'
}

/**
 * One `Range` header: `{ start, end }` (end null for `a-`), `{ suffix }` for
 * `-k`, or null for anything else (several ranges, other units, nonsense).
 */
function parseRange(header) {
  const match = /^\s*bytes\s*=\s*(\d*)\s*-\s*(\d*)\s*$/i.exec(header)
  if (!match) return null
  const [, first, last] = match
  if (first === '' && last === '') return null
  if (first === '') {
    const suffix = Number(last)
    return Number.isSafeInteger(suffix) && suffix > 0 ? { suffix } : null
  }
  const start = Number(first)
  const end = last === '' ? null : Number(last)
  if (!Number.isSafeInteger(start) || (end !== null && (!Number.isSafeInteger(end) || end < start))) return null
  return { start, end }
}

/** The headers on every stream response, errors too. */
function streamHeaders(extra) {
  return {
    'Content-Security-Policy': "default-src 'none'; sandbox",
    'X-Content-Type-Options': 'nosniff',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Cache-Control': 'no-store',
    'Accept-Ranges': 'bytes',
    'Content-Type': 'application/octet-stream',
    'Content-Length': '0',
    ...extra,
  }
}

function emptyResponse(status, extra) {
  return new Response(null, { status, headers: streamHeaders(extra) })
}

/** Asks the page for one range; its answer comes back on the port it was sent. */
function askPage(client, streamId, range) {
  const channel = new MessageChannel()
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      channel.port1.close()
      reject(new Error('the page did not answer'))
    }, CHUNK_TIMEOUT_MS)
    channel.port1.onmessage = (message) => {
      clearTimeout(timer)
      channel.port1.close()
      resolve(message.data)
    }
    client.postMessage({ type: 'get_stream_chunk', v: STREAM_PROTOCOL, accepts: STREAM_ACCEPTS, streamId, range }, [channel.port2])
  })
}

/** The response to the page's answer, checked against what was asked. */
function streamResponse(answer, range) {
  if (typeof answer !== 'object' || answer === null) return emptyResponse(502)
  // A page that speaks none of our versions: it shows its reload prompt.
  if (answer.kind === 'version' || !STREAM_ACCEPTS.includes(answer.v)) return emptyResponse(503)
  const total = answer.total
  if (answer.kind === 'unsatisfiable') {
    return Number.isSafeInteger(total) && total >= 0 ? emptyResponse(416, { 'Content-Range': `bytes */${total}` }) : emptyResponse(502)
  }
  if (answer.kind !== 'bytes' || Object.prototype.toString.call(answer.bytes) !== '[object ArrayBuffer]') return emptyResponse(502)
  const start = answer.start
  const length = answer.bytes.byteLength
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(total) || start < 0) return emptyResponse(502)
  if (length === 0) return emptyResponse(416, { 'Content-Range': `bytes */${total}` })
  const end = start + length - 1
  const asked = 'suffix' in range ? start === Math.max(0, total - range.suffix) : start === range.start && (range.end === null || end <= range.end)
  if (!asked || end >= total || length > ANSWER_MAX_BYTES) return emptyResponse(502)
  return new Response(answer.bytes, {
    status: 206,
    headers: streamHeaders({
      'Content-Range': `bytes ${start}-${end}/${total}`,
      'Content-Length': String(length),
      'Content-Type': mediaType(answer.mimeType),
    }),
  })
}

async function serveStream(event, url) {
  const request = event.request
  // Only a player may read a stream; a navigation, a fetch() or an <img> may not.
  if (request.destination !== 'video' && request.destination !== 'audio') return emptyResponse(403)
  const streamId = url.pathname.slice('/sw/stream/'.length)
  if (!STREAM_ID.test(streamId)) return emptyResponse(404)
  const header = request.headers.get('Range')
  if (!header) return emptyResponse(400)
  const range = parseRange(header)
  if (!range) return emptyResponse(416)
  // The page that asked holds the stream; with no page, nothing is served.
  const client = event.clientId ? await self.clients.get(event.clientId) : undefined
  if (!client) return emptyResponse(404)
  let answer
  try {
    answer = await askPage(client, streamId, range)
  } catch {
    return emptyResponse(504)
  }
  return streamResponse(answer, range)
}

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url)
  if (url.origin !== self.location.origin || !url.pathname.startsWith('/sw/')) return
  if (event.request.method === 'GET' && url.pathname.startsWith('/sw/stream/')) {
    event.respondWith(serveStream(event, url).catch(() => emptyResponse(500)))
    return
  }
  event.respondWith(emptyResponse(404))
})

// ---------------------------------------------------------------------------
// Chat push: a wake-up that carries nothing (the server cannot read
// messages), so the notification only says that something is new.
// ---------------------------------------------------------------------------

async function chatPush() {
  const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true })
  // An open, visible Chat notifies by itself.
  if (windows.some((client) => client.visibilityState === 'visible')) return
  await self.registration.showNotification(params.get('title') || 'Kutup Chat', {
    body: params.get('body') || 'You may have new messages.',
    tag: 'kutup-chat',
    renotify: true,
    icon: '/favicon.svg',
  })
}

async function chatClick() {
  const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true })
  for (const client of windows) {
    if ('focus' in client) return client.focus()
  }
  return self.clients.openWindow('/')
}

// ---------------------------------------------------------------------------
// Calendar push: a reminder, encrypted to this browser, says only which
// event and when ({ eventId, startUtc, allDay, account }), so the
// notification says when, never what ("Event at 09:30").
//
// One reminder is one alert: its tag is the open app's for the same alarm
// (`kutup-calendar:<eventId>:<start ms>:<fire ms>`). A push for one the app
// has shown already shows that notification again, silently (the browser
// wants each push to show one). Any other push alerts, with its time only:
// whether an open tab will fire it isn't known here (another account, a
// hidden calendar, a locked or frozen tab), and a tab firing it later only
// puts its title in, silently.
// ---------------------------------------------------------------------------

function fill(text, values) {
  return text.replace(/\{\{(\w+)\}\}/g, (_, key) => values[key] ?? '')
}

function dayIn(date, zone) {
  return new Intl.DateTimeFormat('en-CA', { timeZone: zone, year: 'numeric', month: '2-digit', day: '2-digit' }).format(date)
}

/** "Event at 09:30", "Event today", "Event on Friday 30 October (at 09:30)", in the account's zone. */
function reminderBody(startUtc, allDay) {
  const ZONE = params.get('zone') || 'UTC'
  const LANG = params.get('lang') || 'en'
  const HOUR12 = params.get('hour12')
  const start = new Date(startUtc)
  const zone = allDay ? 'UTC' : ZONE
  const hourCycle = HOUR12 === null ? {} : { hour12: HOUR12 === 'true' }
  const time = new Intl.DateTimeFormat(LANG, { hour: 'numeric', minute: '2-digit', timeZone: zone, ...hourCycle }).format(start)
  const date = new Intl.DateTimeFormat(LANG, { weekday: 'long', day: 'numeric', month: 'long', timeZone: zone }).format(start)
  // An all-day event's start is its date at UTC midnight.
  const today = dayIn(new Date(), ZONE) === dayIn(start, zone)
  if (allDay) return today ? params.get('today') || 'Event today' : fill(params.get('on') || 'Event on {{date}}', { date })
  return today ? fill(params.get('at') || 'Event at {{time}}', { time }) : fill(params.get('onAt') || 'Event on {{date}} at {{time}}', { date, time })
}

function base64url(bytes) {
  let text = ''
  for (const byte of new Uint8Array(bytes)) text += String.fromCharCode(byte)
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function uuidBytes(uuid) {
  const hex = uuid.replace(/-/g, '')
  const bytes = new Uint8Array(16)
  for (let i = 0; i < 16; i += 1) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return bytes
}

/** The server's `account` for this subscription and account: base64url(HMAC-SHA256(auth, "account" ‖ 0 ‖ id)), 22 characters. */
async function accountTag(auth, account) {
  const key = await crypto.subtle.importKey('raw', auth, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const label = new TextEncoder().encode('account')
  const message = new Uint8Array(label.length + 1 + 16)
  message.set(label, 0)
  message.set(uuidBytes(account), label.length + 1)
  return base64url(await crypto.subtle.sign('HMAC', key, message)).slice(0, 22)
}

/**
 * Whether a push is for the account that registered: its id is in the
 * registration URL, to tell its pushes from another account's in this
 * browser (`account` is keyed by this subscription's own secret, so nothing
 * account-identifying is stored here in clear).
 */
async function ours(account) {
  const registered = params.get('account') || ''
  if (!registered || typeof account !== 'string') return false
  const subscription = await self.registration.pushManager.getSubscription()
  const auth = subscription && subscription.getKey('auth')
  return !!auth && (await accountTag(auth, registered)) === account
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

async function calendarPush(event) {
  let data
  try {
    data = event.data.json()
  } catch {
    return
  }
  // A reminder names an event by its id and gives real times; nothing else is one.
  const start = typeof data.startUtc === 'string' ? Date.parse(data.startUtc) : NaN
  const fire = typeof data.fireAt === 'string' ? Date.parse(data.fireAt) : NaN
  if (typeof data.eventId !== 'string' || !UUID.test(data.eventId) || Number.isNaN(start) || Number.isNaN(fire)) return
  const tag = `kutup-calendar:${data.eventId}:${start}:${fire}`
  const [shown] = await self.registration.getNotifications({ tag })
  if (shown) {
    // The open app showed it (with its title): the same, again, silently.
    await self.registration.showNotification(shown.title, { body: shown.body, tag, icon: shown.icon, data: shown.data, silent: true })
    return
  }
  const mine = await ours(data.account)
  await self.registration.showNotification(params.get('title') || 'Kutup Calendar', {
    body: reminderBody(data.startUtc, data.allDay === true),
    tag,
    icon: '/favicon.svg',
    // Another account's reminder in this browser opens Calendar's start page.
    data: { url: mine ? `/?event=${encodeURIComponent(data.eventId)}` : '/' },
  })
}

async function calendarClick(event) {
  const wanted = (event.notification.data && event.notification.data.url) || '/'
  // Only Calendar's own pages: its start page, or an event by its id.
  const url = wanted === '/' || /^\/\?event=[0-9a-f-]{36}$/.test(wanted) ? wanted : '/'
  const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true })
  for (const client of windows) {
    if ('focus' in client) {
      await client.focus()
      if ('navigate' in client && url !== '/') await client.navigate(url).catch(() => undefined)
      return
    }
  }
  await self.clients.openWindow(url)
}

self.addEventListener('push', (event) => {
  if (PUSH === 'chat') event.waitUntil(chatPush())
  else if (PUSH === 'calendar') event.waitUntil(calendarPush(event))
})

self.addEventListener('notificationclick', (event) => {
  event.notification.close()
  if (PUSH === 'chat') event.waitUntil(chatClick())
  else if (PUSH === 'calendar') event.waitUntil(calendarClick(event))
})
