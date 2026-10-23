// Kutup Calendar's service worker: shows a reminder when its push arrives
// while Calendar is closed (docs/plans/calendar.md, E2b-3). It holds no
// keys: the push, encrypted to this browser, says only which event and when
// ({ eventId, startUtc, allDay, account }), so the notification says when,
// never what ("Event at 09:30"). Its words, zone and language come in the
// registration URL from the page that registered it.
//
// One reminder is one notification: its tag is the open app's for the same
// alarm (`kutup-calendar:<eventId>:<start ms>:<fire ms>`). The open app
// fires its own reminders, named by their titles: while a Calendar window is
// open, a push for one the app showed shows that notification again,
// silently (the browser wants each push to show one), and one the app hasn't
// shown yet comes silently with its time only, for the app's to replace.
// With Calendar closed, a push shows its reminder (time only) as usual.

const params = new URL(self.location.href).searchParams
const TITLE = params.get('title') || 'Kutup Calendar'
const AT = params.get('at') || 'Event at {{time}}'
const TODAY = params.get('today') || 'Event today'
const ON = params.get('on') || 'Event on {{date}}'
const ON_AT = params.get('onAt') || 'Event on {{date}} at {{time}}'
const ZONE = params.get('zone') || 'UTC'
const LANG = params.get('lang') || 'en'
const HOUR12 = params.get('hour12')
// The account that registered: its id, to tell its pushes from another
// account's in this browser (`account` is keyed by this subscription's own
// secret, so nothing account-identifying is stored here in clear).
const ACCOUNT = params.get('account') || ''

self.addEventListener('install', () => self.skipWaiting())
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()))

function fill(text, values) {
  return text.replace(/\{\{(\w+)\}\}/g, (_, key) => values[key] ?? '')
}

function dayIn(date, zone) {
  return new Intl.DateTimeFormat('en-CA', { timeZone: zone, year: 'numeric', month: '2-digit', day: '2-digit' }).format(date)
}

/** "Event at 09:30", "Event today", "Event on Friday 30 October (at 09:30)", in the account's zone. */
function body(startUtc, allDay) {
  const start = new Date(startUtc)
  const zone = allDay ? 'UTC' : ZONE
  const hourCycle = HOUR12 === null ? {} : { hour12: HOUR12 === 'true' }
  const time = new Intl.DateTimeFormat(LANG, { hour: 'numeric', minute: '2-digit', timeZone: zone, ...hourCycle }).format(start)
  const date = new Intl.DateTimeFormat(LANG, { weekday: 'long', day: 'numeric', month: 'long', timeZone: zone }).format(start)
  // An all-day event's start is its date at UTC midnight.
  const today = dayIn(new Date(), ZONE) === dayIn(start, zone)
  if (allDay) return today ? TODAY : fill(ON, { date })
  return today ? fill(AT, { time }) : fill(ON_AT, { date, time })
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

async function ours(account) {
  if (!ACCOUNT || typeof account !== 'string') return false
  const subscription = await self.registration.pushManager.getSubscription()
  const auth = subscription && subscription.getKey('auth')
  return !!auth && (await accountTag(auth, ACCOUNT)) === account
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

self.addEventListener('push', (event) => {
  event.waitUntil((async () => {
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
    const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true })
    const mine = await ours(data.account)
    await self.registration.showNotification(TITLE, {
      body: body(data.startUtc, data.allDay === true),
      tag,
      icon: '/favicon.svg',
      // Calendar is open: it fires this one by its title in a moment, replacing this.
      silent: windows.length > 0,
      // Another account's reminder in this browser opens Calendar's start page.
      data: { url: mine ? `/?event=${encodeURIComponent(data.eventId)}` : '/' },
    })
  })())
})

self.addEventListener('notificationclick', (event) => {
  event.notification.close()
  const wanted = (event.notification.data && event.notification.data.url) || '/'
  // Only Calendar's own pages: its start page, or an event by its id.
  const url = wanted === '/' || /^\/\?event=[0-9a-f-]{36}$/.test(wanted) ? wanted : '/'
  event.waitUntil((async () => {
    const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true })
    for (const client of windows) {
      if ('focus' in client) {
        await client.focus()
        if ('navigate' in client && url !== '/') await client.navigate(url).catch(() => undefined)
        return
      }
    }
    await self.clients.openWindow(url)
  })())
})
