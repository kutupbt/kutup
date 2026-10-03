// Kutup Chat's service worker: shows a notification when a Web Push wake-up
// arrives while Chat is closed. The push carries nothing (the server cannot
// read messages), so the notification only says that something is new;
// opening Chat shows what. Its words come in the registration URL, in the
// language of the page that registered it. See docs/chat-notifications.md.

const params = new URL(self.location.href).searchParams
const TITLE = params.get('title') || 'Kutup Chat'
const BODY = params.get('body') || 'You may have new messages.'

self.addEventListener('install', () => self.skipWaiting())
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()))

self.addEventListener('push', (event) => {
  event.waitUntil((async () => {
    const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true })
    // An open, visible Chat notifies by itself.
    if (windows.some((client) => client.visibilityState === 'visible')) return
    await self.registration.showNotification(TITLE, {
      body: BODY,
      tag: 'kutup-chat',
      renotify: true,
      icon: '/favicon.svg',
    })
  })())
})

self.addEventListener('notificationclick', (event) => {
  event.notification.close()
  event.waitUntil((async () => {
    const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true })
    for (const client of windows) {
      if ('focus' in client) return client.focus()
    }
    return self.clients.openWindow('/')
  })())
})
