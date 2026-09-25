import type { ChatService } from '@kutup/chat-core/service'

// Web Push for this browser: a service worker that shows a notification
// when the server wakes this chat device while Chat is closed.

const WORKER = '/push-sw.js'

export function webPushSupported(): boolean {
  return 'serviceWorker' in navigator && 'PushManager' in window && typeof Notification !== 'undefined'
}

function keyBytes(base64url: string): Uint8Array<ArrayBuffer> {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4))
  const bytes = new Uint8Array(new ArrayBuffer(binary.length))
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index)
  return bytes
}

function sameKey(current: ArrayBuffer | null | undefined, wanted: Uint8Array): boolean {
  if (!current) return false
  const bytes = new Uint8Array(current)
  return bytes.length === wanted.length && bytes.every((byte, index) => byte === wanted[index])
}

/**
 * Subscribe this browser and tell the server to wake this device through
 * it. Safe to repeat (on every start): it renews what changed.
 */
export async function enableWebPush(
  service: ChatService,
  publicKey: string,
  words: { title: string; body: string },
): Promise<void> {
  const query = new URLSearchParams(words).toString()
  const registration = await navigator.serviceWorker.register(`${WORKER}?${query}`, { scope: '/' })
  await navigator.serviceWorker.ready
  const key = keyBytes(publicKey)
  let subscription = await registration.pushManager.getSubscription()
  if (subscription && !sameKey(subscription.options.applicationServerKey, key)) {
    // The server's key changed: a subscription is bound to the old one.
    await subscription.unsubscribe()
    subscription = null
  }
  subscription ??= await registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key })
  await service.setPushSubscription(subscription.endpoint)
}

/** Stop waking this device, and drop the browser's subscription. */
export async function disableWebPush(service: ChatService | null): Promise<void> {
  const registration = await navigator.serviceWorker?.getRegistration('/')
  const subscription = await registration?.pushManager.getSubscription()
  await subscription?.unsubscribe()
  await service?.setPushSubscription(null)
}

/** What the service worker's notification says, in this page's language. */
export function pushWords(t: (key: string) => string): { title: string; body: string } {
  return { title: t('chat.notifications.appName'), body: t('chat.notifications.pushBody') }
}
