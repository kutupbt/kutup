import { deletePushSubscription, savePushSubscription } from '@kutup/calendar-core/api'
import { loadServerSettings } from '@kutup/session/apps'

// Kutup's closed-app reminders (Proton's Calendar has none): this browser's
// push subscription for the calendar's service worker, with the keys the
// server encrypts each reminder to (RFC 8291). The worker's words, zone and
// language travel in its registration URL; it holds no keys.

const WORKER = '/push-sw.js'
const PREF = 'kutup-calendar-push'

export function pushSupported(): boolean {
  return typeof navigator !== 'undefined' && 'serviceWorker' in navigator && typeof window !== 'undefined' && 'PushManager' in window && typeof Notification !== 'undefined'
}

/** Whether this browser takes reminders while Calendar is closed (on unless turned off). */
export function pushWanted(): boolean {
  try {
    return localStorage.getItem(PREF) !== 'off'
  } catch {
    return true
  }
}

const listeners = new Set<() => void>()
let version = 0

/** Changes whenever the setting does (the subscription is renewed then). */
export function pushVersion(): number {
  return version
}

export function onPushChange(listener: () => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

/** The browser's permission may have changed: the subscription is checked again. */
export function refreshPush(): void {
  version += 1
  for (const listener of listeners) listener()
}

export function setPushWanted(on: boolean): void {
  try {
    localStorage.setItem(PREF, on ? 'on' : 'off')
  } catch {
    // Holds until the page reloads.
  }
  version += 1
  for (const listener of listeners) listener()
}

function keyBytes(base64url: string): Uint8Array<ArrayBuffer> {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4))
  const bytes = new Uint8Array(new ArrayBuffer(binary.length))
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index)
  return bytes
}

function base64url(buffer: ArrayBuffer | null): string {
  if (!buffer) throw new Error('the subscription has no keys')
  let text = ''
  for (const byte of new Uint8Array(buffer)) text += String.fromCharCode(byte)
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function sameKey(current: ArrayBuffer | null | undefined, wanted: Uint8Array): boolean {
  if (!current) return false
  const bytes = new Uint8Array(current)
  return bytes.length === wanted.length && bytes.every((byte, index) => byte === wanted[index])
}

/** The server's VAPID key (Chat's: one per server), when it sends pushes. */
export async function pushKey(): Promise<string | null> {
  const settings = await loadServerSettings<{ chat?: { webPushPublicKey?: string } | null }>()
  return settings.chat?.webPushPublicKey ?? null
}

/** What the worker needs: its words, the account's zone and clock, the language, and the account it is for. */
export interface WorkerWords {
  title: string
  at: string
  today: string
  on: string
  onAt: string
  zone: string
  lang: string
  hour12: boolean | null
  account: string
}

/**
 * Subscribes this browser and gives the server its endpoint and keys. Safe
 * to repeat (each start, and when the words, zone or language change): it
 * renews what changed.
 */
export async function enablePush(publicKey: string, words: WorkerWords): Promise<void> {
  const { hour12, ...rest } = words
  const query = new URLSearchParams({ ...rest, ...(hour12 === null ? {} : { hour12: String(hour12) }) }).toString()
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
  await savePushSubscription({
    endpoint: subscription.endpoint,
    p256dh: base64url(subscription.getKey('p256dh')),
    auth: base64url(subscription.getKey('auth')),
  })
}

/** No more reminders here while Calendar is closed. */
export async function disablePush(): Promise<void> {
  const registration = await navigator.serviceWorker?.getRegistration('/')
  const subscription = await registration?.pushManager.getSubscription()
  await subscription?.unsubscribe()
  await deletePushSubscription()
}

/**
 * Shows a reminder through the worker when it is registered (so a later
 * push for the same alarm sees it and stays quiet, and a click opens the
 * event), else as a page notification.
 */
export async function showReminder(title: string, options: { body: string; tag: string; eventId: string }, fallback: () => void): Promise<void> {
  if (typeof Notification === 'undefined' || Notification.permission !== 'granted') return
  const registration = pushSupported() ? await navigator.serviceWorker.getRegistration('/') : undefined
  if (!registration) {
    fallback()
    return
  }
  await registration.showNotification(title, {
    body: options.body,
    tag: options.tag,
    icon: '/favicon.svg',
    data: { url: `/?event=${encodeURIComponent(options.eventId)}` },
  })
}
