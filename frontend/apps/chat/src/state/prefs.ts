import { useSyncExternalStore } from 'react'

/**
 * Chat preferences kept on this device, each one switch in localStorage.
 *
 * - Read receipts are off unless turned on (the old page's storage key):
 *   delivery receipts in direct chats are always sent; "read" only when on.
 * - Link previews are on, as in Signal: typing a link asks this account's
 *   server to fetch the page, and the preview travels encrypted.
 * - Notifications are on (once the browser allows them), with sound, and
 *   show the sender and the message, as Signal's defaults.
 */

function pref<T extends string>(key: string, fallback: T, allowed: readonly T[]) {
  const listeners = new Set<() => void>()
  const read = (): T => {
    try {
      const value = window.localStorage.getItem(key)
      return value !== null && (allowed as readonly string[]).includes(value) ? (value as T) : fallback
    } catch {
      return fallback
    }
  }
  let current = read()
  return {
    get: (): T => current,
    set: (value: T): void => {
      current = value
      try {
        window.localStorage.setItem(key, value)
      } catch {
        // Kept for this tab only.
      }
      for (const listener of listeners) listener()
    },
    use: (): T =>
      useSyncExternalStore(
        (listener) => {
          listeners.add(listener)
          return () => listeners.delete(listener)
        },
        () => current,
      ),
  }
}

function booleanPref(key: string, fallback: boolean) {
  const inner = pref<'0' | '1'>(key, fallback ? '1' : '0', ['0', '1'])
  return {
    get: (): boolean => inner.get() === '1',
    set: (enabled: boolean): void => inner.set(enabled ? '1' : '0'),
    use: (): boolean => inner.use() === '1',
  }
}

const readReceipts = booleanPref('kutup:chat:read-receipts', false)
const linkPreviews = booleanPref('kutup:chat:link-previews', true)

export const setReadReceipts = readReceipts.set
export const useReadReceipts = readReceipts.use
export const setLinkPreviews = linkPreviews.set
export const useLinkPreviews = linkPreviews.use

const notifications = booleanPref('kutup:chat:notifications', true)
const notificationSound = booleanPref('kutup:chat:notification-sound', true)

/** What a notification shows: sender and message, sender only, or neither. */
export type NotificationContent = 'all' | 'name' | 'none'
const notificationContent = pref<NotificationContent>('kutup:chat:notification-content', 'all', ['all', 'name', 'none'])

export const getNotifications = notifications.get
export const setNotifications = notifications.set
export const useNotifications = notifications.use
export const getNotificationSound = notificationSound.get
export const setNotificationSound = notificationSound.set
export const useNotificationSound = notificationSound.use
export const getNotificationContent = notificationContent.get
export const setNotificationContent = notificationContent.set
export const useNotificationContent = notificationContent.use

const notificationPromptDismissed = booleanPref('kutup:chat:notification-prompt-dismissed', false)
export const setNotificationPromptDismissed = notificationPromptDismissed.set
export const useNotificationPromptDismissed = notificationPromptDismissed.use

/** Wake this device through Web Push while Chat is closed; off unless turned on. */
const webPush = booleanPref('kutup:chat:web-push', false)
export const getWebPush = webPush.get
export const setWebPush = webPush.set
export const useWebPush = webPush.use

/** Send call media only through the server's TURN relay, hiding this browser's address. */
const alwaysRelayCalls = booleanPref('kutup:chat:always-relay-calls', false)
export const getAlwaysRelayCalls = alwaysRelayCalls.get
export const setAlwaysRelayCalls = alwaysRelayCalls.set
export const useAlwaysRelayCalls = alwaysRelayCalls.use

/** Send and show typing indicators (Signal's switch covers both ways). */
const typingIndicators = booleanPref('kutup:chat:typing-indicators', true)
export const setTypingIndicators = typingIndicators.set
export const useTypingIndicators = typingIndicators.use

/** The disappearing-message timer new chats start with, in seconds; 0 is off. */
const defaultTimer = pref<string>('kutup:chat:default-timer', '0', ['0', '30', '3600', '86400', '604800', '2592000'])
export const getDefaultTimerSeconds = (): number => Number(defaultTimer.get())
export const setDefaultTimerSeconds = (seconds: number): void => defaultTimer.set(String(seconds))
export const useDefaultTimerSeconds = (): number => Number(defaultTimer.use())
