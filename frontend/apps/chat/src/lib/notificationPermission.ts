import { useSyncExternalStore } from 'react'

// Whether the browser lets this site show notifications. The answer can
// change outside the page (site settings), so it is read again on focus.

export type NotificationPermissionState = NotificationPermission | 'unsupported'

const listeners = new Set<() => void>()

function read(): NotificationPermissionState {
  return typeof Notification === 'undefined' ? 'unsupported' : Notification.permission
}

let current = read()

function refresh(): void {
  const next = read()
  if (next === current) return
  current = next
  for (const listener of listeners) listener()
}

if (typeof window !== 'undefined') window.addEventListener('focus', refresh)

/** Notifications can show here and the person allowed them. */
export function notificationsAllowed(): boolean {
  return read() === 'granted'
}

/** Ask the browser (it must follow a click). */
export async function requestNotificationPermission(): Promise<NotificationPermissionState> {
  if (typeof Notification === 'undefined') return 'unsupported'
  await Notification.requestPermission()
  refresh()
  return current
}

export function useNotificationPermission(): NotificationPermissionState {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    () => current,
  )
}
