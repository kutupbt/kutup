// Desktop notifications (docs/plans/mail-parity.md, P6; Calendar's
// reminders), as Proton's `desktopNotification` helpers: the browser's
// permission is the only switch.

export type NotificationStatus = 'granted' | 'denied' | 'default' | 'unsupported'

export function notificationStatus(): NotificationStatus {
  if (typeof window === 'undefined' || !('Notification' in window)) return 'unsupported'
  return Notification.permission
}

/** Asks the browser; the answer as a status. */
export async function requestNotifications(): Promise<NotificationStatus> {
  if (notificationStatus() === 'unsupported') return 'unsupported'
  try {
    return await Notification.requestPermission()
  } catch {
    return notificationStatus()
  }
}

/** Shows one, when allowed; clicking focuses the app and runs `onClick`. */
export function showNotification(title: string, options: NotificationOptions, onClick?: () => void): void {
  if (notificationStatus() !== 'granted') return
  try {
    const notification = new Notification(title, { icon: '/favicon.svg', ...options })
    notification.onclick = () => {
      window.focus()
      onClick?.()
      notification.close()
    }
  } catch {
    // Some browsers report support but only allow notifications from a service worker.
  }
}
