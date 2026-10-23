import { BellRing, X } from 'lucide-react'
import { useState } from 'react'
import { notificationStatus, requestNotifications } from '../lib/desktopNotifications'
import { Button } from './button'

function dismissed(key: string): boolean {
  try {
    return localStorage.getItem(key) === '1'
  } catch {
    return false
  }
}

/**
 * Proton's DesktopNotificationTopBanner: asks once for the browser's
 * permission, until closed (remembered under `storageKey`). The words are
 * the app's.
 */
export function NotificationBanner({
  storageKey,
  message,
  label,
  enable,
  dismiss,
  onAnswer,
}: {
  storageKey: string
  message: string
  label: string
  enable: string
  dismiss: string
  /** After the browser answered. */
  onAnswer?: () => void
}) {
  const [hidden, setHidden] = useState(() => dismissed(storageKey) || notificationStatus() !== 'default')
  if (hidden) return null
  const close = () => {
    try {
      localStorage.setItem(storageKey, '1')
    } catch {
      // Shown again next time.
    }
    setHidden(true)
  }
  return (
    <div role="region" aria-label={label} className="fixed bottom-4 left-1/2 z-40 flex w-[min(32rem,calc(100vw-2rem))] -translate-x-1/2 items-center gap-3 rounded-lg border border-border bg-card px-4 py-3 text-sm shadow-lg">
      <BellRing className="size-4 shrink-0 text-primary" aria-hidden />
      <span className="flex-1">{message}</span>
      <Button size="sm" onClick={() =>
          void requestNotifications().then(() => {
            setHidden(true)
            onAnswer?.()
          })
        }>
        {enable}
      </Button>
      <Button variant="ghost" size="icon" className="size-8" aria-label={dismiss} onClick={close}>
        <X className="size-4" />
      </Button>
    </div>
  )
}
