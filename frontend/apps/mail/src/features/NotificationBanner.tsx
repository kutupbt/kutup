import { BellRing, X } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { notificationStatus, requestNotifications } from './desktopNotifications'

const DISMISSED = 'kutup.mail.notificationBanner.dismissed'

function dismissed(): boolean {
  try {
    return localStorage.getItem(DISMISSED) === '1'
  } catch {
    return false
  }
}

/** Proton's DesktopNotificationTopBanner: asks once for the browser's permission, until closed. */
export function NotificationBanner() {
  const { t } = useTranslation()
  const [hidden, setHidden] = useState(() => dismissed() || notificationStatus() !== 'default')
  if (hidden) return null
  const close = () => {
    try {
      localStorage.setItem(DISMISSED, '1')
    } catch {
      // Shown again next time.
    }
    setHidden(true)
  }
  return (
    <div role="region" aria-label={t('notifications.bannerLabel')} className="fixed bottom-4 left-1/2 z-40 flex w-[min(32rem,calc(100vw-2rem))] -translate-x-1/2 items-center gap-3 rounded-lg border border-border bg-card px-4 py-3 text-sm shadow-lg">
      <BellRing className="size-4 shrink-0 text-primary" aria-hidden />
      <span className="flex-1">{t('notifications.banner')}</span>
      <Button size="sm" onClick={() => void requestNotifications().then(() => setHidden(true))}>
        {t('notifications.enable')}
      </Button>
      <Button variant="ghost" size="icon" className="size-8" aria-label={t('notifications.dismiss')} onClick={close}>
        <X className="size-4" />
      </Button>
    </div>
  )
}
