import { useTranslation } from 'react-i18next'
import { NotificationBanner as Banner } from '@kutup/ui/components/notification-banner'

/** Proton's DesktopNotificationTopBanner, with Mail's words. */
export function NotificationBanner() {
  const { t } = useTranslation()
  return (
    <Banner
      storageKey="kutup.mail.notificationBanner.dismissed"
      message={t('notifications.banner')}
      label={t('notifications.bannerLabel')}
      enable={t('notifications.enable')}
      dismiss={t('notifications.dismiss')}
    />
  )
}
