import { useTranslation } from 'react-i18next'
import { MobileAccountSubPage } from '@/pages/mobile/account/MobileAccountSubPage'
import { EmptyState } from '@/components/ui/empty-state'

/**
 * MobileNotificationsPage — `/drive/account/notifications`.
 *
 * Placeholder. Kutup doesn't have a notification feed yet; this page exists
 * so the Account row has a dedicated destination (per user feedback: "make
 * each one its own page not open settings page") and shows an honest "not
 * yet wired" empty state.
 */
export default function MobileNotificationsPage() {
  const { t } = useTranslation()
  return (
    <MobileAccountSubPage title={t('mobile.account.notifications', 'Notifications')}>
      <EmptyState
        icon="bell"
        title={t('mobile.account.notifications.emptyTitle', 'No notifications')}
        subtitle={t(
          'mobile.account.notifications.emptySubtitle',
          'Activity from shares, mentions, and updates will appear here.',
        )}
        tint="primary"
      />
    </MobileAccountSubPage>
  )
}
