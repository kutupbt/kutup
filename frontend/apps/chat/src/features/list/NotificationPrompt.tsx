import { Bell } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { requestNotificationPermission, useNotificationPermission } from '../../lib/notificationPermission'
import { setNotificationPromptDismissed, useNotificationPromptDismissed, useNotifications } from '../../state/prefs'

/** Asks once, above the chats, to let the browser show notifications. */
export function NotificationPrompt() {
  const { t } = useTranslation()
  const permission = useNotificationPermission()
  const enabled = useNotifications()
  const dismissed = useNotificationPromptDismissed()
  if (permission !== 'default' || !enabled || dismissed) return null
  return (
    <section className="mx-2 mt-2 flex items-start gap-3 rounded-[10px] border border-border bg-muted/40 p-3" data-testid="chat-notification-prompt">
      <Bell className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
      <div className="min-w-0 flex-1">
        <p className="text-sm">{t('chat.notifications.prompt')}</p>
        <div className="mt-2 flex gap-2">
          <Button size="sm" onClick={() => void requestNotificationPermission()}>{t('chat.notifications.turnOn')}</Button>
          <Button size="sm" variant="ghost" onClick={() => setNotificationPromptDismissed(true)}>{t('chat.notifications.notNow')}</Button>
        </div>
      </div>
    </section>
  )
}
