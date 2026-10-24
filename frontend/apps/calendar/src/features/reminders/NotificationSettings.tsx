import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Label } from '@kutup/ui/components/label'
import { notificationStatus, requestNotifications, type NotificationStatus } from '@kutup/ui/lib/desktopNotifications'
import { disablePush, pushKey, pushSupported, pushWanted, refreshPush, setPushWanted } from './push'

/**
 * Proton's QuickSettingsRequestNotifications: the browser's permission
 * (asked here, or how to allow it again); and Kutup's addition, reminders
 * while Calendar is closed (this browser's push subscription).
 */
export function NotificationSettings() {
  const { t } = useTranslation()
  const [status, setStatus] = useState<NotificationStatus>(notificationStatus)
  const [wanted, setWanted] = useState(pushWanted)
  const key = useQuery({ queryKey: ['calendar', 'push-key'], queryFn: pushKey, staleTime: Infinity })
  return (
    <div className="space-y-2" data-testid="settings-notifications">
      <Label>{t('reminders.settings.title')}</Label>
      {status === 'default' ? (
        <Button type="button" size="sm" variant="outline" onClick={() =>
            void requestNotifications().then((answer) => {
              setStatus(answer)
              refreshPush()
            })
          }>
          {t('reminders.enable')}
        </Button>
      ) : status === 'denied' ? (
        <p className="text-sm text-muted-foreground">{t('reminders.settings.denied')}</p>
      ) : status === 'unsupported' ? (
        <p className="text-sm text-muted-foreground">{t('reminders.settings.unsupported')}</p>
      ) : (
        <p className="text-sm text-muted-foreground">{t('reminders.settings.allowed')}</p>
      )}
      {status === 'granted' && pushSupported() && key.data ? (
        <div className="flex items-start gap-2">
          <Checkbox
            id="settings-push"
            checked={wanted}
            onCheckedChange={(value) => {
              const on = value === true
              setWanted(on)
              setPushWanted(on)
              if (!on) void disablePush().catch(() => undefined)
            }}
            data-testid="settings-push"
          />
          <div className="space-y-0.5">
            <Label htmlFor="settings-push">{t('reminders.settings.push')}</Label>
            <p className="text-xs text-muted-foreground">{t('reminders.settings.pushHint')}</p>
          </div>
        </div>
      ) : null}
    </div>
  )
}
