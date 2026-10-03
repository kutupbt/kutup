import { Bell, BellOff } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@kutup/ui/components/button'
import { cn } from '@kutup/ui/lib/cn'
import { useChat } from '../../app/chatStore'
import { requestNotificationPermission, useNotificationPermission } from '../../lib/notificationPermission'
import { playNotificationSound } from '../../lib/notificationSound'
import { disableWebPush, enableWebPush, pushWords, webPushSupported } from '../../lib/webPush'
import {
  setNotificationContent,
  setNotifications,
  setNotificationSound,
  setWebPush,
  useNotificationContent,
  useNotificationSound,
  useNotifications,
  useWebPush,
  type NotificationContent,
} from '../../state/prefs'
import { SettingsSection } from './SettingsPage'
import { Toggle } from './Toggle'

const CONTENT: NotificationContent[] = ['all', 'name', 'none']

/**
 * Notifications on this device: whether they show (the browser must allow
 * them too), what they reveal on the screen, and the sound.
 */
export function NotificationSettings() {
  const { t } = useTranslation()
  const permission = useNotificationPermission()
  const enabled = useNotifications()
  const sound = useNotificationSound()
  const content = useNotificationContent()
  const webPush = useWebPush()
  const { service, capabilities } = useChat()
  const [pushBusy, setPushBusy] = useState(false)
  const pushKey = capabilities?.webPushPublicKey

  async function changeWebPush(on: boolean) {
    if (!service || pushBusy) return
    setPushBusy(true)
    try {
      if (on && pushKey) {
        await enableWebPush(service, pushKey, pushWords(t))
      } else {
        await disableWebPush(service)
      }
      setWebPush(on)
    } catch (error) {
      console.warn('chat: Web Push change failed', error)
      toast.error(on ? t('chat.notifications.pushFailed') : t('chat.errors.unavailable'))
    } finally {
      setPushBusy(false)
    }
  }

  function test() {
    if (sound) playNotificationSound()
    if (permission !== 'granted') return
    new Notification(t('chat.notifications.appName'), {
      body: t('chat.notifications.test'),
      icon: '/favicon.svg',
      tag: 'kutup-chat-test',
      silent: true,
    })
  }

  return (
    <SettingsSection title={t('chat.settings.notifications')} description={t('chat.notifications.settingsDescription')}>
      <div className="max-w-xl space-y-3">
        {permission === 'default' ? (
          <div className="flex items-start gap-3 rounded-lg border border-primary/40 bg-accent/40 p-4">
            <Bell className="mt-0.5 size-4 shrink-0" aria-hidden />
            <div className="flex-1">
              <p className="text-sm font-medium">{t('chat.notifications.allowTitle')}</p>
              <p className="mt-1 text-sm text-muted-foreground">{t('chat.notifications.allowDescription')}</p>
              <Button size="sm" className="mt-3" onClick={() => void requestNotificationPermission()} data-testid="chat-notifications-allow">
                {t('chat.notifications.allow')}
              </Button>
            </div>
          </div>
        ) : permission === 'denied' || permission === 'unsupported' ? (
          <div className="flex items-start gap-3 rounded-lg border border-border p-4" role="status">
            <BellOff className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
            <p className="text-sm text-muted-foreground">
              {permission === 'denied' ? t('chat.notifications.blocked') : t('chat.notifications.unsupported')}
            </p>
          </div>
        ) : null}

        <Toggle
          checked={enabled}
          onChange={setNotifications}
          title={t('chat.notifications.show')}
          description={t('chat.notifications.showDescription')}
          testId="chat-notifications-toggle"
        />

        <fieldset className="rounded-lg border border-border p-4" disabled={!enabled}>
          <legend className="px-1 text-sm font-medium">{t('chat.notifications.contentTitle')}</legend>
          <div className="mt-2 space-y-2">
            {CONTENT.map((option) => (
              <label key={option} className={cn('flex cursor-pointer items-start gap-3', !enabled && 'opacity-50')}>
                <input
                  type="radio"
                  name="notification-content"
                  className="mt-1 accent-primary"
                  checked={content === option}
                  onChange={() => setNotificationContent(option)}
                  data-testid={`chat-notifications-content-${option}`}
                />
                <span>
                  <span className="block text-sm">{t(`chat.notifications.content.${option}`)}</span>
                  <span className="block text-xs text-muted-foreground">{t(`chat.notifications.content.${option}Hint`)}</span>
                </span>
              </label>
            ))}
          </div>
        </fieldset>

        <Toggle
          checked={sound}
          onChange={setNotificationSound}
          disabled={!enabled}
          title={t('chat.notifications.sound')}
          description={t('chat.notifications.soundDescription')}
          testId="chat-notifications-sound"
        />

        {pushKey && webPushSupported() ? (
          <Toggle
            checked={webPush}
            onChange={(on) => void changeWebPush(on)}
            disabled={pushBusy || (!webPush && permission !== 'granted')}
            title={t('chat.notifications.push')}
            description={t('chat.notifications.pushDescription')}
            testId="chat-web-push-toggle"
          />
        ) : null}

        <Button variant="outline" size="sm" disabled={!enabled} onClick={test} data-testid="chat-notifications-test">
          {t('chat.notifications.sendTest')}
        </Button>
      </div>
    </SettingsSection>
  )
}
