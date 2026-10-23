import { useQuery } from '@tanstack/react-query'
import { useEffect, useSyncExternalStore } from 'react'
import { useTranslation } from 'react-i18next'
import { useRequiredSession } from '@kutup/session/store'
import { useCalendarPrefs } from '../prefs'
import { enablePush, onPushChange, pushKey, pushSupported, pushVersion, pushWanted } from './push'

/**
 * Keeps this browser's reminder subscription current while it is wanted
 * and allowed: on each start, and when the language, zone or clock (the
 * worker's words) change, and when the setting does.
 */
export function usePush(): void {
  const version = useSyncExternalStore(onPushChange, pushVersion, pushVersion)
  const { t, i18n } = useTranslation()
  const session = useRequiredSession()
  const prefs = useCalendarPrefs()
  const key = useQuery({ queryKey: ['calendar', 'push-key'], queryFn: pushKey, staleTime: Infinity })
  const publicKey = key.data
  useEffect(() => {
    if (!publicKey || !pushSupported() || !pushWanted() || Notification.permission !== 'granted') return
    void enablePush(publicKey, {
      title: t('reminders.push.title'),
      at: t('reminders.push.at'),
      today: t('reminders.push.today'),
      on: t('reminders.push.on'),
      onAt: t('reminders.push.onAt'),
      zone: prefs.zone,
      lang: i18n.language,
      hour12: prefs.hour12,
      account: session.userId,
    }).catch(() => undefined)
  }, [publicKey, prefs.zone, prefs.hour12, i18n.language, session.userId, t, version])
}
