import { useQuery } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { loadAlarms, loadEvent, useCalendars, type Alarm } from '@kutup/calendar-core/api'
import { utcToLocal } from '@kutup/crypto/calendar'
import { useMailAccount } from '@kutup/mail-core/api'
import { showNotification } from '@kutup/ui/lib/desktopNotifications'
import { openEditor } from '../editorState'
import { useCalendarPrefs } from '../prefs'
import { alarmTag, LOOK_AHEAD_MS, PADDING_MS, runAlarms } from './alarmChain'
import { alarmText, alarmTitle } from './alarmText'
import { showReminder } from './push'

/** RFC 3339 without milliseconds, as the server writes instants. */
function instant(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d+Z$/, 'Z')
}

/** A sleep longer than this (the clock jumped past a minute's tick) starts the chain again (Proton's useHasSuspendedCounter). */
const SUSPENDED_MS = 90_000

/**
 * Proton's AlarmContainer and AlarmWatcher: while Calendar is open, the
 * caller's device reminders for the shown calendars fire here, named by the
 * event's title (opened with the calendar's key), worded as Proton's, in the
 * calendar's zone. The window is the next two days, fetched again before it
 * ends and after any change (`['calendar']` queries are invalidated by every
 * calendar write).
 */
export function AlarmWatcher() {
  const { t, i18n } = useTranslation()
  const prefs = useCalendarPrefs()
  const account = useMailAccount()
  const calendars = useCalendars()
  const shown = (calendars.data?.calendars ?? []).filter((calendar) => calendar.display)
  const shownIds = shown.map((calendar) => calendar.id).sort()
  const alarms = useQuery({
    queryKey: ['calendar', 'alarms', shownIds.join(',')],
    enabled: !!account.data && calendars.data !== undefined,
    refetchOnWindowFocus: true,
    queryFn: async () => {
      const start = Date.now()
      const end = start + LOOK_AHEAD_MS
      const all = await loadAlarms(instant(start), instant(end))
      return { end, alarms: all.filter((alarm) => alarm.action === 'device' && shownIds.includes(alarm.calendarId)) }
    },
  })

  // Fetched again before the window ends.
  const { refetch } = alarms
  const windowEnd = alarms.data?.end
  useEffect(() => {
    if (windowEnd === undefined) return
    const timer = setTimeout(() => void refetch(), Math.max(windowEnd - PADDING_MS - Date.now(), 0))
    return () => clearTimeout(timer)
  }, [windowEnd, refetch])

  // A computer that slept: the timers are stale; start again.
  const [woke, setWoke] = useState(0)
  useEffect(() => {
    let last = Date.now()
    const timer = setInterval(() => {
      const now = Date.now()
      if (now - last > SUSPENDED_MS) {
        setWoke((n) => n + 1)
        void refetch()
      }
      last = now
    }, 60_000)
    return () => clearInterval(timer)
  }, [refetch])

  const fired = useRef(new Set<string>())
  // What firing needs, read fresh when one fires.
  const latest = useRef({ account: account.data, shown, zone: prefs.zone, hour12: prefs.hour12, language: i18n.language, t })
  latest.current = { account: account.data, shown, zone: prefs.zone, hour12: prefs.hour12, language: i18n.language, t }

  const list = alarms.data?.alarms
  useEffect(() => {
    if (!list) return
    const fire = async (alarm: Alarm) => {
      const { account, shown, zone, hour12, language, t } = latest.current
      const calendar = shown.find((candidate) => candidate.id === alarm.calendarId)
      if (!account || !calendar) return
      const event = await loadEvent(account, calendar, alarm.eventId)
      const nowLocal = await utcToLocal(instant(Date.now()), zone)
      const start = event.fullDay ? alarm.occurrenceStart.slice(0, 10) : await utcToLocal(alarm.occurrenceStart.replace(/\.\d+Z$/, 'Z'), zone)
      const title = alarmTitle(event.verified ? event.fields.summary : null, t('reminders.untitled'))
      const body = alarmText(t, { title, allDay: event.fullDay, start, now: nowLocal, locale: language, hour12 })
      const tag = alarmTag(alarm)
      await showReminder(t('reminders.title'), { body, tag, eventId: event.id }, () =>
        showNotification(t('reminders.title'), { body, tag }, () => openEditor({ kind: 'edit', event })),
      )
    }
    return runAlarms(list, fired.current, fire)
  }, [list, woke])

  return null
}
