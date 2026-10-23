import type { TFunction } from 'i18next'
import { addDays } from '@kutup/calendar-core/time'
import { formatTime } from '../format'

// A reminder's words, as Proton's `getAlarmMessageText`: when the event
// starts relative to now, on the calendar's wall clock (local times in its
// zone, compared as written).

function asUtc(local: string): Date {
  return new Date(local.length === 10 ? `${local}T00:00:00Z` : `${local}Z`)
}

function formatDate(local: string, locale: string, options: Intl.DateTimeFormatOptions): string {
  return new Intl.DateTimeFormat(locale, { ...options, timeZone: 'UTC' }).format(asUtc(local))
}

export interface AlarmTextInput {
  /** The event's title, already cut to Proton's 100 characters. */
  title: string
  allDay: boolean
  /** The occurrence's start and now, local times in the calendar's zone (`yyyy-MM-ddTHH:mm:ss`). */
  start: string
  now: string
  locale: string
  hour12: boolean | null
}

/** The notification's body, as Proton's (`starts now`, `starts at 09:30`, `started yesterday`…). */
export function alarmText(t: TFunction, { title, allDay, start, now, locale, hour12 }: AlarmTextInput): string {
  const startAt = asUtc(start).getTime()
  const nowAt = asUtc(now).getTime()
  // A browser's timers are imprecise: half a minute either way is now.
  if (Math.abs(startAt - nowAt) <= 30_000) return t('reminders.text.startsNow', { title })
  const hour = formatTime(start, locale, hour12)
  const startDay = start.slice(0, 10)
  const today = now.slice(0, 10)
  const sameMonth = start.slice(0, 7) === now.slice(0, 7)
  const sameYear = start.slice(0, 4) === now.slice(0, 4)
  const dayInMonth = formatDate(start, locale, { weekday: 'long', day: 'numeric' })
  const dayInYear = formatDate(start, locale, { weekday: 'long', day: 'numeric', month: 'long' })
  const fullDate = formatDate(start, locale, { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' })
  if (startAt < nowAt) {
    if (startDay === today) return allDay ? t('reminders.text.startsToday', { title }) : t('reminders.text.startedAt', { title, time: hour })
    if (addDays(startDay, 1) === today) {
      return allDay ? t('reminders.text.startedYesterday', { title }) : t('reminders.text.startedYesterdayAt', { title, time: hour })
    }
    if (sameMonth || sameYear) {
      const date = sameMonth ? dayInMonth : dayInYear
      return allDay ? t('reminders.text.startedOn', { title, date }) : t('reminders.text.startedOnAt', { title, date, time: hour })
    }
    return allDay ? t('reminders.text.startedOn', { title, date: fullDate }) : t('reminders.text.startedOnAt', { title, date: fullDate, time: hour })
  }
  if (startDay === today) return allDay ? t('reminders.text.startsToday', { title }) : t('reminders.text.startsAt', { title, time: hour })
  if (addDays(today, 1) === startDay) {
    return allDay ? t('reminders.text.startsTomorrow', { title }) : t('reminders.text.startsTomorrowAt', { title, time: hour })
  }
  if (sameMonth || sameYear) {
    const date = sameMonth ? dayInMonth : dayInYear
    return allDay ? t('reminders.text.startsOn', { title, date }) : t('reminders.text.startsOnAt', { title, date, time: hour })
  }
  return allDay ? t('reminders.text.startsOn', { title, date: fullDate }) : t('reminders.text.startsOnAt', { title, date: fullDate, time: hour })
}

/** Proton's display title: the summary, or "(no title)", cut to 100 characters. */
export function alarmTitle(summary: string | undefined | null, untitled: string): string {
  const title = summary?.trim() || untitled
  return title.length > 100 ? `${title.slice(0, 99)}…` : title
}
