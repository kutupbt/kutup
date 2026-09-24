import type { TFunction } from 'i18next'

// Timestamps as Signal Desktop shows them (formatDateTimeShort): "now",
// minutes for the last hour, the time today, the weekday this week, the day
// and month within half a year, else the full date.

const MINUTE = 60_000
const HOUR = 60 * MINUTE
const DAY = 24 * HOUR

function sameDay(a: Date, b: Date): boolean {
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate()
}

/** A conversation list or message timestamp, short. */
export function formatShortTime(ms: number, now: number, locale: string, t: TFunction): string {
  const age = now - ms
  if (age < MINUTE) return t('chat.time.now')
  if (age < HOUR) return t('chat.time.minutes', { count: Math.floor(age / MINUTE) })
  const at = new Date(ms)
  const today = new Date(now)
  if (sameDay(at, today)) return at.toLocaleTimeString(locale, { hour: 'numeric', minute: '2-digit' })
  if (age < 7 * DAY) return at.toLocaleDateString(locale, { weekday: 'short' })
  if (age < 182 * DAY) return at.toLocaleDateString(locale, { day: 'numeric', month: 'short' })
  return at.toLocaleDateString(locale, { day: 'numeric', month: 'short', year: 'numeric' })
}

/** The time of day, for a message's metadata. */
export function formatClock(ms: number, locale: string): string {
  return new Date(ms).toLocaleTimeString(locale, { hour: 'numeric', minute: '2-digit' })
}

/** A day heading in the timeline: Today, Yesterday, "Tue, 12 Mar", "12 Mar 2024". */
export function formatDayHeader(ms: number, now: number, locale: string, t: TFunction): string {
  const at = new Date(ms)
  const today = new Date(now)
  if (sameDay(at, today)) return t('chat.time.today')
  if (sameDay(at, new Date(now - DAY))) return t('chat.time.yesterday')
  if (now - ms < 182 * DAY) return at.toLocaleDateString(locale, { weekday: 'short', day: 'numeric', month: 'short' })
  return at.toLocaleDateString(locale, { day: 'numeric', month: 'short', year: 'numeric' })
}

export function isSameDay(a: number, b: number): boolean {
  return sameDay(new Date(a), new Date(b))
}
