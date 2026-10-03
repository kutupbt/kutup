import { takenParts, type Dated } from './timeline'

// Dates as people read them, in their language. A day or month key is a
// calendar date, not an instant: it is formatted in UTC so no time zone moves it.

function utcDate(key: string): Date {
  const [y, m, d] = key.split('-').map(Number)
  return new Date(Date.UTC(y, (m ?? 1) - 1, d ?? 1))
}

/** "July 2024". */
export function formatMonth(month: string, locale: string): string {
  return new Intl.DateTimeFormat(locale, { month: 'long', year: 'numeric', timeZone: 'UTC' }).format(utcDate(month))
}

/** "Mon, 1 July", with the year when it is not this year's. */
export function formatDay(day: string, locale: string, now = new Date()): string {
  const date = utcDate(day)
  const sameYear = date.getUTCFullYear() === now.getFullYear()
  return new Intl.DateTimeFormat(locale, {
    weekday: 'short',
    day: 'numeric',
    month: 'long',
    ...(sameYear ? {} : { year: 'numeric' }),
    timeZone: 'UTC',
  }).format(date)
}

/** "UTC+03:00", "UTC−05:30", "UTC". */
export function formatOffset(minutes: number): string {
  if (minutes === 0) return 'UTC'
  const sign = minutes < 0 ? '−' : '+'
  const abs = Math.abs(minutes)
  return `UTC${sign}${String(Math.floor(abs / 60)).padStart(2, '0')}:${String(abs % 60).padStart(2, '0')}`
}

/**
 * When it was taken, as the clock read where it was taken when the photo says
 * so (with that time zone), else in this device's time zone.
 */
export function formatTaken(item: Pick<Dated, 'takenAt' | 'takenOffset'>, locale: string): { date: string; time: string; zone: string | null } {
  const p = takenParts(item)
  const wall = new Date(Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute))
  const date = new Intl.DateTimeFormat(locale, { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' }).format(wall)
  const time = new Intl.DateTimeFormat(locale, { hour: '2-digit', minute: '2-digit', timeZone: 'UTC' }).format(wall)
  return { date, time, zone: item.takenOffset !== undefined ? formatOffset(item.takenOffset) : null }
}

/** "0:07", "12:34", "1:02:03". */
export function formatDuration(ms: number): string {
  const total = Math.max(0, Math.round(ms / 1000))
  const h = Math.floor(total / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60
  const ss = String(s).padStart(2, '0')
  return h > 0 ? `${h}:${String(m).padStart(2, '0')}:${ss}` : `${m}:${ss}`
}
