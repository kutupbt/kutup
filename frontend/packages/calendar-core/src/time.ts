// Calendar dates as the views lay them out: civil dates (`2026-10-29`) with
// no zone, so day arithmetic never meets a daylight-saving jump. Converting
// a date or time to an instant goes through the bundled time zone database
// (`@kutup/crypto/calendar`), as the server does.

/** A civil date, `YYYY-MM-DD`. */
export type CivilDate = string

const DAY_MS = 24 * 60 * 60 * 1000

function toUtcMs(date: CivilDate): number {
  const [y, m, d] = date.split('-').map(Number)
  return Date.UTC(y, m - 1, d)
}

function fromUtcMs(ms: number): CivilDate {
  return new Date(ms).toISOString().slice(0, 10)
}

export function isCivilDate(value: string): boolean {
  return /^\d{4}-\d{2}-\d{2}$/.test(value) && fromUtcMs(toUtcMs(value)) === value
}

export function addDays(date: CivilDate, days: number): CivilDate {
  return fromUtcMs(toUtcMs(date) + days * DAY_MS)
}

/** Days from `a` to `b` (negative when `b` comes first). */
export function daysBetween(a: CivilDate, b: CivilDate): number {
  return Math.round((toUtcMs(b) - toUtcMs(a)) / DAY_MS)
}

/** 0 for Sunday … 6 for Saturday. */
export function weekday(date: CivilDate): number {
  return new Date(toUtcMs(date)).getUTCDay()
}

/** The first day of the week holding `date`, weeks starting on `weekStart` (0 Sunday, 1 Monday, 6 Saturday). */
export function startOfWeek(date: CivilDate, weekStart: number): CivilDate {
  return addDays(date, -((weekday(date) - weekStart + 7) % 7))
}

export function startOfMonth(date: CivilDate): CivilDate {
  return `${date.slice(0, 7)}-01`
}

export function addMonths(date: CivilDate, months: number): CivilDate {
  const [y, m] = date.split('-').map(Number)
  const total = y * 12 + (m - 1) + months
  return `${String(Math.floor(total / 12)).padStart(4, '0')}-${String((total % 12) + 1).padStart(2, '0')}-01`
}

/** The six weeks a month view shows: the week holding the 1st and five more. */
export function monthGrid(date: CivilDate, weekStart: number): CivilDate[][] {
  const first = startOfWeek(startOfMonth(date), weekStart)
  return Array.from({ length: 6 }, (_, week) => Array.from({ length: 7 }, (_, day) => addDays(first, week * 7 + day)))
}

/** The days a view shows: one, a week from `weekStart`, or a month's six weeks. */
export function viewDays(view: 'day' | 'week' | 'month', date: CivilDate, weekStart: number): CivilDate[] {
  if (view === 'day') return [date]
  if (view === 'week') {
    const first = startOfWeek(date, weekStart)
    return Array.from({ length: 7 }, (_, day) => addDays(first, day))
  }
  return monthGrid(date, weekStart).flat()
}

/** Where `view` goes from `date` one step back or forward. */
export function step(view: 'day' | 'week' | 'month', date: CivilDate, by: -1 | 1): CivilDate {
  if (view === 'day') return addDays(date, by)
  if (view === 'week') return addDays(date, 7 * by)
  return addMonths(date, by)
}

/** `HH:MM` of a local date-time string (`2026-10-29T09:30:00`). */
export function timeOf(local: string): string {
  return local.slice(11, 16)
}

/** Minutes since midnight of a local date-time string. */
export function minutesOf(local: string): number {
  return Number(local.slice(11, 13)) * 60 + Number(local.slice(14, 16))
}

/** The first day of the week where the browser's locale starts it (Intl's week info), else Monday. */
export function localeWeekStart(locale: string): number {
  try {
    const info = (new Intl.Locale(locale) as Intl.Locale & { getWeekInfo?: () => { firstDay: number }; weekInfo?: { firstDay: number } })
    const firstDay = info.getWeekInfo?.().firstDay ?? info.weekInfo?.firstDay
    if (firstDay) return firstDay % 7
  } catch {
    // An unknown locale: Monday.
  }
  return 1
}
