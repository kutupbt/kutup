import type { CivilDate } from '@kutup/calendar-core/time'

// Dates and times in the person's language. A civil date or a local time is
// formatted as if in UTC, so the browser's own zone never shifts it: the
// view's zone has already been applied (`utcToLocal`).

function asUtc(local: string): Date {
  return new Date(local.length === 10 ? `${local}T00:00:00Z` : `${local}Z`)
}

export function formatTime(local: string, locale: string, hour12: boolean | null): string {
  return new Intl.DateTimeFormat(locale, {
    hour: 'numeric',
    minute: '2-digit',
    timeZone: 'UTC',
    ...(hour12 === null ? {} : { hour12 }),
  }).format(asUtc(local))
}

export function formatHour(hour: number, locale: string, hour12: boolean | null): string {
  return new Intl.DateTimeFormat(locale, { hour: 'numeric', timeZone: 'UTC', ...(hour12 === null ? {} : { hour12 }) }).format(
    new Date(Date.UTC(2026, 0, 1, hour)),
  )
}

export function formatWeekday(date: CivilDate, locale: string, width: 'short' | 'long' = 'short'): string {
  return new Intl.DateTimeFormat(locale, { weekday: width, timeZone: 'UTC' }).format(asUtc(date))
}

export function formatDayNumber(date: CivilDate, locale: string): string {
  return new Intl.DateTimeFormat(locale, { day: 'numeric', timeZone: 'UTC' }).format(asUtc(date))
}

/** The toolbar's title: "October 2026", or a day. */
export function formatTitle(view: 'day' | 'week' | 'month', date: CivilDate, locale: string): string {
  if (view === 'day') {
    return new Intl.DateTimeFormat(locale, { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' }).format(asUtc(date))
  }
  return new Intl.DateTimeFormat(locale, { month: 'long', year: 'numeric', timeZone: 'UTC' }).format(asUtc(date))
}

export function formatLongDate(date: CivilDate, locale: string): string {
  return new Intl.DateTimeFormat(locale, { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' }).format(asUtc(date))
}

/** The zones to choose from, `current` among them even when the database doesn't name it. */
export function zoneOptions(zones: string[] | undefined, current: string): { value: string; label: string }[] {
  const all = zones ?? [current]
  return (all.includes(current) ? all : [current, ...all]).map((zone) => ({ value: zone, label: zone.replaceAll('_', ' ') }))
}
