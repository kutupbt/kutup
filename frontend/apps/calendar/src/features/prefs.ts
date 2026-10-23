import { useSyncExternalStore } from 'react'
import { localeWeekStart } from '@kutup/calendar-core/time'

// How this browser shows calendars: the time zone, the first day of the
// week and the clock, kept on this device. The zone is the account's too
// (`/api/calendar/settings`): all-day reminders fire in it (`useAccountZone`).

export interface CalendarPrefs {
  /** An IANA zone; the browser's by default. */
  zone: string
  /** 0 Sunday … 6 Saturday; the locale's by default. */
  weekStart: number
  /** null: the locale's clock. */
  hour12: boolean | null
}

const KEY = 'kutup-calendar-prefs'
const listeners = new Set<() => void>()
let cached: CalendarPrefs | null = null

function defaults(): CalendarPrefs {
  return {
    zone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
    weekStart: localeWeekStart(navigator.language),
    hour12: null,
  }
}

function read(): CalendarPrefs {
  if (cached) return cached
  let stored: Partial<CalendarPrefs> = {}
  try {
    stored = JSON.parse(localStorage.getItem(KEY) ?? '{}') as Partial<CalendarPrefs>
  } catch {
    stored = {}
  }
  const base = defaults()
  cached = {
    zone: typeof stored.zone === 'string' && stored.zone ? stored.zone : base.zone,
    weekStart: typeof stored.weekStart === 'number' && stored.weekStart >= 0 && stored.weekStart <= 6 ? stored.weekStart : base.weekStart,
    hour12: typeof stored.hour12 === 'boolean' ? stored.hour12 : null,
  }
  return cached
}

/** Whether this device chose its zone (else it shows the browser's, or the account's once read). */
export function zoneChosen(): boolean {
  try {
    const stored = JSON.parse(localStorage.getItem(KEY) ?? '{}') as Partial<CalendarPrefs>
    return typeof stored.zone === 'string' && stored.zone !== ''
  } catch {
    return false
  }
}

export function setPrefs(change: Partial<CalendarPrefs>): void {
  cached = { ...read(), ...change }
  try {
    localStorage.setItem(KEY, JSON.stringify(cached))
  } catch {
    // Not kept (private window): it holds for this tab.
  }
  for (const listener of listeners) listener()
}

export function useCalendarPrefs(): CalendarPrefs {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    read,
    read,
  )
}
