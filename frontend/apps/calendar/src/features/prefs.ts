import { useSyncExternalStore } from 'react'
import { localeWeekStart } from '@kutup/calendar-core/time'

// How this browser shows calendars: the time zone, the first day of the
// week and the clock. Kept on this device (E1); the account-wide settings
// come with reminders (docs/plans/calendar.md, E2).

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
