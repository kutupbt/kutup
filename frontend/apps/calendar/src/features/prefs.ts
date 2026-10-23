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
/** The account's zone, once read (`useAccountZone`): this device's when it chose none. */
let accountZone: string | null = null

function defaults(): CalendarPrefs {
  return {
    zone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
    weekStart: localeWeekStart(navigator.language),
    hour12: null,
  }
}

/** What this device chose, as stored. */
function stored(): Partial<CalendarPrefs> {
  try {
    return JSON.parse(localStorage.getItem(KEY) ?? '{}') as Partial<CalendarPrefs>
  } catch {
    return {}
  }
}

function read(): CalendarPrefs {
  if (cached) return cached
  const own = stored()
  const base = defaults()
  cached = {
    // A zone chosen here, else the account's, else the browser's.
    zone: typeof own.zone === 'string' && own.zone ? own.zone : (accountZone ?? base.zone),
    weekStart: typeof own.weekStart === 'number' && own.weekStart >= 0 && own.weekStart <= 6 ? own.weekStart : base.weekStart,
    hour12: typeof own.hour12 === 'boolean' ? own.hour12 : null,
  }
  return cached
}

function changed(): void {
  cached = null
  for (const listener of listeners) listener()
}

/** Whether this device chose its zone in the settings (else it shows the account's, or the browser's). */
export function zoneChosen(): boolean {
  const own = stored()
  return typeof own.zone === 'string' && own.zone !== ''
}

/** The account's zone, shown where this device chose none; never stored as this device's choice. */
export function setAccountZone(zone: string | null): void {
  if (zone === accountZone) return
  accountZone = zone
  changed()
}

/** This device's choices (the settings): only what is passed is stored as chosen. */
export function setPrefs(change: Partial<CalendarPrefs>): void {
  try {
    localStorage.setItem(KEY, JSON.stringify({ ...stored(), ...change }))
  } catch {
    // Not kept (private window): it holds for this tab.
    cached = { ...read(), ...change }
    for (const listener of listeners) listener()
    return
  }
  changed()
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
