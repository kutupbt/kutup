import { useSyncExternalStore } from 'react'
import type { CalendarEvent } from '@kutup/calendar-core/api'
import type { CivilDate } from '@kutup/calendar-core/time'

/**
 * What the event editor is open for: a new event (at a day, maybe a span
 * a drag chose), or one to change (maybe moved or resized on the grid,
 * not saved until the editor's Save).
 */
export type EditorTarget =
  | {
      kind: 'new'
      date: CivilDate
      /** The start, minutes since midnight; the end, on `endDate`. */
      minutes?: number
      endDate?: CivilDate
      endMinutes?: number
      allDay?: boolean
      /** All-day: the last day it covers (a drag across days). */
      lastDate?: CivilDate
    }
  | {
      kind: 'edit'
      event: CalendarEvent
      /**
       * Where a drag put it: local date-times in the event's own zone
       * (`YYYY-MM-DDTHH:MM:SS`), or for an all-day event its first and last
       * days (`YYYY-MM-DD`).
       */
      moved?: { start: string; end: string }
    }

let target: EditorTarget | null = null
const listeners = new Set<() => void>()

export function openEditor(next: EditorTarget | null): void {
  target = next
  for (const listener of listeners) listener()
}

export function useEditorTarget(): EditorTarget | null {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    () => target,
    () => target,
  )
}
