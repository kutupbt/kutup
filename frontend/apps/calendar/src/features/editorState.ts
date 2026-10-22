import { useSyncExternalStore } from 'react'
import type { CalendarEvent } from '@kutup/calendar-core/api'
import type { CivilDate } from '@kutup/calendar-core/time'

/** What the event editor is open for: a new event (at a day, maybe an hour), or one to change. */
export type EditorTarget =
  | { kind: 'new'; date: CivilDate; minutes?: number; allDay?: boolean }
  | { kind: 'edit'; event: CalendarEvent }

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
