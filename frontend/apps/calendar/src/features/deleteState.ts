import { useSyncExternalStore } from 'react'
import type { CalendarEvent } from '@kutup/calendar-core/api'
import type { Instance } from './placement'

// The delete being asked about (`EventDeleteFlow` asks), from the editor or
// the event's popover.

export interface DeleteRequest {
  event: CalendarEvent
  instance: Instance | null | undefined
  /** After the delete landed (the editor closes). */
  onDone?: () => void
}

let current: DeleteRequest | null = null
const listeners = new Set<() => void>()

export function setDeleteRequest(next: DeleteRequest | null): void {
  current = next
  for (const listener of listeners) listener()
}

/** Asks to delete `event` (the occurrence `instance` of a repeating one). */
export function requestDelete(event: CalendarEvent, instance?: Instance | null, onDone?: () => void): void {
  setDeleteRequest({ event, instance, onDone })
}

/** The delete being asked about, if any (a button shows it as pending). */
export function useDeleteRequest(): DeleteRequest | null {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    () => current,
    () => current,
  )
}

/** Whether an event is part of a series: one itself, or one changed occurrence of it. */
export function isRecurring(event: CalendarEvent | undefined): boolean {
  return !!event && (!!event.fields.rrule || !!event.fields.recurrenceId)
}
