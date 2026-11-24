import { useSyncExternalStore } from 'react'
import type { CivilDate } from '@kutup/calendar-core/time'
import type { EditorTarget } from './editorState'
import type { Placed } from './placement'

/** A new event as the editor takes it. */
export type NewTarget = Extract<EditorTarget, { kind: 'new' }>

/**
 * The calendar's one popover (Proton's `InteractiveCalendarView` shows one
 * at a time): an event's details (`EventPopover`), a new event's title
 * (`CreateEventPopover`), or a month day's events (`MorePopoverEvent`).
 */
export type PopoverTarget = { kind: 'event'; placed: Placed } | { kind: 'create'; target: NewTarget } | { kind: 'more'; day: CivilDate }

export type OpenPopover = PopoverTarget & {
  /** What it points at; a new event's draft on the grid when it is drawn (`data-calendar-draft`). */
  anchor: Element
  /** Where focus goes back when it closes (what had it when it opened). */
  returnFocus: HTMLElement | null
  /** Each opening's own, so a popover's state starts afresh. */
  id: number
}

let open: OpenPopover | null = null
let next = 1
const listeners = new Set<() => void>()

function emit(): void {
  for (const listener of listeners) listener()
}

/**
 * Opens `target` at `anchor`, closing whatever was open; focus goes back to
 * `returnFocus` (by default what has it now, else the anchor).
 */
export function openPopover(target: PopoverTarget, anchor: Element, returnFocus?: HTMLElement | null): void {
  const focused = document.activeElement instanceof HTMLElement && document.activeElement !== document.body ? document.activeElement : null
  open = { ...target, anchor, returnFocus: returnFocus !== undefined ? returnFocus : (focused ?? (anchor instanceof HTMLElement ? anchor : null)), id: next++ }
  emit()
}

/**
 * Closes the popover. `refocus`: focus goes back where it was (Escape, the
 * close button); not when the person clicked elsewhere, nor when a dialog
 * takes over (it is focused first, so the dialog gives focus back there).
 */
export function closePopover(refocus: boolean): void {
  const was = open
  if (!was) return
  open = null
  emit()
  if (refocus && was.returnFocus?.isConnected) was.returnFocus.focus({ preventScroll: true })
}

/** Hands over to a dialog: focus back where the popover opened from first, so the dialog returns it there. */
export function handOver(then: () => void): void {
  const was = open
  if (was?.returnFocus?.isConnected) was.returnFocus.focus({ preventScroll: true })
  open = null
  emit()
  then()
}

/** The popover open now (read outside React: the anchor's measure). */
export function currentPopover(): OpenPopover | null {
  return open
}

/** Whether a popover is open now (a press on the grid then only closes it, as Proton's). */
export function popoverOpen(): boolean {
  return open !== null
}

export function usePopover(): OpenPopover | null {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    () => open,
    () => open,
  )
}
