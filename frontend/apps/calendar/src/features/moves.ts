import { addDays } from '@kutup/calendar-core/time'
import { openEditor } from './editorState'
import { shiftLocal } from './gridInteraction'
import { eventZone, inZone, type Placed } from './placement'

// An event moved or resized on the grid opens in the editor with its new
// times, saved only by the editor's Save (as Proton's popover asks). Times
// stay in the event's own zone: the grid's are the view's.

/** Opens `placed` moved by days and minutes (an all-day event by days). */
export async function openMoved(placed: Placed, days: number, minutes: number, viewZone: string): Promise<void> {
  if (placed.allDay) {
    openEditor({ kind: 'edit', event: placed.event, moved: { start: addDays(placed.firstDay, days), end: addDays(placed.afterLastDay, days - 1) } })
    return
  }
  await openTimes(placed, shiftLocal(placed.start, days, minutes), shiftLocal(placed.end, days, minutes), viewZone)
}

/** Opens `placed` with new local start and end in the view's zone. */
export async function openTimes(placed: Placed, start: string, end: string, viewZone: string): Promise<void> {
  const zone = eventZone(placed.event)
  const [startThere, endThere] = await Promise.all([inZone(start, viewZone, zone), inZone(end, viewZone, zone)])
  openEditor({ kind: 'edit', event: placed.event, moved: { start: startThere, end: endThere } })
}
