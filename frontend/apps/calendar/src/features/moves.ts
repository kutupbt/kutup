import { addDays, minutesOf, type CivilDate } from '@kutup/calendar-core/time'
import { localToUtc, utcToLocal } from '@kutup/crypto/calendar'
import { openEditor } from './editorState'
import { DAY_MINUTES, localAt, shiftLocal } from './gridInteraction'
import { eventZone, inZone, type Placed } from './placement'

// An event moved or resized on the grid opens in the editor with its new
// times, saved only by the editor's Save (as Proton's popover asks). Times
// stay in the event's own zone: the grid's are the view's. A move keeps the
// event's length on the wall clock: one moved across a change of offset
// starts and ends at the same clock times, so it lasts an hour more or less
// in real time (as Proton's grid, and as a repeating event's occurrences).

/**
 * Opens a new timed event from `start` to `end` (minutes of `date`, in the
 * view's zone). A start the zone skips that day (the hour summer time
 * removes) is read with the offset before the gap (RFC 5545 §3.3.5): 02:30
 * is 03:30, and the event keeps its length.
 */
export async function openNew(date: CivilDate, start: number, end: number, zone: string): Promise<void> {
  const local = localAt(date, start)
  const real = await utcToLocal(await localToUtc(local, zone), zone)
  const shift = real === local ? 0 : (real.slice(0, 10) === date ? minutesOf(real) : minutesOf(real) + DAY_MINUTES) - start
  const from = start + shift
  const to = end + shift
  openEditor({
    kind: 'new',
    date: from >= DAY_MINUTES ? addDays(date, 1) : date,
    minutes: from % DAY_MINUTES,
    ...(to > DAY_MINUTES ? { endDate: addDays(date, Math.floor(to / DAY_MINUTES)), endMinutes: to % DAY_MINUTES } : { endMinutes: to }),
  })
}

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
