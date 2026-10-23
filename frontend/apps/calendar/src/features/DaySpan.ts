import type { PointerEvent as ReactPointerEvent } from 'react'
import { addDays, daysBetween, type CivilDate } from '@kutup/calendar-core/time'
import { openEditor } from './editorState'
import type { Placed } from './placement'
import { follow, type Point } from './press'

// Whole-day drags (Proton's day grid: the all-day row and the month): a
// span of days to make an all-day event, or an event moved by days. The
// day under the pointer is the nearest element with `data-day`.

function dayAt(point: Point): CivilDate | null {
  const element = document.elementFromPoint(point.x, point.y)
  return (element?.closest('[data-day]') as HTMLElement | null)?.dataset.day ?? null
}

export type DaySpanGhost = { kind: 'days'; from: CivilDate; to: CivilDate } | { kind: 'shift'; placed: Placed; days: number }

/** The first and last day of a span, in order. */
export function ordered(a: CivilDate, b: CivilDate): [CivilDate, CivilDate] {
  return a <= b ? [a, b] : [b, a]
}

/** A press on a day's empty space: drag across days for a multi-day all-day event, click for one day. */
export function pressDays(event: ReactPointerEvent, day: CivilDate, show: (ghost: DaySpanGhost | null) => void, scroller: HTMLElement | null) {
  let to = day
  follow(
    event,
    {
      armed: () => show({ kind: 'days', from: day, to }),
      drag: (point) => {
        to = dayAt(point) ?? to
        show({ kind: 'days', from: day, to })
      },
      drop: () => {
        show(null)
        const [first, last] = ordered(day, to)
        openEditor({ kind: 'new', date: first, allDay: true, lastDate: last })
      },
      click: () => openEditor({ kind: 'new', date: day, allDay: true }),
      cancel: () => show(null),
    },
    scroller,
  )
}

/** A press on an event in a day grid: drag to move it by whole days (its times kept), click to open it. */
export function pressShiftDays(
  event: ReactPointerEvent,
  placed: Placed,
  day: CivilDate,
  show: (ghost: DaySpanGhost | null) => void,
  moved: (placed: Placed, days: number, minutes: number) => void,
  scroller: HTMLElement | null,
) {
  event.stopPropagation()
  let days = 0
  follow(
    event,
    {
      armed: () => show({ kind: 'shift', placed, days }),
      drag: (point) => {
        const now = dayAt(point)
        if (now) days = daysBetween(day, now)
        show({ kind: 'shift', placed, days })
      },
      drop: () => {
        show(null)
        if (days !== 0) moved(placed, days, 0)
      },
      click: () => openEditor({ kind: 'edit', event: placed.event }),
      cancel: () => show(null),
    },
    scroller,
  )
}

/** Whether a day-grid ghost lights `day` up. */
export function ghostCovers(ghost: DaySpanGhost | null, day: CivilDate): boolean {
  if (!ghost) return false
  if (ghost.kind === 'days') {
    const [first, last] = ordered(ghost.from, ghost.to)
    return first <= day && day <= last
  }
  return addDays(ghost.placed.firstDay, ghost.days) <= day && day < addDays(ghost.placed.afterLastDay, ghost.days)
}
