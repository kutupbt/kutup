// How pressing and dragging on the calendar's grid turns into a span, as
// Proton's time grid does it (WebClients applications/calendar,
// interactions/timeGridMouseHandler.ts): times snap down to 30 minutes, a
// press becomes a drag past 20 px, a span is at least one slot. Beyond
// Proton (docs/plans/calendar.md, "Calendar UX parity"): touch drags after
// a long press, so a plain swipe still scrolls; regular events resize by
// their bottom edge.

/** Proton's step: 30 minutes, not a setting. */
export const SNAP_MINUTES = 30
/** Proton's `CREATE_SENSITIVITY`: pixels before a press becomes a drag. */
export const DRAG_THRESHOLD_PX = 20
/** A touch must rest this long before it drags (a swipe before it scrolls). */
export const LONG_PRESS_MS = 400
/** How far a resting touch may wander and still count as resting. */
export const LONG_PRESS_SLOP_PX = 10
/** Proton's `DEFAULT_EVENT_DURATION`: a click makes an event this long. */
export const DEFAULT_DURATION_MINUTES = 30
export const DAY_MINUTES = 24 * 60

/**
 * Where the N shortcut's new event goes (Proton's): at the next half hour
 * after `nowMinutes` (the minute of the day in the calendar's zone), for
 * the default length; past today's last start, tomorrow's first, never a
 * start already gone.
 */
export function newEventStart(nowMinutes: number, duration = DEFAULT_DURATION_MINUTES): { dayOffset: number; start: number; end: number } {
  const start = Math.ceil((nowMinutes + 1) / SNAP_MINUTES) * SNAP_MINUTES
  if (start + duration > DAY_MINUTES) return { dayOffset: 1, start: 0, end: duration }
  return { dayOffset: 0, start, end: start + duration }
}

/** Minutes snapped down to the step, within the day. */
export function snap(minutes: number, step = SNAP_MINUTES): number {
  const clamped = Math.min(Math.max(minutes, 0), DAY_MINUTES - 1)
  return Math.floor(clamped / step) * step
}

/**
 * The span a create drag covers, from the pressed slot to the slot under
 * the pointer (both snapped): down, the press slot to the pointer's end;
 * up, the pointer's slot to the press slot; at least one slot, never past
 * midnight. Proton's rules.
 */
export function createSpan(pressSlot: number, pointerSlot: number, step = SNAP_MINUTES): { start: number; end: number } {
  if (pointerSlot >= pressSlot) return { start: pressSlot, end: Math.min(pointerSlot + step, DAY_MINUTES) }
  return { start: pointerSlot, end: pressSlot }
}

/** A plain click's event: the clicked slot and the default length, never past midnight. */
export function clickSpan(slot: number, duration = DEFAULT_DURATION_MINUTES): { start: number; end: number } {
  return { start: slot, end: Math.min(slot + duration, DAY_MINUTES) }
}

/**
 * A resize from the bottom edge: the end follows the pointer's slot end,
 * at least one slot after the start, never past midnight.
 */
export function resizeEnd(start: number, pointerSlot: number, step = SNAP_MINUTES): number {
  return Math.min(Math.max(pointerSlot + step, start + step), DAY_MINUTES)
}

/** A local date-time (`YYYY-MM-DDTHH:MM:SS`) moved by whole days and minutes. */
export function shiftLocal(local: string, days: number, minutes: number): string {
  const [date, time] = local.split('T')
  const [y, m, d] = date.split('-').map(Number)
  const [hh, mm, ss] = time.split(':').map(Number)
  const at = new Date(Date.UTC(y, m - 1, d, hh, mm + minutes, ss))
  at.setUTCDate(at.getUTCDate() + days)
  return at.toISOString().slice(0, 19)
}

/** `YYYY-MM-DDTHH:MM:00` from a day and minutes since midnight (24:00 is the next day's 00:00). */
export function localAt(day: string, minutes: number): string {
  return shiftLocal(`${day}T00:00:00`, 0, minutes)
}

export type PressKind = 'mouse' | 'touch'

/**
 * One press on the grid, from down to up: whether it is still a click, has
 * become a drag, or (touch) was a scroll. A mouse drags once it moves past
 * the threshold; a touch only after resting `LONG_PRESS_MS` (then any move
 * drags), and a touch that moves before is a scroll, never a drag.
 */
export class Press {
  readonly kind: PressKind
  private readonly x: number
  private readonly y: number
  private readonly at: number
  state: 'pressed' | 'armed' | 'dragging' | 'scrolling' = 'pressed'

  constructor(kind: PressKind, x: number, y: number, at: number) {
    this.kind = kind
    this.x = x
    this.y = y
    this.at = at
  }

  /** Time passes (a timer while a touch rests): armed once it has rested long enough. */
  tick(now: number): void {
    if (this.kind === 'touch' && this.state === 'pressed' && now - this.at >= LONG_PRESS_MS) this.state = 'armed'
  }

  /** The pointer moved: what the press is now. */
  move(x: number, y: number, now: number): Press['state'] {
    this.tick(now)
    const far = Math.hypot(x - this.x, y - this.y)
    if (this.state === 'pressed') {
      if (this.kind === 'mouse' && far > DRAG_THRESHOLD_PX) this.state = 'dragging'
      else if (this.kind === 'touch' && far > LONG_PRESS_SLOP_PX) this.state = 'scrolling'
    } else if (this.state === 'armed') {
      this.state = 'dragging'
    }
    return this.state
  }

  /** Whether the press, ending now, was a click (no drag, no scroll). */
  isClick(): boolean {
    return this.state === 'pressed' || this.state === 'armed'
  }
}
