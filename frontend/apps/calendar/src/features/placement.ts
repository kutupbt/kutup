import type { CalendarEvent } from '@kutup/calendar-core/api'
import { addDays, type CivilDate } from '@kutup/calendar-core/time'
import { localToUtc, utcToLocal } from '@kutup/crypto/calendar'

/** An event where the view's zone puts it. */
export interface Placed {
  event: CalendarEvent
  color: string
  allDay: boolean
  /** Local date-times in the view's zone (`2026-10-29T09:30:00`); dates for all-day events. */
  start: string
  end: string
  /** The first day it covers and the day after its last. */
  firstDay: CivilDate
  afterLastDay: CivilDate
}

export async function place(event: CalendarEvent, color: string, zone: string): Promise<Placed> {
  const { start, end } = event.fields
  if ('date' in start) {
    const after = end && 'date' in end ? end.date : addDays(start.date, 1)
    return { event, color, allDay: true, start: start.date, end: after, firstDay: start.date, afterLastDay: after }
  }
  const [startLocal, endLocal] = await Promise.all([utcToLocal(event.startUtc, zone), utcToLocal(event.endUtc, zone)])
  const lastDay = endLocal.slice(11) === '00:00:00' && endLocal > startLocal ? addDays(endLocal.slice(0, 10), -1) : endLocal.slice(0, 10)
  return { event, color, allDay: false, start: startLocal, end: endLocal, firstDay: startLocal.slice(0, 10), afterLastDay: addDays(lastDay, 1) }
}

export function covers(placed: Placed, day: CivilDate): boolean {
  return placed.firstDay <= day && day < placed.afterLastDay
}

/** The zone an event's times are written in (the editor keeps it). */
export function eventZone(event: CalendarEvent): string {
  const start = event.fields.start
  return 'zoned' in start ? start.zoned.tzid : 'UTC'
}

/** A local date-time in the view's zone as the same instant in `zone`. */
export async function inZone(local: string, viewZone: string, zone: string): Promise<string> {
  if (zone === viewZone) return local
  return utcToLocal(await localToUtc(local, viewZone), zone)
}

/** Timed events of one day laid out in columns where they overlap. */
export function columns<T extends { top: number; bottom: number }>(segments: T[]): (T & { column: number; columns: number })[] {
  const sorted = [...segments].sort((a, b) => a.top - b.top || b.bottom - a.bottom)
  const out: (T & { column: number; columns: number })[] = []
  let cluster: (T & { column: number; columns: number })[] = []
  let clusterEnd = -1
  const flush = () => {
    const count = Math.max(1, ...cluster.map((s) => s.column + 1))
    for (const s of cluster) out.push({ ...s, columns: count })
    cluster = []
  }
  for (const segment of sorted) {
    if (segment.top >= clusterEnd) {
      flush()
      clusterEnd = -1
    }
    const used = new Set(cluster.filter((s) => s.bottom > segment.top).map((s) => s.column))
    let column = 0
    while (used.has(column)) column++
    cluster.push({ ...segment, column, columns: 1 })
    clusterEnd = Math.max(clusterEnd, segment.bottom)
  }
  flush()
  return out
}
