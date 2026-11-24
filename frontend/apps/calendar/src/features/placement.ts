import { instantOf, type CalendarEvent } from '@kutup/calendar-core/api'
import { addDays, type CivilDate } from '@kutup/calendar-core/time'
import { localToUtc, occurrences, utcToLocal, type CalendarTime } from '@kutup/crypto/calendar'

/**
 * One occurrence of a repeating event: its times in the event's own form
 * (a date, a wall-clock time in its zone, or UTC), what a `RECURRENCE-ID` or
 * an `EXDATE` naming it carries, and its place in the series.
 */
export interface Instance {
  start: CalendarTime
  end: CalendarTime | null
  startUtc: string
  endUtc: string
  /** 1 for the first; 0 when not counted (a series without COUNT, walked from the window). */
  number: number
}

/** An event where the view's zone puts it. */
export interface Placed {
  /** Unique among what a view draws: the event, and the occurrence's start. */
  key: string
  event: CalendarEvent
  /** A repeating event's occurrence; null for an event that doesn't repeat (or a changed occurrence, itself an event). */
  instance: Instance | null
  color: string
  allDay: boolean
  /** Local date-times in the view's zone (`2026-10-29T09:30:00`); dates for all-day events. */
  start: string
  end: string
  /** The first day it covers and the day after its last. */
  firstDay: CivilDate
  afterLastDay: CivilDate
}

/** The most occurrences of one series a view draws (a daily one over the widest window is far fewer). */
export const MAX_OCCURRENCES = 1000

function meets(startUtc: string, endUtc: string, from: string, to: string): boolean {
  const [start, end, a, b] = [startUtc, endUtc, from, to].map(Date.parse)
  return start < b && (end > a || (start === end && start >= a))
}

async function placeTimes(
  event: CalendarEvent,
  instance: Instance | null,
  color: string,
  zone: string,
  start: CalendarTime,
  end: CalendarTime | null,
  startUtc: string,
  endUtc: string,
): Promise<Placed> {
  const key = instance ? `${event.id}@${startUtc}` : event.id
  if ('date' in start) {
    const after = end && 'date' in end ? end.date : addDays(start.date, 1)
    return { key, event, instance, color, allDay: true, start: start.date, end: after, firstDay: start.date, afterLastDay: after }
  }
  const [startLocal, endLocal] = await Promise.all([utcToLocal(startUtc, zone), utcToLocal(endUtc, zone)])
  const lastDay = endLocal.slice(11) === '00:00:00' && endLocal > startLocal ? addDays(endLocal.slice(0, 10), -1) : endLocal.slice(0, 10)
  return { key, event, instance, color, allDay: false, start: startLocal, end: endLocal, firstDay: startLocal.slice(0, 10), afterLastDay: addDays(lastDay, 1) }
}

/** An event that doesn't repeat (or one changed occurrence), where the view's zone puts it. */
export async function place(event: CalendarEvent, color: string, zone: string): Promise<Placed> {
  return placeTimes(event, null, color, zone, event.fields.start, event.fields.end, event.startUtc, event.endUtc)
}

/** An occurrence's end in the series' form: a date, or the end's wall-clock time in the start's zone. */
async function endOf(start: CalendarTime, endUtc: string): Promise<CalendarTime> {
  if ('date' in start) return { date: endUtc.slice(0, 10) }
  if ('utc' in start) return { utc: endUtc }
  return { zoned: { local: await utcToLocal(endUtc, start.zoned.tzid), tzid: start.zoned.tzid } }
}

/** The occurrences of a repeating event meeting `[from, to)`, each as the series' form names it. */
export async function instancesOf(event: CalendarEvent, from: string, to: string, max = MAX_OCCURRENCES): Promise<Instance[]> {
  const found = await occurrences(event.fields, from, to, max)
  return Promise.all(found.map(async (o) => ({ start: o.start, end: await endOf(o.start, o.endUtc), startUtc: o.startUtc, endUtc: o.endUtc, number: o.number })))
}

/**
 * Every event of a window where the view's zone puts it (Proton's
 * `getRecurringEvents`): a repeating one expanded into its occurrences
 * meeting `[from, to)`, less the ones a changed occurrence (an event with its
 * UID and a RECURRENCE-ID) replaces, wherever that one was moved to. An
 * event or occurrence that doesn't meet the window isn't drawn (the server
 * lists changed occurrences whose original meets it).
 */
export async function placeAll(events: CalendarEvent[], colorOf: (event: CalendarEvent) => string, zone: string, from: string, to: string): Promise<Placed[]> {
  const changed = new Map<string, Set<number>>()
  await Promise.all(
    events
      .filter((event) => event.fields.recurrenceId)
      .map(async (event) => {
        const key = `${event.calendarId}\n${event.fields.uid}`
        const set = changed.get(key) ?? new Set<number>()
        set.add(Date.parse(await instantOf(event.fields.recurrenceId!)))
        changed.set(key, set)
      }),
  )
  const placed = await Promise.all(
    events.map(async (event): Promise<Placed[]> => {
      const color = colorOf(event)
      if (!event.fields.rrule || event.fields.recurrenceId) {
        return meets(event.startUtc, event.endUtc, from, to) ? [await place(event, color, zone)] : []
      }
      const replaced = changed.get(`${event.calendarId}\n${event.fields.uid}`)
      let instances: Instance[]
      try {
        instances = await instancesOf(event, from, to)
      } catch {
        // A series this client can't expand (the server stored it, so it
        // checks out there): its first occurrence only, as it was signed.
        return meets(event.startUtc, event.endUtc, from, to) ? [await place(event, color, zone)] : []
      }
      return Promise.all(
        instances
          .filter((instance) => !replaced?.has(Date.parse(instance.startUtc)))
          .map((instance) => placeTimes(event, instance, color, zone, instance.start, instance.end, instance.startUtc, instance.endUtc)),
      )
    }),
  )
  return placed.flat()
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
