import type { MeetingInfo } from './callLinks'

// How a meeting's planned time is written and read in forms and lists.

/** Lengths the schedule form offers, in minutes. */
export const MEETING_LENGTHS = [15, 30, 45, 60, 90, 120] as const

/** `YYYY-MM-DD` and `HH:MM` in this browser's time zone, for date and time inputs. */
export function localDateTime(ms: number): { date: string; time: string } {
  const at = new Date(ms)
  const pad = (value: number) => String(value).padStart(2, '0')
  return {
    date: `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())}`,
    time: `${pad(at.getHours())}:${pad(at.getMinutes())}`,
  }
}

/** The moment a date and time input name, in this browser's time zone; null when incomplete. */
export function fromLocalDateTime(date: string, time: string): number | null {
  const day = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date)
  const clock = /^(\d{2}):(\d{2})$/.exec(time)
  if (!day || !clock) return null
  const at = new Date(Number(day[1]), Number(day[2]) - 1, Number(day[3]), Number(clock[1]), Number(clock[2]))
  return Number.isNaN(at.getTime()) ? null : at.getTime()
}

/** "Tue, Oct 6, 2:00 PM" in the reader's language and time zone; with the year when it is not this one. */
export function meetingStartText(ms: number, locale: string, nowMs = Date.now()): string {
  const at = new Date(ms)
  return at.toLocaleString(locale, {
    weekday: 'short',
    month: 'short',
    day: 'numeric',
    ...(at.getFullYear() === new Date(nowMs).getFullYear() ? {} : { year: 'numeric' }),
    hour: 'numeric',
    minute: '2-digit',
  })
}

/** Whether a meeting is still ahead (or under way): its planned end has not passed. */
export function isUpcoming(info: MeetingInfo, nowMs: number): boolean {
  if (info.startsAtMs === undefined) return false
  return info.startsAtMs + (info.durationMinutes ?? 60) * 60_000 > nowMs
}

/** The next quarter hour at least ten minutes away: a sensible default start. */
export function defaultStart(nowMs: number): number {
  const quarter = 15 * 60_000
  return Math.ceil((nowMs + 10 * 60_000) / quarter) * quarter
}
