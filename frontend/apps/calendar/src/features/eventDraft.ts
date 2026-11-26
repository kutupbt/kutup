import type { Calendar, CalendarEvent, Reminder } from '@kutup/calendar-core/api'
import { addDays, timeOf, type CivilDate } from '@kutup/calendar-core/time'
import type { CalendarTime, EventFields } from '@kutup/crypto/calendar'
import type { EditorTarget } from './editorState'
import { DEFAULT_DURATION_MINUTES } from './gridInteraction'
import type { FormValues } from './recurrence/actions'
import { ruleOf, type FrequencyModel } from './recurrence/frequency'

// What the event editor and the quick-create popover fill in, and what they
// save: the form's fields read from a target (a new event, one to change,
// one to duplicate) and written back as the Rust core takes them.

export interface Draft {
  calendarId: string
  title: string
  allDay: boolean
  startDate: CivilDate
  startTime: string
  endDate: CivilDate
  endTime: string
  tzid: string
  location: string
  /** The video meeting's link, if the event has one (E5c). */
  conference: string | null
  description: string
  /**
   * Proton's notifications: the calendar's defaults until edited
   * (`custom`); a timed and an all-day list, the one that applies saved.
   */
  reminders: { custom: boolean; timed: Reminder[]; allDay: Reminder[] }
  /** Proton's repeat choice; null until the stored rule is read. */
  frequency: FrequencyModel | null
}

/** The editor's reminders: the event's own (for its kind), else the calendar's defaults. */
export function remindersOf(calendar: Calendar | undefined, own: Reminder[] | null | undefined, allDay: boolean): Draft['reminders'] {
  const defaults = calendar?.defaultReminders ?? { timed: [], allDay: [] }
  if (!own) return { custom: false, timed: defaults.timed, allDay: defaults.allDay }
  return { custom: true, timed: allDay ? defaults.timed : own, allDay: allDay ? own : defaults.allDay }
}

function pad(n: number): string {
  return String(n).padStart(2, '0')
}

/** `HH:MM` from minutes since midnight. */
function hhmm(minutes: number): string {
  return `${pad(Math.floor(minutes / 60) % 24)}:${pad(minutes % 60)}`
}

/** The form a target opens with (its reminders and repeat are read apart). */
export function draftOf(target: EditorTarget, zone: string, defaultCalendar: string): Omit<Draft, 'reminders' | 'frequency'> {
  if (target.kind === 'new') {
    const start = target.minutes ?? 9 * 60
    const end = target.endMinutes ?? start + DEFAULT_DURATION_MINUTES
    const endDate = target.endDate ?? target.date
    return {
      calendarId: target.calendarId ?? defaultCalendar,
      title: target.title ?? '',
      allDay: target.allDay ?? false,
      startDate: target.date,
      startTime: hhmm(start),
      endDate: target.allDay ? (target.lastDate ?? target.date) : end >= 24 * 60 ? addDays(endDate, 1) : endDate,
      endTime: hhmm(end),
      tzid: zone,
      location: '',
      conference: target.conference ?? null,
      description: '',
    }
  }
  // A repeating event opens at its occurrence (Proton's: the form shows the one clicked).
  const instance = target.instance
  const fields = instance ? { ...target.event.fields, start: instance.start, end: instance.end } : target.event.fields
  // A duplicate goes to the event's calendar, or the first one written to when that one is only read.
  const calendarId = target.kind === 'duplicate' && !target.writable ? defaultCalendar : target.event.calendarId
  const base = { calendarId, title: fields.summary ?? '', location: fields.location ?? '', conference: fields.conference ?? null, description: fields.description ?? '' }
  const moved = target.kind === 'edit' ? target.moved : undefined
  if ('date' in fields.start) {
    if (moved) return { ...base, allDay: true, startDate: moved.start, startTime: '09:00', endDate: moved.end, endTime: '10:00', tzid: zone }
    const end = fields.end && 'date' in fields.end ? fields.end.date : addDays(fields.start.date, 1)
    // DTEND is exclusive; the form shows the last day.
    return { ...base, allDay: true, startDate: fields.start.date, startTime: '09:00', endDate: addDays(end, -1), endTime: '10:00', tzid: zone }
  }
  const local = (time: EventFields['start'] | null) => (time === null ? null : 'zoned' in time ? time.zoned.local : 'utc' in time ? time.utc.slice(0, 19) : `${time.date}T00:00:00`)
  const tzid = 'zoned' in fields.start ? fields.start.zoned.tzid : 'UTC'
  const start = moved?.start ?? local(fields.start)!
  const end = moved?.end ?? local(fields.end) ?? start
  return { ...base, allDay: false, startDate: start.slice(0, 10), startTime: timeOf(start), endDate: end.slice(0, 10), endTime: timeOf(end), tzid }
}

export function startOf(draft: Draft): CalendarTime {
  return draft.allDay ? { date: draft.startDate } : { zoned: { local: `${draft.startDate}T${draft.startTime}:00`, tzid: draft.tzid } }
}

/** What the form says, its rule written by the Rust core (`previous`: the stored rule, its WKST kept). */
export async function formOf(draft: Draft, weekStart: number, previous: string | null): Promise<FormValues> {
  const start = startOf(draft)
  return {
    start,
    end: draft.allDay ? { date: addDays(draft.endDate, 1) } : { zoned: { local: `${draft.endDate}T${draft.endTime}:00`, tzid: draft.tzid } },
    rrule: draft.frequency ? await ruleOf(draft.frequency, start, draft.startDate, weekStart, previous) : null,
    summary: draft.title.trim() || null,
    description: draft.description || null,
    location: draft.location.trim() || null,
    conference: draft.conference,
  }
}

/**
 * The editor's fields as the Rust core takes them: a new event, or one that
 * isn't a series changed (a changed occurrence whose series is gone stays
 * one, its RECURRENCE-ID kept). What a newer client wrote is kept.
 */
export function fieldsOf(form: FormValues, domain: string, existing?: CalendarEvent): EventFields {
  const now = new Date().toISOString().replace(/\.\d+Z$/, 'Z')
  const before = existing?.fields
  return {
    ...before,
    uid: before?.uid ?? `${crypto.randomUUID()}@${domain}`,
    dtstamp: now,
    created: before?.created ?? now,
    start: form.start,
    end: form.end,
    recurrenceId: before?.recurrenceId ?? null,
    rrule: before?.recurrenceId ? null : form.rrule,
    exdates: [],
    organizer: null,
    sequence: before ? (before.sequence ?? 0) + 1 : 0,
    summary: form.summary,
    description: form.description,
    location: form.location,
    conference: form.conference,
    status: before?.status ?? 'confirmed',
    transp: before?.transp ?? 'opaque',
    comment: before?.comment ?? null,
    other: before?.other ?? [],
  }
}

/** Whether the end comes after the start (one zone for both, so the local times compare). */
export function endsAfterStart(draft: Draft): boolean {
  if (draft.allDay) return draft.endDate >= draft.startDate
  return `${draft.endDate}T${draft.endTime}` > `${draft.startDate}T${draft.startTime}`
}
