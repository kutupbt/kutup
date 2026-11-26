import { instantOf, type CalendarEvent, type Reminder } from '@kutup/calendar-core/api'
import { addDays, daysBetween, type CivilDate } from '@kutup/calendar-core/time'
import { occurrences, readRule, ruleText, supportedUntil, type CalendarTime, type EventFields } from '@kutup/crypto/calendar'
import { instancesOf, type Instance } from '../placement'

// Changing or deleting one occurrence of a repeating event, it and the ones
// after, or all of them: Proton's (`applications/calendar/src/app/containers/
// calendar/recurrence`, `eventActions/getSaveRecurringEventActions.ts`,
// `getDeleteRecurringEventActions.ts`, `getRecurringUpdateAllPossibilities.ts`,
// `sequence.ts`), planned whole before anything is sent (docs/plans/
// calendar.md, E2 §2 Q-1) as the sync changes to make, in order.

/** Proton's `RECURRING_TYPES`: this event, this and future events, all events. */
export type RecurringType = 'single' | 'future' | 'all'

export type Step =
  | { kind: 'delete'; event: CalendarEvent }
  | { kind: 'update'; event: CalendarEvent; fields: EventFields; reminders?: Reminder[] | null }
  | { kind: 'create'; id: string; fields: EventFields; reminders?: Reminder[] | null }

/** A series and the occurrence acted on. */
export interface SeriesContext {
  /** The series: the event with the UID and no RECURRENCE-ID. */
  parent: CalendarEvent
  /** Its changed occurrences (each an event with a RECURRENCE-ID). */
  children: CalendarEvent[]
  /** The occurrence acted on, in the series' form. */
  occurrence: Instance
  /** The changed occurrence acted on, when it is one. */
  child: CalendarEvent | null
}

/** What the editor's form says the event is now. */
export interface FormValues {
  start: CalendarTime
  end: CalendarTime | null
  rrule: string | null
  summary: string | null
  description: string | null
  location: string | null
  /** The video meeting's link (RFC 7986 CONFERENCE, E5c). */
  conference: string | null
}

/** The span the Rust core expands a series over (Proton's 1970–2037). */
const ALL_FROM = '1970-01-01T00:00:00Z'
const ALL_TO = '2038-01-01T00:00:00Z'

function now(): string {
  return new Date().toISOString().replace(/\.\d+Z$/, 'Z')
}

async function ms(time: CalendarTime): Promise<number> {
  return Date.parse(await instantOf(time))
}

/** The day a time names, on its own wall clock. */
export function dayOf(time: CalendarTime): CivilDate {
  if ('date' in time) return time.date
  if ('zoned' in time) return time.zoned.local.slice(0, 10)
  return time.utc.slice(0, 10)
}

/** The wall-clock date-time a time names (`yyyy-MM-ddTHH:mm:ss`; a date at midnight). */
function localOf(time: CalendarTime): string {
  if ('date' in time) return `${time.date}T00:00:00`
  if ('zoned' in time) return time.zoned.local
  return time.utc.slice(0, 19)
}

function withLocal(time: CalendarTime, local: string): CalendarTime {
  if ('date' in time) return { date: local.slice(0, 10) }
  if ('zoned' in time) return { zoned: { local, tzid: time.zoned.tzid } }
  return { utc: `${local}Z` }
}

function addMinutes(local: string, minutes: number): string {
  return new Date(Date.parse(`${local}Z`) + minutes * 60_000).toISOString().slice(0, 19)
}

function minutesBetween(a: string, b: string): number {
  return Math.round((Date.parse(`${b}Z`) - Date.parse(`${a}Z`)) / 60_000)
}

/**
 * The series around `target` (opened in the editor at `instance`), from every
 * event with its UID (`loadSeries`); null when there is none to act on (a
 * changed occurrence whose series is gone: Proton's orphan, a single event).
 */
export async function seriesContext(events: CalendarEvent[], target: CalendarEvent, instance: Instance | null | undefined): Promise<SeriesContext | null> {
  const parent = events.find((event) => !event.fields.recurrenceId && event.fields.rrule)
  if (!parent) return null
  const children = events.filter((event) => event.fields.recurrenceId)
  const child = target.fields.recurrenceId ? (children.find((event) => event.id === target.id) ?? target) : null
  let occurrence: Instance | null = instance && !child ? instance : null
  if (!occurrence) {
    // The occurrence a changed one replaces, or the series' first.
    const at = child ? await instantOf(child.fields.recurrenceId!) : parent.startUtc
    const until = new Date(Date.parse(at) + 1000).toISOString().replace(/\.\d+Z$/, 'Z')
    const found = (await instancesOf(parent, at, until, 4)).find((o) => Date.parse(o.startUtc) === Date.parse(at))
    occurrence = found ?? {
      start: child ? child.fields.recurrenceId! : parent.fields.start,
      end: null,
      startUtc: at,
      endUtc: at,
      number: 0,
    }
  }
  return { parent, children, occurrence, child }
}

/** Whether the occurrence is the series' first. */
export function isFirst(context: SeriesContext): boolean {
  return Date.parse(context.occurrence.startUtc) === Date.parse(context.parent.startUtc)
}

/** Whether a series has one occurrence only (Proton's `isSingleOccurrence`: only "all" applies). */
export async function isSingleOccurrence(parent: CalendarEvent): Promise<boolean> {
  return (await occurrences(parent.fields, ALL_FROM, ALL_TO, 2).catch(() => [])).length < 2
}

/**
 * The series cut before the occurrence (Proton's `deleteFutureRecurrence`):
 * COUNT down to the ones before, or UNTIL the previous day's end in its
 * zone; the EXDATEs after it go (they would name no occurrence).
 */
export async function cutBefore(parent: CalendarEvent, occurrence: Instance): Promise<EventFields> {
  const fields = parent.fields
  const rule = await readRule(fields.rrule!)
  const cut = rule.count
    ? { ...rule, count: occurrence.number - 1 }
    : { ...rule, until: await supportedUntil(fields.start, addDays(dayOf(occurrence.start), -1)) }
  const at = Date.parse(occurrence.startUtc)
  const exdates: CalendarTime[] = []
  for (const exdate of fields.exdates ?? []) if ((await ms(exdate)) < at) exdates.push(exdate)
  const ends = cut.count !== undefined && cut.count !== null && cut.count < 1
  // Nothing left to repeat: a single event, which takes no EXDATE.
  return { ...fields, dtstamp: now(), rrule: ends ? null : await ruleText(cut), exdates: ends ? [] : exdates }
}

/** Whether "this and future events" applies (Proton's `getHasFutureOption`): not the first, and one is left before it. */
export async function hasFutureOption(context: SeriesContext): Promise<boolean> {
  if (isFirst(context)) return false
  // A COUNT series' occurrences are numbered; one walked from the window isn't.
  const rule = await readRule(context.parent.fields.rrule!).catch(() => null)
  if (!rule || (rule.count && context.occurrence.number < 2)) return false
  try {
    const cut = await cutBefore(context.parent, context.occurrence)
    return cut.rrule !== null && (await occurrences(cut, ALL_FROM, ALL_TO, 1)).length >= 1
  } catch {
    return false
  }
}

/** The choices a change offers (Proton's `getRecurringSaveType` / `getRecurringDeleteType`). */
export async function choicesFor(context: SeriesContext): Promise<RecurringType[]> {
  if (await isSingleOccurrence(context.parent)) return ['all']
  return (await hasFutureOption(context)) ? ['single', 'future', 'all'] : ['single', 'all']
}

async function sameInstant(a: CalendarTime | null, b: CalendarTime | null): Promise<boolean> {
  if (!a || !b) return a === b
  return ('date' in a) === ('date' in b) && (await ms(a)) === (await ms(b))
}

/** The changed occurrences at or after the occurrence (Proton's `getRecurrenceEventsAfter`). */
async function childrenFrom(context: SeriesContext): Promise<CalendarEvent[]> {
  const at = Date.parse(context.occurrence.startUtc)
  const after: CalendarEvent[] = []
  for (const child of context.children) if ((await ms(child.fields.recurrenceId!)) >= at) after.push(child)
  return after
}

/** The series' EXDATEs at or after the occurrence (Proton's `getExdatesAfter`). */
async function exdatesFrom(context: SeriesContext): Promise<CalendarTime[]> {
  const at = Date.parse(context.occurrence.startUtc)
  const after: CalendarTime[] = []
  for (const exdate of context.parent.fields.exdates ?? []) if ((await ms(exdate)) >= at) after.push(exdate)
  return after
}

/** What the confirmation warns of (Proton's `editRecurringConfirmationTexts`). */
export interface SaveWarnings {
  /** Changed or deleted occurrences that the choice drops. */
  modificationsLost: boolean
  /** "This event" with the rule changed: the change of rule is dropped. */
  ruleLost: boolean
}

/** The occurrence's times before the change: a changed occurrence's own, else the series' at it. */
function oldTimes(context: SeriesContext): { start: CalendarTime; end: CalendarTime | null } {
  if (context.child) return { start: context.child.fields.start, end: context.child.fields.end }
  return { start: context.occurrence.start, end: context.occurrence.end }
}

/** Whether a change moves the occurrence or changes the rule (Proton's `isBreakingChange`). */
async function breaking(context: SeriesContext, form: FormValues): Promise<{ timesChanged: boolean; ruleEqual: boolean }> {
  const old = oldTimes(context)
  const timesChanged = !(await sameInstant(old.start, form.start)) || !(await sameInstant(old.end, form.end))
  return { timesChanged, ruleEqual: form.rrule === context.parent.fields.rrule }
}

export async function saveWarnings(type: RecurringType, context: SeriesContext, form: FormValues): Promise<SaveWarnings> {
  const { timesChanged, ruleEqual } = await breaking(context, form)
  let modificationsLost = false
  if (type === 'all') modificationsLost = (timesChanged || !ruleEqual) && (context.children.length > 0 || (context.parent.fields.exdates ?? []).length > 0)
  if (type === 'future') modificationsLost = (await childrenFrom(context)).some((c) => c.id !== context.child?.id) || (await exdatesFrom(context)).length > 0
  return { modificationsLost, ruleLost: type === 'single' && !ruleEqual }
}

/** Proton's `getFutureRecurrenceUID`: `<uid>_R<yyyymmdd>[T<hhmmss>]@<domain>`, an older `_R` part replaced. */
export function futureUid(uid: string, occurrence: CalendarTime): string {
  const local = localOf(occurrence).replace(/[-:]/g, '')
  const offset = 'date' in occurrence ? `R${local.slice(0, 8)}` : `R${local.slice(0, 15)}`
  const at = uid.lastIndexOf('@')
  const pre = at === -1 ? uid : uid.slice(0, at)
  const post = at === -1 ? '' : uid.slice(at)
  const clean = pre.replace(/(?:_R\d{8}(?:T\d{6})?)+$/, '')
  // The UID's limit (255): the front gives way, as Proton's `getSupportedUID`.
  const whole = `${clean}_${offset}${post}`
  return whole.length > 255 ? whole.slice(whole.length - 255) : whole
}

/** A rule whose UNTIL a later start passed, ending on that start's day (Proton's `getSafeRruleUntil`). */
async function safeUntil(rrule: string | null, start: CalendarTime): Promise<string | null> {
  if (!rrule) return null
  const rule = await readRule(rrule)
  if (!rule.until) return rrule
  if ((await ms(start)) <= (await ms(rule.until))) return rrule
  return ruleText({ ...rule, until: await supportedUntil(start, dayOf(start)) })
}

/**
 * The new series' rule from "this and future" (Proton's
 * `createFutureRecurrence` / `getComponentWithUpdatedRrule`): a COUNT left as
 * it was counts the occurrences from here on.
 */
async function futureRule(form: FormValues, parent: CalendarEvent, number: number): Promise<string | null> {
  if (!form.rrule) return null
  const next = await readRule(form.rrule)
  const old = await readRule(parent.fields.rrule!)
  if (next.count && old.count === next.count) {
    const count = next.count - (number - 1)
    return count < 1 ? null : ruleText({ ...next, count })
  }
  return safeUntil(form.rrule, form.start)
}

function withForm(fields: EventFields, form: FormValues): EventFields {
  return { ...fields, start: form.start, end: form.end, summary: form.summary, description: form.description, location: form.location, conference: form.conference, dtstamp: now() }
}

/**
 * "All events" changed (Proton's `updateAllRecurrence`, chosen by
 * `getRecurringUpdateAllPossibilities`): times and rule as they were keep the
 * series' start and its changes (Proton does this for organizers; Kutup for
 * every series); the same day with a new time moves every occurrence to that
 * time; else the series starts where the form says. Moved or re-ruled, the
 * changed and deleted occurrences go.
 */
async function planAll(context: SeriesContext, form: FormValues, reminders: Reminder[] | null | undefined): Promise<Step[]> {
  const { parent } = context
  const { timesChanged, ruleEqual } = await breaking(context, form)
  const sequence = (parent.fields.sequence ?? 0) + (timesChanged || !ruleEqual ? 1 : 0)
  if (!timesChanged && ruleEqual) {
    const fields: EventFields = {
      ...parent.fields,
      summary: form.summary,
      description: form.description,
      location: form.location,
      conference: form.conference,
      dtstamp: now(),
      sequence,
    }
    // Proton's smart rules: what changed in the series changes in its changed occurrences.
    const changes: Partial<EventFields> = {}
    for (const key of ['summary', 'description', 'location', 'conference'] as const) if (form[key] !== (parent.fields[key] ?? null)) changes[key] = form[key]
    const steps: Step[] = []
    if (Object.keys(changes).length > 0) {
      for (const child of context.children) {
        const changed = (Object.keys(changes) as (keyof typeof changes)[]).some((key) => child.fields[key] !== changes[key])
        if (!changed) continue
        steps.push({
          kind: 'update',
          event: child,
          fields: { ...child.fields, ...changes, dtstamp: now(), sequence: Math.max(child.fields.sequence ?? 0, sequence) },
        })
      }
    }
    return [{ kind: 'update', event: parent, fields, reminders }, ...steps]
  }
  const old = oldTimes(context)
  let start = form.start
  let end = form.end
  if (dayOf(old.start) === dayOf(form.start) && ruleEqual) {
    // The series' first day, at the form's time and length.
    const first = dayOf(parent.fields.start)
    const startLocal = `${first}${localOf(form.start).slice(10)}`
    start = withLocal(form.start, startLocal)
    if (form.end) {
      if ('date' in form.end && 'date' in form.start) end = { date: addDays(first, daysBetween(form.start.date, form.end.date)) }
      else end = withLocal(form.end, addMinutes(startLocal, minutesBetween(localOf(form.start), localOf(form.end))))
    }
  }
  const fields: EventFields = {
    ...withForm(parent.fields, { ...form, start, end }),
    rrule: await safeUntil(form.rrule, start),
    exdates: [],
    sequence,
  }
  return [...context.children.map((child): Step => ({ kind: 'delete', event: child })), { kind: 'update', event: parent, fields, reminders }]
}

/**
 * The sync changes saving the form as `type` makes. `reminders`: the
 * member's own list, null for the calendar's defaults, undefined to keep.
 */
export async function planSave(type: RecurringType, context: SeriesContext, form: FormValues, reminders: Reminder[] | null | undefined): Promise<Step[]> {
  const { parent, child, occurrence } = context
  const parentSequence = parent.fields.sequence ?? 0
  if (type === 'single') {
    const { timesChanged } = await breaking(context, form)
    if (child) {
      // A changed occurrence changed again: its SEQUENCE never behind the series' (Proton's).
      const base = Math.max(parentSequence, child.fields.sequence ?? 0)
      const fields: EventFields = { ...withForm(child.fields, form), rrule: null, exdates: [], sequence: base + (timesChanged ? 1 : 0) }
      return [{ kind: 'update', event: child, fields, reminders }]
    }
    // Proton's `createSingleRecurrence`: the occurrence becomes an event of its own.
    const fields: EventFields = {
      ...withForm(parent.fields, form),
      created: now(),
      recurrenceId: occurrence.start,
      rrule: null,
      exdates: [],
      sequence: parentSequence + (timesChanged ? 1 : 0),
    }
    return [{ kind: 'create', id: crypto.randomUUID(), fields, reminders: reminders ?? undefined }]
  }
  if (type === 'future') {
    const deletes = (await childrenFrom(context)).map((event): Step => ({ kind: 'delete', event }))
    const cut: EventFields = { ...(await cutBefore(parent, occurrence)), sequence: parentSequence + 1 }
    const fields: EventFields = {
      ...withForm(parent.fields, form),
      uid: futureUid(parent.fields.uid, occurrence.start),
      created: now(),
      recurrenceId: null,
      rrule: await futureRule(form, parent, occurrence.number),
      exdates: [],
      sequence: 0,
    }
    return [...deletes, { kind: 'update', event: parent, fields: cut }, { kind: 'create', id: crypto.randomUUID(), fields, reminders: reminders ?? undefined }]
  }
  return planAll(context, form, reminders)
}

/** The sync changes deleting as `type` makes (Proton's `getDeleteRecurringEventActions`). */
export async function planDelete(type: RecurringType, context: SeriesContext): Promise<Step[]> {
  const { parent, child, occurrence } = context
  if (type === 'single') {
    const steps: Step[] = child ? [{ kind: 'delete', event: child }] : []
    // Proton's `deleteSingleRecurrence`: an EXDATE on the series, once.
    const at = Date.parse(occurrence.startUtc)
    const exdates = parent.fields.exdates ?? []
    let present = false
    for (const exdate of exdates) if ((await ms(exdate)) === at) present = true
    if (!present) {
      const next = [...exdates, occurrence.start]
      const sorted = (await Promise.all(next.map(async (time) => ({ time, at: await ms(time) })))).sort((a, b) => a.at - b.at).map((x) => x.time)
      steps.push({ kind: 'update', event: parent, fields: { ...parent.fields, dtstamp: now(), exdates: sorted } })
    }
    return steps
  }
  if (type === 'future') {
    const deletes = (await childrenFrom(context)).map((event): Step => ({ kind: 'delete', event }))
    return [...deletes, { kind: 'update', event: parent, fields: await cutBefore(parent, occurrence) }]
  }
  // Changed occurrences first: stopped half-way, none is left without its series.
  return [...context.children.map((event): Step => ({ kind: 'delete', event })), { kind: 'delete', event: parent }]
}
