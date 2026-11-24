import { addDays, daysBetween, weekday, type CivilDate } from '@kutup/calendar-core/time'
import { readRule, ruleText, supportedUntil, utcToLocal, type CalendarTime, type RuleFields } from '@kutup/crypto/calendar'

// The editor's repeat choice, as Proton's (`applications/calendar`:
// `FrequencyInput`, `CustomFrequencyModal`, `modelToFrequencyProperties`,
// `propertiesToFrequencyModel`, `getFrequencyModelChange`). The rule itself
// is the Rust core's: this module only says which parts the editor sets, and
// the core writes them canonically (or refuses them).

export type Frequency = 'daily' | 'weekly' | 'monthly' | 'yearly'
/** Proton's `FREQUENCY`: a preset, `custom`, `once`, or `other` (a rule the editor can't show, kept as it is). */
export type FrequencyType = 'once' | Frequency | 'custom' | 'other'
/** Proton's `MONTHLY_TYPE`: on the start's day of the month, on its nth weekday, on its last weekday. */
export type MonthlyType = 'onMonthDay' | 'onNthDay' | 'onLastDay'
export type EndType = 'never' | 'until' | 'count'

export interface FrequencyModel {
  type: FrequencyType
  /** The custom rule's frequency (presets carry theirs in `type`). */
  frequency: Frequency
  interval: number
  /** Weekly: the days, 0 Sunday … 6 Saturday (the start's always among them). */
  weeklyDays: number[]
  monthly: MonthlyType
  ends: { type: EndType; count: number; until: CivilDate | null }
  /** `other`: the rule as stored, kept unchanged. */
  text: string | null
}

const DAY_NAMES = ['SU', 'MO', 'TU', 'WE', 'TH', 'FR', 'SA'] as const

/** Proton's limits on INTERVAL (`FREQUENCY_INTERVALS_MAX`), as the Rust core's. */
export const MAX_INTERVAL: Record<Frequency, number> = { daily: 999, weekly: 4999, monthly: 999, yearly: 99 }
/** Proton's `FREQUENCY_COUNT_MAX`; the server's own limit (`calendarMaxCount`) is read in its place. */
export const DEFAULT_MAX_COUNT = 49

/** Which of its month's weekdays `date` is, from the start: 1 … 5 (Proton's `getPositiveSetpos`). */
export function positiveSetPos(date: CivilDate): number {
  return Math.floor((Number(date.slice(8, 10)) - 1) / 7) + 1
}

/** -1 when `date` is the last of its weekday in its month (Proton's `getNegativeSetpos`), else less. */
export function negativeSetPos(date: CivilDate): number {
  const next = addDays(date, 7)
  return next.slice(0, 7) === date.slice(0, 7) ? -2 : -1
}

/** The monthly choices a start offers (Proton's `useMonthlyOptions`): never a fifth weekday; the last only when it is. */
export function monthlyTypes(date: CivilDate): MonthlyType[] {
  const types: MonthlyType[] = ['onMonthDay']
  if (positiveSetPos(date) !== 5) types.push('onNthDay')
  if (negativeSetPos(date) === -1) types.push('onLastDay')
  return types
}

/** The weekdays Proton's "Every weekday" takes: five from the week's first day. */
export function workWeek(weekStart: number): number[] {
  return Array.from({ length: 5 }, (_, i) => (weekStart + i) % 7)
}

export function isWorkday(date: CivilDate, weekStart: number): boolean {
  return workWeek(weekStart).includes(weekday(date))
}

/** A new event's: does not repeat (Proton's `getInitialFrequencyModel`). */
export function onceModel(start: CivilDate): FrequencyModel {
  return {
    type: 'once',
    frequency: 'weekly',
    interval: 1,
    weeklyDays: [weekday(start)],
    monthly: 'onMonthDay',
    ends: { type: 'never', count: 2, until: null },
    text: null,
  }
}

function sameDays(a: number[], b: number[]): boolean {
  const x = [...new Set(a)].sort()
  const y = [...new Set(b)].sort()
  return x.length === y.length && x.every((day, i) => day === y[i])
}

/**
 * The option the picker shows for `model` (Proton's `getSelectedFrequency`):
 * a custom rule that a preset says is that preset.
 */
export function presetOf(model: FrequencyModel, start: CivilDate, weekStart: number): FrequencyType | `monthly:${MonthlyType}` | 'workdays' {
  if (model.type === 'once' || model.type === 'other') return model.type
  const frequency = model.type === 'custom' ? model.frequency : model.type
  if (model.type === 'custom' && (model.interval !== 1 || model.ends.type !== 'never')) return 'custom'
  if (frequency === 'weekly') {
    if (sameDays(model.weeklyDays, [weekday(start)])) return 'weekly'
    if (isWorkday(start, weekStart) && sameDays(model.weeklyDays, workWeek(weekStart))) return 'workdays'
    return 'custom'
  }
  if (frequency === 'monthly') return monthlyTypes(start).includes(model.monthly) ? `monthly:${model.monthly}` : 'custom'
  return frequency
}

/** The model a picked preset makes (Proton's `FrequencyInput` onChange): interval 1, never ending. */
export function pickPreset(model: FrequencyModel, preset: ReturnType<typeof presetOf>, start: CivilDate, weekStart: number): FrequencyModel {
  const plain = { ...model, interval: 1, ends: { type: 'never' as const, count: 2, until: null }, text: null }
  if (preset === 'once') return { ...plain, type: 'once' }
  if (preset === 'workdays') return { ...plain, type: 'weekly', frequency: 'weekly', weeklyDays: workWeek(weekStart) }
  if (preset === 'weekly') return { ...plain, type: 'weekly', frequency: 'weekly', weeklyDays: [weekday(start)] }
  if (preset.startsWith('monthly:')) return { ...plain, type: 'monthly', frequency: 'monthly', monthly: preset.slice(8) as MonthlyType }
  if (preset === 'daily' || preset === 'yearly') return { ...plain, type: preset, frequency: preset }
  return model
}

/** The rule's frequency, presets and custom alike. */
export function frequencyOf(model: FrequencyModel): Frequency {
  return model.type === 'custom' || model.type === 'once' || model.type === 'other' ? model.frequency : model.type
}

/**
 * The `RRULE` for `model` and a series starting at `start` (its date
 * `startDate`), or null when it doesn't repeat (Proton's
 * `modelToFrequencyProperties`). `previous`, the rule stored: its WKST kept
 * unless the rule changed otherwise (Proton keeps WKST unless the rule was
 * edited).
 */
export async function ruleOf(
  model: FrequencyModel,
  start: CalendarTime,
  startDate: CivilDate,
  weekStart: number,
  previous: string | null = null,
): Promise<string | null> {
  if (model.type === 'once') return null
  if (model.type === 'other') return model.text
  const frequency = frequencyOf(model)
  const rule: RuleFields = { frequency }
  if (model.interval > 1) rule.interval = model.interval
  if (frequency === 'weekly') {
    const days = [...new Set(model.weeklyDays)].sort()
    if (!days.includes(weekday(startDate))) throw new Error('a weekly series repeats on its start’s day')
    if (days.length > 1) {
      rule.byDay = days.map((day) => DAY_NAMES[day])
      rule.wkst = DAY_NAMES[weekStart]
    }
  }
  if (frequency === 'monthly' && model.monthly !== 'onMonthDay') {
    rule.byDay = [DAY_NAMES[weekday(startDate)]]
    rule.bySetPos = model.monthly === 'onLastDay' ? -1 : positiveSetPos(startDate)
  }
  if (model.ends.type === 'count') rule.count = model.ends.count
  if (model.ends.type === 'until' && model.ends.until) rule.until = await supportedUntil(start, model.ends.until)
  const text = await ruleText(rule)
  if (previous && rule.wkst !== undefined) {
    // The stored rule's WKST stays when nothing else changed.
    const old = await readRule(previous).catch(() => null)
    if (old && old.wkst !== (rule.wkst ?? null)) {
      const same = await ruleText({ ...rule, wkst: old.wkst ?? null }).catch(() => null)
      if (same === previous) return previous
    }
  }
  return text
}

/** The day an UNTIL names, in the series' zone. */
async function untilDate(until: CalendarTime, start: CalendarTime): Promise<CivilDate> {
  if ('date' in until) return until.date
  const instant = 'utc' in until ? until.utc : until.zoned.local
  const zone = 'zoned' in start ? start.zoned.tzid : 'UTC'
  return (await utcToLocal(instant, zone)).slice(0, 10)
}

/**
 * The editor's model of a stored rule (Proton's `propertiesToFrequencyModel`):
 * a preset when it is one, custom when the editor makes it, else `other`
 * (kept as it is unless another is picked).
 */
export async function modelOf(text: string | null, start: CalendarTime, startDate: CivilDate): Promise<FrequencyModel> {
  const base = onceModel(startDate)
  if (!text) return base
  let rule: RuleFields
  try {
    rule = await readRule(text)
  } catch {
    return { ...base, type: 'other', text }
  }
  const frequency = rule.frequency
  const days = (rule.byDay ?? []).map((name) => DAY_NAMES.indexOf(name as (typeof DAY_NAMES)[number]))
  const setPos = rule.bySetPos ?? null
  const monthly: MonthlyType = setPos === -1 ? 'onLastDay' : setPos !== null ? 'onNthDay' : 'onMonthDay'
  // What the editor writes: no BYMONTHDAY, BYMONTH or BYYEARDAY (the start's
  // day), a monthly weekday that is the start's.
  const editable =
    rule.byMonthDay == null &&
    rule.byMonth == null &&
    rule.byYearDay == null &&
    (frequency !== 'monthly' ||
      setPos === null ||
      (days.length === 1 && days[0] === weekday(startDate) && (setPos === -1 ? negativeSetPos(startDate) === -1 : setPos === positiveSetPos(startDate)))) &&
    (frequency !== 'weekly' || days.length === 0 || days.includes(weekday(startDate)))
  if (!editable) return { ...base, type: 'other', frequency, text }
  const interval = rule.interval ?? 1
  const ends: FrequencyModel['ends'] = rule.count
    ? { type: 'count', count: rule.count, until: null }
    : rule.until
      ? { type: 'until', count: 2, until: await untilDate(rule.until, start) }
      : { type: 'never', count: 2, until: null }
  const weeklyDays = [...new Set([weekday(startDate), ...(frequency === 'weekly' ? days : [])])]
  const simple = interval === 1 && ends.type === 'never' && (frequency !== 'weekly' || weeklyDays.length === 1)
  return { type: simple ? frequency : 'custom', frequency, interval, weeklyDays, monthly, ends, text: null }
}

/**
 * The model after the start moved from `before` to `after` (Proton's
 * `getFrequencyModelChange`): the weekly day follows the start, a monthly
 * weekday that no longer applies becomes the one that does, an end before
 * the start moves to it.
 */
export function followStart(model: FrequencyModel, before: CivilDate, after: CivilDate): FrequencyModel {
  if (before === after) return model
  const from = weekday(before)
  const to = weekday(after)
  const days = model.weeklyDays.length === 1 || !model.weeklyDays.includes(to) ? model.weeklyDays.map((day) => (day === from ? to : day)) : model.weeklyDays
  let monthly = model.monthly
  if (monthly === 'onLastDay' && negativeSetPos(after) !== -1) monthly = 'onNthDay'
  else if (monthly === 'onNthDay' && positiveSetPos(after) === 5) monthly = 'onLastDay'
  const until = model.ends.until && daysBetween(after, model.ends.until) < 0 ? after : model.ends.until
  return { ...model, weeklyDays: [...new Set(days.includes(to) ? days : [...days, to])], monthly, ends: { ...model.ends, until } }
}
