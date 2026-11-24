import type { TFunction } from 'i18next'
import { addDays, weekday, type CivilDate } from '@kutup/calendar-core/time'
import { formatWeekday } from '../format'
import { frequencyOf, positiveSetPos, type FrequencyModel } from './frequency'

// How a repeat reads in the event's popover (Proton's
// `getTimezonedFrequencyString`): "Weekly on Monday", "Every 2 weeks on
// Monday, Wednesday, until 1 Dec 2026", "Monthly on the last Friday, 5 times";
// a rule the editor doesn't make reads "Custom weekly" and the like.

export interface RuleTextInput {
  /** The repeat as the editor reads it (`modelOf`). */
  model: FrequencyModel
  /** The series' first day, on its own wall clock. */
  start: CivilDate
  weekStart: number
  locale: string
  /** The series' zone and the view's: a repeat whose days depend on the zone names it when they differ. */
  zone: string | null
  viewZone: string
}

/** A day of `date`'s week with weekday `day` (0 Sunday), for its name. */
function named(date: CivilDate, day: number): CivilDate {
  return addDays(date, day - weekday(date))
}

function formatDate(date: CivilDate, locale: string): string {
  return new Intl.DateTimeFormat(locale, { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' }).format(new Date(`${date}T00:00:00Z`))
}

/** The repeat in words, as Proton's popover shows it; empty for one that doesn't repeat. */
export function ruleText(t: TFunction, { model, start, weekStart, locale, zone, viewZone }: RuleTextInput): string {
  if (model.type === 'once') return ''
  if (model.type === 'other') {
    // Proton's "Custom weekly" and the like, by the rule's own FREQ (one the core can't read has no other).
    const freq = /(?:^|;)FREQ=(DAILY|WEEKLY|MONTHLY|YEARLY)(?:;|$)/i.exec(model.text ?? '')?.[1]
    return freq ? t(`recurrence.text.custom.${freq.toLowerCase()}`) : t('recurrence.customShown')
  }
  const frequency = frequencyOf(model)
  const interval = model.interval
  const count = { count: interval }
  const days = [...new Set([...model.weeklyDays, weekday(start)])].sort((a, b) => ((a - weekStart + 7) % 7) - ((b - weekStart + 7) % 7))
  let text: string
  if (frequency === 'daily') text = interval === 1 ? t('recurrence.text.daily') : t('recurrence.text.everyDays', count)
  else if (frequency === 'weekly') {
    const names = days.map((d) => formatWeekday(named(start, d), locale, 'long')).join(', ')
    if (days.length === 7) text = interval === 1 ? t('recurrence.text.weeklyAll') : t('recurrence.text.everyWeeksAll', count)
    else text = interval === 1 ? t('recurrence.text.weekly', { days: names }) : t('recurrence.text.everyWeeks', { ...count, days: names })
  } else if (frequency === 'monthly') {
    const day = formatWeekday(start, locale, 'long')
    const on =
      model.monthly === 'onLastDay'
        ? t('recurrence.onLastDay', { day })
        : model.monthly === 'onNthDay'
          ? t('recurrence.onNthDay', { nth: t(`recurrence.nth.${positiveSetPos(start)}`), day })
          : t('recurrence.onMonthDay', { day: Number(start.slice(8, 10)) })
    text = interval === 1 ? t('recurrence.text.monthly', { on }) : t('recurrence.text.everyMonths', { ...count, on })
  } else text = interval === 1 ? t('recurrence.text.yearly') : t('recurrence.text.everyYears', count)

  const until = model.ends.type === 'until' ? model.ends.until : null
  if (model.ends.type === 'count') text = t('recurrence.text.times', { text, count: model.ends.count })
  else if (until) text = t('recurrence.text.until', { text, date: formatDate(until, locale) })

  // Proton's `isTimezoneStringNeeded`: the zone is named when the days it repeats on depend on it.
  const needsZone =
    frequency === 'monthly' || (frequency === 'weekly' && (days.length !== 7 || (model.type === 'custom' && !!until))) || (model.type === 'custom' && !!until)
  return zone && zone !== viewZone && needsZone ? `${text} (${zone})` : text
}
