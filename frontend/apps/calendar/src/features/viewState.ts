import { useSearchParams } from 'react-router-dom'
import { addDays, daysBetween, isCivilDate, startOfWeek, step, viewDays, type CivilDate } from '@kutup/calendar-core/time'

// What the calendar shows, kept in the address (`?view=week&date=…&range=…`)
// as Proton keeps its view, date and custom range (`VIEWS.CUSTOM`: a range
// of days shown as a week, or of weeks shown as a month).

export type View = 'day' | 'week' | 'month'
export const VIEWS: readonly View[] = ['day', 'week', 'month']

/** Proton's largest custom range: six more weeks than the first (its month grid's six rows). */
const MAX_WEEKS = 5

export interface CalendarLocation {
  view: View
  date: CivilDate | undefined
  /** Proton's `range`: days after `date` (a week view), or weeks after its week (a month view); 0 for none. */
  range: number
}

/** The days a view shows, with its custom range (Proton's `getDateRange`). */
export function shownDays(view: View, date: CivilDate, range: number, weekStart: number): CivilDate[] {
  if (range > 0 && view === 'week') return Array.from({ length: range + 1 }, (_, i) => addDays(date, i))
  if (range > 0 && view === 'month') {
    const first = startOfWeek(date, weekStart)
    return Array.from({ length: (range + 1) * 7 }, (_, i) => addDays(first, i))
  }
  return viewDays(view, date, weekStart)
}

/** Where the arrows go (Proton's `getDateDiff`): a custom range steps by its own length. */
export function stepDate(view: View, date: CivilDate, range: number, by: -1 | 1): CivilDate {
  if (range > 0 && view === 'week') return addDays(date, by * (range + 1))
  if (range > 0 && view === 'month') return addDays(date, by * (range + 1) * 7)
  return step(view, date, by)
}

/**
 * The view a span chosen on the mini calendar opens (Proton's
 * `handleChangeDateRange`): a week of its days, or of a week or more, a
 * month of its weeks.
 */
export function rangeView(first: CivilDate, last: CivilDate): { view: View; date: CivilDate; range: number } {
  const days = daysBetween(first, last)
  if (days >= 7) return { view: 'month', date: first, range: Math.min(Math.floor(days / 7), MAX_WEEKS) }
  return { view: 'week', date: first, range: days }
}

/** Reads the address (dates checked, a bad one is today's) and changes it. */
export function useCalendarLocation(today: CivilDate | undefined): CalendarLocation & {
  go: (next: { view?: View; date?: CivilDate; range?: number }) => void
} {
  const [params, setParams] = useSearchParams()
  const view: View = VIEWS.includes(params.get('view') as View) ? (params.get('view') as View) : 'week'
  const requested = params.get('date')
  const date = requested && isCivilDate(requested) ? requested : today
  const asked = Number(params.get('range'))
  const range = view !== 'day' && Number.isInteger(asked) && asked > 0 && asked <= (view === 'week' ? 6 : MAX_WEEKS) ? asked : 0
  const go = (next: { view?: View; date?: CivilDate; range?: number }) =>
    setParams((now) => {
      const p = new URLSearchParams(now)
      if (next.view) p.set('view', next.view)
      if (next.date) p.set('date', next.date)
      if (next.range !== undefined) {
        if (next.range > 0) p.set('range', String(next.range))
        else p.delete('range')
      }
      return p
    })
  return { view, date, range, go }
}
