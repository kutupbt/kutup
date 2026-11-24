import { ChevronLeft, ChevronRight } from 'lucide-react'
import { useEffect, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { addDays, addMonths, monthGrid, type CivilDate } from '@kutup/calendar-core/time'
import { cn } from '@kutup/ui/lib/cn'
import { ordered } from './DaySpan'
import { formatDayNumber, formatLongDate, formatWeekday } from './format'
import { useCalendarPrefs } from './prefs'
import { useToday } from './today'
import { rangeView, shownDays, useCalendarLocation } from './viewState'

function monthLabel(month: CivilDate, locale: string): string {
  return new Intl.DateTimeFormat(locale, { month: 'long', year: 'numeric', timeZone: 'UTC' }).format(new Date(`${month}T00:00:00Z`))
}

/**
 * Proton's `LocalizedMiniCalendar` in the sidebar: a month of days; a click
 * goes to that day in the view shown, a drag across days or weeks shows that
 * custom range (Proton's `onSelectDateRange`); the arrows step through months
 * without moving the view. The days shown are marked. On the keyboard the
 * arrows move between days (one day in the Tab order), Page Up and Page Down
 * between months, Enter goes there.
 */
export function MiniCalendar() {
  const { t, i18n } = useTranslation()
  const prefs = useCalendarPrefs()
  const today = useToday(prefs.zone)
  const { view, date, range, go } = useCalendarLocation(today)
  // The month on show: the view's, until the arrows move it (Proton's `temporaryDate`).
  const [month, setMonth] = useState<CivilDate | undefined>(undefined)
  const [focusDay, setFocusDay] = useState<CivilDate | undefined>(undefined)
  const [drag, setDrag] = useState<{ from: CivilDate; to: CivilDate } | null>(null)
  const dragRef = useRef<{ from: CivilDate; to: CivilDate } | null>(null)
  const cells = useRef(new Map<CivilDate, HTMLButtonElement>())
  const keyMoved = useRef(false)
  useEffect(() => {
    setMonth(undefined)
    setFocusDay(undefined)
  }, [date])
  useEffect(() => {
    if (!keyMoved.current || !focusDay) return
    keyMoved.current = false
    cells.current.get(focusDay)?.focus()
  }, [focusDay, month])
  if (!date) return null

  const shownMonth = month ?? `${date.slice(0, 7)}-01`
  const weeks = monthGrid(shownMonth, prefs.weekStart)
  const gridDays = weeks.flat()
  // The days the view shows are marked (Proton's `dateRange`, for a week or a custom range).
  const shown = view === 'week' || range > 0 ? shownDays(view, date, range, prefs.weekStart) : null
  const [markFrom, markTo] = drag ? ordered(drag.from, drag.to) : shown ? [shown[0], shown.at(-1)!] : [null, null]
  const tabDay = focusDay && gridDays.includes(focusDay) ? focusDay : gridDays.includes(date) ? date : shownMonth

  const endDrag = () => {
    window.removeEventListener('pointerup', endDrag)
    const span = dragRef.current
    dragRef.current = null
    setDrag(null)
    if (span && span.from !== span.to) {
      const [first, last] = ordered(span.from, span.to)
      // The click after a drag isn't one.
      const swallow = (c: MouseEvent) => {
        c.stopPropagation()
        c.preventDefault()
      }
      window.addEventListener('click', swallow, { capture: true, once: true })
      window.setTimeout(() => window.removeEventListener('click', swallow, true), 0)
      go(rangeView(first, last))
    }
  }

  const onKey = (e: ReactKeyboardEvent, day: CivilDate) => {
    let next: CivilDate | null = null
    if (e.key === 'ArrowLeft') next = addDays(day, -1)
    else if (e.key === 'ArrowRight') next = addDays(day, 1)
    else if (e.key === 'ArrowUp') next = addDays(day, -7)
    else if (e.key === 'ArrowDown') next = addDays(day, 7)
    else if (e.key === 'PageUp') next = addDays(addMonths(day, -1), Number(day.slice(8, 10)) - 1)
    else if (e.key === 'PageDown') next = addDays(addMonths(day, 1), Number(day.slice(8, 10)) - 1)
    if (!next) return
    e.preventDefault()
    e.stopPropagation()
    // A month too short for the day ends on its last.
    if (e.key === 'PageUp' || e.key === 'PageDown') {
      const target = addMonths(day, e.key === 'PageUp' ? -1 : 1)
      if (next.slice(0, 7) !== target.slice(0, 7)) next = addDays(addMonths(target, 1), -1)
    }
    keyMoved.current = true
    setFocusDay(next)
    if (!gridDays.includes(next) || next.slice(0, 7) !== shownMonth.slice(0, 7)) setMonth(`${next.slice(0, 7)}-01`)
  }

  return (
    <div className="px-2 pb-2" data-testid="mini-calendar">
      <h2 className="sr-only">{t('mini.title')}</h2>
      <div className="flex items-center gap-1 px-1 pb-1">
        <span className="min-w-0 flex-1 truncate text-sm font-medium" aria-live="polite" data-testid="mini-calendar-month">
          {monthLabel(shownMonth, i18n.language)}
        </span>
        <button
          type="button"
          onClick={() => setMonth(addMonths(shownMonth, -1))}
          aria-label={t('mini.previous')}
          title={t('mini.previous')}
          className="grid size-7 place-items-center rounded-md text-chrome-muted hover:bg-chrome-accent hover:text-chrome-foreground"
          data-testid="mini-calendar-previous"
        >
          <ChevronLeft className="size-4" aria-hidden />
        </button>
        <button
          type="button"
          onClick={() => setMonth(addMonths(shownMonth, 1))}
          aria-label={t('mini.next')}
          title={t('mini.next')}
          className="grid size-7 place-items-center rounded-md text-chrome-muted hover:bg-chrome-accent hover:text-chrome-foreground"
          data-testid="mini-calendar-next"
        >
          <ChevronRight className="size-4" aria-hidden />
        </button>
      </div>
      <table className="w-full table-fixed select-none border-collapse text-center text-xs" role="grid" aria-label={monthLabel(shownMonth, i18n.language)}>
        <thead>
          <tr>
            {weeks[0].map((day) => (
              <th key={day} scope="col" className="pb-1 font-normal text-chrome-muted">
                <abbr title={formatWeekday(day, i18n.language, 'long')} className="no-underline">
                  {formatWeekday(day, i18n.language, 'narrow')}
                </abbr>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {weeks.map((week) => (
            <tr key={week[0]}>
              {week.map((day) => {
                const inRange = markFrom !== null && markTo !== null && markFrom <= day && day <= markTo
                const selected = day === date
                return (
                  <td key={day} className={cn('p-0', inRange && 'bg-chrome-accent', inRange && day === markFrom && 'rounded-l-full', inRange && day === markTo && 'rounded-r-full')}>
                    <button
                      ref={(el) => {
                        if (el) cells.current.set(day, el)
                        else cells.current.delete(day)
                      }}
                      type="button"
                      tabIndex={day === tabDay ? 0 : -1}
                      aria-label={formatLongDate(day, i18n.language)}
                      aria-current={day === today ? 'date' : undefined}
                      aria-pressed={selected || inRange}
                      onPointerDown={(e) => {
                        if (e.pointerType !== 'mouse' || e.button !== 0) return
                        dragRef.current = { from: day, to: day }
                        window.addEventListener('pointerup', endDrag)
                      }}
                      onPointerEnter={() => {
                        if (!dragRef.current || dragRef.current.to === day) return
                        dragRef.current = { ...dragRef.current, to: day }
                        setDrag(dragRef.current)
                      }}
                      onClick={() => go({ date: day })}
                      onKeyDown={(e) => onKey(e, day)}
                      onFocus={() => setFocusDay(day)}
                      className={cn(
                        'mx-auto grid size-7 place-items-center rounded-full tabular-nums hover:bg-chrome-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-chrome-active',
                        day.slice(0, 7) !== shownMonth.slice(0, 7) && 'text-chrome-muted/70',
                        day === today && 'bg-primary font-semibold text-primary-foreground hover:bg-primary/90',
                        selected && day !== today && 'font-semibold ring-1 ring-chrome-active',
                      )}
                      data-testid={`mini-day-${day}`}
                    >
                      {formatDayNumber(day, i18n.language)}
                    </button>
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
