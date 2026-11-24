import { useQuery } from '@tanstack/react-query'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useCalendars, useEvents, type Calendar } from '@kutup/calendar-core/api'
import { addDays, type CivilDate } from '@kutup/calendar-core/time'
import { localToUtc } from '@kutup/crypto/calendar'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { CalendarSkeleton } from '@kutup/ui/components/skeleton'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'
import { CalendarPopovers } from './CalendarPopovers'
import { draftCovers, ghostCovers, pressDays, pressShiftDays, type DaySpanGhost } from './DaySpan'
import { EventChip } from './EventChip'
import { formatDayNumber, formatLongDate, formatTitle, formatWeekday } from './format'
import { newEventStart } from './gridInteraction'
import { openMoved, openNew } from './moves'
import { covers, placeAll, type Placed } from './placement'
import { openPopover, usePopover } from './popoverState'
import { holdTouches, pressActive } from './press'
import { useCalendarPrefs } from './prefs'
import { TimeGrid } from './TimeGrid'
import { useNowMinutes, useToday } from './today'
import { shownDays, stepDate, useCalendarLocation, VIEWS } from './viewState'

/** The calendar: a day, a week or a month of the shown calendars' events. */
export function CalendarPage() {
  const { t, i18n } = useTranslation()
  const prefs = useCalendarPrefs()
  const today = useToday(prefs.zone)
  const nowMinutes = useNowMinutes(prefs.zone)
  const { view, date, range: customRange, go } = useCalendarLocation(today)

  const days = useMemo(() => (date ? shownDays(view, date, customRange, prefs.weekStart) : []), [view, date, customRange, prefs.weekStart])
  // Proton's `handleClickDateWeekView`: a day's header opens that day.
  const openDay = (day: CivilDate) => go({ view: 'day', date: day, range: 0 })
  const range = useQuery({
    queryKey: ['calendar', 'range', prefs.zone, days[0], days.at(-1)],
    enabled: days.length > 0,
    queryFn: async () => ({
      start: await localToUtc(`${days[0]}T00:00:00`, prefs.zone),
      end: await localToUtc(`${addDays(days.at(-1)!, 1)}T00:00:00`, prefs.zone),
    }),
  })
  const calendars = useCalendars()
  const events = useEvents(calendars.data?.calendars, range.data?.start ?? '', range.data?.end ?? '')
  const colors = useMemo(() => new Map((calendars.data?.calendars ?? []).map((c: Calendar) => [c.id, c.color])), [calendars.data])
  const placed = useQuery({
    queryKey: ['calendar', 'placed', prefs.zone, events.dataUpdatedAt],
    enabled: !!events.data && !!range.data,
    // Repeating events drawn occurrence by occurrence in the shown days.
    queryFn: () => placeAll(events.data!.events, (event) => colors.get(event.calendarId) ?? '#8080ff', prefs.zone, range.data!.start, range.data!.end),
  })

  // Proton's shortcuts: ← → through time, T today, 1 2 3 the views, N a new event.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLElement && e.target.closest('input, textarea, select, [role="dialog"]')) return
      if (e.altKey || e.ctrlKey || e.metaKey || !date || pressActive()) return
      if (e.key === 'ArrowLeft') go({ date: stepDate(view, date, customRange, -1) })
      else if (e.key === 'ArrowRight') go({ date: stepDate(view, date, customRange, 1) })
      else if ((e.key === 't' || e.key === 'T') && today) go({ date: today, range: 0 })
      else if (e.key === '1') go({ view: 'day', range: 0 })
      else if (e.key === '2') go({ view: 'week', range: 0 })
      else if (e.key === '3') go({ view: 'month', range: 0 })
      else if ((e.key === 'n' || e.key === 'N') && today) {
        // At the next half hour from now in the calendar's zone, as
        // Proton's new event: tomorrow's first once today's last has begun.
        const next = newEventStart(nowMinutes)
        void openNew(addDays(today, next.dayOffset), next.start, next.end, prefs.zone)
      } else return
      e.preventDefault()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  })

  if (!date || calendars.isPending) return <CalendarSkeleton label={t('common.loading')} />
  if (calendars.isError) return <Alert variant="error">{apiErrorMessage(calendars.error, t('calendars.loadFailed'))}</Alert>

  const unreadable = (calendars.data.unreadable ?? 0) + (events.data?.unreadable ?? 0)
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-2">
        <Button variant="outline" size="sm" onClick={() => today && go({ date: today, range: 0 })} data-testid="calendar-today">
          {t('view.today')}
        </Button>
        <Button variant="ghost" size="icon" aria-label={t('view.previous')} onClick={() => go({ date: stepDate(view, date, customRange, -1) })} data-testid="calendar-previous">
          <ChevronLeft />
        </Button>
        <Button variant="ghost" size="icon" aria-label={t('view.next')} onClick={() => go({ date: stepDate(view, date, customRange, 1) })} data-testid="calendar-next">
          <ChevronRight />
        </Button>
        <h1 className="min-w-0 flex-1 truncate font-display text-lg font-semibold" data-testid="calendar-title">
          {formatTitle(view, date, i18n.language)}
        </h1>
        <div role="tablist" aria-label={t('view.label')} className="flex rounded-md border border-border p-0.5">
          {VIEWS.map((option) => (
            <button
              key={option}
              type="button"
              role="tab"
              aria-selected={view === option && customRange === 0}
              onClick={() => go({ view: option, range: 0 })}
              className={cn('rounded px-3 py-1 text-sm', view === option && customRange === 0 ? 'bg-accent font-medium' : 'text-muted-foreground hover:text-foreground')}
              data-testid={`calendar-view-${option}`}
            >
              {t(`view.${option}`)}
            </button>
          ))}
        </div>
      </div>
      {unreadable > 0 ? (
        <Alert variant="warn" className="m-3">
          {t('events.unreadable', { count: unreadable })}
        </Alert>
      ) : null}
      {events.isError ? <Alert variant="error" className="m-3">{apiErrorMessage(events.error, t('events.loadFailed'))}</Alert> : null}
      {calendars.data.calendars.length === 0 ? (
        <p className="p-6 text-sm text-muted-foreground">{t('calendars.none')}</p>
      ) : view === 'month' ? (
        <MonthView days={days} month={customRange > 0 ? null : date.slice(0, 7)} today={today} placed={placed.data ?? []} onOpenDay={openDay} />
      ) : (
        <TimeGrid days={days} today={today} placed={placed.data ?? []} scrollKey={`${view}-${date}-${customRange}`} onOpenDay={openDay} />
      )}
      <CalendarPopovers placed={placed.data ?? []} />
    </div>
  )
}

/**
 * The month (or a custom range of weeks): drag across days for an all-day
 * event; a day's number opens that day, "+N more" its events (Proton's
 * `MorePopoverEvent`).
 */
function MonthView({
  days,
  month,
  today,
  placed,
  onOpenDay,
}: {
  days: CivilDate[]
  /** The month shown (its other days dimmed); null for a custom range. */
  month: string | null
  today?: CivilDate
  placed: Placed[]
  onOpenDay: (day: CivilDate) => void
}) {
  const { t, i18n } = useTranslation()
  const prefs = useCalendarPrefs()
  const popover = usePopover()
  const [ghost, setGhost] = useState<DaySpanGhost | null>(null)
  const shown = 3
  // An armed touch (or a pen) over the month's cells drags, never scrolls.
  const grid = useRef<HTMLDivElement>(null)
  useEffect(() => (grid.current ? holdTouches(grid.current) : undefined), [])
  return (
    <div
      ref={grid}
      className="grid min-h-0 flex-1 select-none grid-cols-7"
      style={{ gridTemplateRows: `auto repeat(${days.length / 7}, minmax(0, 1fr))` }}
      data-testid="calendar-month"
    >
      {days.slice(0, 7).map((day) => (
        <div key={`head-${day}`} className="border-b border-border px-2 py-1 text-xs font-medium text-muted-foreground">
          {formatWeekday(day, i18n.language)}
        </div>
      ))}
      {days.map((day) => {
        const here = placed
          .filter((p) => covers(p, day))
          .sort((a, b) => Number(b.allDay) - Number(a.allDay) || a.start.localeCompare(b.start))
        return (
          <div
            key={day}
            role="button"
            tabIndex={0}
            data-day={day}
            // Proton's day grid: drag across days for a multi-day all-day event, click for one.
            aria-label={t('view.newOn', { day: formatLongDate(day, i18n.language) })}
            onPointerDown={(e) => {
              if (e.target instanceof Element && e.target.closest('[data-testid="calendar-event"], [data-day-link], [data-more]')) return
              pressDays(e, day, setGhost, null)
            }}
            onKeyDown={(e) => {
              if (e.target !== e.currentTarget || (e.key !== 'Enter' && e.key !== ' ')) return
              e.preventDefault()
              openPopover({ kind: 'create', target: { kind: 'new', date: day, allDay: true } }, e.currentTarget)
            }}
            className={cn(
              'min-h-24 touch-pan-y space-y-0.5 overflow-hidden border-b border-r border-border p-1',
              month !== null && !day.startsWith(month) && 'bg-muted/40 text-muted-foreground',
              (ghostCovers(ghost, day) || draftCovers(popover, day)) && 'bg-primary/15',
            )}
            data-testid={`calendar-day-${day}`}
          >
            <button
              type="button"
              data-day-link
              onClick={() => onOpenDay(day)}
              aria-label={t('view.openDay', { day: formatLongDate(day, i18n.language) })}
              aria-current={day === today ? 'date' : undefined}
              className={cn(
                'ml-auto grid size-6 place-items-center rounded-full text-xs hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                day === today && 'bg-primary text-primary-foreground hover:bg-primary/90',
              )}
              data-testid={`calendar-day-link-${day}`}
            >
              {formatDayNumber(day, i18n.language)}
            </button>
            {here.slice(0, shown).map((p) => (
              <EventChip
                key={p.key}
                placed={p}
                showTime
                faded={ghost?.kind === 'shift' && ghost.placed === p}
                onPointerDown={(e) => pressShiftDays(e, p, day, setGhost, (q, d, m) => void openMoved(q, d, m, prefs.zone), null)}
              />
            ))}
            {here.length > shown ? (
              <button
                type="button"
                data-more
                onClick={(e) => openPopover({ kind: 'more', day }, e.currentTarget.closest('[data-day]') ?? e.currentTarget, e.currentTarget)}
                className="w-full rounded px-1.5 text-left text-xs text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                aria-haspopup="dialog"
                aria-label={t('view.moreLabel', { count: here.length - shown, day: formatLongDate(day, i18n.language) })}
                data-testid="calendar-more"
              >
                {t('view.more', { count: here.length - shown })}
              </button>
            ) : null}
          </div>
        )
      })}
    </div>
  )
}
