import { useQuery } from '@tanstack/react-query'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'
import { useCalendars, useEvents, type Calendar } from '@kutup/calendar-core/api'
import { addDays, isCivilDate, step, viewDays, type CivilDate } from '@kutup/calendar-core/time'
import { localToUtc } from '@kutup/crypto/calendar'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'
import { ghostCovers, pressDays, pressShiftDays, type DaySpanGhost } from './DaySpan'
import { EventChip } from './EventChip'
import { openEditor } from './editorState'
import { formatDayNumber, formatTitle, formatWeekday } from './format'
import { newEventStart } from './gridInteraction'
import { openMoved, openNew } from './moves'
import { covers, place, type Placed } from './placement'
import { holdTouches, pressActive } from './press'
import { useCalendarPrefs } from './prefs'
import { TimeGrid } from './TimeGrid'
import { useNowMinutes, useToday } from './today'

type View = 'day' | 'week' | 'month'
const VIEWS: readonly View[] = ['day', 'week', 'month']

/** The calendar: a day, a week or a month of the shown calendars' events. */
export function CalendarPage() {
  const { t, i18n } = useTranslation()
  const prefs = useCalendarPrefs()
  const today = useToday(prefs.zone)
  const nowMinutes = useNowMinutes(prefs.zone)
  const [params, setParams] = useSearchParams()
  const view: View = VIEWS.includes(params.get('view') as View) ? (params.get('view') as View) : 'week'
  const requested = params.get('date')
  const date: CivilDate | undefined = requested && isCivilDate(requested) ? requested : today
  const go = (next: { view?: View; date?: CivilDate }) =>
    setParams((now) => {
      const p = new URLSearchParams(now)
      if (next.view) p.set('view', next.view)
      if (next.date) p.set('date', next.date)
      return p
    })

  const days = useMemo(() => (date ? viewDays(view, date, prefs.weekStart) : []), [view, date, prefs.weekStart])
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
    enabled: !!events.data,
    queryFn: () => Promise.all(events.data!.events.map((event) => place(event, colors.get(event.calendarId) ?? '#8080ff', prefs.zone))),
  })

  // Proton's shortcuts: ← → through time, T today, 1 2 3 the views, N a new event.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLElement && e.target.closest('input, textarea, select, [role="dialog"]')) return
      if (e.altKey || e.ctrlKey || e.metaKey || !date || pressActive()) return
      if (e.key === 'ArrowLeft') go({ date: step(view, date, -1) })
      else if (e.key === 'ArrowRight') go({ date: step(view, date, 1) })
      else if ((e.key === 't' || e.key === 'T') && today) go({ date: today })
      else if (e.key === '1') go({ view: 'day' })
      else if (e.key === '2') go({ view: 'week' })
      else if (e.key === '3') go({ view: 'month' })
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

  if (!date || calendars.isPending) return <LoadingPanel label={t('common.loading')} />
  if (calendars.isError) return <Alert variant="error">{apiErrorMessage(calendars.error, t('calendars.loadFailed'))}</Alert>

  const unreadable = (calendars.data.unreadable ?? 0) + (events.data?.unreadable ?? 0)
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-2">
        <Button variant="outline" size="sm" onClick={() => today && go({ date: today })} data-testid="calendar-today">
          {t('view.today')}
        </Button>
        <Button variant="ghost" size="icon" aria-label={t('view.previous')} onClick={() => go({ date: step(view, date, -1) })} data-testid="calendar-previous">
          <ChevronLeft />
        </Button>
        <Button variant="ghost" size="icon" aria-label={t('view.next')} onClick={() => go({ date: step(view, date, 1) })} data-testid="calendar-next">
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
              aria-selected={view === option}
              onClick={() => go({ view: option })}
              className={cn('rounded px-3 py-1 text-sm', view === option ? 'bg-accent font-medium' : 'text-muted-foreground hover:text-foreground')}
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
        <MonthView days={days} month={date.slice(0, 7)} today={today} placed={placed.data ?? []} />
      ) : (
        <TimeGrid days={days} today={today} placed={placed.data ?? []} scrollKey={`${view}-${date}`} />
      )}
    </div>
  )
}


function MonthView({ days, month, today, placed }: { days: CivilDate[]; month: string; today?: CivilDate; placed: Placed[] }) {
  const { t, i18n } = useTranslation()
  const prefs = useCalendarPrefs()
  const [ghost, setGhost] = useState<DaySpanGhost | null>(null)
  const shown = 3
  // An armed touch (or a pen) over the month's cells drags, never scrolls.
  const grid = useRef<HTMLDivElement>(null)
  useEffect(() => (grid.current ? holdTouches(grid.current) : undefined), [])
  return (
    <div ref={grid} className="grid min-h-0 flex-1 select-none grid-cols-7 grid-rows-[auto_repeat(6,minmax(0,1fr))]" data-testid="calendar-month">
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
            onPointerDown={(e) => {
              if (e.target instanceof Element && e.target.closest('[data-testid="calendar-event"]')) return
              pressDays(e, day, setGhost, null)
            }}
            onKeyDown={(e) => e.key === 'Enter' && openEditor({ kind: 'new', date: day, allDay: true })}
            className={cn(
              'min-h-24 touch-pan-y space-y-0.5 overflow-hidden border-b border-r border-border p-1',
              !day.startsWith(month) && 'bg-muted/40 text-muted-foreground',
              ghostCovers(ghost, day) && 'bg-primary/15',
            )}
            data-testid={`calendar-day-${day}`}
          >
            <div className={cn('ml-auto grid size-6 place-items-center rounded-full text-xs', day === today && 'bg-primary text-primary-foreground')}>
              {formatDayNumber(day, i18n.language)}
            </div>
            {here.slice(0, shown).map((p) => (
              <EventChip
                key={p.event.id}
                placed={p}
                showTime
                faded={ghost?.kind === 'shift' && ghost.placed === p}
                onPointerDown={(e) => pressShiftDays(e, p, day, setGhost, (q, d, m) => void openMoved(q, d, m, prefs.zone), null)}
              />
            ))}
            {here.length > shown ? <div className="px-1.5 text-xs text-muted-foreground">{t('view.more', { count: here.length - shown })}</div> : null}
          </div>
        )
      })}
    </div>
  )
}
