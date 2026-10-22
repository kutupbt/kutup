import { useQuery } from '@tanstack/react-query'
import { ChevronLeft, ChevronRight, ShieldAlert } from 'lucide-react'
import { useEffect, useMemo, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'
import { useCalendars, useEvents, type Calendar, type CalendarEvent } from '@kutup/calendar-core/api'
import { addDays, isCivilDate, minutesOf, step, viewDays, type CivilDate } from '@kutup/calendar-core/time'
import { localToUtc, utcToLocal } from '@kutup/crypto/calendar'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'
import { openEditor } from './editorState'
import { formatDayNumber, formatHour, formatTime, formatTitle, formatWeekday } from './format'
import { useCalendarPrefs } from './prefs'
import { useToday } from './today'

type View = 'day' | 'week' | 'month'
const VIEWS: readonly View[] = ['day', 'week', 'month']
const HOUR_PX = 48

/** An event where the view's zone puts it. */
interface Placed {
  event: CalendarEvent
  color: string
  allDay: boolean
  /** Local date-times in the view's zone (`2026-10-29T09:30:00`); dates for all-day events. */
  start: string
  end: string
  /** The first day it covers and the day after its last. */
  firstDay: CivilDate
  afterLastDay: CivilDate
}

async function place(event: CalendarEvent, color: string, zone: string): Promise<Placed> {
  const { start, end } = event.fields
  if ('date' in start) {
    const after = end && 'date' in end ? end.date : addDays(start.date, 1)
    return { event, color, allDay: true, start: start.date, end: after, firstDay: start.date, afterLastDay: after }
  }
  const [startLocal, endLocal] = await Promise.all([utcToLocal(event.startUtc, zone), utcToLocal(event.endUtc, zone)])
  const lastDay = endLocal.slice(11) === '00:00:00' && endLocal > startLocal ? addDays(endLocal.slice(0, 10), -1) : endLocal.slice(0, 10)
  return { event, color, allDay: false, start: startLocal, end: endLocal, firstDay: startLocal.slice(0, 10), afterLastDay: addDays(lastDay, 1) }
}

function covers(placed: Placed, day: CivilDate): boolean {
  return placed.firstDay <= day && day < placed.afterLastDay
}

/** The calendar: a day, a week or a month of the shown calendars' events. */
export function CalendarPage() {
  const { t, i18n } = useTranslation()
  const prefs = useCalendarPrefs()
  const today = useToday(prefs.zone)
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

  // Arrow keys move through time, "t" comes back to today.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLElement && e.target.closest('input, textarea, select, [role="dialog"]')) return
      if (!date) return
      if (e.key === 'ArrowLeft') go({ date: step(view, date, -1) })
      else if (e.key === 'ArrowRight') go({ date: step(view, date, 1) })
      else if (e.key === 't' && today) go({ date: today })
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
        <TimeGrid days={days} today={today} placed={placed.data ?? []} />
      )}
    </div>
  )
}

function EventChip({ placed, showTime }: { placed: Placed; showTime: boolean }) {
  const { t, i18n } = useTranslation()
  const prefs = useCalendarPrefs()
  const title = placed.event.fields.summary ?? t('events.untitled')
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation()
        openEditor({ kind: 'edit', event: placed.event })
      }}
      className="flex w-full min-w-0 items-center gap-1 truncate rounded px-1.5 py-0.5 text-left text-xs hover:brightness-95"
      style={{ background: `${placed.color}26`, borderLeft: `3px solid ${placed.color}` }}
      data-testid="calendar-event"
    >
      {!placed.event.verified ? <ShieldAlert className="size-3 shrink-0 text-destructive" aria-label={t('events.unverifiedShort')} /> : null}
      {showTime && !placed.allDay ? <span className="shrink-0 tabular-nums text-muted-foreground">{formatTime(placed.start, i18n.language, prefs.hour12)}</span> : null}
      <span className="truncate">{title}</span>
    </button>
  )
}

function MonthView({ days, month, today, placed }: { days: CivilDate[]; month: string; today?: CivilDate; placed: Placed[] }) {
  const { t, i18n } = useTranslation()
  const shown = 3
  return (
    <div className="grid min-h-0 flex-1 grid-cols-7 grid-rows-[auto_repeat(6,minmax(0,1fr))]" data-testid="calendar-month">
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
            onClick={() => openEditor({ kind: 'new', date: day, allDay: true })}
            onKeyDown={(e) => e.key === 'Enter' && openEditor({ kind: 'new', date: day, allDay: true })}
            className={cn('min-h-24 space-y-0.5 overflow-hidden border-b border-r border-border p-1', !day.startsWith(month) && 'bg-muted/40 text-muted-foreground')}
            data-testid={`calendar-day-${day}`}
          >
            <div className={cn('ml-auto grid size-6 place-items-center rounded-full text-xs', day === today && 'bg-primary text-primary-foreground')}>
              {formatDayNumber(day, i18n.language)}
            </div>
            {here.slice(0, shown).map((p) => (
              <EventChip key={p.event.id} placed={p} showTime />
            ))}
            {here.length > shown ? <div className="px-1.5 text-xs text-muted-foreground">{t('view.more', { count: here.length - shown })}</div> : null}
          </div>
        )
      })}
    </div>
  )
}

/** Timed events of one day laid out in columns where they overlap. */
function columns(segments: { placed: Placed; top: number; bottom: number }[]) {
  const sorted = [...segments].sort((a, b) => a.top - b.top || b.bottom - a.bottom)
  const out: { placed: Placed; top: number; bottom: number; column: number; columns: number }[] = []
  let cluster: typeof out = []
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

function TimeGrid({ days, today, placed }: { days: CivilDate[]; today?: CivilDate; placed: Placed[] }) {
  const { i18n } = useTranslation()
  const prefs = useCalendarPrefs()
  const scroller = useRef<HTMLDivElement>(null)
  useEffect(() => {
    scroller.current?.scrollTo({ top: 7 * HOUR_PX })
  }, [])
  const allDay = (day: CivilDate) => placed.filter((p) => p.allDay && covers(p, day))
  return (
    <div className="flex min-h-0 flex-1 flex-col" data-testid="calendar-week">
      <div className="grid border-b border-border" style={{ gridTemplateColumns: `3.5rem repeat(${days.length}, minmax(0, 1fr))` }}>
        <div />
        {days.map((day) => (
          <div key={day} className="border-l border-border px-2 py-1 text-center">
            <div className="text-xs text-muted-foreground">{formatWeekday(day, i18n.language)}</div>
            <div className={cn('mx-auto grid size-7 place-items-center rounded-full text-sm', day === today && 'bg-primary text-primary-foreground')}>
              {formatDayNumber(day, i18n.language)}
            </div>
            <div className="mt-1 space-y-0.5">
              {allDay(day).map((p) => (
                <EventChip key={p.event.id} placed={p} showTime={false} />
              ))}
            </div>
          </div>
        ))}
      </div>
      <div ref={scroller} className="min-h-0 flex-1 overflow-y-auto">
        <div className="relative grid" style={{ gridTemplateColumns: `3.5rem repeat(${days.length}, minmax(0, 1fr))`, height: 24 * HOUR_PX }}>
          <div>
            {Array.from({ length: 24 }, (_, hour) => (
              <div key={hour} className="h-12 pr-2 text-right text-[11px] text-muted-foreground" style={{ height: HOUR_PX }}>
                {hour === 0 ? null : formatHour(hour, i18n.language, prefs.hour12)}
              </div>
            ))}
          </div>
          {days.map((day) => {
            const dayStart = `${day}T00:00:00`
            const dayEnd = `${addDays(day, 1)}T00:00:00`
            const segments = placed
              .filter((p) => !p.allDay && p.start < dayEnd && (p.end > dayStart || (p.end === p.start && p.start >= dayStart)))
              .map((p) => {
                const from = p.start < dayStart ? 0 : minutesOf(p.start)
                const to = p.end >= dayEnd ? 24 * 60 : minutesOf(p.end)
                return { placed: p, top: from, bottom: Math.max(to, from + 20) }
              })
            return (
              <div key={day} className="relative border-l border-border" data-testid={`calendar-column-${day}`}>
                {Array.from({ length: 24 }, (_, hour) => (
                  <button
                    key={hour}
                    type="button"
                    aria-label={`${day} ${formatHour(hour, i18n.language, prefs.hour12)}`}
                    onClick={() => openEditor({ kind: 'new', date: day, minutes: hour * 60 })}
                    className="block w-full border-b border-border/60 hover:bg-accent/40"
                    style={{ height: HOUR_PX }}
                  />
                ))}
                {columns(segments).map((s) => (
                  <div
                    key={s.placed.event.id}
                    className="absolute px-0.5"
                    style={{
                      top: (s.top / 60) * HOUR_PX,
                      height: ((s.bottom - s.top) / 60) * HOUR_PX,
                      left: `${(s.column / s.columns) * 100}%`,
                      width: `${100 / s.columns}%`,
                    }}
                  >
                    <TimedBlock placed={s.placed} />
                  </div>
                ))}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

function TimedBlock({ placed }: { placed: Placed }) {
  const { t, i18n } = useTranslation()
  const prefs = useCalendarPrefs()
  return (
    <button
      type="button"
      onClick={() => openEditor({ kind: 'edit', event: placed.event })}
      className="flex h-full w-full flex-col overflow-hidden rounded px-1.5 py-0.5 text-left text-xs hover:brightness-95"
      style={{ background: `${placed.color}33`, borderLeft: `3px solid ${placed.color}` }}
      data-testid="calendar-event"
    >
      <span className="flex items-center gap-1 truncate font-medium">
        {!placed.event.verified ? <ShieldAlert className="size-3 shrink-0 text-destructive" aria-label={t('events.unverifiedShort')} /> : null}
        <span className="truncate">{placed.event.fields.summary ?? t('events.untitled')}</span>
      </span>
      <span className="truncate tabular-nums text-muted-foreground">
        {formatTime(placed.start, i18n.language, prefs.hour12)} – {formatTime(placed.end, i18n.language, prefs.hour12)}
      </span>
    </button>
  )
}
