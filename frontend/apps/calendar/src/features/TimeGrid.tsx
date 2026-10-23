import { ShieldAlert } from 'lucide-react'
import { useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type PointerEvent as ReactPointerEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { addDays, minutesOf, type CivilDate } from '@kutup/calendar-core/time'
import { cn } from '@kutup/ui/lib/cn'
import { ghostCovers, pressDays, pressShiftDays, type DaySpanGhost } from './DaySpan'
import { EventChip } from './EventChip'
import { openEditor } from './editorState'
import { formatHour, formatLongDate, formatTime, formatDayNumber, formatWeekday } from './format'
import { clickSpan, createSpan, DAY_MINUTES, localAt, resizeEnd, shiftLocal, snap, SNAP_MINUTES } from './gridInteraction'
import { openMoved, openNew, openTimes } from './moves'
import { columns, covers, type Placed } from './placement'
import { follow, holdTouches, type Point } from './press'
import { useCalendarPrefs } from './prefs'
import { useNowMinutes } from './today'

export const HOUR_PX = 48
const SLOTS = DAY_MINUTES / SNAP_MINUTES
/** The bottom edge of a timed event that resizes it. */
const RESIZE_EDGE_PX = 6

/**
 * What a drag or the keyboard shows before it lands: a new event's span on
 * a day (minutes), or an event's new times (local, in the view's zone).
 */
type Ghost = { kind: 'create'; day: number; start: number; end: number } | { kind: 'times'; placed: Placed; start: string; end: string }

/** Where an interval falls on a day's column, in minutes, if it does. */
function segment(start: string, end: string, day: CivilDate): { top: number; bottom: number } | null {
  const dayStart = `${day}T00:00:00`
  const dayEnd = `${addDays(day, 1)}T00:00:00`
  if (!(start < dayEnd && (end > dayStart || (end === start && start >= dayStart)))) return null
  const top = start < dayStart ? 0 : minutesOf(start)
  const bottom = end >= dayEnd ? DAY_MINUTES : minutesOf(end)
  return { top, bottom: Math.max(bottom, top + 20) }
}

/**
 * The day and week views: the all-day row, then 24 hours of half-hour
 * slots. Press and drag to make an event (snapped to 30 minutes), drag one
 * to move it, drag its bottom edge to resize it; a touch drags after a long
 * press. On the keyboard: arrows move between slots and days, Shift with ↑
 * or ↓ widens the span, Enter opens it; on an event, Alt with the arrows
 * moves it, Alt+Shift with ↑ or ↓ resizes it, Enter or Space opens it.
 */
export function TimeGrid({ days, today, placed, scrollKey }: { days: CivilDate[]; today?: CivilDate; placed: Placed[]; scrollKey: string }) {
  const { t, i18n } = useTranslation()
  const prefs = useCalendarPrefs()
  const scroller = useRef<HTMLDivElement>(null)
  const columnsRef = useRef<(HTMLDivElement | null)[]>([])
  const cells = useRef(new Map<string, HTMLButtonElement>())
  const now = useNowMinutes(prefs.zone)
  const [ghost, setGhostState] = useState<Ghost | null>(null)
  const ghostRef = useRef<Ghost | null>(null)
  const setGhost = (next: Ghost | null) => {
    ghostRef.current = next
    setGhostState(next)
  }
  const [dayGhost, setDayGhost] = useState<DaySpanGhost | null>(null)
  // The keyboard's place: a slot, and where a Shift selection began.
  const [focus, setFocus] = useState<{ day: number; slot: number; anchor: number | null }>({ day: 0, slot: 18, anchor: null })
  // A view with fewer days keeps a slot in the Tab order.
  const focusDay = Math.min(focus.day, days.length - 1)
  // Focus follows the keyboard only: never on opening (scroll to now stays).
  const keyMoved = useRef(false)
  const [said, setSaid] = useState('')

  // Proton's scroll to now: the current time in the middle, on opening, on Today and on a change of view.
  useLayoutEffect(() => {
    const el = scroller.current
    if (el) el.scrollTop = Math.max(0, (now / 60) * HOUR_PX - el.clientHeight / 2)
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only when the view or date changes
  }, [scrollKey])
  useEffect(() => (scroller.current ? holdTouches(scroller.current) : undefined), [])

  /** The day column and minute of the day under a point. */
  const at = (point: Point): { day: number; minutes: number } => {
    let day = days.length - 1
    for (let i = 0; i < days.length; i++) {
      const rect = columnsRef.current[i]?.getBoundingClientRect()
      if (rect && point.x < rect.right) {
        day = i
        break
      }
    }
    const rect = columnsRef.current[day]?.getBoundingClientRect()
    return { day, minutes: rect ? ((point.y - rect.top) / HOUR_PX) * 60 : 0 }
  }

  const describe = (dayIndex: number, start: number, end: number) =>
    t('grid.span', {
      day: formatLongDate(days[dayIndex], i18n.language),
      start: formatTime(localAt(days[dayIndex], start), i18n.language, prefs.hour12),
      end: formatTime(localAt(days[dayIndex], end), i18n.language, prefs.hour12),
    })

  // A press on a day's empty time: drag for a span, click for one slot (the default length).
  const pressCreate = (event: ReactPointerEvent, dayIndex: number) => {
    if (event.target instanceof Element && event.target.closest('[data-event]')) return
    const pressSlot = snap(at({ x: event.clientX, y: event.clientY }).minutes)
    follow(
      event,
      {
        armed: () => setGhost({ kind: 'create', day: dayIndex, ...createSpan(pressSlot, pressSlot) }),
        // Proton's: a span stays on the day it began.
        drag: (point) => setGhost({ kind: 'create', day: dayIndex, ...createSpan(pressSlot, snap(at(point).minutes)) }),
        drop: () => {
          const g = ghostRef.current
          setGhost(null)
          if (g?.kind === 'create') void openNew(days[g.day], g.start, g.end, prefs.zone)
        },
        click: () => {
          const span = clickSpan(pressSlot)
          void openNew(days[dayIndex], span.start, span.end, prefs.zone)
        },
        cancel: () => setGhost(null),
      },
      scroller.current,
    )
  }

  // A press on an event: drag to move it (across days too), its bottom edge to resize it.
  const pressEvent = (event: ReactPointerEvent<HTMLElement>, p: Placed, dayIndex: number, resizable: boolean) => {
    event.stopPropagation()
    const rect = event.currentTarget.getBoundingClientRect()
    const resizing = resizable && event.clientY > rect.bottom - RESIZE_EDGE_PX
    const origin = at({ x: event.clientX, y: event.clientY })
    const originSlot = snap(origin.minutes)
    const startMinutes = minutesOf(p.start)
    const dayOfStart = p.start.slice(0, 10)
    follow(
      event,
      {
        armed: () => setGhost({ kind: 'times', placed: p, start: p.start, end: p.end }),
        drag: (point) => {
          const now = at(point)
          if (resizing) {
            const from = dayOfStart === days[dayIndex] ? startMinutes : 0
            setGhost({ kind: 'times', placed: p, start: p.start, end: localAt(days[dayIndex], resizeEnd(from, snap(now.minutes))) })
          } else {
            const dayShift = now.day - origin.day
            const minutes = snap(now.minutes) - originSlot
            setGhost({ kind: 'times', placed: p, start: shiftLocal(p.start, dayShift, minutes), end: shiftLocal(p.end, dayShift, minutes) })
          }
        },
        drop: () => {
          const g = ghostRef.current
          setGhost(null)
          if (g?.kind === 'times' && (g.start !== p.start || g.end !== p.end)) void openTimes(p, g.start, g.end, prefs.zone)
        },
        click: () => openEditor({ kind: 'edit', event: p.event }),
        cancel: () => setGhost(null),
      },
      scroller.current,
    )
  }

  // The keyboard on a slot.
  useEffect(() => {
    if (!keyMoved.current) return
    keyMoved.current = false
    cells.current.get(`${focusDay}-${focus.slot}`)?.focus({ preventScroll: false })
  }, [focusDay, focus.slot])
  const keySpan = (f: typeof focus) => {
    const span = f.anchor === null ? clickSpan(f.slot * SNAP_MINUTES) : createSpan(f.anchor * SNAP_MINUTES, f.slot * SNAP_MINUTES)
    return span
  }
  const onSlotKey = (event: ReactKeyboardEvent, dayIndex: number, slot: number) => {
    const move = (next: { day?: number; slot?: number }, extend: boolean) => {
      event.preventDefault()
      const f = {
        day: next.day ?? dayIndex,
        slot: Math.min(Math.max(next.slot ?? slot, 0), SLOTS - 1),
        anchor: extend ? (focus.anchor ?? slot) : null,
      }
      keyMoved.current = true
      setFocus(f)
      if (f.anchor !== null) {
        const span = keySpan(f)
        setGhost({ kind: 'create', day: f.day, ...span })
        setSaid(describe(f.day, span.start, span.end))
      } else setGhost(null)
    }
    if (event.key === 'ArrowUp') move({ slot: slot - 1 }, event.shiftKey)
    else if (event.key === 'ArrowDown') move({ slot: slot + 1 }, event.shiftKey)
    else if (event.key === 'ArrowLeft' && dayIndex > 0) move({ day: dayIndex - 1 }, false)
    else if (event.key === 'ArrowRight' && dayIndex < days.length - 1) move({ day: dayIndex + 1 }, false)
    else if (event.key === 'Escape' && focus.anchor !== null) {
      event.preventDefault()
      setFocus({ day: dayIndex, slot, anchor: null })
      setGhost(null)
    } else if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      const span = keySpan({ day: dayIndex, slot, anchor: focus.anchor })
      setFocus({ day: dayIndex, slot, anchor: null })
      setGhost(null)
      void openNew(days[dayIndex], span.start, span.end, prefs.zone)
    } else return
    // Keys the grid took stay out of the page's shortcuts.
    event.stopPropagation()
  }

  // The keyboard on an event: Alt+arrows move it, Alt+Shift+↑/↓ resize it, Enter or Space opens it as moved.
  const onEventKey = (event: ReactKeyboardEvent, p: Placed) => {
    const current = ghostRef.current?.kind === 'times' && ghostRef.current.placed === p ? ghostRef.current : null
    const start = current?.start ?? p.start
    const end = current?.end ?? p.end
    const show = (nextStart: string, nextEnd: string) => {
      event.preventDefault()
      event.stopPropagation()
      setGhost({ kind: 'times', placed: p, start: nextStart, end: nextEnd })
      setSaid(
        t('grid.moved', {
          start: `${formatLongDate(nextStart.slice(0, 10), i18n.language)} ${formatTime(nextStart, i18n.language, prefs.hour12)}`,
          end: formatTime(nextEnd, i18n.language, prefs.hour12),
        }),
      )
    }
    if (event.altKey && event.shiftKey && (event.key === 'ArrowUp' || event.key === 'ArrowDown')) {
      const nextEnd = shiftLocal(end, 0, event.key === 'ArrowUp' ? -SNAP_MINUTES : SNAP_MINUTES)
      if (nextEnd >= shiftLocal(start, 0, SNAP_MINUTES)) show(start, nextEnd)
      else event.preventDefault()
    } else if (event.altKey && event.key.startsWith('Arrow')) {
      const [days_, minutes] =
        event.key === 'ArrowUp' ? [0, -SNAP_MINUTES] : event.key === 'ArrowDown' ? [0, SNAP_MINUTES] : event.key === 'ArrowLeft' ? [-1, 0] : [1, 0]
      show(shiftLocal(start, days_, minutes), shiftLocal(end, days_, minutes))
    } else if (event.key === 'Escape' && current) {
      event.preventDefault()
      event.stopPropagation()
      setGhost(null)
    } else if ((event.key === 'Enter' || event.key === ' ') && current) {
      event.preventDefault()
      event.stopPropagation()
      setGhost(null)
      void openTimes(p, current.start, current.end, prefs.zone)
    }
  }

  const allDay = (day: CivilDate) => placed.filter((p) => p.allDay && covers(p, day))
  const moving = ghost?.kind === 'times' ? ghost.placed : dayGhost?.kind === 'shift' ? dayGhost.placed : null
  return (
    <div className="flex min-h-0 flex-1 flex-col" data-testid="calendar-week">
      <div className="sr-only" role="status" aria-live="polite" data-testid="calendar-announce">
        {said}
      </div>
      <div className="grid border-b border-border" style={{ gridTemplateColumns: `3.5rem repeat(${days.length}, minmax(0, 1fr))` }}>
        <div />
        {days.map((day) => (
          <div
            key={day}
            data-day={day}
            onPointerDown={(e) => {
              if (e.target instanceof Element && e.target.closest('[data-testid="calendar-event"]')) return
              pressDays(e, day, setDayGhost, null)
            }}
            className={cn('min-h-12 touch-pan-y border-l border-border px-2 py-1 text-center', ghostCovers(dayGhost, day) && 'bg-primary/15')}
            data-testid={`calendar-allday-${day}`}
          >
            <div className="text-xs text-muted-foreground">{formatWeekday(day, i18n.language)}</div>
            <div className={cn('mx-auto grid size-7 place-items-center rounded-full text-sm', day === today && 'bg-primary text-primary-foreground')}>
              {formatDayNumber(day, i18n.language)}
            </div>
            <div className="mt-1 space-y-0.5">
              {allDay(day).map((p) => (
                <EventChip
                  key={p.event.id}
                  placed={p}
                  showTime={false}
                  faded={moving === p}
                  onPointerDown={(e) => pressShiftDays(e, p, day, setDayGhost, (q, d, m) => void openMoved(q, d, m, prefs.zone), null)}
                />
              ))}
            </div>
          </div>
        ))}
      </div>
      <div ref={scroller} className="min-h-0 flex-1 overflow-y-auto" data-testid="calendar-scroller">
        <div className="relative grid" style={{ gridTemplateColumns: `3.5rem repeat(${days.length}, minmax(0, 1fr))`, height: 24 * HOUR_PX }}>
          <div>
            {Array.from({ length: 24 }, (_, hour) => (
              <div key={hour} className="pr-2 text-right text-[11px] text-muted-foreground" style={{ height: HOUR_PX }}>
                {hour === 0 ? null : formatHour(hour, i18n.language, prefs.hour12)}
              </div>
            ))}
          </div>
          {days.map((day, dayIndex) => {
            const segments = placed
              .filter((p) => !p.allDay)
              .flatMap((p) => {
                const s = segment(p.start, p.end, day)
                return s ? [{ placed: p, ...s }] : []
              })
            const ghostHere =
              ghost?.kind === 'create'
                ? ghost.day === dayIndex
                  ? { top: ghost.start, bottom: ghost.end }
                  : null
                : ghost
                  ? segment(ghost.start, ghost.end, day)
                  : null
            return (
              <div
                key={day}
                ref={(el) => {
                  columnsRef.current[dayIndex] = el
                }}
                className="relative touch-pan-y select-none border-l border-border"
                onPointerDown={(e) => pressCreate(e, dayIndex)}
                data-testid={`calendar-column-${day}`}
              >
                {Array.from({ length: SLOTS }, (_, slot) => (
                  <button
                    key={slot}
                    ref={(el) => {
                      if (el) cells.current.set(`${dayIndex}-${slot}`, el)
                      else cells.current.delete(`${dayIndex}-${slot}`)
                    }}
                    type="button"
                    tabIndex={focusDay === dayIndex && focus.slot === slot ? 0 : -1}
                    aria-label={t('grid.slot', { day: formatLongDate(day, i18n.language), time: formatTime(localAt(day, slot * SNAP_MINUTES), i18n.language, prefs.hour12) })}
                    onFocus={() => (focusDay !== dayIndex || focus.slot !== slot ? setFocus({ day: dayIndex, slot, anchor: null }) : undefined)}
                    // A Shift selection ends when focus leaves the grid's slots.
                    onBlur={(e) => {
                      if (!(e.relatedTarget instanceof HTMLElement && e.relatedTarget.closest('[data-slot]')) && ghostRef.current?.kind === 'create') {
                        setFocus((f) => ({ ...f, anchor: null }))
                        setGhost(null)
                      }
                    }}
                    data-slot
                    onKeyDown={(e) => onSlotKey(e, dayIndex, slot)}
                    // A pointer's click is the column's press; a key's is handled above.
                    onClick={(e) => e.preventDefault()}
                    className={cn('block w-full hover:bg-accent/40 focus-visible:relative focus-visible:z-10', slot % 2 === 1 && 'border-b border-border/60')}
                    style={{ height: HOUR_PX / 2 }}
                    data-testid={`calendar-slot-${day}-${slot}`}
                  />
                ))}
                {day === today ? (
                  <div className="pointer-events-none absolute inset-x-0 z-20 h-0.5 bg-destructive" style={{ top: (now / 60) * HOUR_PX }} data-testid="calendar-now" aria-hidden>
                    <div className="absolute -left-1 -top-1 size-2.5 rounded-full bg-destructive" />
                  </div>
                ) : null}
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
                    <TimedBlock
                      placed={s.placed}
                      faded={moving === s.placed}
                      // Only the segment where the event ends resizes it.
                      resizable={endsOn(s.placed, day)}
                      onPointerDown={(e, resizable) => pressEvent(e, s.placed, dayIndex, resizable)}
                      onKeyDown={(e) => onEventKey(e, s.placed)}
                      // A keyboard move not opened is dropped when focus leaves it.
                      onBlur={() => {
                        if (ghostRef.current?.kind === 'times' && ghostRef.current.placed === s.placed) setGhost(null)
                      }}
                    />
                  </div>
                ))}
                {ghostHere ? (
                  <div
                    className="pointer-events-none absolute inset-x-0.5 z-30 rounded border-2 border-primary bg-primary/20 px-1.5 py-0.5 text-xs tabular-nums"
                    style={{ top: (ghostHere.top / 60) * HOUR_PX, height: ((ghostHere.bottom - ghostHere.top) / 60) * HOUR_PX }}
                    data-testid="calendar-ghost"
                  >
                    {ghost?.kind === 'create'
                      ? `${formatTime(localAt(day, ghost.start), i18n.language, prefs.hour12)} – ${formatTime(localAt(day, ghost.end), i18n.language, prefs.hour12)}`
                      : ghost
                        ? `${formatTime(ghost.start, i18n.language, prefs.hour12)} – ${formatTime(ghost.end, i18n.language, prefs.hour12)}`
                        : null}
                  </div>
                ) : null}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

/** Whether a timed event ends on `day` (at its midnight included). */
function endsOn(placed: Placed, day: CivilDate): boolean {
  return placed.end.slice(0, 10) === day || placed.end === `${addDays(day, 1)}T00:00:00`
}

function TimedBlock({
  placed,
  faded,
  resizable,
  onPointerDown,
  onKeyDown,
  onBlur,
}: {
  placed: Placed
  faded: boolean
  resizable: boolean
  onPointerDown: (event: ReactPointerEvent<HTMLElement>, resizable: boolean) => void
  onKeyDown: (event: ReactKeyboardEvent) => void
  onBlur: () => void
}) {
  const { t, i18n } = useTranslation()
  const prefs = useCalendarPrefs()
  return (
    <button
      type="button"
      data-event
      onPointerDown={(e) => onPointerDown(e, resizable)}
      onKeyDown={onKeyDown}
      onBlur={onBlur}
      onClick={(e) => {
        e.stopPropagation()
        // A pointer's click is the grid's press; a key's opens the event.
        if (e.detail === 0) openEditor({ kind: 'edit', event: placed.event })
      }}
      aria-keyshortcuts="Alt+ArrowUp Alt+ArrowDown Alt+ArrowLeft Alt+ArrowRight Alt+Shift+ArrowUp Alt+Shift+ArrowDown"
      className={cn(
        'group relative flex h-full w-full touch-pan-y flex-col overflow-hidden rounded px-1.5 py-0.5 text-left text-xs hover:brightness-95',
        faded && 'opacity-40',
      )}
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
      {resizable ? (
        <span
          aria-hidden
          className="absolute inset-x-0 bottom-0 cursor-ns-resize opacity-0 group-hover:opacity-100"
          style={{ height: RESIZE_EDGE_PX }}
          data-testid="calendar-event-resize"
        >
          <span className="mx-auto mt-0.5 block h-0.5 w-6 rounded bg-foreground/40" />
        </span>
      ) : null}
    </button>
  )
}
