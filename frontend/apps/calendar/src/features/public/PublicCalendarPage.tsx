import { CalendarDays, ChevronLeft, ChevronRight, Lock } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { addDays, viewDays, type CivilDate } from '@kutup/calendar-core/time'
import { localToUtc, utcToLocal } from '@kutup/crypto/calendar'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { LoadingPanel } from '@kutup/ui/components/states'
import { formatLongDate, formatTime, formatTitle } from '../format'
import { covers, placeAll, type Placed } from '../placement'
import { closePublicCalendar, LinkKeyMissing, LinkNotFound, linkProof, loadBusyBlocks, loadPublicEvents, loadPublicLink, openPublicCalendar, type BusyBlock } from './publicClient'

/** The viewer's own zone: a link has no account, so no calendar zone to read. */
const ZONE = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'

/** One row of the agenda: an event's title, or "Busy". */
interface Item {
  key: string
  allDay: boolean
  start: string
  end: string
  title: string | null
}

function todayIn(zone: string): CivilDate {
  return new Intl.DateTimeFormat('en-CA', { timeZone: zone, year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date())
}

/** A busy block where the viewer's zone puts it (as `place` does an event). */
async function placeBusy(block: BusyBlock, index: number): Promise<Placed> {
  if (block.fullDay) {
    const first = block.startUtc.slice(0, 10)
    const after = block.endUtc.slice(0, 10) > first ? block.endUtc.slice(0, 10) : addDays(first, 1)
    return { key: `busy-${index}`, event: { id: `busy-${index}` } as Placed['event'], instance: null, color: '', allDay: true, start: first, end: after, firstDay: first, afterLastDay: after }
  }
  const [start, end] = await Promise.all([utcToLocal(block.startUtc, ZONE), utcToLocal(block.endUtc, ZONE)])
  const lastDay = end.slice(11) === '00:00:00' && end > start ? addDays(end.slice(0, 10), -1) : end.slice(0, 10)
  return { key: `busy-${index}`, event: { id: `busy-${index}` } as Placed['event'], instance: null, color: '', allDay: false, start, end, firstDay: start.slice(0, 10), afterLastDay: addDays(lastDay, 1) }
}

/**
 * A calendar link's page (`/l/{id}#secret`, docs/plans/calendar-e3.md §3):
 * read-only, without an account. A full link's events open in this browser
 * with the key in the fragment; a busy link shows when its owner is busy.
 */
export function PublicCalendarPage() {
  const { t, i18n } = useTranslation()
  const { linkId = '' } = useParams()
  // Read once: the fragment is the key, and never goes to the server.
  const [secret] = useState(() => decodeURIComponent(window.location.hash.replace(/^#/, '')))
  const [date, setDate] = useState<CivilDate>(() => todayIn(ZONE))
  const days = useMemo(() => viewDays('week', date, 1), [date])

  const link = useQuery({ queryKey: ['public-link', linkId], queryFn: () => loadPublicLink(linkId, secret), retry: false, staleTime: Infinity })
  const calendar = useQuery({
    queryKey: ['public-calendar', linkId, secret],
    enabled: link.data?.kind === 'full',
    retry: false,
    staleTime: Infinity,
    gcTime: 0,
    queryFn: () => openPublicCalendar(linkId, link.data!, secret),
  })
  // The keys live in WASM: freed when the page goes.
  useEffect(() => {
    const opened = calendar.data
    return () => {
      if (opened) closePublicCalendar(opened)
    }
  }, [calendar.data])

  const range = useQuery({
    queryKey: ['public-range', days[0], days.at(-1)],
    queryFn: async () => ({
      start: await localToUtc(`${days[0]}T00:00:00`, ZONE),
      end: await localToUtc(`${addDays(days.at(-1)!, 1)}T00:00:00`, ZONE),
    }),
  })
  const items = useQuery({
    queryKey: ['public-items', linkId, link.data?.kind, range.data?.start, range.data?.end, !!calendar.data],
    enabled: !!range.data && (link.data?.kind === 'busy' || !!calendar.data),
    queryFn: async () => {
      const { start, end } = range.data!
      if (link.data!.kind === 'busy') {
        const blocks = await loadBusyBlocks(linkId, start, end)
        return { placed: await Promise.all(blocks.map(placeBusy)), unreadable: 0, busy: true }
      }
      const loaded = await loadPublicEvents(linkId, calendar.data!, start, end, (await linkProof(linkId, secret)) ?? '')
      return { placed: await placeAll(loaded.events, () => '', ZONE, start, end), unreadable: loaded.unreadable, busy: false }
    },
  })

  const failure = link.error ?? calendar.error
  const title = link.data?.kind === 'busy' ? t('publicLink.busyTitle') : (calendar.data?.name ?? '')

  if (failure) {
    const key = failure instanceof LinkNotFound ? 'gone' : failure instanceof LinkKeyMissing ? 'incomplete' : 'unreadable'
    return (
      <main className="mx-auto flex min-h-svh max-w-md flex-col justify-center gap-4 p-6">
        <Alert variant="error" title={t(`publicLink.errors.${key}.title`)}>
          {t(`publicLink.errors.${key}.body`)}
        </Alert>
      </main>
    )
  }
  if (link.data?.kind === 'query') {
    return (
      <main className="mx-auto flex min-h-svh max-w-md flex-col justify-center gap-4 p-6">
        <Alert title={t('publicLink.forApps.title')}>{t('publicLink.forApps.body')}</Alert>
      </main>
    )
  }
  if (!link.data || (link.data.kind === 'full' && !calendar.data)) return <LoadingPanel label={t('publicLink.opening')} />

  const byDay: { day: CivilDate; items: Item[] }[] = days.map((day) => ({
    day,
    items: (items.data?.placed ?? [])
      .filter((p) => covers(p, day))
      .sort((a, b) => Number(b.allDay) - Number(a.allDay) || a.start.localeCompare(b.start))
      .map((p) => ({ key: `${p.key}-${day}`, allDay: p.allDay, start: p.start, end: p.end, title: items.data!.busy ? null : (p.event.fields.summary ?? null) })),
  }))

  return (
    <main className="mx-auto max-w-3xl space-y-4 p-4 sm:p-6" data-testid="public-calendar">
      <header className="space-y-1">
        <h1 className="flex items-center gap-2 text-xl font-semibold">
          <CalendarDays className="size-5 shrink-0" aria-hidden />
          <span className="min-w-0 truncate">{title}</span>
        </h1>
        {calendar.data?.description ? <p className="text-sm text-muted-foreground">{calendar.data.description}</p> : null}
        <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Lock className="size-3.5" aria-hidden />
          {t(link.data.kind === 'busy' ? 'publicLink.busyNote' : 'publicLink.fullNote')}
        </p>
      </header>
      <nav className="flex items-center gap-2" aria-label={t('publicLink.weeks')}>
        <Button variant="outline" size="icon" aria-label={t('publicLink.previous')} onClick={() => setDate(addDays(date, -7))}>
          <ChevronLeft />
        </Button>
        <Button variant="outline" onClick={() => setDate(todayIn(ZONE))}>
          {t('publicLink.today')}
        </Button>
        <Button variant="outline" size="icon" aria-label={t('publicLink.next')} onClick={() => setDate(addDays(date, 7))}>
          <ChevronRight />
        </Button>
        <h2 className="ml-2 text-sm font-medium" aria-live="polite">
          {formatTitle('week', date, i18n.language)}
        </h2>
      </nav>
      {items.isError ? <Alert variant="error">{t('publicLink.errors.events')}</Alert> : null}
      {items.data?.unreadable ? <Alert variant="warn">{t('publicLink.unreadable', { count: items.data.unreadable })}</Alert> : null}
      <ol className="divide-y divide-border rounded-md border border-border">
        {byDay.map(({ day, items: dayItems }) => (
          <li key={day} className="flex flex-col gap-1 px-3 py-2 sm:flex-row sm:gap-4">
            <h3 className="w-40 shrink-0 text-sm font-medium">{formatLongDate(day, i18n.language)}</h3>
            {items.isPending ? (
              <p className="text-sm text-muted-foreground">{t('common.loading')}</p>
            ) : dayItems.length ? (
              <ul className="min-w-0 flex-1 space-y-1">
                {dayItems.map((item) => (
                  <li key={item.key} className="flex gap-3 text-sm" data-testid="public-item">
                    <span className="w-28 shrink-0 tabular-nums text-muted-foreground">
                      {item.allDay ? t('publicLink.allDay') : `${formatTime(item.start, i18n.language, null)}–${formatTime(item.end, i18n.language, null)}`}
                    </span>
                    <span className="min-w-0 truncate">{item.title ?? (items.data?.busy ? t('publicLink.busy') : t('publicLink.untitled'))}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">{t('publicLink.free')}</p>
            )}
          </li>
        ))}
      </ol>
    </main>
  )
}
