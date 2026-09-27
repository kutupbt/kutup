import { useWindowVirtualizer } from '@tanstack/react-virtual'
import { Check, ImageUp } from 'lucide-react'
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'
import { useRequiredSession } from '@kutup/session/store'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { Alert } from '@kutup/ui/components/alert'
import { cn } from '@kutup/ui/lib/cn'
import { formatDay, formatMonth } from '../library/format'
import type { Photo } from '../library/library'
import { useLibraryContext } from '../library/libraryContext'
import { columnsFor, daysOf, timelineRows, type TimelineRow } from '../library/timeline'
import { PhotoViewer } from '../viewer/PhotoViewer'
import type { Album } from '../albums/albums'
import { PhotoTile } from './PhotoTile'
import { Scrubber } from './Scrubber'
import { SelectionBar } from './SelectionBar'

const GAP = 3
const MONTH_ROW = 72
const DAY_ROW = 44

function rowHeight(row: TimelineRow<Photo>, tile: number): number {
  if (row.kind === 'month') return MONTH_ROW
  if (row.kind === 'day') return DAY_ROW
  return tile + GAP
}

/**
 * The width of an element, as it changes. A callback ref: the element only
 * appears once the library has loaded.
 */
function useWidth(): [(el: HTMLDivElement | null) => void, number, HTMLDivElement | null] {
  const [el, setEl] = useState<HTMLDivElement | null>(null)
  const [width, setWidth] = useState(0)
  useLayoutEffect(() => {
    if (!el) return
    setWidth(el.clientWidth)
    const observer = new ResizeObserver(() => setWidth(el.clientWidth))
    observer.observe(el)
    return () => observer.disconnect()
  }, [el])
  return [setEl, width, el]
}

/** Files dropped anywhere on the page upload into the library. */
function useDropZone(onFiles: (files: File[]) => void, enabled: boolean): boolean {
  const [over, setOver] = useState(false)
  useEffect(() => {
    if (!enabled) return
    let depth = 0
    const hasFiles = (e: DragEvent) => Boolean(e.dataTransfer?.types.includes('Files'))
    const enter = (e: DragEvent) => {
      if (!hasFiles(e)) return
      depth++
      setOver(true)
    }
    const leave = (e: DragEvent) => {
      if (!hasFiles(e)) return
      depth = Math.max(0, depth - 1)
      if (depth === 0) setOver(false)
    }
    const overHandler = (e: DragEvent) => {
      if (hasFiles(e)) e.preventDefault()
    }
    const drop = (e: DragEvent) => {
      if (!hasFiles(e)) return
      e.preventDefault()
      depth = 0
      setOver(false)
      const files = [...(e.dataTransfer?.files ?? [])].filter((f) => f.size > 0 || f.type)
      if (files.length) onFiles(files)
    }
    window.addEventListener('dragenter', enter)
    window.addEventListener('dragleave', leave)
    window.addEventListener('dragover', overHandler)
    window.addEventListener('drop', drop)
    return () => {
      window.removeEventListener('dragenter', enter)
      window.removeEventListener('dragleave', leave)
      window.removeEventListener('dragover', overHandler)
      window.removeEventListener('drop', drop)
    }
  }, [onFiles, enabled])
  return over
}

export interface PhotoGridProps {
  /** The photos to show, newest first. */
  photos: Photo[]
  title: string
  empty: { title: string; description: string; action?: ReactNode }
  /** Files dropped on the page upload into the library (not on Hidden). */
  dropToUpload?: boolean
  /** Beside the title (an album's menu). */
  actions?: ReactNode
  /** The album shown: the selection can take photos out of it. */
  album?: Album
}

/**
 * Photos newest first, by day under month headings: virtualized, with a
 * month scrubber, selection, the viewer, and dropping files to upload. The
 * timeline, Favourites, Archive and Hidden are each one of these.
 */
export function PhotoGrid({ photos, title, empty: emptyState, dropToUpload = true, actions, album }: PhotoGridProps) {
  const { t, i18n } = useTranslation()
  const session = useRequiredSession()
  const { loading, error, upload, preferences, marks } = useLibraryContext()
  const days = useMemo(() => daysOf(photos), [photos])
  const [params, setParams] = useSearchParams()
  const openId = params.get('photo')
  const [listRef, width, listEl] = useWidth()
  const narrow = width > 0 && width < 640
  const columns = width > 0 ? columnsFor(width, narrow ? 96 : 176, GAP) : 4
  const tile = width > 0 ? (width - GAP * (columns - 1)) / columns : 0
  const rows = useMemo(() => timelineRows(days, columns), [days, columns])

  const [selected, setSelected] = useState<Set<string>>(() => new Set())
  const anchor = useRef<string | null>(null)
  const order = useMemo(() => new Map(photos.map((p, i) => [p.id, i])), [photos])
  // Photos that went away (moved, deleted) leave the selection.
  useEffect(() => {
    setSelected((current) => {
      const kept = [...current].filter((id) => order.has(id))
      return kept.length === current.size ? current : new Set(kept)
    })
  }, [order])

  // Where the grid starts on the page: the heading above it changes (a
  // selection replaces it, an empty library adds a message).
  const [margin, setMargin] = useState(0)
  const selecting = selected.size > 0
  const empty = photos.length === 0
  useLayoutEffect(() => {
    if (listEl) setMargin(Math.round(listEl.getBoundingClientRect().top + window.scrollY))
  }, [listEl, width, selecting, empty])

  const toggle = useCallback(
    (photo: Photo, range: boolean) => {
      setSelected((current) => {
        const next = new Set(current)
        const from = anchor.current !== null ? order.get(anchor.current) : undefined
        const to = order.get(photo.id)
        if (range && from !== undefined && to !== undefined) {
          const [a, b] = from < to ? [from, to] : [to, from]
          for (let i = a; i <= b; i++) next.add(photos[i].id)
        } else if (next.has(photo.id)) {
          next.delete(photo.id)
        } else {
          next.add(photo.id)
        }
        return next
      })
      anchor.current = photo.id
    },
    [order, photos],
  )

  const toggleDay = useCallback((items: Photo[]) => {
    setSelected((current) => {
      const next = new Set(current)
      const all = items.every((p) => next.has(p.id))
      for (const p of items) {
        if (all) next.delete(p.id)
        else next.add(p.id)
      }
      return next
    })
  }, [])

  const open = useCallback(
    (photo: Photo) => {
      setParams((p) => {
        const next = new URLSearchParams(p)
        next.set('photo', photo.id)
        return next
      })
    },
    [setParams],
  )
  const closeViewer = useCallback(() => {
    setParams((p) => {
      const next = new URLSearchParams(p)
      next.delete('photo')
      return next
    }, { replace: true })
  }, [setParams])

  const dropping = useDropZone(useCallback((files: File[]) => void upload(files), [upload]), dropToUpload)

  const virtualizer = useWindowVirtualizer({
    count: rows.length,
    estimateSize: (i) => rowHeight(rows[i], tile),
    overscan: 4,
    scrollMargin: margin,
  })
  // Sizes follow the width: tell the virtualizer when tiles resize.
  useEffect(() => {
    virtualizer.measure()
  }, [virtualizer, tile, rows])

  const monthRows = useMemo(
    () => rows.flatMap((row, index) => (row.kind === 'month' ? [{ month: row.month, index }] : [])),
    [rows],
  )

  if (error) {
    return (
      <div className="px-4 py-6 md:px-8">
        <Alert variant="error" title={t('timeline.failedTitle')}>
          {t('timeline.failedDescription')}
        </Alert>
      </div>
    )
  }
  if (loading && photos.length === 0) return <LoadingPanel label={t('timeline.loading')} />

  const selection = photos.filter((p) => selected.has(p.id))
  const viewerIndex = openId ? photos.findIndex((p) => p.id === openId) : -1

  return (
    <div className="relative min-h-[calc(100svh-3.5rem)]">
      {selection.length > 0 ? (
        <SelectionBar photos={selection} album={album} onClear={() => setSelected(new Set())} />
      ) : (
        <div className="flex items-baseline justify-between gap-4 px-4 pb-2 pt-5 md:px-8">
          <h1 className="min-w-0 truncate font-display text-2xl font-semibold tracking-tight">{title}</h1>
          <div className="flex shrink-0 items-center gap-2">
            {photos.length > 0 ? (
              <p className="text-sm text-muted-foreground">{t('timeline.count', { count: photos.length })}</p>
            ) : null}
            {actions}
          </div>
        </div>
      )}

      {photos.length === 0 ? (
        <div className="px-4 md:px-8">
          <EmptyState title={emptyState.title} description={emptyState.description} action={emptyState.action} />
        </div>
      ) : null}

      <div className="flex gap-2 px-1 md:pl-8 md:pr-2">
        <div ref={listRef} className="min-w-0 flex-1">
          <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
            {virtualizer.getVirtualItems().map((item) => {
              const row = rows[item.index]
              const top = item.start - virtualizer.options.scrollMargin
              if (row.kind === 'month') {
                return (
                  <h2
                    key={row.key}
                    className="absolute inset-x-0 flex items-end px-2 pb-2 font-display text-xl font-semibold tracking-tight md:px-0"
                    style={{ top, height: MONTH_ROW }}
                  >
                    {formatMonth(row.month, i18n.language)}
                  </h2>
                )
              }
              if (row.kind === 'day') {
                const all = row.items.every((p) => selected.has(p.id))
                return (
                  <div key={row.key} className="group/day absolute inset-x-0 flex items-center gap-2 px-2 md:px-0" style={{ top, height: DAY_ROW }}>
                    <button
                      type="button"
                      role="checkbox"
                      aria-checked={all}
                      aria-label={t('timeline.selectDay', { day: formatDay(row.day, i18n.language) })}
                      onClick={() => toggleDay(row.items)}
                      className={cn(
                        // In the margin beside the heading on wide screens, so headings line up with the photos.
                        'flex size-5 shrink-0 items-center justify-center rounded-full border-2 transition-opacity focus-visible:opacity-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring md:absolute md:-left-7',
                        all ? 'border-primary bg-primary text-primary-foreground' : 'border-muted-foreground/50 text-transparent opacity-0 group-hover/day:opacity-100',
                        selection.length > 0 && 'opacity-100',
                      )}
                    >
                      <Check className="size-3" strokeWidth={3} aria-hidden />
                    </button>
                    <h3 className="text-sm font-medium text-muted-foreground">{formatDay(row.day, i18n.language)}</h3>
                  </div>
                )
              }
              return (
                <div key={row.key} className="absolute left-0 flex" style={{ top, gap: GAP }}>
                  {row.items.map((photo) => (
                    <PhotoTile
                      key={photo.id}
                      photo={photo}
                      userId={session.userId}
                      size={tile}
                      selected={selected.has(photo.id)}
                      favourite={marks.favourites.has(photo.id)}
                      selecting={selection.length > 0}
                      onOpen={open}
                      onToggle={toggle}
                    />
                  ))}
                </div>
              )
            })}
          </div>
        </div>
        {monthRows.length > 1 && !narrow ? (
          <Scrubber months={monthRows} onJump={(index) => virtualizer.scrollToIndex(index, { align: 'start' })} />
        ) : null}
      </div>

      {dropping && preferences ? (
        <div className="pointer-events-none fixed inset-0 z-40 flex items-center justify-center bg-background/80 backdrop-blur-sm">
          <div className="flex flex-col items-center gap-3 rounded-xl border-2 border-dashed border-primary px-10 py-8 text-center">
            <ImageUp className="size-8 text-primary" aria-hidden />
            <p className="font-medium">{t('upload.drop')}</p>
          </div>
        </div>
      ) : null}

      {viewerIndex >= 0 ? (
        <PhotoViewer
          photos={photos}
          index={viewerIndex}
          onNavigate={(photo) => setParams((p) => {
            const next = new URLSearchParams(p)
            next.set('photo', photo.id)
            return next
          }, { replace: true })}
          onClose={closeViewer}
        />
      ) : null}
    </div>
  )
}
