import { Loader2, MapPin, Radio, Square } from 'lucide-react'
import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { cn } from '@kutup/ui/lib/cn'
import { useNow } from '../../lib/useNow'
import { liveShareEnded, type LiveShareState } from '../../state/liveLocations'
import { readStream, type StreamReading } from './liveStream'
import { formatCoordinates, openInMapsUrl } from './places'

const MapView = lazy(() => import('@kutup/map/MapView').then((m) => ({ default: m.MapView })))

const POLL_MS = 10_000

/** True while the element is on screen. */
function useOnScreen<T extends Element>() {
  const ref = useRef<T>(null)
  const [visible, setVisible] = useState(false)
  useEffect(() => {
    const element = ref.current
    if (!element || typeof IntersectionObserver === 'undefined') return
    const observer = new IntersectionObserver(([entry]) => setVisible(entry.isIntersecting), { rootMargin: '200px' })
    observer.observe(element)
    return () => observer.disconnect()
  }, [])
  return [ref, visible] as const
}

/**
 * A live location in its bubble (docs/plans/maps.md): the sharer's latest
 * position, read from their stream every 10 seconds while the bubble is on
 * screen and the share runs, drawn on a map (maps on) or as coordinates;
 * how long ago it was updated; until when; and, for the sharer, "Stop
 * sharing". The position is decrypted here; the server only hands over the
 * sealed update.
 */
export function LiveLocationBody({
  state,
  localServer,
  onStop,
}: {
  state: LiveShareState
  localServer: string
  /** The sharer's own share, still running. */
  onStop?: () => Promise<void>
}) {
  const { t, i18n } = useTranslation()
  const now = useNow(15_000)
  const [ref, onScreen] = useOnScreen<HTMLDivElement>()
  const [reading, setReading] = useState<StreamReading | null>(null)
  const [gone, setGone] = useState(false)
  const [stopping, setStopping] = useState(false)
  const ended = liveShareEnded(state, now) || gone
  const stream = state.latest

  const { server, streamId, key, readCapability } = stream
  useEffect(() => {
    if (!onScreen || ended) return
    let cancelled = false
    const read = () =>
      readStream({ server, streamId, key, readCapability }, localServer).then(
        (next) => {
          if (cancelled) return
          if (next === null) setGone(true)
          else if (next.update) setReading(next)
        },
        () => undefined,
      )
    void read()
    const timer = window.setInterval(() => void read(), POLL_MS)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [onScreen, ended, streamId, server, key, readCapability, localServer])

  // A new stream (a new key) starts from nothing known about it.
  useEffect(() => setGone(false), [streamId])

  const position = reading?.update ?? null
  const until = new Date(stream.untilMs).toLocaleTimeString(i18n.language, { hour: '2-digit', minute: '2-digit' })
  const minutes = position ? Math.max(0, Math.round((now - position.atMs) / 60_000)) : null
  const placeholder = (
    <div className="flex h-36 w-full items-center justify-center gap-2 bg-muted text-sm text-muted-foreground">
      {position ? <MapPin className="size-5" aria-hidden /> : <Loader2 className={cn('size-5', !ended && 'animate-spin')} aria-hidden />}
      <span className="font-mono">{position ? formatCoordinates(position) : ended ? t('chat.liveLocation.noPosition') : t('chat.liveLocation.waiting')}</span>
    </div>
  )

  return (
    <div className="w-64 max-w-full overflow-hidden rounded-lg border border-border bg-background text-foreground" data-testid="chat-live-location" data-ended={ended}>
      <div ref={ref} className="h-36 w-full">
        {onScreen && position ? (
          <Suspense fallback={placeholder}>
            <MapView
              center={position}
              zoom={15}
              markers={[position]}
              interactive={false}
              fallback={placeholder}
              className="h-36 w-full"
              ariaLabel={t('chat.liveLocation.mapLabel')}
            />
          </Suspense>
        ) : (
          placeholder
        )}
      </div>
      <div className="space-y-1 px-3 py-2">
        <p className="flex items-center gap-1.5 text-sm font-medium" data-testid="chat-live-location-status">
          <Radio className={cn('size-4', ended ? 'text-muted-foreground' : 'text-primary')} aria-hidden />
          {ended ? t('chat.liveLocation.ended') : t('chat.liveLocation.until', { time: until })}
        </p>
        {position ? (
          <p className="text-xs text-muted-foreground" data-testid="chat-live-location-updated">
            <span className="font-mono">{formatCoordinates(position)}</span>
            {' · '}
            {minutes === 0 ? t('chat.liveLocation.updatedNow') : t('chat.liveLocation.updatedAgo', { count: minutes ?? 0 })}
          </p>
        ) : null}
        <div className="flex gap-1 pt-1">
          {position ? (
            <Button asChild variant="outline" size="sm" className="h-7 px-2 text-xs">
              <a href={openInMapsUrl(position)} target="_blank" rel="noopener noreferrer">
                {t('chat.location.openInMaps')}
              </a>
            </Button>
          ) : null}
          {onStop && !ended ? (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="h-7 px-2 text-xs text-destructive"
              disabled={stopping}
              onClick={() => {
                setStopping(true)
                void onStop().finally(() => setStopping(false))
              }}
              data-testid="chat-live-location-stop"
            >
              {stopping ? <Loader2 className="animate-spin" /> : <Square />}
              {t('chat.liveLocation.stop')}
            </Button>
          ) : null}
        </div>
      </div>
    </div>
  )
}
