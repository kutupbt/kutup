import { Copy, ExternalLink, MapPin } from 'lucide-react'
import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { ChatLocationV1 } from '@kutup/chat-core/types'
import { Button } from '@kutup/ui/components/button'
import { formatCoordinates, openInMapsUrl } from './places'

const MapView = lazy(() => import('@kutup/map/MapView').then((m) => ({ default: m.MapView })))

/** True once the element is on screen, false again when it leaves (maps are costly to keep). */
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
 * A place in its bubble: a small map when this person has maps on (drawn
 * only while it is on screen), else the coordinates; its label; "Open in
 * maps" and "Copy".
 */
export function LocationBody({ location }: { location: ChatLocationV1 }) {
  const { t } = useTranslation()
  const [ref, onScreen] = useOnScreen<HTMLDivElement>()
  const coordinates = formatCoordinates(location)
  const placeholder = (
    <div className="flex h-36 w-full items-center justify-center gap-2 bg-muted text-sm text-muted-foreground">
      <MapPin className="size-5" aria-hidden />
      <span className="font-mono">{coordinates}</span>
    </div>
  )

  return (
    <div className="w-64 max-w-full overflow-hidden rounded-lg border border-border bg-background text-foreground" data-testid="chat-location">
      <div ref={ref} className="h-36 w-full">
        {onScreen ? (
          <Suspense fallback={placeholder}>
            <MapView
              center={location}
              zoom={15}
              markers={[location]}
              interactive={false}
              fallback={placeholder}
              className="h-36 w-full"
              ariaLabel={t('chat.location.mapLabel')}
            />
          </Suspense>
        ) : (
          placeholder
        )}
      </div>
      <div className="space-y-1 px-3 py-2">
        {location.label ? <p className="break-words text-sm font-medium" data-testid="chat-location-label">{location.label}</p> : null}
        <p className="font-mono text-xs text-muted-foreground" data-testid="chat-location-coordinates">{coordinates}</p>
        <div className="flex gap-1 pt-1">
          <Button asChild variant="outline" size="sm" className="h-7 px-2 text-xs">
            <a href={openInMapsUrl(location)} target="_blank" rel="noopener noreferrer">
              <ExternalLink />
              {t('chat.location.openInMaps')}
            </a>
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-7 px-2 text-xs"
            onClick={() => {
              void navigator.clipboard
                .writeText(coordinates)
                .then(() => toast.success(t('chat.location.copied')))
                .catch(() => toast.error(t('chat.message.copyFailed')))
            }}
          >
            <Copy />
            {t('chat.location.copy')}
          </Button>
        </div>
      </div>
    </div>
  )
}
