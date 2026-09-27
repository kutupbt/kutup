import { MapPinned } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'
import { thumbnailUrl } from '@kutup/drive-core/thumbnails'
import { clusterPoints, recentGroup, type Cluster } from '@kutup/map/cluster'
import { useMapConfig } from '@kutup/map/config'
import { maplibregl, useKutupMap } from '@kutup/map/useKutupMap'
import { appUrl } from '@kutup/session/apps'
import { Button } from '@kutup/ui/components/button'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { formatDay } from '../library/format'
import type { Photo } from '../library/library'
import { useLibraryContext } from '../library/libraryContext'
import { daysOf } from '../library/timeline'
import { useThumbnail } from '../timeline/useThumbnail'
import { PhotoViewer } from '../viewer/PhotoViewer'

/** How close, in pixels, two markers may be before they become one. */
const MARKER_DISTANCE = 72

interface Located extends Photo {
  lat: number
  lon: number
}

/** A marker: the newest photo of its group, with how many there are. */
function markerElement(label: string, count: number): { root: HTMLButtonElement; image: HTMLImageElement } {
  const root = document.createElement('button')
  root.type = 'button'
  root.className =
    'relative block size-14 cursor-pointer overflow-hidden rounded-lg border-2 border-white bg-muted shadow-md transition-transform hover:scale-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring'
  root.setAttribute('aria-label', label)
  const image = document.createElement('img')
  image.alt = ''
  image.draggable = false
  image.className = 'size-full object-cover'
  root.append(image)
  if (count > 1) {
    const badge = document.createElement('span')
    badge.className =
      'absolute right-0.5 top-0.5 min-w-5 rounded-full bg-primary px-1 text-center text-[11px] font-semibold leading-5 text-primary-foreground'
    badge.textContent = count > 999 ? '999+' : String(count)
    root.append(badge)
  }
  return { root, image }
}

function PanelTile({ photo, onOpen }: { photo: Photo; onOpen: (photo: Photo) => void }) {
  const url = useThumbnail(photo.file)
  return (
    <button
      type="button"
      onClick={() => onOpen(photo)}
      aria-label={photo.file.name ?? ''}
      className="aspect-square overflow-hidden bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring"
    >
      {url ? <img src={url} alt="" className="size-full object-cover" draggable={false} /> : null}
    </button>
  )
}

/**
 * Where your photos were taken, as Ente shows it (docs/plans/photos.md,
 * "Places"): photos near each other on screen are one marker showing the
 * newest; opening a group zooms to it, a single photo opens. The panel lists
 * what is in view, newest first. Places come only from each photo's
 * encrypted details, put on the map here; only map tiles are fetched.
 */
export function PlacesPage() {
  const { t, i18n } = useTranslation()
  const { photos, marks, loading } = useLibraryContext()
  const mapConfig = useMapConfig()
  const [params, setParams] = useSearchParams()
  const located = useMemo(
    () =>
      photos.flatMap((p): Located[] =>
        p.media?.lat !== undefined && p.media.lon !== undefined && !marks.archived.has(p.id) && !marks.hidden.has(p.id)
          ? [{ ...p, lat: p.media.lat, lon: p.media.lon }]
          : [],
      ),
    [photos, marks.archived, marks.hidden],
  )
  const byId = useMemo(() => new Map(located.map((p) => [p.id, p])), [located])
  // Where it opens: the group of your newest photos (Ente's rule).
  const start = useMemo(() => recentGroup(located), [located])
  const first = start[0]
  const { container, map, effective } = useKutupMap({ center: first ?? { lat: 20, lon: 0 }, zoom: first ? 11 : 1.5 })
  const [visible, setVisible] = useState<string[]>([])
  const markers = useRef(new Map<string, maplibregl.Marker>())
  const framed = useRef(false)

  const open = useCallback(
    (photo: Photo) =>
      setParams((p) => {
        const next = new URLSearchParams(p)
        next.set('photo', photo.id)
        return next
      }),
    [setParams],
  )

  // Frame the recent group once there is a map and something to show.
  useEffect(() => {
    if (!map || framed.current || start.length === 0) return
    framed.current = true
    const bounds = new maplibregl.LngLatBounds()
    for (const p of start) bounds.extend([p.lon, p.lat])
    map.fitBounds(bounds, { padding: 80, maxZoom: 14, duration: 0 })
  }, [map, start])

  // Group after every move, and draw the groups as picture markers.
  useEffect(() => {
    if (!map) return
    const drawn = markers.current
    const refresh = () => {
      const bounds = map.getBounds()
      const canvas = map.getCanvas()
      const { clusters, visible: inView } = clusterPoints(
        located,
        {
          west: bounds.getWest(),
          east: bounds.getEast(),
          south: bounds.getSouth(),
          north: bounds.getNorth(),
          zoom: map.getZoom(),
          width: canvas.clientWidth,
          height: canvas.clientHeight,
        },
        MARKER_DISTANCE,
      )
      setVisible(inView)
      const wanted = new Map<string, Cluster>(clusters.map((c) => [`${c.id}:${c.count}`, c]))
      for (const [key, marker] of drawn) {
        if (!wanted.has(key)) {
          marker.remove()
          drawn.delete(key)
        }
      }
      for (const [key, cluster] of wanted) {
        if (drawn.has(key)) continue
        const photo = byId.get(cluster.id)
        if (!photo) continue
        const label = cluster.count > 1 ? t('places.group', { count: cluster.count }) : (photo.file.name ?? '')
        const { root, image } = markerElement(label, cluster.count)
        void thumbnailUrl(photo.file, 'sm').then((url) => {
          if (url) image.src = url
        })
        root.addEventListener('click', (event) => {
          event.stopPropagation()
          const { west, south, east, north } = cluster.bounds
          if (cluster.count > 1 && (west !== east || south !== north)) {
            map.fitBounds([[west, south], [east, north]], { padding: 96, maxZoom: 18 })
          } else {
            open(photo)
          }
        })
        drawn.set(key, new maplibregl.Marker({ element: root }).setLngLat([cluster.lon, cluster.lat]).addTo(map))
      }
    }
    refresh()
    map.on('moveend', refresh)
    map.on('resize', refresh)
    return () => {
      map.off('moveend', refresh)
      map.off('resize', refresh)
      for (const marker of drawn.values()) marker.remove()
      drawn.clear()
    }
  }, [map, located, byId, open, t])

  const inView = useMemo(() => visible.map((id) => byId.get(id)).filter((p): p is Located => Boolean(p)), [visible, byId])
  const days = useMemo(() => daysOf(inView), [inView])
  const openId = params.get('photo')
  const viewerList = inView.some((p) => p.id === openId) ? inView : located
  const viewerIndex = openId ? viewerList.findIndex((p) => p.id === openId) : -1

  if ((loading && photos.length === 0) || mapConfig.isPending) return <LoadingPanel label={t('timeline.loading')} />
  if (!effective) {
    return (
      <div className="px-4 py-6 md:px-8">
        <EmptyState
          title={t('places.mapsOffTitle')}
          description={t('places.mapsOff')}
          action={
            <Button asChild>
              <a href={appUrl('account', '/settings/maps')}>{t('places.turnOn')}</a>
            </Button>
          }
        />
      </div>
    )
  }

  return (
    <div className="flex h-[calc(100svh-3.5rem)] flex-col md:flex-row">
      <div className="relative h-[55svh] shrink-0 md:h-auto md:min-w-0 md:flex-1">
        <div ref={container} className="size-full" role="region" aria-label={t('places.mapLabel')} data-testid="places-map" />
        {located.length === 0 ? (
          <div className="pointer-events-none absolute inset-x-4 top-4 flex justify-center">
            <p className="pointer-events-auto max-w-md rounded-lg bg-background/95 px-4 py-3 text-center text-sm shadow">
              {t('places.none')}
            </p>
          </div>
        ) : null}
      </div>
      <aside
        aria-label={t('places.inView')}
        className="min-h-0 flex-1 overflow-y-auto border-t border-border md:w-96 md:flex-none md:border-l md:border-t-0"
      >
        <div className="sticky top-0 z-10 flex items-center gap-2 bg-background/95 px-4 py-3 backdrop-blur-sm">
          <MapPinned className="size-4 text-muted-foreground" aria-hidden />
          <h1 className="text-sm font-medium">{t('places.count', { count: inView.length })}</h1>
        </div>
        {inView.length === 0 ? (
          <p className="px-4 py-6 text-sm text-muted-foreground">{located.length > 0 ? t('places.moveMap') : t('places.noneShort')}</p>
        ) : (
          days.map((day) => (
            <section key={day.day} className="pb-3">
              <h2 className="px-4 pb-1.5 pt-2 text-xs font-medium text-muted-foreground">{formatDay(day.day, i18n.language)}</h2>
              <div className="grid grid-cols-3 gap-0.5 px-0.5">
                {day.items.map((photo) => (
                  <PanelTile key={photo.id} photo={photo} onOpen={open} />
                ))}
              </div>
            </section>
          ))
        )}
      </aside>
      {viewerIndex >= 0 ? (
        <PhotoViewer
          photos={viewerList}
          index={viewerIndex}
          onNavigate={(photo) =>
            setParams(
              (p) => {
                const next = new URLSearchParams(p)
                next.set('photo', photo.id)
                return next
              },
              { replace: true },
            )
          }
          onClose={() =>
            setParams(
              (p) => {
                const next = new URLSearchParams(p)
                next.delete('photo')
                return next
              },
              { replace: true },
            )
          }
        />
      ) : null}
    </div>
  )
}
