import maplibregl, { type StyleSpecification } from 'maplibre-gl'
import 'maplibre-gl/dist/maplibre-gl.css'
import { useEffect, useRef, type ReactNode } from 'react'
import { freshAccessToken } from '@kutup/session/client'
import { useEffectiveMap, type EffectiveMap } from './config'
import { relayRequest } from './relay'

export interface MapPoint {
  lat: number
  lon: number
}

export interface MapViewProps {
  center: MapPoint
  zoom?: number
  markers?: MapPoint[]
  /** False for a small map in a message: no panning, no zoom buttons. */
  interactive?: boolean
  /** Called with the point clicked or tapped, for choosing a place. */
  onPick?: (point: MapPoint) => void
  /** Shown instead of the map while maps are off for this person. */
  fallback?: ReactNode
  className?: string
  ariaLabel: string
}

function styleOf(map: EffectiveMap): string | StyleSpecification {
  if (map.provider.kind === 'vector') return map.url
  return {
    version: 8,
    sources: {
      base: {
        type: 'raster',
        tiles: [map.url],
        tileSize: 256,
        maxzoom: 19,
        attribution: map.provider.attribution,
      },
    },
    layers: [{ id: 'base', type: 'raster', source: 'base' }],
  }
}

/**
 * A map, drawn with the provider this person chose (docs/plans/maps.md), or
 * `fallback` while maps are off. The places shown are drawn here in the
 * browser; the provider (or, through the relay, this server) sees only
 * which tiles are loaded. The map is built once per provider; moving the
 * centre or the markers updates it in place.
 */
export function MapView({
  center,
  zoom = 13,
  markers = [],
  interactive = true,
  onPick,
  fallback = null,
  className,
  ariaLabel,
}: MapViewProps) {
  const effective = useEffectiveMap()
  const container = useRef<HTMLDivElement>(null)
  const mapRef = useRef<maplibregl.Map | null>(null)
  const markerRefs = useRef<maplibregl.Marker[]>([])
  const pick = useRef(onPick)
  pick.current = onPick
  const initial = useRef({ center, zoom })
  const styleKey = effective ? `${effective.provider.id}:${effective.url}` : null

  useEffect(() => {
    if (!effective || !container.current) return
    const style = styleOf(effective)
    const map = new maplibregl.Map({
      container: container.current,
      style,
      center: [initial.current.center.lon, initial.current.center.lat],
      zoom: initial.current.zoom,
      interactive,
      // A small map in a message credits its data in one line below
      // instead (the licence requires the credit; the control would cover
      // half of it).
      attributionControl: interactive ? { compact: true } : false,
      transformRequest: (url) => relayRequest(url),
    })
    if (interactive) map.addControl(new maplibregl.NavigationControl({ showCompass: false }), 'top-right')
    map.on('click', (event) => pick.current?.({ lat: event.lngLat.lat, lon: event.lngLat.lng }))
    mapRef.current = map

    // An expired token fails relayed requests with 401: refresh it once and
    // reload the style so the missing tiles are fetched again.
    let refreshing = false
    map.on('error', (event: { error?: { status?: number } }) => {
      if (event.error?.status !== 401 || refreshing || !effective.viaProxy) return
      refreshing = true
      void freshAccessToken()
        .then(() => map.setStyle(style))
        .catch(() => undefined)
        .finally(() => {
          window.setTimeout(() => (refreshing = false), 30_000)
        })
    })
    return () => {
      markerRefs.current = []
      mapRef.current = null
      map.remove()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [styleKey, interactive])

  useEffect(() => {
    mapRef.current?.jumpTo({ center: [center.lon, center.lat], zoom })
  }, [center.lat, center.lon, zoom, styleKey])

  const markerKey = markers.map((m) => `${m.lat},${m.lon}`).join(';')
  useEffect(() => {
    const map = mapRef.current
    if (!map) return
    for (const marker of markerRefs.current) marker.remove()
    markerRefs.current = markers.map((m) => new maplibregl.Marker().setLngLat([m.lon, m.lat]).addTo(map))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [markerKey, styleKey])

  if (!effective) return <>{fallback}</>
  if (interactive) {
    return <div ref={container} className={className} role="region" aria-label={ariaLabel} data-testid="kutup-map" />
  }
  return (
    <div className={`relative ${className ?? ''}`} role="img" aria-label={ariaLabel} data-testid="kutup-map">
      <div ref={container} className="h-full w-full" />
      <p className="pointer-events-none absolute inset-x-0 bottom-0 truncate bg-background/80 px-1.5 text-[9px] leading-4 text-muted-foreground">
        {effective.provider.attribution}
      </p>
    </div>
  )
}
