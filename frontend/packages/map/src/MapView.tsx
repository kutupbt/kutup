import maplibregl, { type StyleSpecification } from 'maplibre-gl'
import 'maplibre-gl/dist/maplibre-gl.css'
import { useEffect, useRef, type ReactNode } from 'react'
import { freshAccessToken } from '@kutup/session/client'
import { useEffectiveMap, type EffectiveMap } from './config'
import { relayRequest } from './relay'

export interface MapMarker {
  lat: number
  lon: number
}

export interface MapViewProps {
  center: MapMarker
  zoom?: number
  markers?: MapMarker[]
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
 * which tiles are loaded.
 */
export function MapView({ center, zoom = 13, markers = [], fallback = null, className, ariaLabel }: MapViewProps) {
  const effective = useEffectiveMap()
  const container = useRef<HTMLDivElement>(null)
  const styleKey = effective ? `${effective.provider.id}:${effective.url}` : null

  useEffect(() => {
    if (!effective || !container.current) return
    const style = styleOf(effective)
    const map = new maplibregl.Map({
      container: container.current,
      style,
      center: [center.lon, center.lat],
      zoom,
      attributionControl: { compact: true },
      transformRequest: (url) => relayRequest(url),
    })
    map.addControl(new maplibregl.NavigationControl({ showCompass: false }), 'top-right')
    for (const marker of markers) new maplibregl.Marker().setLngLat([marker.lon, marker.lat]).addTo(map)

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
    return () => map.remove()
    // The map is rebuilt only when the provider or route changes; moving the
    // centre or markers is cheap enough to rebuild too.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [styleKey, center.lat, center.lon, zoom, JSON.stringify(markers)])

  if (!effective) return <>{fallback}</>
  return <div ref={container} className={className} role="region" aria-label={ariaLabel} data-testid="kutup-map" />
}
