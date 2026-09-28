import maplibregl, { type StyleSpecification } from 'maplibre-gl'
import 'maplibre-gl/dist/maplibre-gl.css'
import { useEffect, useRef, useState } from 'react'
import { freshAccessToken } from '@kutup/session/client'
import { useEffectiveMap, type EffectiveMap } from './config'
import { absoluteStyle, relayRequest } from './relay'

export { maplibregl }

export function styleOf(map: EffectiveMap): string | StyleSpecification {
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

export interface KutupMap {
  /** Put on the element the map fills (a callback ref: it may appear later). */
  container: (element: HTMLDivElement | null) => void
  /** The map once built (null while maps are off or loading). */
  map: maplibregl.Map | null
  /** The provider in use, or null while maps are off for this person. */
  effective: EffectiveMap | null
}

/**
 * A MapLibre map drawn with the provider this person chose
 * (docs/plans/maps.md), through the relay when it is on. Built once per
 * provider; `initial` is where it opens. For maps that manage their own
 * markers (Photos' Places); `MapView` is the simple one.
 */
export function useKutupMap({
  center,
  zoom,
  interactive = true,
}: {
  center: { lat: number; lon: number }
  zoom: number
  interactive?: boolean
}): KutupMap {
  const effective = useEffectiveMap()
  const [element, container] = useState<HTMLDivElement | null>(null)
  const [map, setMap] = useState<maplibregl.Map | null>(null)
  const initial = useRef({ center, zoom })
  const styleKey = effective ? `${effective.provider.id}:${effective.url}` : null

  useEffect(() => {
    if (!effective || !element) return
    const style = styleOf(effective)
    const built = new maplibregl.Map({
      container: element,
      center: [initial.current.center.lon, initial.current.center.lat],
      zoom: initial.current.zoom,
      interactive,
      // A small map in a message credits its data in one line below
      // instead (the licence requires the credit; the control would cover
      // half of it).
      attributionControl: interactive ? { compact: true } : false,
      transformRequest: (url) => relayRequest(url),
    })
    const load = () => built.setStyle(style, { transformStyle: (_previous, next) => absoluteStyle(next) })
    load()
    if (interactive) built.addControl(new maplibregl.NavigationControl({ showCompass: false }), 'top-right')

    // An expired token fails relayed requests with 401: refresh it once and
    // reload the style so the missing tiles are fetched again.
    let refreshing = false
    built.on('error', (event: { error?: { status?: number } }) => {
      if (event.error?.status !== 401 || refreshing || !effective.viaProxy) return
      refreshing = true
      void freshAccessToken()
        .then(load)
        .catch(() => undefined)
        .finally(() => {
          window.setTimeout(() => (refreshing = false), 30_000)
        })
    })
    setMap(built)
    return () => {
      setMap(null)
      built.remove()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [styleKey, interactive, element])

  return { container, map, effective }
}
