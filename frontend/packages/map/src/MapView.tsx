import { useEffect, useRef, type ReactNode } from 'react'
import { maplibregl, useKutupMap } from './useKutupMap'

export interface MapPoint {
  lat: number
  lon: number
}

/** A marker; with an id it can be selected and clicked. */
export interface MapMarker extends MapPoint {
  id?: string
  /** Its name, for the tooltip and screen readers. */
  label?: string
  /** Its colour (e.g. the list it belongs to); the default blue otherwise. */
  color?: string
}

/** Fly to a point; a new `seq` flies again, even to the same point. */
export interface MapFocus extends MapPoint {
  zoom: number
  seq: number
}

export interface MapViewProps {
  center: MapPoint
  zoom?: number
  markers?: MapMarker[]
  /** The marker drawn highlighted. */
  selectedId?: string | null
  onMarkerClick?: (id: string) => void
  /**
   * Frame all markers: once for each new key, as soon as there are markers
   * (a map showing one list after another fits each in turn).
   */
  fitKey?: string | null
  focus?: MapFocus | null
  /** False for a small map in a message: no panning, no zoom buttons. */
  interactive?: boolean
  /** Called with the point clicked or tapped, for choosing a place. */
  onPick?: (point: MapPoint) => void
  /** A right-click on the map: the point, and where on the map it was (pixels). */
  onContextMenu?: (point: MapPoint & { x: number; y: number }) => void
  /** Shown instead of the map while maps are off for this person. */
  fallback?: ReactNode
  className?: string
  ariaLabel: string
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
  selectedId = null,
  onMarkerClick,
  fitKey = null,
  focus = null,
  interactive = true,
  onPick,
  onContextMenu,
  fallback = null,
  className,
  ariaLabel,
}: MapViewProps) {
  const { container, map, effective } = useKutupMap({ center, zoom, interactive })
  const markerRefs = useRef<maplibregl.Marker[]>([])
  const pick = useRef(onPick)
  pick.current = onPick
  const contextMenu = useRef(onContextMenu)
  contextMenu.current = onContextMenu
  const markerClick = useRef(onMarkerClick)
  markerClick.current = onMarkerClick
  const fitted = useRef<string | null>(null)

  useEffect(() => {
    if (!map) return
    const onClick = (event: maplibregl.MapMouseEvent) => pick.current?.({ lat: event.lngLat.lat, lon: event.lngLat.lng })
    const onMenu = (event: maplibregl.MapMouseEvent) => {
      if (!contextMenu.current) return
      event.originalEvent.preventDefault()
      contextMenu.current({ lat: event.lngLat.lat, lon: event.lngLat.lng, x: event.point.x, y: event.point.y })
    }
    map.on('click', onClick)
    map.on('contextmenu', onMenu)
    return () => {
      map.off('click', onClick)
      map.off('contextmenu', onMenu)
      markerRefs.current = []
    }
  }, [map])

  useEffect(() => {
    map?.jumpTo({ center: [center.lon, center.lat], zoom })

  }, [center.lat, center.lon, zoom, map])

  const markerKey = markers.map((m) => `${m.id ?? ''}:${m.lat},${m.lon}:${m.label ?? ''}:${m.color ?? ''}`).join(';')
  useEffect(() => {
    if (!map) return
    for (const marker of markerRefs.current) marker.remove()
    markerRefs.current = markers.map((m) => {
      const selected = m.id !== undefined && m.id === selectedId
      const marker = new maplibregl.Marker(selected ? { color: '#0369a1', scale: 1.25 } : m.color ? { color: m.color } : {}).setLngLat([m.lon, m.lat])
      const element = marker.getElement()
      if (m.label) {
        element.title = m.label
        element.setAttribute('aria-label', m.label)
      }
      if (m.id !== undefined && interactive) {
        const id = m.id
        element.style.cursor = 'pointer'
        element.setAttribute('role', 'button')
        element.tabIndex = 0
        const activate = (event: Event) => {
          event.stopPropagation()
          markerClick.current?.(id)
        }
        element.addEventListener('click', activate)
        // A right-click on a pin opens it too, rather than the map's menu.
        element.addEventListener('contextmenu', (event) => {
          event.preventDefault()
          activate(event)
        })
        element.addEventListener('keydown', (event) => {
          if (event.key === 'Enter' || event.key === ' ') activate(event)
        })
      }
      if (selected) element.style.zIndex = '1'
      return marker.addTo(map)
    })
    if (fitKey !== null && fitted.current !== fitKey && markers.length > 0) {
      fitted.current = fitKey
      if (markers.length === 1) {
        map.jumpTo({ center: [markers[0].lon, markers[0].lat], zoom: 14 })
      } else {
        const bounds = new maplibregl.LngLatBounds()
        for (const m of markers) bounds.extend([m.lon, m.lat])
        map.fitBounds(bounds, { padding: 48, maxZoom: 15, duration: 0 })
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [markerKey, selectedId, map, fitKey])

  useEffect(() => {
    if (focus) map?.flyTo({ center: [focus.lon, focus.lat], zoom: focus.zoom, duration: 600 })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focus?.seq, map])

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
