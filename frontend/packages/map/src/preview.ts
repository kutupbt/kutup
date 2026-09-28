import maplibregl from 'maplibre-gl'
import type { EffectiveMap } from './config'
import type { Place } from './list'
import { absoluteStyle, relayRequest } from './relay'
import { styleOf } from './useKutupMap'

// A place list's picture for Drive (docs/plans/maps.md): the list's places
// on the map this person uses, drawn once in a hidden map fitted to them.
// It loads tiles the way the open list does (the same provider, through the
// relay when that is on), so it reveals nothing the list itself did not.

const WIDTH = 960
const HEIGHT = 720
const PADDING = 72
/** A lone place, or places close together, are not zoomed in past this. */
const MAX_ZOOM = 14
/** Tiles still loading after this: no picture (a half-drawn map is worse). */
const IDLE_TIMEOUT_MS = 20_000

/** The rectangle the picture shows: every place, as [west, south, east, north]. */
export function previewBounds(places: Pick<Place, 'lat' | 'lon'>[]): [number, number, number, number] | null {
  if (places.length === 0) return null
  let west = Infinity
  let south = Infinity
  let east = -Infinity
  let north = -Infinity
  for (const p of places) {
    west = Math.min(west, p.lon)
    east = Math.max(east, p.lon)
    south = Math.min(south, p.lat)
    north = Math.max(north, p.lat)
  }
  return [west, south, east, north]
}

/**
 * The provider's credit as one plain line (the data licence asks for it
 * wherever the map is shown). Attributions are HTML with links.
 */
export function creditText(attribution: string): string {
  const text = new DOMParser().parseFromString(attribution, 'text/html').body.textContent ?? ''
  return text.replace(/\s+/g, ' ').trim()
}

function whenIdle(map: maplibregl.Map): Promise<boolean> {
  return new Promise((resolve) => {
    const timer = window.setTimeout(() => resolve(false), IDLE_TIMEOUT_MS)
    void map.once('idle', () => {
      window.clearTimeout(timer)
      resolve(true)
    })
  })
}

// MapLibre's default marker (what Maps shows): a 27×41 teardrop with a white
// dot, its tip on the place.
const PIN_PATH =
  'M27,13.5C27,19.07 20.25,27 14.75,34.5C14.02,35.5 12.98,35.5 12.25,34.5C6.75,27 0,19.22 0,13.5C0,6.04 6.04,0 13.5,0C20.96,0 27,6.04 27,13.5Z'
const PIN_TIP = { x: 13.5, y: 35.25 }
/** Twice Maps' size: the picture is mostly seen shrunk to a card. */
const PIN_SCALE = 2
const PIN_HEIGHT = 41 * PIN_SCALE

function drawPin(ctx: CanvasRenderingContext2D, x: number, y: number, color: string): void {
  ctx.save()
  ctx.translate(x - PIN_TIP.x * PIN_SCALE, y - PIN_TIP.y * PIN_SCALE)
  ctx.scale(PIN_SCALE, PIN_SCALE)
  ctx.shadowColor = 'rgba(0, 0, 0, 0.3)'
  ctx.shadowBlur = 4
  ctx.shadowOffsetY = 2
  ctx.fillStyle = color
  ctx.fill(new Path2D(PIN_PATH))
  ctx.shadowColor = 'transparent'
  ctx.beginPath()
  ctx.arc(13.5, 13.5, 5.5, 0, Math.PI * 2)
  ctx.fillStyle = '#ffffff'
  ctx.fill()
  ctx.restore()
}

function drawCredit(ctx: CanvasRenderingContext2D, credit: string): void {
  if (!credit) return
  ctx.font = '13px system-ui, -apple-system, "Segoe UI", sans-serif'
  const room = WIDTH - 16
  let text = credit
  // Too long for one line: OpenStreetMap's own short credit, or cut.
  if (ctx.measureText(text).width > room) {
    text = /openstreetmap/i.test(credit) ? '© OpenStreetMap contributors' : credit
    while (ctx.measureText(text).width > room && text.length > 1) text = text.slice(0, -2) + '…'
  }
  const width = ctx.measureText(text).width + 12
  ctx.fillStyle = 'rgba(255, 255, 255, 0.85)'
  ctx.fillRect(WIDTH - width - 4, HEIGHT - 24, width, 20)
  ctx.fillStyle = '#333333'
  ctx.textBaseline = 'middle'
  ctx.fillText(text, WIDTH - width + 2, HEIGHT - 14)
}

/**
 * The list's places on the map, as a PNG, or null: no places, the map could
 * not be drawn (no WebGL), or its tiles did not arrive in time.
 */
export async function drawListPreview(effective: EffectiveMap, places: Place[], color: string): Promise<Blob | null> {
  const bounds = previewBounds(places)
  if (!bounds) return null
  const host = document.createElement('div')
  host.setAttribute('aria-hidden', 'true')
  Object.assign(host.style, {
    position: 'fixed',
    left: '-10000px',
    top: '0',
    width: `${WIDTH}px`,
    height: `${HEIGHT}px`,
    pointerEvents: 'none',
  })
  document.body.appendChild(host)
  let map: maplibregl.Map | null = null
  try {
    map = new maplibregl.Map({
      container: host,
      bounds,
      // Room above for the pins, which stand on their places.
      fitBoundsOptions: { padding: { top: PADDING + PIN_HEIGHT, bottom: PADDING, left: PADDING, right: PADDING }, maxZoom: MAX_ZOOM },
      interactive: false,
      attributionControl: false,
      // Read back once drawn; the same size on every screen.
      canvasContextAttributes: { preserveDrawingBuffer: true },
      pixelRatio: 1,
      fadeDuration: 0,
      transformRequest: (url) => relayRequest(url),
    })
    map.setStyle(styleOf(effective), { transformStyle: (_previous, next) => absoluteStyle(next) })
    if (!(await whenIdle(map))) return null
    const canvas = document.createElement('canvas')
    canvas.width = WIDTH
    canvas.height = HEIGHT
    const ctx = canvas.getContext('2d')
    if (!ctx) return null
    ctx.drawImage(map.getCanvas(), 0, 0, WIDTH, HEIGHT)
    for (const place of places) {
      const at = map.project([place.lon, place.lat])
      if (at.x < -PIN_HEIGHT || at.y < 0 || at.x > WIDTH + PIN_HEIGHT || at.y > HEIGHT + PIN_HEIGHT) continue
      drawPin(ctx, at.x, at.y, color)
    }
    drawCredit(ctx, creditText(effective.provider.attribution))
    return await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, 'image/png'))
  } catch {
    return null
  } finally {
    map?.remove()
    host.remove()
  }
}
