// Grouping points that would overlap on screen (docs/plans/photos.md,
// "Places"), after Ente's clusterer (`rust/crates/location/src/cluster.rs`):
// points are projected to screen pixels at the current zoom; each joins the
// nearest group within `minDistance` pixels (looked up through a grid of
// cells that size), else starts its own. Points come newest first, so a
// group's first point, its face, is its newest. Points just outside the view
// are grouped too, so markers at the edge do not pop in and out; only those
// inside are "visible". Across the date line, longitudes are taken on the
// side of the view.

export interface ClusterPoint {
  id: string
  lat: number
  lon: number
}

export interface Viewport {
  west: number
  south: number
  east: number
  north: number
  zoom: number
  /** The view's size in pixels. */
  width: number
  height: number
}

export interface Cluster {
  /** The first (newest) point: its picture stands for the group. */
  id: string
  lat: number
  lon: number
  count: number
  /** What the group covers, to zoom to it. */
  bounds: { west: number; south: number; east: number; north: number }
}

export interface Clustered {
  clusters: Cluster[]
  /** Ids of the points inside the view, in the order given. */
  visible: string[]
}

/** MapLibre draws the world 512 pixels wide at zoom 0. */
const TILE_SIZE = 512
const MAX_LATITUDE = 85.05112878

function worldX(lon: number, world: number): number {
  return ((lon + 180) / 360) * world
}

function worldY(lat: number, world: number): number {
  const clamped = Math.max(-MAX_LATITUDE, Math.min(MAX_LATITUDE, lat))
  const sin = Math.sin((clamped * Math.PI) / 180)
  return (0.5 - Math.log((1 + sin) / (1 - sin)) / (4 * Math.PI)) * world
}

/** A longitude inside [west, east], allowing for a view across the date line. */
function lonVisible(lon: number, west: number, east: number): boolean {
  if (east - west >= 360) return true
  const span = (((east - west) % 360) + 360) % 360
  const offset = (((lon - west) % 360) + 360) % 360
  return offset <= span
}

/** `lon` moved by whole turns to be nearest `origin` (to measure a group across the date line). */
function unwrap(lon: number, origin: number): number {
  return origin + ((((lon - origin + 180) % 360) + 360) % 360) - 180
}

function normalize(lon: number): number {
  return ((((lon + 180) % 360) + 360) % 360) - 180
}

export function clusterPoints(points: readonly ClusterPoint[], view: Viewport, minDistance = 72): Clustered {
  const world = TILE_SIZE * 2 ** view.zoom
  // The view's pixel box in world pixels, around its centre.
  const centreLon = view.east >= view.west ? (view.west + view.east) / 2 : normalize((view.west + view.east + 360) / 2)
  const centreX = worldX(centreLon, world)
  const top = worldY(view.north, world)
  const bottom = worldY(view.south, world)
  const halfWidth = view.width / 2
  // Group what lies within one marker of the view, too.
  const margin = minDistance
  const minX = centreX - halfWidth - margin
  const maxX = centreX + halfWidth + margin
  const minY = top - margin
  const maxY = bottom + margin

  type Projected = { point: ClusterPoint; x: number; y: number }
  const inside: Projected[] = []
  const around: Projected[] = []
  const visible: string[] = []
  for (const point of points) {
    const isVisible = lonVisible(point.lon, view.west, view.east) && point.lat >= view.south && point.lat <= view.north
    if (isVisible) visible.push(point.id)
    const canonical = worldX(point.lon, world)
    // The copy of the world nearest the view's centre.
    const x = canonical + Math.round((centreX - canonical) / world) * world
    const y = worldY(point.lat, world)
    if (x < minX || x > maxX || y < minY || y > maxY) continue
    ;(isVisible ? inside : around).push({ point, x, y })
  }

  interface Group {
    first: ClusterPoint
    x: number
    y: number
    count: number
    west: number
    east: number
    south: number
    north: number
  }
  const groups: Group[] = []
  const cells = new Map<string, number[]>()
  const cellOf = (x: number, y: number) => [Math.floor(x / minDistance), Math.floor(y / minDistance)] as const
  const limit = minDistance * minDistance
  for (const { point, x, y } of [...inside, ...around]) {
    const [cx, cy] = cellOf(x, y)
    let best = -1
    let bestDistance = Infinity
    for (let dx = -1; dx <= 1; dx++) {
      for (let dy = -1; dy <= 1; dy++) {
        for (const index of cells.get(`${cx + dx}:${cy + dy}`) ?? []) {
          const g = groups[index]
          const d = (x - g.x) ** 2 + (y - g.y) ** 2
          if (d <= limit && d < bestDistance) {
            best = index
            bestDistance = d
          }
        }
      }
    }
    if (best >= 0) {
      const g = groups[best]
      g.count++
      g.north = Math.max(g.north, point.lat)
      g.south = Math.min(g.south, point.lat)
      const lon = unwrap(point.lon, g.first.lon)
      g.east = Math.max(g.east, lon)
      g.west = Math.min(g.west, lon)
    } else {
      groups.push({ first: point, x, y, count: 1, west: point.lon, east: point.lon, south: point.lat, north: point.lat })
      const key = `${cx}:${cy}`
      const list = cells.get(key)
      if (list) list.push(groups.length - 1)
      else cells.set(key, [groups.length - 1])
    }
  }

  return {
    visible,
    clusters: groups.map((g) => ({
      id: g.first.id,
      lat: g.first.lat,
      lon: g.first.lon,
      count: g.count,
      bounds: { west: normalize(g.west), east: normalize(g.east), south: g.south, north: g.north },
    })),
  }
}
