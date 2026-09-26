import { MAX_NAME, MAX_NOTE, MAX_PLACES, NotAPlaceList, parseListJson, type Place } from './list'

// Place lists in and out of other apps (docs/plans/maps.md, step 4): KML
// (Google My Maps, Google Earth) and GPX (GPS devices, OsmAnd, Organic Maps).
// Only points come in — KML placemarks with a Point, GPX waypoints — since a
// list holds places, not routes or tracks; what is left out is counted so
// the person is told. Everything is read and written on the device.

/** The largest file read (a list holds at most MAX_PLACES places anyway). */
export const MAX_IMPORT_BYTES = 10 * 1024 * 1024

export type ImportedPlace = Pick<Place, 'name' | 'note' | 'lat' | 'lon'>

export interface ImportedList {
  /** The list's own name in the file, if it has one. */
  title: string | null
  places: ImportedPlace[]
  /** Lines, shapes, routes and tracks left out; points without coordinates. */
  skipped: number
}

export class UnreadablePlaceFile extends Error {
  constructor() {
    super('not a KML, GPX or Kutup place list')
  }
}

const clamp = (value: string, max: number) => [...value].slice(0, max).join('')

function childText(element: Element, name: string): string {
  for (const child of Array.from(element.children)) {
    if (child.localName === name) return (child.textContent ?? '').trim()
  }
  return ''
}

function byName(root: Document | Element, name: string): Element[] {
  return Array.from(root.getElementsByTagNameNS('*', name))
}

/** Tags from a KML description (it may be HTML) are dropped: a note is plain text. */
function plain(text: string): string {
  if (!/[<>]/.test(text)) return text
  const doc = new DOMParser().parseFromString(`<body>${text}</body>`, 'text/html')
  return (doc.body.textContent ?? '').trim()
}

function point(name: string, note: string, lat: number, lon: number, fallbackName: (n: number) => string, n: number): ImportedPlace | null {
  if (!Number.isFinite(lat) || !Number.isFinite(lon) || lat < -90 || lat > 90 || lon < -180 || lon > 180) return null
  return { name: clamp(name.trim() || fallbackName(n), MAX_NAME), note: clamp(note, MAX_NOTE), lat, lon }
}

function fromKml(doc: Document, fallbackName: (n: number) => string): ImportedList {
  const places: ImportedPlace[] = []
  let skipped = 0
  for (const placemark of byName(doc, 'Placemark')) {
    const pointElement = byName(placemark, 'Point')[0]
    const coordinates = pointElement ? byName(pointElement, 'coordinates')[0]?.textContent?.trim() : undefined
    const [lon, lat] = (coordinates ?? '').split(/[\s,]+/).map(Number)
    const place = coordinates
      ? point(childText(placemark, 'name'), plain(childText(placemark, 'description')), lat ?? NaN, lon ?? NaN, fallbackName, places.length + 1)
      : null
    if (place && places.length < MAX_PLACES) places.push(place)
    else skipped += 1
  }
  const documentElement = byName(doc, 'Document')[0]
  const title = documentElement ? childText(documentElement, 'name') : ''
  return { title: title || null, places, skipped }
}

function fromGpx(doc: Document, fallbackName: (n: number) => string): ImportedList {
  const places: ImportedPlace[] = []
  let skipped = byName(doc, 'rte').length + byName(doc, 'trk').length
  for (const waypoint of byName(doc, 'wpt')) {
    const place = point(
      childText(waypoint, 'name'),
      childText(waypoint, 'desc') || childText(waypoint, 'cmt'),
      Number(waypoint.getAttribute('lat')),
      Number(waypoint.getAttribute('lon')),
      fallbackName,
      places.length + 1,
    )
    if (place && places.length < MAX_PLACES) places.push(place)
    else skipped += 1
  }
  const metadata = byName(doc, 'metadata')[0]
  const title = metadata ? childText(metadata, 'name') : ''
  return { title: title || null, places, skipped }
}

/**
 * The places in a KML, GPX or `.kutupmap` file. `fallbackName` names a
 * place that has none ("Place 3").
 */
export function readPlaceFile(text: string, fallbackName: (n: number) => string): ImportedList {
  const trimmed = text.trim()
  if (trimmed.startsWith('{')) {
    try {
      return { title: null, places: parseListJson(new TextEncoder().encode(trimmed)), skipped: 0 }
    } catch (error) {
      if (error instanceof NotAPlaceList) throw new UnreadablePlaceFile()
      throw error
    }
  }
  const doc = new DOMParser().parseFromString(trimmed, 'application/xml')
  if (doc.getElementsByTagName('parsererror').length > 0) throw new UnreadablePlaceFile()
  const root = doc.documentElement.localName
  if (root === 'kml') return fromKml(doc, fallbackName)
  if (root === 'gpx') return fromGpx(doc, fallbackName)
  throw new UnreadablePlaceFile()
}

const escapeXml = (value: string) =>
  value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;')

// Characters XML 1.0 cannot carry at all (a note is free text).
// eslint-disable-next-line no-control-regex
const xmlSafe = (value: string) => escapeXml(value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f￾￿]/g, ''))

/** KML 2.2: one Placemark per place, its note as the description. */
export function toKml(title: string, places: Place[]): string {
  const placemarks = places
    .map(
      (p) =>
        `    <Placemark>\n      <name>${xmlSafe(p.name)}</name>\n` +
        (p.note ? `      <description>${xmlSafe(p.note)}</description>\n` : '') +
        `      <Point><coordinates>${p.lon},${p.lat}</coordinates></Point>\n    </Placemark>`,
    )
    .join('\n')
  return (
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<kml xmlns="http://www.opengis.net/kml/2.2">\n  <Document>\n' +
    `    <name>${xmlSafe(title)}</name>\n${placemarks}\n  </Document>\n</kml>\n`
  )
}

/** GPX 1.1: one waypoint per place, its note as the description. */
export function toGpx(title: string, places: Place[]): string {
  const waypoints = places
    .map(
      (p) =>
        `  <wpt lat="${p.lat}" lon="${p.lon}">\n    <name>${xmlSafe(p.name)}</name>\n` +
        (p.note ? `    <desc>${xmlSafe(p.note)}</desc>\n` : '') +
        '  </wpt>',
    )
    .join('\n')
  return (
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<gpx version="1.1" creator="Kutup" xmlns="http://www.topografix.com/GPX/1/1">\n' +
    `  <metadata><name>${xmlSafe(title)}</name></metadata>\n${waypoints}\n</gpx>\n`
  )
}
