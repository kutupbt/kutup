import * as Y from 'yjs'

// A place list (docs/plans/maps.md, step 4): a Drive file named `*.kutupmap`,
// like a map in Google My Maps. Edited live, it is a Yjs document whose
// `places` map holds one entry per place, keyed by the place's id (so two
// people adding, moving or removing places never fight over positions in an
// array). Its title is the file's name. Stored and downloaded, it is JSON:
//
//   { "format": "kutupmap", "version": 1, "places": [Place, …] }
//
// the upload a new list starts from, and what Drive's Download gives.

export const LIST_EXTENSION = 'kutupmap'
export const LIST_MIME = 'application/vnd.kutup.map+json'

export const MAX_PLACES = 5000
export const MAX_NAME = 200
export const MAX_NOTE = 2000

export interface Place {
  id: string
  name: string
  note: string
  lat: number
  lon: number
  /** `user@server` of whoever added it. */
  addedBy: string
  /** RFC 3339. */
  addedAt: string
}

export function isListName(name: string | null | undefined): boolean {
  return Boolean(name && name.toLowerCase().endsWith(`.${LIST_EXTENSION}`))
}

/** The list's title: its file name without the extension. */
export function listTitle(name: string): string {
  return isListName(name) ? name.slice(0, -(LIST_EXTENSION.length + 1)) : name
}

const clamp = (value: string, max: number) => [...value].slice(0, max).join('')

/** A place as stored, or null when it is not one (bad coordinates, no name). */
export function normalizePlace(value: unknown): Place | null {
  if (!value || typeof value !== 'object') return null
  const v = value as Record<string, unknown>
  const lat = Number(v.lat)
  const lon = Number(v.lon)
  const name = typeof v.name === 'string' ? clamp(v.name.trim(), MAX_NAME) : ''
  if (!Number.isFinite(lat) || !Number.isFinite(lon) || lat < -90 || lat > 90 || lon < -180 || lon > 180 || !name) return null
  const id = typeof v.id === 'string' && /^[A-Za-z0-9-]{1,64}$/.test(v.id) ? v.id : crypto.randomUUID()
  return {
    id,
    name,
    note: typeof v.note === 'string' ? clamp(v.note, MAX_NOTE) : '',
    lat,
    lon,
    addedBy: typeof v.addedBy === 'string' ? clamp(v.addedBy, 320) : '',
    addedAt: typeof v.addedAt === 'string' && !Number.isNaN(Date.parse(v.addedAt)) ? v.addedAt : new Date(0).toISOString(),
  }
}

/** Oldest first, then by name: the order a list is shown and exported in. */
function ordered(places: Place[]): Place[] {
  return [...places].sort((a, b) => a.addedAt.localeCompare(b.addedAt) || a.name.localeCompare(b.name) || a.id.localeCompare(b.id))
}

export function encodeListJson(places: Place[]): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({ format: 'kutupmap', version: 1, places: ordered(places) }, null, 1))
}

export class NotAPlaceList extends Error {
  constructor() {
    super('not a Kutup place list')
  }
}

/** The places in a stored list. An empty file (or a 1-byte placeholder) is an empty list. */
export function parseListJson(bytes: Uint8Array): Place[] {
  const text = new TextDecoder().decode(bytes).trim()
  if (text.length <= 1) return []
  let value: unknown
  try {
    value = JSON.parse(text)
  } catch {
    throw new NotAPlaceList()
  }
  const v = value as { format?: unknown; version?: unknown; places?: unknown }
  if (v?.format !== 'kutupmap' || v.version !== 1 || !Array.isArray(v.places)) throw new NotAPlaceList()
  const seen = new Set<string>()
  const places: Place[] = []
  for (const raw of v.places.slice(0, MAX_PLACES)) {
    const place = normalizePlace(raw)
    if (!place || seen.has(place.id)) continue
    seen.add(place.id)
    places.push(place)
  }
  return places
}

// ------------------------------------------------------------ the live list

type PlaceEntry = Y.Map<string | number>

export function placesMap(doc: Y.Doc): Y.Map<PlaceEntry> {
  return doc.getMap<PlaceEntry>('places')
}

function entryOf(place: Place): PlaceEntry {
  const entry = new Y.Map<string | number>()
  for (const [key, value] of Object.entries(place)) if (key !== 'id') entry.set(key, value)
  return entry
}

/** The places in a live document, in list order. */
export function placesOf(doc: Y.Doc): Place[] {
  const places: Place[] = []
  placesMap(doc).forEach((entry, id) => {
    const place = normalizePlace({ ...entry.toJSON(), id })
    if (place) places.push(place)
  })
  return ordered(places)
}

/** Write `places` into an empty document (a new list's first content). */
export function fillDoc(doc: Y.Doc, places: Place[]): void {
  const map = placesMap(doc)
  doc.transact(() => {
    for (const place of places) map.set(place.id, entryOf(place))
  })
}

export function addPlace(doc: Y.Doc, place: Place): void {
  if (placesMap(doc).size >= MAX_PLACES) throw new Error('too many places')
  placesMap(doc).set(place.id, entryOf(place))
}

/** Change a place's name, note or position; its author and time stay. */
export function updatePlace(doc: Y.Doc, id: string, patch: Partial<Pick<Place, 'name' | 'note' | 'lat' | 'lon'>>): void {
  const entry = placesMap(doc).get(id)
  if (!entry) return
  doc.transact(() => {
    if (patch.name !== undefined) entry.set('name', clamp(patch.name.trim(), MAX_NAME))
    if (patch.note !== undefined) entry.set('note', clamp(patch.note, MAX_NOTE))
    if (patch.lat !== undefined) entry.set('lat', patch.lat)
    if (patch.lon !== undefined) entry.set('lon', patch.lon)
  })
}

export function removePlace(doc: Y.Doc, id: string): void {
  placesMap(doc).delete(id)
}

/** Make `live` hold exactly `old`'s places (restoring a version). */
export function replacePlaces(live: Y.Doc, old: Y.Doc): void {
  const map = placesMap(live)
  const target = placesOf(old)
  live.transact(() => {
    for (const id of [...map.keys()]) map.delete(id)
    for (const place of target) map.set(place.id, entryOf(place))
  })
}

/** A saved state (a Yjs update, as versions store it) as list JSON. */
export function stateToListJson(state: Uint8Array): Uint8Array {
  const doc = new Y.Doc()
  try {
    Y.applyUpdateV2(doc, state)
    return encodeListJson(placesOf(doc))
  } finally {
    doc.destroy()
  }
}
