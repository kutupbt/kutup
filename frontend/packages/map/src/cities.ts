import { fold } from '@kutup/ui/lib/fold'
import citiesUrl from '../assets/cities.json?url'

// City search on the device (docs/plans/maps.md), like Ente's: the whole
// list (GeoNames cities15000, CC BY 4.0) is downloaded from this origin once
// and matched in the browser, so no query leaves the device.

export interface City {
  name: string
  country: string
  lat: number
  lon: number
}

/** Shown wherever city search is offered. */
export const CITIES_ATTRIBUTION = 'GeoNames (CC BY 4.0)'

type Row = [name: string, asciiName: string, country: string, lat: number, lon: number]
interface Indexed {
  city: City
  keys: string[]
}

let loading: Promise<Indexed[]> | null = null

function index(rows: Row[]): Indexed[] {
  return rows.map(([name, ascii, country, lat, lon]) => ({
    city: { name, country, lat, lon },
    keys: ascii ? [fold(name), fold(ascii)] : [fold(name)],
  }))
}

export function loadCities(): Promise<Indexed[]> {
  loading ??= fetch(citiesUrl)
    .then((response) => {
      if (!response.ok) throw new Error(`cities: ${response.status}`)
      return response.json() as Promise<Row[]>
    })
    .then(index)
    .catch((error: unknown) => {
      loading = null
      throw error
    })
  return loading
}

/**
 * Cities whose name (or ASCII name) starts with the query, then those with a
 * word starting with it, each most populous first.
 */
export function searchCities(all: Indexed[], query: string, limit = 8): City[] {
  const q = fold(query.trim())
  if (q.length < 2) return []
  const starts: City[] = []
  const words: City[] = []
  for (const { city, keys } of all) {
    if (keys.some((key) => key.startsWith(q))) starts.push(city)
    else if (words.length < limit && keys.some((key) => key.includes(` ${q}`) || key.includes(`-${q}`))) words.push(city)
    if (starts.length >= limit) break
  }
  return [...starts, ...words].slice(0, limit)
}

/** For tests: search over given rows. */
export function indexForTesting(rows: Row[]): Indexed[] {
  return index(rows)
}
