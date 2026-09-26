import { createContext, useContext } from 'react'
import type * as Y from 'yjs'
import type { Place } from '@kutup/map/list'
import type { ListEntry } from './lists'

// Everything the Maps app knows about places, across lists: the lists, each
// one's saved places, the open list's live places, and writing to any list
// (docs/plans/maps.md). A place added to several lists keeps one id in all
// of them, which is how a place's card knows its lists.

/** The list open in the panel, live. */
export interface OpenList {
  fileId: string
  doc: Y.Doc
  places: Place[]
}

/** The place whose card is shown over the map. */
export interface ShownPlace {
  place: Place
  /** The list it was opened from. */
  fileId: string
}

export interface Atlas {
  lists: ListEntry[]
  loading: boolean
  error: unknown
  /** Each list's places: live for the open one, as last saved for the others. */
  placesOf: (fileId: string) => Place[] | undefined
  savedLoading: boolean
  open: OpenList | null
  setOpen: (open: OpenList | null) => void
  shown: ShownPlace | null
  showPlace: (shown: ShownPlace | null) => void
  /** Whether this account may change a list. */
  editable: (entry: ListEntry) => boolean
  /** Change a list: live when it is open, else by joining its session briefly. */
  write: (entry: ListEntry, change: (doc: Y.Doc) => void) => Promise<void>
  /** This account, `user@server`, for who added a place. */
  me: string | null
  /** A list's colour on the map. */
  colorOf: (fileId: string) => string
}

export const AtlasContext = createContext<Atlas | null>(null)

export function useAtlas(): Atlas {
  const atlas = useContext(AtlasContext)
  if (!atlas) throw new Error('useAtlas outside the maps layout')
  return atlas
}

/** The same place: one id, or the same spot (to about a metre). */
export function samePlace(a: Pick<Place, 'id' | 'lat' | 'lon'>, b: Pick<Place, 'id' | 'lat' | 'lon'>): boolean {
  return a.id === b.id || (Math.abs(a.lat - b.lat) < 1e-5 && Math.abs(a.lon - b.lon) < 1e-5)
}

export class ListBusy extends Error {
  constructor() {
    super('the list could not be reached')
  }
}
