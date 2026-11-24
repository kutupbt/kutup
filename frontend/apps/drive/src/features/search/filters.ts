// Search filters (docs/plans/drive-parity.md, "Search"): beside the
// toolbar's type filter, when an item was last changed, where it is, who
// created it and whether you share it. Proton Drive's index keeps the same
// fields for each entry (modification time, sharing, key author); as the
// names, they are known only in this browser, so filtering happens here.
// The filters live in the URL next to the query, so Back and a reload keep them.

export const MODIFIED_WITHIN = ['today', 'week', 'month', 'year'] as const
export type ModifiedWithin = (typeof MODIFIED_WITHIN)[number]
export const PLACES = ['mine', 'shared'] as const
export type Place = (typeof PLACES)[number]
export const CREATORS = ['me', 'others'] as const
export type Creator = (typeof CREATORS)[number]

export interface SearchFilters {
  modified: ModifiedWithin | null
  place: Place | null
  createdBy: Creator | null
  sharedByMe: boolean
}

export const NO_FILTERS: SearchFilters = { modified: null, place: null, createdBy: null, sharedByMe: false }

/** The URL parameter each filter is kept in. */
const PARAM = { modified: 'modified', place: 'in', createdBy: 'by', sharedByMe: 'shared' } as const

function oneOf<T extends string>(value: string | null, allowed: readonly T[]): T | null {
  return value !== null && (allowed as readonly string[]).includes(value) ? (value as T) : null
}

/** The filters a URL carries; anything it does not know is no filter. */
export function filtersFromParams(params: URLSearchParams): SearchFilters {
  return {
    modified: oneOf(params.get(PARAM.modified), MODIFIED_WITHIN),
    place: oneOf(params.get(PARAM.place), PLACES),
    createdBy: oneOf(params.get(PARAM.createdBy), CREATORS),
    sharedByMe: params.get(PARAM.sharedByMe) === 'me',
  }
}

/** `params` (the query kept) with `filters` in place of the ones it had. */
export function withFilters(params: URLSearchParams, filters: SearchFilters): URLSearchParams {
  const next = new URLSearchParams(params)
  for (const key of Object.values(PARAM)) next.delete(key)
  if (filters.modified) next.set(PARAM.modified, filters.modified)
  if (filters.place) next.set(PARAM.place, filters.place)
  if (filters.createdBy) next.set(PARAM.createdBy, filters.createdBy)
  if (filters.sharedByMe) next.set(PARAM.sharedByMe, 'me')
  return next
}

/** How many filters are on. */
export function activeFilters(filters: SearchFilters): number {
  return [filters.modified, filters.place, filters.createdBy].filter(Boolean).length + (filters.sharedByMe ? 1 : 0)
}

const DAY_MS = 24 * 60 * 60 * 1000

/** The earliest change `modified` lets through: since midnight here today, or the last 7, 30 or 365 days. */
export function modifiedSince(modified: ModifiedWithin, now: Date): Date {
  switch (modified) {
    case 'today':
      return new Date(now.getFullYear(), now.getMonth(), now.getDate())
    case 'week':
      return new Date(now.getTime() - 7 * DAY_MS)
    case 'month':
      return new Date(now.getTime() - 30 * DAY_MS)
    case 'year':
      return new Date(now.getTime() - 365 * DAY_MS)
  }
}

/** What the filters look at in one result. */
export interface FilterSubject {
  modifiedAt: string
  /** In My files (not shared with you by someone else). */
  owned: boolean
  /** Created by this account: a file's uploader, a folder's owner. */
  createdByMe: boolean
  /** Shared by this account with people or by link (the item itself). */
  sharedByMe: boolean
}

export function passesFilters(subject: FilterSubject, filters: SearchFilters, now: Date): boolean {
  if (filters.modified && !(Date.parse(subject.modifiedAt) >= modifiedSince(filters.modified, now).getTime())) return false
  if (filters.place === 'mine' && !subject.owned) return false
  if (filters.place === 'shared' && subject.owned) return false
  if (filters.createdBy === 'me' && !subject.createdByMe) return false
  if (filters.createdBy === 'others' && subject.createdByMe) return false
  if (filters.sharedByMe && !subject.sharedByMe) return false
  return true
}
