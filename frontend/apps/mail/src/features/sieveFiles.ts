import type { MailFilter } from '@kutup/mail-core/filters'
import type { MailPlaces } from '@kutup/mail-core/places'
import { filtersToSieve, type SievePlaces } from '@kutup/mail-core/sieve'

/** The folders by path ("Work/Clients") and the labels, for Sieve's `fileinto`. */
export function sievePlaces(places: MailPlaces | undefined): SievePlaces {
  if (!places) return { folders: [], labels: [] }
  const path = (id: string): string => {
    const folder = places.folders.get(id)
    if (!folder) return ''
    return folder.parentId ? `${path(folder.parentId)}/${folder.name}` : folder.name
  }
  return {
    folders: [...places.folders.values()].filter((f) => !f.unnamed).map((f) => ({ id: f.id, path: path(f.id) })),
    labels: places.labels.map((l) => ({ id: l.id, name: l.name })),
  }
}

/** Downloads the filters as one Sieve script (Proton's dialect). */
export function exportSieve(filters: MailFilter[], places: MailPlaces | undefined) {
  const url = URL.createObjectURL(new Blob([filtersToSieve(filters, sievePlaces(places))], { type: 'application/sieve' }))
  const link = document.createElement('a')
  link.href = url
  link.download = 'kutup-filters.sieve'
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 0)
}
