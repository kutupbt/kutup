import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { addPlace, listTitle, type Place } from '@kutup/map/list'
import { useAtlas } from './atlasContext'
import type { ListOption } from './PlaceDialog'

/** The lists a place can be added to or removed from: those this account may change. */
export function useWritableLists(): ListOption[] {
  const atlas = useAtlas()
  return atlas.lists
    .filter((entry) => atlas.editable(entry))
    .map((entry) => ({ id: entry.file.id, title: listTitle(entry.file.name ?? ''), color: atlas.colorOf(entry.file.id) }))
    .sort((a, b) => a.title.localeCompare(b.title))
}

/**
 * Add one new place to the chosen lists, with one id in all of them. Returns
 * the place, or null when it went into none.
 */
export function useAddToLists() {
  const { t } = useTranslation()
  const atlas = useAtlas()
  return async (values: Pick<Place, 'name' | 'note' | 'lat' | 'lon'>, listIds: string[]): Promise<Place | null> => {
    if (!atlas.me) return null
    const place: Place = { id: crypto.randomUUID(), ...values, addedBy: atlas.me, addedAt: new Date().toISOString() }
    let added = 0
    for (const id of listIds) {
      const entry = atlas.lists.find((l) => l.file.id === id)
      if (!entry) continue
      try {
        await atlas.write(entry, (doc) => addPlace(doc, place))
        added += 1
      } catch {
        toast.error(t('place.addFailed', { list: listTitle(entry.file.name ?? '') }))
      }
    }
    if (added > 0) toast.success(t('place.addedTo', { count: added }))
    return added > 0 ? place : null
  }
}
