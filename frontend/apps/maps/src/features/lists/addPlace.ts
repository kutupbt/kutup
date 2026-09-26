import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { addPlace, listTitle, type Place } from '@kutup/map/list'
import { useAtlas } from './atlasContext'
import { useCreateList, useSaveFolder } from './lists'
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
 * Add one new place to the chosen lists, with one id in all of them, and to a
 * new map made for it if `newList` is given (in the "Save new maps to"
 * folder). Returns the place and the list to show it from, or null when it
 * went into none.
 */
export function useAddToLists() {
  const { t } = useTranslation()
  const atlas = useAtlas()
  const createList = useCreateList()
  const { folder: saveFolder } = useSaveFolder()
  return async (
    values: Pick<Place, 'name' | 'note' | 'lat' | 'lon'>,
    listIds: string[],
    newList: string | null = null,
  ): Promise<{ place: Place; fileId: string | null } | null> => {
    if (!atlas.me) return null
    const place: Place = { id: crypto.randomUUID(), ...values, addedBy: atlas.me, addedAt: new Date().toISOString() }
    let added = 0
    let newFileId: string | null = null
    if (newList) {
      try {
        if (!saveFolder) throw new Error('no folder for new maps')
        // Made with the place already in it: nothing to join.
        const path = await createList(saveFolder, newList, [place])
        newFileId = path.split('/').pop() ?? null
        added += 1
      } catch {
        toast.error(t('place.newListFailed', { list: newList }))
      }
    }
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
    return added > 0 ? { place, fileId: newFileId ?? listIds[0] ?? null } : null
  }
}
