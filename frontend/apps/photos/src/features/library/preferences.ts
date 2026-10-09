import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createOwnedCollectionV1 } from '@kutup/crypto'
import { foldersKey, useFolders, type FolderIndex } from '@kutup/drive-core/folders'
import type { DriveIdentity } from '@kutup/drive-core/identity'
import type { Folder } from '@kutup/drive-core/model'
import { loadFolderFiles } from '@kutup/drive-core/files'
import { asNameTaken, canonicalName, freeName, inFolder, nameHashIn, namesIn } from '@kutup/drive-core/names'
import api from '@kutup/session/client'

// Which Drive folders make up the library, and where uploads go
// (docs/plans/photos.md). The server keeps folder ids only.

export interface PhotosPreferences {
  /** One of your own folders; null until the first upload makes "Photos". */
  uploadFolderId: string | null
  /** Other folders shown, each with its subfolders. */
  libraryFolderIds: string[]
}

export const preferencesKey = ['photos-preferences'] as const

/** The upload folder's name when Photos makes it, in My files. */
export const DEFAULT_UPLOAD_FOLDER = 'Photos'

export function usePhotosPreferences() {
  return useQuery({
    queryKey: preferencesKey,
    queryFn: async () => (await api.get<PhotosPreferences>('/photos/preferences')).data,
  })
}

export function useSavePreferences() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (next: PhotosPreferences) => (await api.put<PhotosPreferences>('/photos/preferences', next)).data,
    onSuccess: (saved) => queryClient.setQueryData(preferencesKey, saved),
  })
}

/**
 * The upload folder, made on first use: "Photos" in My files (an existing
 * one of that name is taken rather than a second made), then remembered.
 */
export async function ensureUploadFolder(
  index: FolderIndex,
  preferences: PhotosPreferences,
  me: DriveIdentity,
  save: (next: PhotosPreferences) => Promise<PhotosPreferences>,
): Promise<string> {
  const chosen = preferences.uploadFolderId ? index.byId.get(preferences.uploadFolderId) : undefined
  if (chosen?.key) return chosen.id
  const wanted = canonicalName(DEFAULT_UPLOAD_FOLDER)
  const existing = index
    .childrenOf(index.root.id)
    .find((f) => f.source === 'owned' && f.name !== null && canonicalName(f.name) === wanted)
  let id = existing?.id
  if (!id) {
    let name = DEFAULT_UPLOAD_FOLDER
    for (let attempt = 0; !id; attempt++) {
      const created = await createOwnedCollectionV1(me.masterKey, me.userId, name, index.root.id)
      try {
        await api.post('/collections', { ...created.payload, nameHash: await nameHashIn(inFolder(index.root), name) })
        id = created.payload.id
      } catch (error) {
        // Names are unique in a folder (docs/plans/drive-unique-names.md):
        // a "Photos" folder made meanwhile is the one; a file of that name
        // leaves the next free name.
        const taken = asNameTaken(error)
        if (!taken || attempt > 2) throw error
        if (taken.holder?.kind === 'folder') id = taken.holder.id
        else name = freeName(name, namesIn(await loadFolderFiles(index.root), index.childrenOf(index.root.id)))
      }
    }
  }
  await save({ ...preferences, uploadFolderId: id })
  return id
}

/** A folder and everything under it that this account can open. */
export function folderTree(index: FolderIndex, rootId: string): Folder[] {
  const out: Folder[] = []
  const seen = new Set<string>()
  const walk = (id: string) => {
    if (seen.has(id)) return
    seen.add(id)
    const folder = index.byId.get(id)
    if (!folder?.key) return
    out.push(folder)
    for (const child of index.childrenOf(id)) walk(child.id)
  }
  walk(rootId)
  return out
}

/** Where a folder is, for people: "My files / Trips / 2024". */
export function folderPathName(index: FolderIndex, folder: Folder, myFiles: string): string {
  const names: string[] = []
  let at: Folder | undefined = folder
  for (let depth = 0; at && depth < 32; depth++) {
    names.unshift(at.isRoot ? myFiles : (at.name ?? '…'))
    at = at.parentId ? index.byId.get(at.parentId) : undefined
  }
  return names.join(' / ')
}

export { foldersKey, useFolders }
