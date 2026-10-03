import { useQueries, useQueryClient } from '@tanstack/react-query'
import { folderFilesKey, loadFolderFiles } from '@kutup/drive-core/files'
import { useSharedFiles, type SharedFile } from '@kutup/drive-core/fileShares'
import { foldersKey, useFolders } from '@kutup/drive-core/folders'
import type { DriveFile, Folder } from '@kutup/drive-core/model'
import { streamUpload } from '@kutup/files/upload/streamUpload'
import { encodeListJson, isListName, LIST_EXTENSION, LIST_MIME, type Place } from '@kutup/map/list'
import { useMapConfig } from '@kutup/map/config'
import { freshAccessToken } from '@kutup/session/client'

// A place list is a Drive file (docs/plans/maps.md, step 4). The Maps app
// shows every one this account can reach: its own wherever they are, in
// folders shared with it, and files shared with it by themselves, here or on
// other servers. Those on other servers are view only until editing across
// servers exists.

export interface ListEntry {
  folder: Folder
  file: DriveFile
  /** Set when the file is shared with this account by itself. */
  shared?: SharedFile
  /** Where it opens in this app. */
  path: string
}

export function listPath(folder: Pick<Folder, 'id' | 'source' | 'remoteShareId'>, fileId: string): string {
  if (folder.source === 'file') return `/shared/${fileId}`
  if (folder.source === 'remote' && folder.remoteShareId) return `/remote/${folder.remoteShareId}/${fileId}`
  return `/lists/${folder.id}/${fileId}`
}

export function useLists() {
  const folders = useFolders()
  const sharedFiles = useSharedFiles()
  const readable = (folders.data?.all ?? []).filter((f) => f.key)
  const listings = useQueries({
    queries: readable.map((folder) => ({
      queryKey: folderFilesKey(folder),
      queryFn: () => loadFolderFiles(folder),
    })),
  })
  const lists: ListEntry[] = []
  const seen = new Set<string>()
  listings.forEach((listing, i) => {
    const folder = readable[i]
    if (!folder || !listing.data) return
    for (const file of listing.data) {
      if (!isListName(file.name) || seen.has(file.id)) continue
      seen.add(file.id)
      lists.push({ folder, file, path: listPath(folder, file.id) })
    }
  })
  for (const shared of sharedFiles.data ?? []) {
    // A file shared by itself that is also in a shared folder shows once.
    // One waiting for its owner cannot be named yet, so nor told apart
    // from other files: it shows up once the owner hands the new key on.
    if (seen.has(shared.file.id) || !isListName(shared.file.name)) continue
    seen.add(shared.file.id)
    lists.push({ folder: shared.container, file: shared.file, shared, path: listPath(shared.container, shared.file.id) })
  }
  return {
    index: folders.data,
    lists,
    loading: folders.isPending || sharedFiles.isPending || listings.some((l) => l.isPending),
    error: folders.error ?? sharedFiles.error ?? listings.find((l) => l.error)?.error ?? null,
  }
}

/**
 * Where new lists go: the folder chosen in settings when it is still one of
 * this account's own, open folders, else My files. `fellBack` says the chosen
 * one is gone (deleted or in the trash).
 */
export function useSaveFolder(): { folder: Folder | undefined; fellBack: boolean } {
  const folders = useFolders()
  const config = useMapConfig()
  const chosen = config.data?.preferences.saveFolderId ?? null
  const index = folders.data
  if (!index) return { folder: undefined, fellBack: false }
  const folder = chosen ? index.byId.get(chosen) : undefined
  if (folder && folder.source === 'owned' && folder.key) return { folder, fellBack: false }
  return { folder: index.root, fellBack: chosen !== null }
}

/** `Trip.kutupmap`, then `Trip (1).kutupmap`, … — never a name the folder has. */
export function uniqueListName(title: string, taken: Iterable<string>): string {
  const names = new Set([...taken].map((n) => n.toLocaleLowerCase()))
  for (let n = 0; ; n++) {
    const candidate = n === 0 ? `${title}.${LIST_EXTENSION}` : `${title} (${n}).${LIST_EXTENSION}`
    if (!names.has(candidate.toLocaleLowerCase())) return candidate
  }
}

/** Make a list in `folder` (empty, or with imported places); returns where it opens. */
export function useCreateList() {
  const queryClient = useQueryClient()
  return async (folder: Folder, title: string, places: Place[] = []): Promise<string> => {
    if (!folder.key || !folder.canUpload) throw new Error('folder is not open')
    const existing = await loadFolderFiles(folder)
    const name = uniqueListName(title.trim(), existing.flatMap((f) => (f.name ? [f.name] : [])))
    const uploaded = await streamUpload({
      file: new File([encodeListJson(places).slice()], name, { type: LIST_MIME }),
      collection: { id: folder.id, keyEpoch: folder.keyEpoch, collectionKey: folder.key },
      accessToken: freshAccessToken,
    })
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ['files'] }),
      queryClient.invalidateQueries({ queryKey: foldersKey }),
    ])
    return listPath(folder, uploaded.fileId)
  }
}
