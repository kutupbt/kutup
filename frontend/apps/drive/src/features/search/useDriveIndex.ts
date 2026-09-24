import { useQueries } from '@tanstack/react-query'
import { folderFilesKey, loadFolderFiles } from '../drive/files'
import { useFolders } from '../drive/folders'
import type { DriveFile, Folder } from '../drive/model'

export interface IndexedFile {
  folder: Folder
  file: DriveFile
}

/**
 * Every folder and file the account can see, decrypted, for search. The
 * server cannot search names it cannot read, so the browser lists each
 * folder once (the same cached queries the folder pages use) and searches
 * in memory. Off until search is used, so browsing never pays for it.
 */
export function useDriveIndex(enabled: boolean) {
  const folders = useFolders()
  const readable = enabled ? (folders.data?.all ?? []).filter((f) => f.key) : []
  const lists = useQueries({
    queries: readable.map((folder) => ({
      queryKey: folderFilesKey(folder),
      queryFn: () => loadFolderFiles(folder),
    })),
  })
  const files: IndexedFile[] = []
  lists.forEach((list, i) => {
    const folder = readable[i]
    if (!folder || !list.data) return
    for (const file of list.data) if (file.name) files.push({ folder, file })
  })
  return {
    index: folders.data,
    files,
    loading: folders.isPending || lists.some((l) => l.isPending),
  }
}
