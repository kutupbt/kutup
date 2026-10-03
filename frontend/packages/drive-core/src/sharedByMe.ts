import { useQueries, useQuery } from '@tanstack/react-query'
import api from '@kutup/session/client'
import { folderFilesKey, loadFolderFiles } from './files'
import { useFolders } from './folders'
import type { DriveFile, Folder } from './model'

// What this account shares (docs/plans/drive-file-sharing.md): its folders
// shared with people or by link, and its files shared by themselves. The
// server gives counts; names come from this account's own folder listings.

interface SharedByMeRow {
  collectionId: string
  fileId?: string
  people: number
  otherServers: number
  links: number
}

export interface SharedByMeItem {
  folder: Folder
  file?: DriveFile
  people: number
  otherServers: number
  links: number
}

export const sharedByMeKey = ['shared-by-me'] as const

export function useSharedByMe() {
  const folders = useFolders()
  const rows = useQuery({
    queryKey: sharedByMeKey,
    refetchOnMount: 'always',
    queryFn: async () => (await api.get<SharedByMeRow[]>('/shared-by-me')).data,
  })
  // The folders whose files are shared, listed to name them.
  const index = folders.data
  const listed = [...new Set((rows.data ?? []).filter((r) => r.fileId).map((r) => r.collectionId))]
    .map((id) => index?.byId.get(id))
    .filter((f): f is Folder => Boolean(f?.key))
  const listings = useQueries({
    queries: listed.map((folder) => ({ queryKey: folderFilesKey(folder), queryFn: () => loadFolderFiles(folder) })),
  })
  const files = new Map<string, DriveFile>()
  for (const listing of listings) for (const file of listing.data ?? []) files.set(file.id, file)

  const items: SharedByMeItem[] = []
  for (const row of rows.data ?? []) {
    const folder = index?.byId.get(row.collectionId)
    if (!folder) continue
    const counts = { people: row.people, otherServers: row.otherServers, links: row.links }
    if (!row.fileId) {
      items.push({ folder, ...counts })
      continue
    }
    const file = files.get(row.fileId)
    if (file) items.push({ folder, file, ...counts })
  }
  return {
    items,
    loading: folders.isPending || rows.isPending || listings.some((l) => l.isPending),
    error: folders.error ?? rows.error ?? null,
  }
}
