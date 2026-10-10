import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useMemo } from 'react'
import { allFilesKey, loadAllFiles, loadFolderFiles } from '@kutup/drive-core/files'
import { useDriveIdentity } from '@kutup/drive-core/identity'
import { useSharedFiles } from '@kutup/drive-core/fileShares'
import { foldersKey, useFolders } from '@kutup/drive-core/folders'
import { uploadUnderFreeName } from '@kutup/drive-core/names'
import type { DriveFile, Folder } from '@kutup/drive-core/model'
import { documentKindOf, newDocument, type DocumentKind } from '@kutup/drive-core/documents'
import { streamUpload } from '@kutup/files/upload/streamUpload'
import { freshAccessToken } from '@kutup/session/client'
import { filePath } from '@kutup/editors/paths'

// A document (a note, an office document, a whiteboard) is a Drive file.
// The Office home shows every one this account can open in an editor: its
// own wherever they are, in folders shared with it, and files shared with it
// by themselves. Folders on other servers are left out: the editors cannot
// open their files yet.

export interface DocumentEntry {
  folder: Folder
  file: DriveFile
  kind: DocumentKind
  /** The owner's account, when the document is someone else's. */
  owner: string | null
  /** Where it opens: the file page, here in Office. */
  href: string
}

export function useDocuments() {
  const folders = useFolders()
  const sharedFiles = useSharedFiles()
  const identity = useDriveIdentity()
  const queryClient = useQueryClient()
  // Every folder's files in one request (one per folder before;
  // docs/research/18-web-performance.md), opened once the folders are.
  const listing = useQuery({
    queryKey: [...allFilesKey, identity.data?.userId],
    enabled: Boolean(folders.data),
    queryFn: () => loadAllFiles(folders.data!.all, queryClient),
  })
  const documents = useMemo(
    () => collectDocuments(folders.data?.all ?? [], listing.data, sharedFiles.data ?? []),
    [folders.data, listing.data, sharedFiles.data],
  )
  return {
    root: folders.data?.root,
    documents,
    loading: folders.isPending || sharedFiles.isPending || listing.isPending,
    // Without the folders nothing can be listed; the files failing leaves
    // only the files shared by themselves.
    error: folders.error ?? null,
    incomplete: Boolean(sharedFiles.error) || Boolean(listing.error),
  }
}

/** Every document in the folders' files and the files shared by themselves, once each. */
function collectDocuments(
  folders: Folder[],
  listing: Map<string, DriveFile[]> | undefined,
  sharedFiles: NonNullable<ReturnType<typeof useSharedFiles>['data']>,
): DocumentEntry[] {
  const documents: DocumentEntry[] = []
  const seen = new Set<string>()
  folders.forEach((folder) => {
    const files = listing?.get(folder.id)
    if (!files) return
    for (const file of files) {
      const kind = documentKindOf(file.name)
      if (!kind || seen.has(file.id)) continue
      seen.add(file.id)
      documents.push({
        folder,
        file,
        kind,
        owner: folder.source === 'owned' ? null : (folder.ownerAccount ?? null),
        href: filePath(folder, file.id),
      })
    }
  })
  for (const shared of sharedFiles) {
    // A file shared by itself that is also in a shared folder shows once.
    // One on another server, or still waiting for its owner's new key,
    // cannot be opened in the editor from here.
    const kind = documentKindOf(shared.file.name)
    if (!kind || seen.has(shared.file.id) || shared.container.remoteFileShareId) continue
    // Waiting for the owner's new key (or gone), it would only open on a
    // page that says so.
    if (shared.state === 'waiting' || shared.state === 'gone') continue
    seen.add(shared.file.id)
    documents.push({
      folder: shared.container,
      file: shared.file,
      kind,
      owner: shared.ownerAccount,
      href: filePath(shared.container, shared.file.id),
    })
  }
  return documents
}

export type DocumentOrder = 'recent' | 'name'

/** Most recently changed first, or by name. */
export function sortDocuments(documents: DocumentEntry[], order: DocumentOrder, locale: string): DocumentEntry[] {
  const sorted = [...documents]
  if (order === 'name') {
    sorted.sort((a, b) => (a.file.name ?? '').localeCompare(b.file.name ?? '', locale, { numeric: true, sensitivity: 'base' }))
  } else {
    sorted.sort((a, b) => b.file.updatedAt.localeCompare(a.file.updatedAt))
  }
  return sorted
}

/** Those of `kind` (all when null) whose name contains `query`. */
export function filterDocuments(documents: DocumentEntry[], kind: DocumentKind | null, query: string, locale: string): DocumentEntry[] {
  const needle = query.trim().toLocaleLowerCase(locale)
  return documents.filter(
    (d) => (!kind || d.kind === kind) && (!needle || (d.file.name ?? '').toLocaleLowerCase(locale).includes(needle)),
  )
}

/** Make an empty document in `folder`; returns where it opens (a path here). */
export function useCreateDocument() {
  const queryClient = useQueryClient()
  return async (folder: Folder, kind: DocumentKind, title: string): Promise<string> => {
    if (!folder.key || !folder.canUpload) throw new Error('folder is not open')
    const existing = await loadFolderFiles(folder)
    const file = newDocument(kind, title, existing.flatMap((f) => (f.name ? [f.name] : [])))
    const key = folder.key
    const uploaded = await uploadUnderFreeName(folder, file, (named, nameHash) =>
      streamUpload({
        file: named,
        collection: { id: folder.id, keyEpoch: folder.keyEpoch, collectionKey: key },
        accessToken: freshAccessToken,
        nameHash,
      }),
    )
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ['files'] }),
      queryClient.invalidateQueries({ queryKey: foldersKey }),
    ])
    return filePath(folder, uploaded.fileId)
  }
}
