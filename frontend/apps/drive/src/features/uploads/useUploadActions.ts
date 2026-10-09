import { useQueryClient } from '@tanstack/react-query'
import { useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import type { PendingUpload } from '@kutup/files/upload/pendingUploads'
import { resumeUpload } from '@kutup/files/upload/streamUpload'
import type { FolderEntry } from '@kutup/files/upload/uploadFolder'
import api, { freshAccessToken } from '@kutup/session/client'
import { updateSession } from '@kutup/session/store'
import { filesKey } from '@kutup/drive-core/files'
import { cachedFolderIndex, foldersKey } from '@kutup/drive-core/folders'
import { useDriveIdentity } from '@kutup/drive-core/identity'
import type { Folder } from '@kutup/drive-core/model'
import { recordContentHash } from '@kutup/drive-core/names'
import { thumbnailAfterUpload } from '../thumbnails/schedule'
import { ConflictPolicy } from '@kutup/drive-ui/nameConflicts'
import { classifyUploadError, isFolderKeyChanged } from '@kutup/drive-ui/uploadError'
import { uploads } from '@kutup/drive-ui/uploadStore'
import { uploadDirectoryInto } from './folderUpload'
import { BatchListing, placeFile } from './upload'

export { uploadCreating, uploadOne } from './upload'

export function useUploadActions() {
  const queryClient = useQueryClient()
  const identity = useDriveIdentity()
  const { t } = useTranslation()
  // The root's stored name is a fixed English key; show it the way the sidebar does.
  const displayName = useCallback((folder: Folder) => (folder.isRoot ? t('nav.myFiles') : (folder.name ?? '')), [t])

  const settled = useCallback(() => {
    void queryClient.invalidateQueries({ queryKey: ['files'] })
    void queryClient.invalidateQueries({ queryKey: foldersKey })
    // Storage used changes with every upload; the sidebar meter reads the session.
    void api
      .get<{ storageUsedBytes: number; storageQuotaBytes: number }>('/user/me')
      .then(({ data }) => updateSession({ storageUsedBytes: data.storageUsedBytes, storageQuotaBytes: data.storageQuotaBytes }))
      .catch(() => {})
  }, [queryClient])

  /** The folder as the server has it now (after its key rotated). */
  const reloadFolder = useCallback(
    async (folder: Folder): Promise<Folder> => {
      // A folder on another server: bring its stored share up to the new key.
      if (folder.remoteShareId) await api.post(`/drive/federation/shares/${folder.remoteShareId}/refresh`)
      await queryClient.invalidateQueries({ queryKey: foldersKey })
      const fresh = cachedFolderIndex(queryClient)?.byId.get(folder.id)
      if (!fresh?.key) throw new Error('the folder is no longer available')
      return fresh
    },
    [queryClient],
  )

  const subfoldersOf = useCallback(
    (folder: Folder) => () => cachedFolderIndex(queryClient)?.childrenOf(folder.id) ?? [],
    [queryClient],
  )

  const uploadFiles = useCallback(
    (folder: Folder, files: File[]) => {
      // One batch: its listing read once, and "apply to all" for its clashes.
      const policy = new ConflictPolicy(files.length)
      const listing = new BatchListing(folder, subfoldersOf(folder))
      const folderName = displayName(folder)
      uploads.add(
        files.map((file) => ({
          name: file.name,
          folderName,
          total: file.size,
          run: async (signal, progress, waiting) => {
            const place = (into: Folder, list: BatchListing) =>
              placeFile({ folder: into, file, folderName, listing: list, policy, signal, progress, waiting })
            try {
              return await place(folder, listing)
            } catch (error) {
              // Its owner removed someone meanwhile: once more, under the new key.
              if (!isFolderKeyChanged(error)) throw error
              const fresh = await reloadFolder(folder)
              return place(fresh, new BatchListing(fresh, subfoldersOf(fresh)))
            }
          },
        })),
        settled,
        classifyUploadError,
      )
    },
    [settled, displayName, reloadFolder, subfoldersOf],
  )

  /** A dropped or picked directory: its tree becomes folders, one queue entry. */
  const uploadDirectory = useCallback(
    (folder: Folder, entries: FolderEntry[], name: string) => {
      const me = identity.data
      if (!me || !folder.key || !folder.canManage) return
      const key = folder.key
      uploads.add(
        [
          {
            name,
            folderName: displayName(folder),
            total: entries.length,
            unit: 'files',
            run: async (signal, progress, waiting) => {
              await uploadDirectoryInto({
                me,
                parent: { ...folder, key },
                entries,
                folderName: displayName(folder),
                subfoldersOf: (parent) => cachedFolderIndex(queryClient)?.childrenOf(parent.id) ?? [],
                signal,
                waiting,
                onProgress: (done, total) => progress(done, total),
              })
            },
          },
        ],
        settled,
        classifyUploadError,
      )
    },
    [identity.data, settled, displayName, queryClient],
  )

  const refreshFolder = useCallback(
    (folder: Folder) => queryClient.invalidateQueries({ queryKey: filesKey(folder.remoteShareId ?? folder.id) }),
    [queryClient],
  )

  /** Go on with an upload a reload or a crash stopped (the upload panel). */
  const resumeOne = useCallback(
    (upload: PendingUpload, file: File, folder: Folder) => {
      uploads.add(
        [
          {
            name: file.name,
            folderName: displayName(folder),
            total: file.size,
            run: async (signal, progress, waiting) => {
              if (!folder.key) throw new Error('folder is not open')
              const uploaded = await resumeUpload({
                upload,
                file,
                collection: { id: folder.id, keyEpoch: folder.keyEpoch, collectionKey: folder.key },
                accessToken: freshAccessToken,
                onProgress: progress,
                onWaiting: waiting,
                signal,
              })
              await recordContentHash(folder, uploaded.fileId, uploaded.contentSha256)
              thumbnailAfterUpload(uploaded, file)
            },
          },
        ],
        settled,
        classifyUploadError,
      )
    },
    [displayName, settled],
  )

  return { uploadFiles, uploadDirectory, resumeOne, settled, refreshFolder }
}
