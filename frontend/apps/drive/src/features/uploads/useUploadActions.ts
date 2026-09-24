import { useQueryClient } from '@tanstack/react-query'
import { useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { createFileRecordV1, encryptStream } from '@kutup/crypto'
import { streamUpload, type UploadedFile } from '@kutup/files/upload/streamUpload'
import { uploadFolder, type FolderEntry } from '@kutup/files/upload/uploadFolder'
import api, { freshAccessToken } from '@kutup/session/client'
import { updateSession } from '@kutup/session/store'
import { filesKey } from '../drive/files'
import { foldersKey } from '../drive/folders'
import { useDriveIdentity } from '../drive/identity'
import { folderLocation, type Folder } from '../drive/model'
import { thumbnailAfterUpload } from '../thumbnails/schedule'
import { classifyUploadError } from './uploadError'
import { uploads } from './uploadStore'

/**
 * A file into a federated folder: the other server takes one multipart body,
 * so it is encrypted whole in memory and proxied by our server.
 */
async function uploadRemote(folder: Folder, shareId: string, file: File, signal: AbortSignal, progress: (s: number, t: number) => void) {
  if (!folder.key) throw new Error('folder is not open')
  const bytes = new Uint8Array(await file.arrayBuffer())
  const record = await createFileRecordV1(folder.id, folder.keyEpoch, folder.key, {
    name: file.name,
    mimeType: file.type || 'application/octet-stream',
    size: file.size,
  })
  const encrypted = await encryptStream(bytes, record.fileKey, {
    fileId: record.fileId,
    collectionId: folder.id,
    epoch: folder.keyEpoch,
  })
  const form = new FormData()
  form.append('fileId', record.fileId)
  form.append('metadataEnvelope', record.metadataEnvelope)
  form.append('fileKeyEnvelope', record.fileKeyEnvelope)
  form.append('file', new Blob([encrypted.slice()], { type: 'application/octet-stream' }), 'encrypted')
  await api.post(`/drive/federation/shares/${shareId}/files`, form, {
    signal,
    onUploadProgress: (e) => progress(Math.round((e.progress ?? 0) * file.size), file.size),
  })
}

/**
 * Put a file into `folder`, returning what was made (null for a folder on
 * another server, whose files this server does not hold). Its thumbnail is
 * queued from the plaintext still in hand.
 */
export async function uploadOne(folder: Folder, file: File, signal?: AbortSignal, progress?: (s: number, t: number) => void): Promise<UploadedFile | null> {
  if (!folder.key) throw new Error('folder is not open')
  const location = folderLocation(folder)
  if (location.kind === 'remote') {
    await uploadRemote(folder, location.shareId, file, signal ?? new AbortController().signal, progress ?? (() => {}))
    return null
  }
  const uploaded = await streamUpload({
    file,
    collection: { id: folder.id, keyEpoch: folder.keyEpoch, collectionKey: folder.key },
    accessToken: freshAccessToken,
    onProgress: progress,
    signal,
  })
  thumbnailAfterUpload(uploaded, file)
  return uploaded
}

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

  const uploadFiles = useCallback(
    (folder: Folder, files: File[]) => {
      uploads.add(
        files.map((file) => ({
          name: file.name,
          folderName: displayName(folder),
          total: file.size,
          run: async (signal, progress) => {
            await uploadOne(folder, file, signal, progress)
          },
        })),
        settled,
        classifyUploadError,
      )
    },
    [settled, displayName],
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
            run: async (signal, progress) => {
              await uploadFolder({
                entries,
                parentCollection: { id: folder.id, keyEpoch: folder.keyEpoch, collectionKey: key },
                masterKey: me.masterKey,
                ownerUserId: me.userId,
                accessToken: freshAccessToken,
                signal,
                onProgress: (done, total) => progress(done, total),
                onFileUploaded: thumbnailAfterUpload,
              })
            },
          },
        ],
        settled,
        classifyUploadError,
      )
    },
    [identity.data, settled, displayName],
  )

  const refreshFolder = useCallback(
    (folder: Folder) => queryClient.invalidateQueries({ queryKey: filesKey(folder.remoteShareId ?? folder.id) }),
    [queryClient],
  )

  return { uploadFiles, uploadDirectory, settled, refreshFolder }
}
