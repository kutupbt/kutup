import { useQueryClient } from '@tanstack/react-query'
import { useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { createFileRecordV1, type FileMetadataV1, type MediaMetadataV1 } from '@kutup/crypto'
import { readMedia } from '@kutup/files/media'
import { newFileBlobStreamEncryptorV1 } from '@kutup/crypto/fileBlob'
import { PLAIN_CHUNK } from '@kutup/crypto/streamEncryptor'
import { streamUpload, type UploadedFile } from '@kutup/files/upload/streamUpload'
import { uploadFolder, type FolderEntry } from '@kutup/files/upload/uploadFolder'
import api, { freshAccessToken } from '@kutup/session/client'
import { updateSession } from '@kutup/session/store'
import { filesKey } from '@kutup/drive-core/files'
import { foldersKey, type FolderIndex } from '@kutup/drive-core/folders'
import { useDriveIdentity } from '@kutup/drive-core/identity'
import { folderLocation, type Folder } from '@kutup/drive-core/model'
import { thumbnailAfterUpload } from '../thumbnails/schedule'
import { classifyUploadError, isFolderKeyChanged } from './uploadError'
import { uploads } from './uploadStore'

/**
 * A file into a federated folder: the other server takes one multipart body,
 * which our server spools to disk and streams on. It is encrypted a chunk at
 * a time into a Blob (which the browser may keep on disk), never whole in
 * memory.
 */
async function uploadRemote(folder: Folder, shareId: string, file: File, media: MediaMetadataV1 | undefined, signal: AbortSignal, progress: (s: number, t: number) => void) {
  if (!folder.key) throw new Error('folder is not open')
  const metadata: FileMetadataV1 = { name: file.name, mimeType: file.type || 'application/octet-stream', size: file.size }
  if (media) metadata.media = media
  const record = await createFileRecordV1(folder.id, folder.keyEpoch, folder.key, metadata)
  const enc = await newFileBlobStreamEncryptorV1(record.fileKey, {
    fileId: record.fileId,
    generation: record.keyGeneration,
  })
  const parts: BlobPart[] = [enc.prefix as BlobPart]
  if (file.size === 0) parts.push(enc.push(new Uint8Array(0), true) as BlobPart)
  for (let pos = 0; pos < file.size; ) {
    if (signal.aborted) throw new DOMException('Upload cancelled', 'AbortError')
    const end = Math.min(pos + PLAIN_CHUNK, file.size)
    const plain = new Uint8Array(await file.slice(pos, end).arrayBuffer())
    parts.push(enc.push(plain, end === file.size) as BlobPart)
    pos = end
  }
  const form = new FormData()
  form.append('fileId', record.fileId)
  form.append('metadataEnvelope', record.metadataEnvelope)
  form.append('fileKeyEnvelope', record.fileKeyEnvelope)
  form.append('file', new Blob(parts, { type: 'application/octet-stream' }), 'encrypted')
  await api.post(`/drive/federation/shares/${shareId}/files`, form, {
    signal,
    onUploadProgress: (e) => progress(Math.round((e.progress ?? 0) * file.size), file.size),
  })
}

/**
 * Put a file into `folder`, returning what was made (null for a folder on
 * another server, whose files this server does not hold). A photo's or
 * video's details are read first and sealed with its name
 * (docs/plans/photos.md); `media` gives them instead (a copy keeps the
 * original's). Its thumbnail is queued from the plaintext still in hand.
 */
export async function uploadOne(
  folder: Folder,
  file: File,
  signal?: AbortSignal,
  progress?: (s: number, t: number) => void,
  media?: MediaMetadataV1 | null,
): Promise<UploadedFile | null> {
  if (!folder.key) throw new Error('folder is not open')
  const details = media === undefined ? await readMedia(file, signal) : (media ?? undefined)
  const location = folderLocation(folder)
  if (location.kind === 'remote') {
    await uploadRemote(folder, location.shareId, file, details, signal ?? new AbortController().signal, progress ?? (() => {}))
    return null
  }
  const uploaded = await streamUpload({
    file,
    collection: { id: folder.id, keyEpoch: folder.keyEpoch, collectionKey: folder.key },
    accessToken: freshAccessToken,
    onProgress: progress,
    signal,
    media: details,
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

  /** The folder as the server has it now (after its key rotated). */
  const reloadFolder = useCallback(
    async (folder: Folder): Promise<Folder> => {
      // A folder on another server: bring its stored share up to the new key.
      if (folder.remoteShareId) await api.post(`/drive/federation/shares/${folder.remoteShareId}/refresh`)
      await queryClient.invalidateQueries({ queryKey: foldersKey })
      const fresh = queryClient.getQueryData<FolderIndex>(foldersKey)?.byId.get(folder.id)
      if (!fresh?.key) throw new Error('the folder is no longer available')
      return fresh
    },
    [queryClient],
  )

  const uploadFiles = useCallback(
    (folder: Folder, files: File[]) => {
      uploads.add(
        files.map((file) => ({
          name: file.name,
          folderName: displayName(folder),
          total: file.size,
          run: async (signal, progress) => {
            try {
              await uploadOne(folder, file, signal, progress)
            } catch (error) {
              // Its owner removed someone meanwhile: once more, under the new key.
              if (!isFolderKeyChanged(error)) throw error
              await uploadOne(await reloadFolder(folder), file, signal, progress)
            }
          },
        })),
        settled,
        classifyUploadError,
      )
    },
    [settled, displayName, reloadFolder],
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
