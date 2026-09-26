import { useQueryClient } from '@tanstack/react-query'
import { useCallback, useMemo, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { cachedFolderIndex, foldersKey } from '@kutup/drive-core/folders'
import { useDriveIdentity } from '@kutup/drive-core/identity'
import type { Folder } from '@kutup/drive-core/model'
import { enqueueThumbnail } from '@kutup/drive-core/thumbnailQueue'
import { storeThumbnails } from '@kutup/drive-core/thumbnails'
import { classifyUploadError, isFolderKeyChanged } from '@kutup/drive-ui/uploadError'
import { uploads } from '@kutup/drive-ui/uploadStore'
import { mediaKindOf, readMedia } from '@kutup/files/media'
import { thumbnailsOfImage, thumbnailsOfVideo } from '@kutup/files/thumbnails'
import { streamUpload } from '@kutup/files/upload/streamUpload'
import api, { freshAccessToken } from '@kutup/session/client'
import { updateSession } from '@kutup/session/store'
import { duplicateKey, duplicateKeys, type Photo } from '../library/library'
import { ensureUploadFolder, useSavePreferences, type PhotosPreferences } from '../library/preferences'

/**
 * Upload photos and videos into the upload folder (docs/plans/photos.md):
 * each one's details are read first and sealed with it; one the library
 * already has (same name, same content) is skipped, as Ente does. Anything
 * that is not a photo or a video is left out, and the person is told.
 */
export function useUploadPhotos(photos: readonly Photo[], preferences: PhotosPreferences | undefined) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const identity = useDriveIdentity()
  const save = useSavePreferences()
  // Read when a job runs: the library as listed, and what this tab added
  // since (a batch holding the same photo twice uploads it once).
  const libraryKeys = useMemo(() => duplicateKeys(photos), [photos])
  const library = useRef(libraryKeys)
  library.current = libraryKeys
  const added = useRef(new Set<string>())

  const settled = useCallback(() => {
    void queryClient.invalidateQueries({ queryKey: ['files'] })
    void api
      .get<{ storageUsedBytes: number; storageQuotaBytes: number }>('/user/me')
      .then(({ data }) => updateSession({ storageUsedBytes: data.storageUsedBytes, storageQuotaBytes: data.storageQuotaBytes }))
      .catch(() => {})
  }, [queryClient])

  const uploadFolder = useCallback(async (): Promise<Folder> => {
    const me = identity.data
    if (!me || !preferences) throw new Error('the library is not ready')
    const index = cachedFolderIndex(queryClient)
    if (!index) throw new Error('the library is not ready')
    const id = await ensureUploadFolder(index, preferences, me, (next) => save.mutateAsync(next))
    let folder = index.byId.get(id)
    if (!folder) {
      await queryClient.invalidateQueries({ queryKey: foldersKey })
      folder = cachedFolderIndex(queryClient)?.byId.get(id)
    }
    if (!folder?.key) throw new Error('the upload folder is not available')
    return folder
  }, [identity.data, preferences, queryClient, save])

  const uploadOne = useCallback(
    async (folder: Folder, file: File, signal: AbortSignal, progress: (sent: number, total: number) => void) => {
      if (!folder.key) throw new Error('folder is not open')
      const media = await readMedia(file, signal)
      const key = media?.hash ? duplicateKey(file.name, media.hash) : null
      if (key) {
        if (library.current.has(key) || added.current.has(key)) return 'skipped' as const
        added.current.add(key)
      }
      let uploaded
      try {
        uploaded = await streamUpload({
          file,
          collection: { id: folder.id, keyEpoch: folder.keyEpoch, collectionKey: folder.key },
          accessToken: freshAccessToken,
          onProgress: progress,
          signal,
          media,
        })
      } catch (error) {
        // Not uploaded after all: trying again is not a duplicate.
        if (key) added.current.delete(key)
        throw error
      }
      // Its thumbnails, from the plaintext still in hand, in the background.
      enqueueThumbnail(uploaded.fileId, async () => {
        const made = mediaKindOf(file.name, file.type) === 'video' ? await thumbnailsOfVideo(file) : await thumbnailsOfImage(file)
        return storeThumbnails(
          { fileId: uploaded.fileId, fileKey: uploaded.fileKey, keyGeneration: uploaded.keyGeneration },
          made,
          'original',
        )
      })
      return undefined
    },
    [],
  )

  return useCallback(
    async (files: File[]) => {
      const media = files.filter((f) => mediaKindOf(f.name, f.type))
      const left = files.length - media.length
      if (left > 0) toast.info(t('upload.notMedia', { count: left }))
      if (media.length === 0) return
      let folder: Folder
      try {
        folder = await uploadFolder()
      } catch {
        toast.error(t('upload.noFolder'))
        return
      }
      const folderName = folder.name ?? ''
      uploads.add(
        media.map((file) => ({
          name: file.name,
          folderName,
          total: file.size,
          run: async (signal, progress) => {
            try {
              return await uploadOne(folder, file, signal, progress)
            } catch (error) {
              // Its owner re-keyed it meanwhile: once more, under the new key.
              if (!isFolderKeyChanged(error)) throw error
              await queryClient.invalidateQueries({ queryKey: foldersKey })
              const fresh = cachedFolderIndex(queryClient)?.byId.get(folder.id)
              if (!fresh?.key) throw error
              folder = fresh
              return uploadOne(fresh, file, signal, progress)
            }
          },
        })),
        settled,
        classifyUploadError,
      )
    },
    [t, uploadFolder, uploadOne, queryClient, settled],
  )
}
