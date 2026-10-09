import { useQueryClient } from '@tanstack/react-query'
import { useCallback, useMemo, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { MediaMetadataV1 } from '@kutup/crypto'
import { cachedFolderIndex, foldersKey } from '@kutup/drive-core/folders'
import { useDriveIdentity } from '@kutup/drive-core/identity'
import type { Folder } from '@kutup/drive-core/model'
import { uploadUnderFreeName } from '@kutup/drive-core/names'
import { enqueueThumbnail } from '@kutup/drive-core/thumbnailQueue'
import { storeThumbnails } from '@kutup/drive-core/thumbnails'
import { classifyUploadError, isFolderKeyChanged } from '@kutup/drive-ui/uploadError'
import { uploads } from '@kutup/drive-ui/uploadStore'
import { looksLive, mediaKindOf, pairLivePhotos, readMedia } from '@kutup/files/media'
import { thumbnailsOfImage, thumbnailsOfVideo } from '@kutup/files/thumbnails'
import type { PendingUpload } from '@kutup/files/upload/pendingUploads'
import { resumeUpload, streamUpload, type UploadedFile } from '@kutup/files/upload/streamUpload'
import api, { freshAccessToken } from '@kutup/session/client'
import { getSession, updateSession } from '@kutup/session/store'
import { duplicateKey, duplicateKeys, type Photo } from '../library/library'
import { ensureUploadFolder, useSavePreferences, type PhotosPreferences } from '../library/preferences'

/** Its thumbnails, from the plaintext still in hand, in the background. */
function thumbnailsAfterUpload(uploaded: UploadedFile, file: File) {
  enqueueThumbnail(uploaded.fileId, async () => {
    const made = mediaKindOf(file.name, file.type) === 'video' ? await thumbnailsOfVideo(file) : await thumbnailsOfImage(file)
    return storeThumbnails(
      { fileId: uploaded.fileId, fileKey: uploaded.fileKey, keyGeneration: uploaded.keyGeneration },
      made,
      'original',
    )
  })
}

/** A still in the library now: its file id and details (for its live video). */
interface Still {
  id: string
  media: MediaMetadataV1 | undefined
}

/**
 * What a still's upload came to. The queue runs one job at a time in order
 * and a still is queued before its video, so when the video runs the still
 * has finished — or was cancelled, never ran, and left this empty.
 */
class StillOutcome {
  value: Still | null = null
  settle(value: Still | null) {
    this.value = value
  }
}

/**
 * Upload photos and videos into the upload folder (docs/plans/photos.md):
 * each one's details are read first and sealed with it; one the library
 * already has (same name, same content) is skipped, as Ente does. A still and
 * a short video with one name become a live photo: the still goes first and
 * the video names it. Anything that is not a photo or a video is left out,
 * and the person is told.
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
  const added = useRef(new Map<string, string>())

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

  /**
   * One file. `still` is the upload its live photo video waits for; `done`
   * reports this file's id (a still's, for its video).
   */
  const uploadOne = useCallback(
    async (
      folder: Folder,
      file: File,
      signal: AbortSignal,
      progress: (sent: number, total: number) => void,
      still: StillOutcome | undefined,
      done: (still: Still | null) => void,
      waiting?: (waiting: boolean) => void,
    ): Promise<'skipped' | undefined> => {
      if (!folder.key) throw new Error('folder is not open')
      let media = await readMedia(file, signal)
      const key = media?.hash ? duplicateKey(file.name, media.hash) : null
      const existing = key ? (library.current.get(key) ?? added.current.get(key)) : undefined
      if (existing) {
        done({ id: existing, media })
        return 'skipped'
      }
      const paired = still?.value
      if (paired && looksLive(paired.media, media)) media = { ...(media ?? {}), liveOf: paired.id }
      let uploaded
      const owner = getSession()?.userId
      const folderKey = folder.key
      try {
        // Cameras reuse names: a different photo under a taken one is kept
        // as `name (2)` (the same photo was skipped above).
        uploaded = await uploadUnderFreeName(folder, file, (named, nameHash) =>
          streamUpload({
            file: named,
            collection: { id: folder.id, keyEpoch: folder.keyEpoch, collectionKey: folderKey },
            accessToken: freshAccessToken,
            onProgress: progress,
            onWaiting: waiting,
            signal,
            media,
            // A reload or a crash leaves it to go on with (the upload panel).
            resumable: owner ? { owner } : undefined,
            nameHash,
          }),
        )
      } catch (error) {
        done(null)
        throw error
      }
      if (key) added.current.set(key, uploaded.fileId)
      done({ id: uploaded.fileId, media })
      thumbnailsAfterUpload(uploaded, file)
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
      // Live photos: each still before its video, which waits for it.
      const pairs = pairLivePhotos(media)
      const stillOf = new Map<File, File>(pairs)
      const outcomes = new Map<File, StillOutcome>()
      for (const still of pairs.values()) outcomes.set(still, new StillOutcome())
      const ordered = [...media].sort((a, b) => Number(stillOf.has(a)) - Number(stillOf.has(b)))
      const folderName = folder.name ?? ''
      uploads.add(
        ordered.map((file) => {
          const own = outcomes.get(file)
          const pairedStill = stillOf.get(file)
          const still = pairedStill ? outcomes.get(pairedStill) : undefined
          const done = (value: Still | null) => own?.settle(value)
          return {
            name: file.name,
            folderName,
            total: file.size,
            run: async (
              signal: AbortSignal,
              progress: (sent: number, total: number) => void,
              waiting: (waiting: boolean) => void,
            ) => {
              try {
                return await uploadOne(folder, file, signal, progress, still, done, waiting)
              } catch (error) {
                // Its owner re-keyed it meanwhile: once more, under the new key.
                if (!isFolderKeyChanged(error)) {
                  done(null)
                  throw error
                }
                await queryClient.invalidateQueries({ queryKey: foldersKey })
                const fresh = cachedFolderIndex(queryClient)?.byId.get(folder.id)
                if (!fresh?.key) {
                  done(null)
                  throw error
                }
                folder = fresh
                return uploadOne(fresh, file, signal, progress, still, done, waiting).catch((again: unknown) => {
                  done(null)
                  throw again
                })
              }
            },
          }
        }),
        settled,
        classifyUploadError,
      )
    },
    [t, uploadFolder, uploadOne, queryClient, settled],
  )
}

/**
 * Go on with an upload a reload or a crash stopped (the upload panel): the
 * same file chosen again goes on from where the server stopped, then gets
 * its thumbnails as any upload does.
 */
export function useResumePhotos() {
  const queryClient = useQueryClient()
  const { t } = useTranslation()
  const settled = useCallback(() => {
    void queryClient.invalidateQueries({ queryKey: ['files'] })
    void api
      .get<{ storageUsedBytes: number; storageQuotaBytes: number }>('/user/me')
      .then(({ data }) => updateSession({ storageUsedBytes: data.storageUsedBytes, storageQuotaBytes: data.storageQuotaBytes }))
      .catch(() => {})
  }, [queryClient])
  return useCallback(
    (upload: PendingUpload, file: File, folder: Folder) => {
      uploads.add(
        [
          {
            name: file.name,
            folderName: folder.isRoot ? t('uploads.myFiles') : (folder.name ?? ''),
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
              thumbnailsAfterUpload(uploaded, file)
            },
          },
        ],
        settled,
        classifyUploadError,
      )
    },
    [settled, t],
  )
}
