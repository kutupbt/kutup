import { useEffect } from 'react'
import { renameFileRecordV1, type MediaMetadataV1 } from '@kutup/crypto'
import { fileMetadataOf, type DriveFile, type Folder } from '@kutup/drive-core/model'
import { readOriginal } from '@kutup/drive-core/original'
import { enqueueThumbnail, thumbnailInHand, thumbnailWaiting } from '@kutup/drive-core/thumbnailQueue'
import { storeThumbnails } from '@kutup/drive-core/thumbnails'
import { readMedia } from '@kutup/files/media'
import { thumbnailsOfImage, thumbnailsOfVideo } from '@kutup/files/thumbnails'
import api from '@kutup/session/client'
import { rememberMedia, type Photo } from './library'

// Photos from before Photos existed, or uploaded elsewhere, lack their
// details (when, where, a hash) and sometimes a thumbnail. One download fills
// in both, in the background, one file at a time (the queue Drive's
// thumbnails use), never on a data-saving connection (docs/plans/photos.md).

/** Larger files are left with their upload date: reading them costs too much. */
const MAX_BYTES = 512 * 1024 * 1024
/** Each file is tried once per tab. */
const tried = new Set<string>()

/**
 * Whether this account may rewrite the file's metadata and pictures: a file
 * in a folder here, under the folder's current key, that it manages or
 * uploaded. Others' photos it may only view are read for this tab only
 * (writing would also charge its storage for someone else's files).
 */
export function mayWrite(folder: Folder, file: DriveFile, userId: string): boolean {
  if (folder.source === 'remote' || folder.source === 'file') return false
  if (file.keyEpoch !== folder.keyEpoch) return false
  return folder.canManage || file.uploaderUserId === userId
}

/** Seal the details as a new metadata revision, name and all unchanged. */
export async function writeMedia(file: DriveFile, media: MediaMetadataV1): Promise<void> {
  if (!file.fileKey) throw new Error('file is not open')
  const next = await renameFileRecordV1(
    { id: file.id, keyGeneration: file.keyGeneration, metadataRevision: file.metadataRevision },
    file.fileKey,
    fileMetadataOf(file, { media }),
  )
  await api.put(`/files/${file.id}`, next)
}

function saveData(): boolean {
  return Boolean((navigator as Navigator & { connection?: { saveData?: boolean } }).connection?.saveData)
}

function needs(photo: Photo, userId: string): { media: boolean; thumbnail: boolean } {
  const write = mayWrite(photo.folder, photo.file, userId)
  return {
    media: !photo.media,
    thumbnail: write && (!photo.file.thumbnails.sm || photo.file.thumbnailStale),
  }
}

/** Queue the catch-up for one photo; `first` when it is on screen now. */
export function catchUp(photo: Photo, userId: string, first = false): void {
  const { folder, file } = photo
  const want = needs(photo, userId)
  if (!want.media && !want.thumbnail) return
  if (file.size > MAX_BYTES || saveData()) return
  const attempt = `${file.id}:${file.metadataRevision}:${file.thumbnails.sm ?? ''}`
  // Tried already: only moved ahead while it still waits, never retried.
  if (tried.has(attempt) && !(first && thumbnailWaiting(file.id))) return
  // Being drawn now, or just drawn (the listing may not show it yet).
  if (thumbnailInHand(file.id) && !thumbnailWaiting(file.id)) return
  tried.add(attempt)
  const name = file.name!
  enqueueThumbnail(
    file.id,
    async () => {
      const blob = await readOriginal(folder, file)
      // Its own date is not known here: no "file date" fallback (0).
      const plain = new File([blob], name, { type: file.mimeType, lastModified: 0 })
      let stored = false
      if (want.media) {
        const media = await readMedia(plain)
        if (media) {
          if (mayWrite(folder, file, userId)) {
            try {
              await writeMedia(file, media)
              stored = true
            } catch {
              rememberMedia(file.id, media)
            }
          } else {
            rememberMedia(file.id, media)
          }
        }
      }
      if (want.thumbnail && file.fileKey) {
        const made = photo.kind === 'image' ? await thumbnailsOfImage(plain) : await thumbnailsOfVideo(plain)
        const drawn = await storeThumbnails(
          { fileId: file.id, fileKey: file.fileKey, keyGeneration: file.keyGeneration },
          made,
          'original',
        )
        stored = drawn || stored
      }
      return stored
    },
    first,
  )
}

/** Works through the library in the background, newest uploads first. */
export function useLibraryCatchUp(photos: readonly Photo[], userId: string, enabled: boolean): void {
  useEffect(() => {
    if (!enabled) return
    const pending = photos
      .filter((p) => {
        const want = needs(p, userId)
        return want.media || want.thumbnail
      })
      .sort((a, b) => b.file.createdAt.localeCompare(a.file.createdAt))
    for (const photo of pending) catchUp(photo, userId)
  }, [photos, userId, enabled])
}
