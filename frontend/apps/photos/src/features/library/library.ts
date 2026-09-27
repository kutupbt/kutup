import { useQueries } from '@tanstack/react-query'
import { useMemo, useSyncExternalStore } from 'react'
import type { MediaMetadataV1 } from '@kutup/crypto'
import { mediaKindOf } from '@kutup/files/media'
import { folderFilesKey, loadFolderFiles } from '@kutup/drive-core/files'
import type { FolderIndex } from '@kutup/drive-core/folders'
import type { DriveFile, Folder } from '@kutup/drive-core/model'
import { folderTree, useFolders, usePhotosPreferences, type PhotosPreferences } from './preferences'
import { daysOf, newestFirst, type Dated } from './timeline'

// The library (docs/plans/photos.md): every photo and video in the upload
// folder and the folders added to it, with their subfolders, read the way
// Drive reads folders (the same cached queries) and sorted on the device.

export interface Photo extends Dated {
  folder: Folder
  file: DriveFile
  kind: 'image' | 'video'
  /** The photo's details: sealed with it, or read on this device for now. */
  media: MediaMetadataV1 | null
  /** Whether `takenAt` is when it was taken (false: when it was uploaded). */
  dated: boolean
  /** A live photo's video, shown with its still rather than on its own. */
  live?: Photo
}

/**
 * Live photos: a video naming a still that is in the list joins it (and
 * leaves the list); one whose still is not here stays a video.
 */
export function joinLivePhotos(items: Photo[]): Photo[] {
  const byId = new Map(items.map((p) => [p.id, p]))
  const joined = new Set<string>()
  const stills = new Map<string, Photo>()
  for (const p of items) {
    const still = p.kind === 'video' && p.media?.liveOf ? byId.get(p.media.liveOf) : undefined
    if (still && still.kind === 'image' && !stills.has(still.id)) {
      stills.set(still.id, { ...still, live: p })
      joined.add(p.id)
    }
  }
  return items.filter((p) => !joined.has(p.id)).map((p) => stills.get(p.id) ?? p)
}

/** The files a photo stands for: a live photo's still and its video. */
export function filesOf(photo: Photo): Photo[] {
  return photo.live ? [photo, photo.live] : [photo]
}

// Details read on this device for photos whose metadata this account cannot
// rewrite (shared with it to view only), kept for this tab.
const localMedia = new Map<string, MediaMetadataV1>()
const listeners = new Set<() => void>()
let version = 0

export function rememberMedia(fileId: string, media: MediaMetadataV1): void {
  localMedia.set(fileId, media)
  version++
  for (const l of listeners) l()
}

function useLocalMediaVersion(): number {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    () => version,
  )
}

/** The folders the library reads: the upload folder's tree and each added one's. */
export function libraryFolders(index: FolderIndex, preferences: PhotosPreferences): Folder[] {
  const roots = [preferences.uploadFolderId, ...preferences.libraryFolderIds].filter((id): id is string => Boolean(id))
  const seen = new Set<string>()
  const out: Folder[] = []
  for (const root of roots) {
    for (const folder of folderTree(index, root)) {
      if (seen.has(folder.id)) continue
      seen.add(folder.id)
      out.push(folder)
    }
  }
  return out
}

export function toPhoto(folder: Folder, file: DriveFile): Photo | null {
  if (!file.name || !file.fileKey) return null
  // Photos and videos only (not drawings such as SVG, which Drive calls images).
  const kind = mediaKindOf(file.name, file.mimeType)
  if (!kind) return null
  const media = file.media ?? localMedia.get(file.id) ?? null
  const taken = media?.takenAt
  return {
    id: file.id,
    folder,
    file,
    kind,
    media,
    takenAt: taken ?? Date.parse(file.createdAt),
    takenOffset: taken !== undefined ? media?.takenOffset : undefined,
    dated: taken !== undefined,
  }
}

export function useLibrary() {
  const preferences = usePhotosPreferences()
  const folders = useFolders()
  const localVersion = useLocalMediaVersion()
  const readable = useMemo(
    () => (folders.data && preferences.data ? libraryFolders(folders.data, preferences.data) : []),
    [folders.data, preferences.data],
  )
  const listings = useQueries({
    queries: readable.map((folder) => ({
      queryKey: folderFilesKey(folder),
      queryFn: () => loadFolderFiles(folder),
    })),
  })
  // Changes when any listing does; the listings themselves are new objects each render.
  const stamp = listings.map((l) => l.dataUpdatedAt).join(',')
  const photos = useMemo(() => {
    const out: Photo[] = []
    listings.forEach(({ data: files }, i) => {
      const folder = readable[i]
      if (!folder || !files) return
      for (const file of files) {
        const photo = toPhoto(folder, file)
        if (photo) out.push(photo)
      }
    })
    return newestFirst(joinLivePhotos(out))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [readable, localVersion, stamp])
  const days = useMemo(() => daysOf(photos), [photos])
  const loading = preferences.isPending || folders.isPending || listings.some((l) => l.isPending)
  const error = preferences.isError || folders.isError
  return useMemo(
    () => ({ preferences: preferences.data, index: folders.data, folders: readable, photos, days, loading, error }),
    [preferences.data, folders.data, readable, photos, days, loading, error],
  )
}

/** "name + hash" of every photo that has a hash, to its file id: how duplicates are found. */
export function duplicateKeys(photos: readonly Photo[]): Map<string, string> {
  const keys = new Map<string, string>()
  for (const p of photos) if (p.media?.hash && p.file.name) keys.set(duplicateKey(p.file.name, p.media.hash), p.id)
  return keys
}

export function duplicateKey(name: string, hash: string): string {
  return `${name.normalize('NFC').toLocaleLowerCase()}\n${hash}`
}
