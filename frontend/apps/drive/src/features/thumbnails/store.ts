import {
  openThumbnailV1,
  sealThumbnailV1,
  thumbnailMimeType,
  type ThumbnailVariant,
} from '@kutup/crypto/thumbnail'
import api from '@kutup/session/client'
import { fileKeyAt } from '../drive/keyring'
import type { DriveFile, Folder } from '../drive/model'
import type { MadeThumbnails } from './make'

/** What a thumbnail is sealed to: the file and its key. */
export interface ThumbnailTarget {
  fileId: string
  fileKey: Uint8Array
  keyEpoch: number
}

/**
 * Seal and store each thumbnail made for a file, replacing what was there.
 * `source` is the version it was drawn from, or `original` for the upload;
 * the listing compares it with the latest version to spot stale ones.
 */
export async function storeThumbnails(
  target: ThumbnailTarget,
  made: MadeThumbnails,
  source: string,
): Promise<boolean> {
  let stored = false
  for (const variant of ['sm', 'lg'] as const) {
    const image = made[variant]
    if (!image) continue
    const envelope = await sealThumbnailV1(image, target.fileKey, {
      fileId: target.fileId,
      epoch: target.keyEpoch,
      variant,
    })
    await api.put(
      `/files/${target.fileId}/thumbnails/${variant}?${new URLSearchParams({ source }).toString()}`,
      envelope,
      { headers: { 'Content-Type': 'application/octet-stream' } },
    )
    stored = true
  }
  return stored
}

// Decrypted thumbnails, as blob: URLs, for this tab only. Keyed by the
// stored version, so a replaced thumbnail is a new entry; the oldest are
// released past the limit (a grid shows at most a few hundred at once).
const LIMIT = 400
const cache = new Map<string, Promise<string | null>>()

function remember(key: string, value: Promise<string | null>): void {
  cache.set(key, value)
  while (cache.size > LIMIT) {
    const [oldest, url] = cache.entries().next().value as [string, Promise<string | null>]
    cache.delete(oldest)
    void url.then((u) => u && URL.revokeObjectURL(u))
  }
}

/** The file's thumbnail as a displayable URL, or null (none, or unreadable). */
export function thumbnailUrl(folder: Folder, file: DriveFile, variant: ThumbnailVariant): Promise<string | null> {
  const stamp = file.thumbnails[variant]
  if (!stamp || !file.fileKey) return Promise.resolve(null)
  const key = `${file.id}:${variant}:${stamp}`
  const hit = cache.get(key)
  if (hit) {
    // Most recently used goes to the back.
    cache.delete(key)
    cache.set(key, hit)
    return hit
  }
  // Sealed at the epoch it was drawn at (a file re-keyed since keeps it).
  const epoch = (variant === 'sm' ? file.thumbnails.smKeyEpoch : file.thumbnails.lgKeyEpoch) ?? file.keyEpoch
  const loading = (async () => {
    try {
      const fileKey = await fileKeyAt(folder, file, epoch)
      const { data } = await api.get<ArrayBuffer>(
        `/files/${file.id}/thumbnails/${variant}?${new URLSearchParams({ v: stamp }).toString()}`,
        { responseType: 'arraybuffer' },
      )
      const opened = await openThumbnailV1(new Uint8Array(data), fileKey, {
        fileId: file.id,
        epoch,
        variant,
      })
      return URL.createObjectURL(new Blob([opened.image as BlobPart], { type: thumbnailMimeType(opened.format) }))
    } catch {
      // A missing, corrupt or swapped thumbnail shows the kind icon instead.
      return null
    }
  })()
  remember(key, loading)
  return loading
}
