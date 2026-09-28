import {
  openThumbnailV1,
  sealThumbnailV1,
  thumbnailMimeType,
  type ThumbnailVariant,
} from '@kutup/crypto/thumbnail'
import api from '@kutup/session/client'
import { fileKeyAt } from './keyring'
import type { DriveFile } from './model'
import type { MadeThumbnails } from '@kutup/files/thumbnails'

/** What a thumbnail is sealed to: the file and its current key. */
export interface ThumbnailTarget {
  fileId: string
  fileKey: Uint8Array
  keyGeneration: number
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
      generation: target.keyGeneration,
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

/** Remove the file's thumbnails (its content no longer has a picture). */
export async function removeThumbnails(fileId: string): Promise<boolean> {
  await api.delete(`/files/${fileId}/thumbnails`)
  return true
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
export function thumbnailUrl(
  file: DriveFile,
  variant: ThumbnailVariant,
  /** Where the sealed thumbnail is read, under the API base (a public link's route). */
  path = `/files/${file.id}/thumbnails/${variant}`,
): Promise<string | null> {
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
  // Sealed under the key generation it was drawn at (a file re-keyed since keeps it).
  const generation =
    (variant === 'sm' ? file.thumbnails.smKeyGeneration : file.thumbnails.lgKeyGeneration) ?? file.keyGeneration
  const loading = (async () => {
    try {
      const fileKey = await fileKeyAt(file, generation)
      const { data } = await api.get<ArrayBuffer>(
        `${path}?${new URLSearchParams({ v: stamp }).toString()}`,
        { responseType: 'arraybuffer' },
      )
      const opened = await openThumbnailV1(new Uint8Array(data), fileKey, {
        fileId: file.id,
        generation,
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
