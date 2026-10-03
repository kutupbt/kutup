// A photo's or video's details, read on the device before it is uploaded
// (docs/plans/photos.md). They are sealed in the file's metadata under its
// key; the server never sees them.

import type { MediaMetadataV1 } from '@kutup/crypto/fileRecord'
import { hashBlob } from '@kutup/crypto/contentHash'
import { dateFromFileName } from './dates'
import { readImageFacts, type ImageFacts } from './exif'
import { readVideoFacts, type VideoFacts } from './mp4'

export { dateFromFileName, parseCameraDate } from './dates'
export { looksLive, pairLivePhotos } from './livePhotos'

const IMAGE_EXTENSIONS = new Set([
  'jpg', 'jpeg', 'jpe', 'jfif', 'png', 'gif', 'webp', 'heic', 'heif', 'avif', 'tif', 'tiff', 'bmp',
  'dng', 'cr2', 'cr3', 'nef', 'nrw', 'arw', 'raf', 'orf', 'rw2', 'pef', 'srw',
])
const VIDEO_EXTENSIONS = new Set(['mp4', 'm4v', 'mov', 'qt', '3gp', '3g2', 'webm', 'mkv', 'avi'])
/** Containers the box reader understands. */
const ISO_BMFF = new Set(['mp4', 'm4v', 'mov', 'qt', '3gp', '3g2'])

export type MediaKind = 'image' | 'video'

function extension(name: string): string {
  const dot = name.lastIndexOf('.')
  return dot < 0 ? '' : name.slice(dot + 1).toLowerCase()
}

/** Whether a file is a photo or a video, by its type or name. */
export function mediaKindOf(name: string, mimeType?: string): MediaKind | null {
  const ext = extension(name)
  if (mimeType?.startsWith('image/') && mimeType !== 'image/svg+xml') return 'image'
  if (mimeType?.startsWith('video/')) return 'video'
  if (IMAGE_EXTENSIONS.has(ext)) return 'image'
  if (VIDEO_EXTENSIONS.has(ext)) return 'video'
  return null
}

/** Only values the format accepts, so reading never fails an upload. */
function clean(media: MediaMetadataV1): MediaMetadataV1 | undefined {
  const out: MediaMetadataV1 = {}
  if (media.takenAt !== undefined && media.takenFrom && Number.isSafeInteger(media.takenAt)
    && media.takenAt >= Date.UTC(1800, 0, 1) && media.takenAt < Date.UTC(2200, 0, 1)) {
    out.takenAt = media.takenAt
    out.takenFrom = media.takenFrom
    if (media.takenOffset !== undefined && Number.isInteger(media.takenOffset) && Math.abs(media.takenOffset) <= 840) {
      out.takenOffset = media.takenOffset
    }
  }
  if (media.lat !== undefined && media.lon !== undefined && Number.isFinite(media.lat) && Number.isFinite(media.lon)
    && Math.abs(media.lat) <= 90 && Math.abs(media.lon) <= 180 && !(media.lat === 0 && media.lon === 0)) {
    out.lat = media.lat
    out.lon = media.lon
  }
  const dim = (v: number | undefined) => v !== undefined && Number.isInteger(v) && v >= 1 && v <= 1_000_000
  if (dim(media.width) && dim(media.height)) {
    out.width = media.width
    out.height = media.height
  }
  if (media.durationMs !== undefined && Number.isInteger(media.durationMs) && media.durationMs >= 0
    && media.durationMs <= 10 * 24 * 3600 * 1000) {
    out.durationMs = media.durationMs
  }
  if (media.camera?.trim()) out.camera = [...media.camera.trim()].slice(0, 100).join('')
  if (media.hash) out.hash = media.hash
  if (media.caption) out.caption = [...media.caption].slice(0, 2000).join('')
  if (media.liveOf && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(media.liveOf)) out.liveOf = media.liveOf
  return Object.keys(out).length ? out : undefined
}

/**
 * The details of a photo or video: when (the file's own tags, else a date in
 * its name, else its modification date), where, its size and length, and a
 * content hash for finding duplicates. Undefined for other files. Tags that
 * cannot be read are skipped; only a failed read of the content throws.
 */
export async function readMedia(file: File, signal?: AbortSignal): Promise<MediaMetadataV1 | undefined> {
  const kind = mediaKindOf(file.name, file.type)
  if (!kind) return undefined
  let facts: ImageFacts & VideoFacts = {}
  try {
    if (kind === 'image') facts = await readImageFacts(file)
    else if (ISO_BMFF.has(extension(file.name)) || file.type === 'video/mp4' || file.type === 'video/quicktime') {
      facts = await readVideoFacts(file)
    }
  } catch {
    facts = {}
  }
  const media: MediaMetadataV1 = {
    lat: facts.lat,
    lon: facts.lon,
    width: facts.width,
    height: facts.height,
    durationMs: facts.durationMs,
    camera: facts.camera,
  }
  if (facts.taken) {
    media.takenAt = facts.taken.takenAt
    media.takenOffset = facts.taken.takenOffset
    media.takenFrom = kind === 'image' ? 'exif' : 'video'
  } else {
    const named = dateFromFileName(file.name)
    if (named !== undefined) {
      media.takenAt = named
      media.takenFrom = 'filename'
    } else if (file.lastModified > 0) {
      media.takenAt = file.lastModified
      media.takenFrom = 'file'
    }
  }
  media.hash = await hashBlob(file, signal)
  return clean(media)
}
