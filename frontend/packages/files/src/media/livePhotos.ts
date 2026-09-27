// Live photos (docs/plans/photos.md): a still and a short video taken
// together. Phones export them as two files with one name, IMG_1234.HEIC and
// IMG_1234.MOV; they stay two Drive files, and the video names its still
// (`media.liveOf`). Pairing follows Ente's rules: the same base name
// (ignoring case and the `_3` / `_HEVC` suffixes some exports add), one
// still and one video, and, once their details are read, a short video
// taken within a day of the still.

const STILL = new Set(['heic', 'heif', 'jpg', 'jpeg'])
const MOTION = new Set(['mov', 'mp4'])
/** Live photo videos are about three seconds. */
export const MAX_LIVE_VIDEO_MS = 6_000
const MAX_APART_MS = 24 * 3600 * 1000

function split(name: string): { base: string; ext: string } {
  const dot = name.lastIndexOf('.')
  return dot > 0 ? { base: name.slice(0, dot).toLowerCase(), ext: name.slice(dot + 1).toLowerCase() } : { base: name.toLowerCase(), ext: '' }
}

/** Candidate pairs among files uploaded together: video → its still. */
export function pairLivePhotos<T extends { name: string }>(files: readonly T[]): Map<T, T> {
  const groups = new Map<string, { stills: T[]; videos: T[] }>()
  for (const file of files) {
    const { base, ext } = split(file.name)
    const key = MOTION.has(ext) ? base.replace(/_(3|hevc)$/, '') : base
    const group = groups.get(key) ?? { stills: [], videos: [] }
    if (STILL.has(ext)) group.stills.push(file)
    else if (MOTION.has(ext)) group.videos.push(file)
    else continue
    groups.set(key, group)
  }
  const pairs = new Map<T, T>()
  for (const { stills, videos } of groups.values()) {
    if (stills.length === 1 && videos.length === 1) pairs.set(videos[0]!, stills[0]!)
  }
  return pairs
}

/** Whether their details fit a live photo (unknown details do not rule it out). */
export function looksLive(
  still: { takenAt?: number } | undefined,
  video: { takenAt?: number; durationMs?: number } | undefined,
): boolean {
  if (video?.durationMs !== undefined && video.durationMs > MAX_LIVE_VIDEO_MS) return false
  if (still?.takenAt !== undefined && video?.takenAt !== undefined && Math.abs(still.takenAt - video.takenAt) > MAX_APART_MS) return false
  return true
}
