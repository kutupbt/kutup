// Playing a video or a song from Kutup's block format
// (docs/plans/drive-block-format.md §4), whoever reads it: Drive's file
// page and Quick Look, Photos, public links, Chat. Streamed through the
// service worker where one controls the page, so a seek fetches one block
// and memory doesn't grow with the file; without one, the whole object into
// a Blob, up to `drive.stream.blob_fallback_max_bytes`.

import { streamingAvailable, TooManyStreams, type PlayerStream } from './page'
import type { StreamLimits } from './limits'

export type Playback =
  /** A `/sw/stream/…` URL, or a Blob's URL; `close` ends it. */
  | { kind: 'ready'; src: string; streamed: boolean; close: () => void }
  /** No service worker, and larger than the site lets a tab hold in memory. */
  | { kind: 'tooLarge' }
  /** This tab plays `drive.stream.max_concurrent` streams already. */
  | { kind: 'busy' }

export interface MediaPlaybackSource {
  /** The plaintext size. */
  size: number
  mimeType: string
  /** The limits that apply: the account's, or the defaults on a page without a session. */
  limits: () => Promise<StreamLimits>
  /** A stream of it for a player (a service worker controls the page). */
  stream: (limits: StreamLimits, signal?: AbortSignal) => Promise<PlayerStream>
  /** All of it, for a page no service worker controls. */
  readWhole: (signal?: AbortSignal, onProgress?: (read: number) => void) => Promise<Blob | Uint8Array>
}

/** Opens `source` for a player: streamed where it can be. */
export async function openMediaPlayback(
  source: MediaPlaybackSource,
  signal?: AbortSignal,
  onProgress?: (read: number) => void,
): Promise<Playback> {
  const limits = await source.limits()
  if (limits.maxBytes > 0 && source.size <= limits.maxBytes && (await streamingAvailable())) {
    signal?.throwIfAborted()
    try {
      const stream = await source.stream(limits, signal)
      return { kind: 'ready', src: stream.src, streamed: true, close: stream.close }
    } catch (error) {
      if (error instanceof TooManyStreams) return { kind: 'busy' }
      throw error
    }
  }
  if (source.size > limits.blobFallbackMaxBytes) return { kind: 'tooLarge' }
  const whole = await source.readWhole(signal, onProgress)
  const blob = whole instanceof Blob ? whole : new Blob([whole as BlobPart], { type: source.mimeType })
  const src = URL.createObjectURL(blob.type === source.mimeType ? blob : new Blob([blob], { type: source.mimeType }))
  return { kind: 'ready', src, streamed: false, close: () => URL.revokeObjectURL(src) }
}
