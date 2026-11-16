// Playing a video or a song from Kutup's block format
// (docs/plans/drive-block-format.md §4), whoever reads it: Drive's file
// page and Quick Look, Photos, public links, Chat. Streamed through the
// service worker where one controls the page, so a seek fetches one block
// and memory doesn't grow with the file; without one, the whole object into
// a Blob, up to `drive.stream.blob_fallback_max_bytes`. A stream that fails
// before it plays falls back the same way.

import { streamingAvailable, TooManyStreams, type PlayerStream } from './page'
import type { StreamLimits } from './limits'
import { streamMediaType } from '../blockReader/protocol'

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

/** What a streamed playback becomes when its stream fails before it plays. */
export type PlaybackFallback = Playback | { kind: 'failed' }

/** What a player hears about a stream: the worker refused it, the element failed, or a frame showed. */
export type StreamEvent = 'refused' | 'mediaError' | 'firstFrame'

export interface StreamWatchState {
  /** A frame (or a song's first data) showed: the stream works. */
  played: boolean
  /** It fell back already. */
  fellBack: boolean
}

/**
 * Whether a stream falls back to a whole download (docs/plans/drive-block-format.md
 * §4): only before it has played, when the worker refused a request for it
 * (some WebKit builds give a media element an empty `destination`) or the
 * element failed; then only within `drive.stream.blob_fallback_max_bytes`.
 */
export function streamFallbackDecision(
  state: StreamWatchState,
  event: StreamEvent,
  size: number,
  limits: Pick<StreamLimits, 'blobFallbackMaxBytes'>,
): 'keep' | 'fallBack' | 'tooLarge' {
  if (state.played || state.fellBack || event === 'firstFrame') return 'keep'
  return size <= limits.blobFallbackMaxBytes ? 'fallBack' : 'tooLarge'
}

/** Whether `element` plays `src` (a path such as `/sw/stream/…`). */
function plays(element: EventTarget | null, src: string): boolean {
  let url: string | null = null
  if (typeof HTMLMediaElement !== 'undefined' && element instanceof HTMLMediaElement) url = element.currentSrc || element.getAttribute('src')
  else if (typeof HTMLSourceElement !== 'undefined' && element instanceof HTMLSourceElement) url = element.getAttribute('src')
  if (!url) return false
  try {
    const at = new URL(url, window.location.href)
    return at.origin === window.location.origin && at.pathname === src
  } catch {
    return false
  }
}

/**
 * Hears the media elements on this page that play `src`: their `error` and
 * `loadeddata` (the first frame), caught on the way down, as they don't
 * bubble. Returns the removal.
 */
export function watchMediaElements(src: string, onEvent: (event: StreamEvent) => void): () => void {
  if (typeof document === 'undefined') return () => {}
  const failed = (event: Event) => {
    if (plays(event.target, src)) onEvent('mediaError')
  }
  const loaded = (event: Event) => {
    if (plays(event.target, src)) onEvent('firstFrame')
  }
  document.addEventListener('error', failed, true)
  document.addEventListener('loadeddata', loaded, true)
  return () => {
    document.removeEventListener('error', failed, true)
    document.removeEventListener('loadeddata', loaded, true)
  }
}

/** All of `source` in a Blob, for a player. */
async function openWhole(source: MediaPlaybackSource, signal?: AbortSignal, onProgress?: (read: number) => void): Promise<Playback> {
  const whole = await source.readWhole(signal, onProgress)
  // The service worker's allowlist: a `blob:` URL of this origin is never a document.
  const type = streamMediaType(source.mimeType)
  const blob = whole instanceof Blob ? whole : new Blob([whole as BlobPart], { type })
  const src = URL.createObjectURL(blob.type === type ? blob : new Blob([blob], { type }))
  return { kind: 'ready', src, streamed: false, close: () => URL.revokeObjectURL(src) }
}

/**
 * A stream that falls back to a whole download when it fails before it
 * plays (`streamFallbackDecision`), handing `onFallback` what replaces it.
 * Its `close` ends the stream, the download and what replaced it.
 */
function watchedStream(
  source: MediaPlaybackSource,
  limits: StreamLimits,
  stream: PlayerStream,
  onFallback: (next: PlaybackFallback) => void,
  signal?: AbortSignal,
  onProgress?: (read: number) => void,
): Playback {
  const state: StreamWatchState = { played: false, fellBack: false }
  const controller = new AbortController()
  const stopOuter = () => controller.abort()
  signal?.addEventListener('abort', stopOuter, { once: true })
  let replacement: Playback | null = null
  const unwatch: Array<() => void> = []
  const stopWatching = () => {
    for (const stop of unwatch.splice(0)) stop()
  }
  const happened = (event: StreamEvent) => {
    const decision = streamFallbackDecision(state, event, source.size, limits)
    if (event === 'firstFrame') state.played = true
    if (decision === 'keep' || controller.signal.aborted) return
    state.fellBack = true
    stopWatching()
    stream.close()
    if (decision === 'tooLarge') {
      onFallback({ kind: 'tooLarge' })
      return
    }
    openWhole(source, controller.signal, onProgress).then(
      (whole) => {
        if (controller.signal.aborted) {
          if (whole.kind === 'ready') whole.close()
          return
        }
        replacement = whole
        onFallback(whole)
      },
      () => {
        if (!controller.signal.aborted) onFallback({ kind: 'failed' })
      },
    )
  }
  unwatch.push(watchMediaElements(stream.src, happened))
  unwatch.push(stream.onRefused(() => happened('refused')))
  const close = () => {
    controller.abort()
    signal?.removeEventListener('abort', stopOuter)
    stopWatching()
    stream.close()
    if (replacement?.kind === 'ready') replacement.close()
  }
  return { kind: 'ready', src: stream.src, streamed: true, close }
}

/**
 * Opens `source` for a player: streamed where it can be. With `onFallback`,
 * a stream that fails before its first frame (the worker refused it, or the
 * element failed) is replaced by a whole download, which `onFallback` gets.
 */
export async function openMediaPlayback(
  source: MediaPlaybackSource,
  signal?: AbortSignal,
  onProgress?: (read: number) => void,
  onFallback?: (next: PlaybackFallback) => void,
): Promise<Playback> {
  const limits = await source.limits()
  if (limits.maxBytes > 0 && source.size <= limits.maxBytes && (await streamingAvailable())) {
    signal?.throwIfAborted()
    let stream: PlayerStream
    try {
      stream = await source.stream(limits, signal)
    } catch (error) {
      if (error instanceof TooManyStreams) return { kind: 'busy' }
      throw error
    }
    if (onFallback) return watchedStream(source, limits, stream, onFallback, signal, onProgress)
    return { kind: 'ready', src: stream.src, streamed: true, close: stream.close }
  }
  if (source.size > limits.blobFallbackMaxBytes) return { kind: 'tooLarge' }
  return openWhole(source, signal, onProgress)
}
