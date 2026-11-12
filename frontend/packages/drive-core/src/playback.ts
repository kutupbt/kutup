// Playing a Drive file's video or audio (docs/plans/drive-block-format.md
// §4): streamed through Kutup's service worker from the block reader, so a
// seek fetches one block and memory doesn't grow with the file; without a
// service worker, the whole file into a Blob, up to
// `drive.stream.blob_fallback_max_bytes`. Photos' viewer and Drive's Quick
// Look both play this way.

import { useEffect, useState } from 'react'
import { driveStreamLimits } from '@kutup/files/stream/limits'
import { openPlayerStream, streamingAvailable, TooManyStreams } from '@kutup/files/stream/page'
import { resolveApiBase } from '@kutup/session/apiBase'
import { freshAccessToken } from '@kutup/session/client'
import { currentContentOf } from './keyring'
import { contentPath, fileLocation, type DriveFile, type Folder } from './model'
import { readOriginal } from './original'

export type Playback =
  /** A `/sw/stream/…` URL, or a Blob's URL; `close` ends it. */
  | { kind: 'ready'; src: string; streamed: boolean; close: () => void }
  /** No service worker, and larger than the site lets a tab hold in memory. */
  | { kind: 'tooLarge' }
  /** This tab plays `drive.stream.max_concurrent` streams already. */
  | { kind: 'busy' }

type PlaybackFolder = Pick<Folder, 'id' | 'source' | 'remoteShareId' | 'remoteFileShareId'>

/** Opens the file's current content for a player: streamed where it can be. */
export async function openPlayback(
  folder: PlaybackFolder,
  file: DriveFile,
  signal?: AbortSignal,
  onProgress?: (read: number) => void,
): Promise<Playback> {
  if (!file.fileKey) throw new Error('file is not open')
  const limits = await driveStreamLimits()
  const mimeType = file.mimeType || 'application/octet-stream'
  if (limits.maxBytes > 0 && file.size <= limits.maxBytes && (await streamingAvailable())) {
    signal?.throwIfAborted()
    const current = await currentContentOf(file)
    try {
      const stream = await openPlayerStream({
        url: `${await resolveApiBase()}${contentPath(fileLocation(folder), file.id)}`,
        fileKey: current.fileKey,
        expected: current.expected,
        accessToken: freshAccessToken,
        mimeType,
        limits,
        signal,
      })
      return { kind: 'ready', src: stream.src, streamed: true, close: stream.close }
    } catch (error) {
      if (error instanceof TooManyStreams) return { kind: 'busy' }
      throw error
    }
  }
  if (file.size > limits.blobFallbackMaxBytes) return { kind: 'tooLarge' }
  const blob = await readOriginal(folder, file, signal, onProgress)
  const src = URL.createObjectURL(new Blob([blob], { type: mimeType }))
  return { kind: 'ready', src, streamed: false, close: () => URL.revokeObjectURL(src) }
}

export type PlaybackState = { kind: 'loading'; read: number } | Playback | { kind: 'failed' }

/** A file's playback while `enabled`, closed when the file changes or the component goes. */
export function usePlayback(folder: PlaybackFolder, file: DriveFile, enabled = true): PlaybackState {
  const [state, setState] = useState<PlaybackState>({ kind: 'loading', read: 0 })
  useEffect(() => {
    if (!enabled) return
    const controller = new AbortController()
    let opened: Playback | null = null
    let alive = true
    setState({ kind: 'loading', read: 0 })
    openPlayback(folder, file, controller.signal, (read) => alive && setState({ kind: 'loading', read })).then(
      (playback) => {
        opened = playback
        if (!alive) {
          if (playback.kind === 'ready') playback.close()
          return
        }
        setState(playback)
      },
      () => alive && setState({ kind: 'failed' }),
    )
    return () => {
      alive = false
      controller.abort()
      if (opened?.kind === 'ready') opened.close()
    }
    // A file is played by its id and the content it has now.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [file.id, file.content?.revisionId, file.contentKeyGeneration, enabled])
  return state
}
