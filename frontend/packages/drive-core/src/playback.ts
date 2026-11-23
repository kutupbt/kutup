// Playing a Drive file's video or audio (docs/plans/drive-block-format.md
// §4): streamed through Kutup's service worker from the block reader, so a
// seek fetches one block and memory doesn't grow with the file; without a
// service worker, the whole file into a Blob, up to
// `drive.stream.blob_fallback_max_bytes`. Drive's file page and Quick Look,
// Photos' viewer and the public links' players all play this way.

import { useEffect, useState } from 'react'
import { driveStreamLimits } from '@kutup/files/stream/limits'
import { openPlayerStream } from '@kutup/files/stream/page'
import type { DriveObjectToOpen } from '@kutup/crypto/driveBlocks'
import { openMediaPlayback, type Playback, type PlaybackFallback } from '@kutup/files/stream/playback'
import { resolveApiBase } from '@kutup/session/apiBase'
import { freshAccessToken } from '@kutup/session/client'
import { currentContentOf } from './keyring'
import { contentPath, fileLocation, type DriveFile, type Folder } from './model'
import { readOriginal } from './original'

export type { Playback, PlaybackFallback } from '@kutup/files/stream/playback'

type PlaybackFolder = Pick<Folder, 'id' | 'source' | 'remoteShareId' | 'remoteFileShareId'>

/**
 * Opens the file's current content for a player: streamed where it can be.
 * A stream that fails before it plays is replaced by a whole download,
 * handed to `onFallback`.
 */
export async function openPlayback(
  folder: PlaybackFolder,
  file: DriveFile,
  signal?: AbortSignal,
  onProgress?: (read: number) => void,
  onFallback?: (next: PlaybackFallback) => void,
): Promise<Playback> {
  if (!file.fileKey) throw new Error('file is not open')
  const mimeType = file.mimeType || 'application/octet-stream'
  return openMediaPlayback(
    {
      size: file.size,
      mimeType,
      limits: () => driveStreamLimits(),
      stream: async (limits, streamSignal) => {
        const current = await currentContentOf(file)
        return openPlayerStream({
          source: {
            family: 'drive',
            url: `${await resolveApiBase()}${contentPath(fileLocation(folder), file.id)}`,
            fileKey: current.fileKey,
            expected: current.expected,
          },
          accessToken: freshAccessToken,
          mimeType,
          limits,
          signal: streamSignal,
        })
      },
      readWhole: (readSignal, progress) => readOriginal(folder, file, readSignal, progress),
    },
    signal,
    onProgress,
    onFallback,
  )
}

/** What a public link's player opens: everything it needs comes from the link. */
export interface PublicPlaybackTarget {
  /** The link's content route, which answers Range without a session. */
  url: string
  size: number
  mimeType: string
  /** The file key and what the object must be (its metadata's commitment). */
  content: () => Promise<{ fileKey: Uint8Array; expected: DriveObjectToOpen }>
  readWhole: (signal?: AbortSignal, onProgress?: (read: number) => void) => Promise<Blob | Uint8Array>
  /**
   * The viewer's own sign-in when they have one here, for a server whose
   * links open only for signed-in viewers (docs/plans/server-personal-data.md,
   * A11); empty for anyone else.
   */
  accessToken?: string
  /** Headers each range request adds: a protected link's proof (docs/plans/drive-link-password.md). */
  headers?: Record<string, string>
}

/** A file reached through a public link: the viewer's token if any, and the default limits. */
export async function openPublicPlayback(
  target: PublicPlaybackTarget,
  signal?: AbortSignal,
  onProgress?: (read: number) => void,
  onFallback?: (next: PlaybackFallback) => void,
): Promise<Playback> {
  const mimeType = target.mimeType || 'application/octet-stream'
  return openMediaPlayback(
    {
      size: target.size,
      mimeType,
      limits: () => driveStreamLimits({ anonymous: true }),
      stream: async (limits, streamSignal) => {
        const { fileKey, expected } = await target.content()
        return openPlayerStream({
          source: { family: 'drive', url: target.url, fileKey, expected, headers: target.headers },
          accessToken: target.accessToken ?? '',
          mimeType,
          limits,
          signal: streamSignal,
        })
      },
      readWhole: target.readWhole,
    },
    signal,
    onProgress,
    onFallback,
  )
}

export type PlaybackState = { kind: 'loading'; read: number } | Playback | { kind: 'failed' }

/**
 * What `open` gives while `enabled`, closed when `key` changes or the
 * component goes. `key` names what is played (a file and its content). A
 * stream that fails before it plays becomes what `open`'s `onFallback`
 * hands over.
 */
export function usePlaybackOf(
  open: (signal: AbortSignal, onProgress: (read: number) => void, onFallback: (next: PlaybackFallback) => void) => Promise<Playback>,
  key: string,
  enabled = true,
): PlaybackState {
  const [state, setState] = useState<PlaybackState>({ kind: 'loading', read: 0 })
  useEffect(() => {
    if (!enabled) return
    const controller = new AbortController()
    let opened: Playback | null = null
    let alive = true
    setState({ kind: 'loading', read: 0 })
    open(
      controller.signal,
      (read) => alive && setState({ kind: 'loading', read }),
      // The first playback's close ends what replaced it.
      (next) => alive && setState(next),
    ).then(
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
    // What is played is named by `key`; `open` is a new closure each render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, enabled])
  return state
}

/** A file's playback while `enabled`, closed when the file changes or the component goes. */
export function usePlayback(folder: PlaybackFolder, file: DriveFile, enabled = true): PlaybackState {
  return usePlaybackOf(
    (signal, onProgress, onFallback) => openPlayback(folder, file, signal, onProgress, onFallback),
    `${file.id}/${file.content?.revisionId ?? ''}/${file.contentKeyGeneration}`,
    enabled,
  )
}
