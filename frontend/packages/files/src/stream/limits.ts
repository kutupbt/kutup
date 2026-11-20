// Drive's streaming limits (docs/plans/drive-block-format.md §7): site
// settings an administrator sets, read from `GET /api/v1/drive/limits` once
// per page. A public link's page has no session, so it uses the defaults.

import api from '@kutup/session/client'
import { cacheBlocksFor } from '../blockReader/plan'
import type { BlockReaderSettings } from '../blockReader/protocol'

export interface StreamLimits {
  /** The largest file a player streams; 0 never streams. */
  maxBytes: number
  cacheBlocks: number
  readaheadBlocks: number
  /** Streams one tab plays at once. */
  maxConcurrent: number
  responseMaxBytes: number
  /** Without a service worker, the largest file loaded whole into memory instead. */
  blobFallbackMaxBytes: number
}

const MIB = 1024 * 1024
const GIB = 1024 * MIB

/** The server's defaults (site_settings.rs `DRIVE_STREAM_*`). */
export const DEFAULT_STREAM_LIMITS: StreamLimits = {
  maxBytes: 10 * GIB,
  cacheBlocks: 3,
  readaheadBlocks: 1,
  maxConcurrent: 3,
  responseMaxBytes: 5 * MIB,
  blobFallbackMaxBytes: GIB,
}

interface DriveLimitsWire {
  streamMaxBytes: number
  streamCacheBlocks: number
  streamReadaheadBlocks: number
  streamMaxConcurrent: number
  streamResponseMaxBytes: number
  streamBlobFallbackMaxBytes: number
}

let loaded: Promise<StreamLimits> | null = null

/** This account's streaming limits; the defaults on a public page or when they can't be read. */
export function driveStreamLimits(options: { anonymous?: boolean } = {}): Promise<StreamLimits> {
  if (options.anonymous) return Promise.resolve(DEFAULT_STREAM_LIMITS)
  loaded ??= api.get<DriveLimitsWire>('/drive/limits').then(
    ({ data }) => ({
      maxBytes: data.streamMaxBytes,
      cacheBlocks: data.streamCacheBlocks,
      readaheadBlocks: data.streamReadaheadBlocks,
      maxConcurrent: data.streamMaxConcurrent,
      responseMaxBytes: data.streamResponseMaxBytes,
      blobFallbackMaxBytes: data.streamBlobFallbackMaxBytes,
    }),
    () => {
      // Read again next time.
      loaded = null
      return DEFAULT_STREAM_LIMITS
    },
  )
  return loaded
}

/** A block reader's settings under these limits, on this device. */
export function readerSettings(limits: StreamLimits): BlockReaderSettings {
  const nav = typeof navigator === 'undefined' ? null : navigator
  return {
    cacheBlocks: cacheBlocksFor(limits.cacheBlocks, nav?.userAgent ?? '', nav?.maxTouchPoints ?? 0),
    readaheadBlocks: limits.readaheadBlocks,
    responseMaxBytes: limits.responseMaxBytes,
  }
}

/** For tests: forget what was read. */
export function resetStreamLimits(): void {
  loaded = null
}
