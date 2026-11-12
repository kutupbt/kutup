// The messages around a block reader (docs/plans/drive-block-format.md §4):
// the service worker's stream protocol, versioned, and the page's requests
// to its dedicated reader Worker.
//
// The service worker (`@kutup/config` `src/sw/kutup-sw.js`, a plain script
// with no imports) speaks the same stream protocol; a test holds the two to
// the same version numbers.

import type { DriveObjectToOpen } from '@kutup/crypto/driveBlocks'
import type { StreamRange } from './plan'

/** The stream protocol this page speaks. */
export const STREAM_PROTOCOL_VERSION = 1

/** The most bytes one answer may carry: the largest `drive.stream.response_max_bytes`. */
export const STREAM_ANSWER_HARD_MAX_BYTES = 16 * 1024 * 1024

/**
 * The service worker asks the page that made a request for its bytes: `v`
 * is the worker's own version, `accepts` every version it can still serve
 * (its own and the one before, for a release), and the answer goes back on
 * the message's one port.
 */
export interface StreamChunkRequest {
  type: 'get_stream_chunk'
  v: number
  accepts: number[]
  streamId: string
  range: StreamRange
}

/** What goes back over the port: the bytes, a range past the end, a failure, or a version the page doesn't speak. */
export type StreamChunkAnswer =
  | { v: 1; kind: 'bytes'; start: number; total: number; mimeType: string; bytes: ArrayBuffer }
  | { v: 1; kind: 'unsatisfiable'; total: number }
  | { v: 1; kind: 'error'; message: string }
  | { v: number; kind: 'version' }

export function isStreamChunkRequest(data: unknown): data is StreamChunkRequest {
  if (typeof data !== 'object' || data === null) return false
  const d = data as Partial<StreamChunkRequest>
  return d.type === 'get_stream_chunk' && typeof d.v === 'number' && Array.isArray(d.accepts) && typeof d.streamId === 'string' && isRange(d.range)
}

function isRange(range: unknown): range is StreamRange {
  if (typeof range !== 'object' || range === null) return false
  const r = range as Record<string, unknown>
  if ('suffix' in r) return Number.isSafeInteger(r.suffix) && (r.suffix as number) > 0
  return Number.isSafeInteger(r.start) && (r.start as number) >= 0 && (r.end === null || (Number.isSafeInteger(r.end) && (r.end as number) >= 0))
}

/** Whether this page can answer a worker that accepts these versions. */
export function speaksWith(accepts: readonly number[]): boolean {
  return accepts.includes(STREAM_PROTOCOL_VERSION)
}

/** What a block reader is opened with. */
export interface BlockReaderSettings {
  /** Verified plaintext blocks kept (`drive.stream.cache_blocks`). */
  cacheBlocks: number
  /** Blocks fetched ahead of the one read (`drive.stream.readahead_blocks`). */
  readaheadBlocks: number
  /** The most bytes one stream answer carries (`drive.stream.response_max_bytes`). */
  responseMaxBytes: number
}

export interface BlockReaderTarget {
  /** The content route, answered with Range. */
  url: string
  fileKey: Uint8Array
  /** What the object must be (the committed content, or a revision by its record). */
  expected: DriveObjectToOpen
}

/** Who signed an opened revision's manifest. */
export interface OpenedSigner {
  accountId: string
  incarnationId: string
}

export interface OpenedObject {
  fileId: string
  revisionId: string
  size: number
  blockCount: number
  blockSize: number
  signer: OpenedSigner | null
}

/** Page → reader Worker. `token` is the bearer token to fetch with from then on ('' for a public link). */
export type ReaderRequest =
  | { type: 'open'; id: number; target: BlockReaderTarget; settings: BlockReaderSettings; token: string }
  | { type: 'block'; id: number; index: number; token: string }
  | { type: 'signedBy'; id: number; key: string }
  | { type: 'serve'; range: StreamRange; mimeType: string; token: string }
  | { type: 'close' }

/** Reader Worker → page. */
export type ReaderResponse =
  | { type: 'ready' }
  | { type: 'opened'; id: number; opened: OpenedObject }
  | { type: 'block'; id: number; bytes: Uint8Array }
  | { type: 'signedBy'; id: number; ok: boolean }
  | { type: 'error'; id: number; message: string; aborted: boolean }
