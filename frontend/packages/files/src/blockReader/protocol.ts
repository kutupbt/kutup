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
 * The types a stream or its Blob fallback may be served as; anything else
 * is `application/octet-stream`, so a stream's URL is never a document. The
 * service worker keeps the same list (`MEDIA_TYPES`); a test holds the two
 * equal.
 */
export const STREAM_MEDIA_TYPES: readonly string[] = [
  'video/mp4',
  'video/webm',
  'video/ogg',
  'video/quicktime',
  'video/x-matroska',
  'video/mp2t',
  'audio/mpeg',
  'audio/mp4',
  'audio/x-m4a',
  'audio/aac',
  'audio/ogg',
  'audio/opus',
  'audio/webm',
  'audio/flac',
  'audio/x-flac',
  'audio/wav',
  'audio/wave',
  'audio/x-wav',
]

const MEDIA_TYPE_SET = new Set(STREAM_MEDIA_TYPES)

/** A served type: one of `STREAM_MEDIA_TYPES` (its parameters dropped), else application/octet-stream. */
export function streamMediaType(type: unknown): string {
  const base = typeof type === 'string' ? (type.split(';')[0] ?? '').trim().toLowerCase() : ''
  return MEDIA_TYPE_SET.has(base) ? base : 'application/octet-stream'
}

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

/**
 * The service worker tells the page it refused a request for one of its
 * streams (not a player's request: some WebKit builds give a media element
 * an empty `destination`), so the page can fall back to a whole download.
 * No port, and only the stream id the page put in the URL.
 */
export interface StreamRefused {
  type: 'stream_refused'
  v: number
  streamId: string
}

export function isStreamRefused(data: unknown): data is StreamRefused {
  if (typeof data !== 'object' || data === null) return false
  const d = data as Partial<StreamRefused>
  return d.type === 'stream_refused' && typeof d.v === 'number' && typeof d.streamId === 'string'
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

/** A Drive revision: opened against its metadata's commitment, or its own sealed record. */
export interface DriveBlockSource {
  family: 'drive'
  /** The content route, answered with Range. */
  url: string
  fileKey: Uint8Array
  /** What the object must be (the committed content, or a revision by its record). */
  expected: DriveObjectToOpen
}

/** A Chat attachment (docs/chat-media.md): opened against its E2EE descriptor. */
export interface ChatMediaBlockSource {
  family: 'chatMedia'
  /** `/api/v1/chat/media/objects/{attachmentId}` on the account's own server, answered with Range. */
  url: string
  attachmentKey: Uint8Array
  attachmentId: string
  /** The sealed manifest's SHA-256 the descriptor carries (canonical base64). */
  manifestSha256: string
  /** The descriptor's plaintext and ciphertext lengths: the manifest's must be these. */
  size: number
  objectLength: number
}

/** What a reader opens: one object of a block family, and what it must be. */
export type BlockReaderTarget = DriveBlockSource | ChatMediaBlockSource

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
  | { type: 'open'; id: number; target: BlockReaderTarget; settings: BlockReaderSettings; token: string; client: string | null }
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
