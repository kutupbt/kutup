// The page's side of media streaming (docs/plans/drive-block-format.md §4).
//
// A player's `src` is `/sw/stream/{streamId}`. Kutup's service worker
// (`@kutup/config` src/sw/kutup-sw.js) keeps nothing: for each Range it
// posts `get_stream_chunk` to the page that asked, with a fresh port. This
// page knows its own stream ids and hands the port to that stream's block
// reader Worker, which answers on it directly with a transferred buffer. The
// window registers nothing in the service worker, so a worker stopped or
// replaced between two requests loses nothing: the next request finds the
// page as before.
//
// No service worker controlling the page within 15 s (a private window, a
// Shift-reload, workers turned off): the player falls back to a whole
// download into a Blob, up to `drive.stream.blob_fallback_max_bytes`.

import { randomBytes } from '@kutup/crypto/random'
import { openBlockReader, type AccessToken, type BlockReaderHandle } from '../blockReader/client'
import { isStreamChunkRequest, speaksWith, STREAM_PROTOCOL_VERSION, type BlockReaderTarget, type StreamChunkAnswer } from '../blockReader/protocol'
import { readerSettings, type StreamLimits } from './limits'

/** The service worker's script, at scope `/`. */
export const SERVICE_WORKER_SCRIPT = '/kutup-sw.js'
/** Where streams are served from. */
export const STREAM_PATH = '/sw/stream/'
/** How long a page waits for a service worker to control it before it falls back. */
export const CONTROLLER_WAIT_MS = 15_000
/** What the page dispatches when it must reload (`@kutup/config` reloadGuard.ts `RELOAD_NEEDED_EVENT`). */
export const RELOAD_NEEDED_EVENT = 'kutup:reload-needed'

/** This tab plays `drive.stream.max_concurrent` streams already. */
export class TooManyStreams extends Error {
  constructor(readonly limit: number) {
    super(`this tab plays ${limit} streams already`)
    this.name = 'TooManyStreams'
  }
}

interface Stream {
  reader: BlockReaderHandle
  mimeType: string
}

const streams = new Map<string, Stream>()
/** Streams opening: they count toward the limit before they are in `streams`. */
let opening = 0
let listening: ServiceWorkerContainer | null = null
let registering: Promise<ServiceWorkerRegistration | null> | null = null
let versionSaid = false

/** Answers one request on its port, as the service worker reads it. */
function answer(port: MessagePort, message: StreamChunkAnswer) {
  port.postMessage(message)
  port.close()
}

/** The page's handler for the service worker's messages: only `get_stream_chunk` for its own streams. */
export function onServiceWorkerMessage(event: Pick<MessageEvent, 'data' | 'ports'>): void {
  const request = event.data as unknown
  if (!isStreamChunkRequest(request)) return
  const [port] = event.ports
  if (!port) return
  if (!speaksWith(request.accepts)) {
    // The worker and this page are of different releases: a newer worker
    // than this page (it no longer serves this version), or an older one.
    answer(port, { v: STREAM_PROTOCOL_VERSION, kind: 'version' })
    reloadNeeded()
    return
  }
  const stream = streams.get(request.streamId)
  if (!stream) {
    answer(port, { v: STREAM_PROTOCOL_VERSION, kind: 'error', message: 'no such stream' })
    return
  }
  void stream.reader.serve(port, request.range, stream.mimeType)
}

function reloadNeeded() {
  if (versionSaid || typeof window === 'undefined') return
  versionSaid = true
  // An older worker is replaced at its next update check; ask for one now.
  const workers = container()
  void Promise.resolve(workers?.getRegistration('/'))
    .then((registration) => registration?.update())
    .catch(() => {})
    .finally(() => window.dispatchEvent(new Event(RELOAD_NEEDED_EVENT)))
}

function container(): ServiceWorkerContainer | null {
  return typeof navigator !== 'undefined' && 'serviceWorker' in navigator ? navigator.serviceWorker : null
}

/**
 * Registers Kutup's service worker unless it is registered already. A
 * registration Chat or Calendar made for Web Push (`/kutup-sw.js?push=…`)
 * is the same worker and is kept as it is: registering the bare script
 * would drop its words.
 */
async function register(workers: ServiceWorkerContainer): Promise<ServiceWorkerRegistration | null> {
  const existing = await workers.getRegistration('/')
  const script = existing?.active ?? existing?.waiting ?? existing?.installing
  if (existing && script && new URL(script.scriptURL).pathname === SERVICE_WORKER_SCRIPT) {
    void existing.update().catch(() => {})
    return existing
  }
  return workers.register(SERVICE_WORKER_SCRIPT, { scope: '/', updateViaCache: 'none' })
}

/** Starts listening for stream requests and registers the worker; once per page. */
export function prepareStreaming(): void {
  const workers = container()
  if (!workers) return
  if (listening !== workers) {
    listening = workers
    workers.addEventListener('message', onServiceWorkerMessage)
  }
  registering ??= register(workers).catch(() => {
    registering = null
    return null
  })
}

/** Whether a service worker controls this page (within `waitMs`): if not, there is no streaming. */
export async function streamingAvailable(waitMs = CONTROLLER_WAIT_MS): Promise<boolean> {
  const workers = container()
  if (!workers) return false
  prepareStreaming()
  if (workers.controller) return true
  return new Promise<boolean>((resolve) => {
    const done = (controlled: boolean) => {
      clearTimeout(timer)
      workers.removeEventListener('controllerchange', changed)
      resolve(controlled)
    }
    const changed = () => {
      if (workers.controller) done(true)
    }
    const timer = setTimeout(() => done(Boolean(workers.controller)), waitMs)
    workers.addEventListener('controllerchange', changed)
    // The worker claims open pages when it activates; ready is when that starts.
    void workers.ready.then(() => changed()).catch(() => {})
  })
}

/** 128 random bits, base64url: a stream's id, known only to this page and its worker. */
function newStreamId(): string {
  const bytes = randomBytes(16)
  let text = ''
  for (const byte of bytes) text += String.fromCharCode(byte)
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export interface PlayerStream {
  /** The player's `src`. */
  src: string
  /** The plaintext size. */
  size: number
  /** Stops the reader's fetches, drops its blocks and forgets the stream. */
  close: () => void
}

export interface OpenPlayerStreamOptions {
  /** The object streamed, and what it must be. */
  source: BlockReaderTarget
  accessToken: AccessToken
  /** What the player is told the bytes are; the worker serves only audio and video types as themselves. */
  mimeType: string
  limits: StreamLimits
  signal?: AbortSignal
}

/**
 * Opens a stream of an object (a Drive revision, a Chat attachment) for a player: its manifest and signer
 * checked before the player gets a byte. The caller has made sure a worker
 * controls the page (`streamingAvailable`). Throws `TooManyStreams` at the
 * tab's limit.
 */
export async function openPlayerStream(options: OpenPlayerStreamOptions): Promise<PlayerStream> {
  if (streams.size + opening >= options.limits.maxConcurrent) throw new TooManyStreams(options.limits.maxConcurrent)
  opening++
  let reader: BlockReaderHandle
  try {
    prepareStreaming()
    reader = await openBlockReader({
      source: options.source,
      accessToken: options.accessToken,
      settings: readerSettings(options.limits),
      signal: options.signal,
    })
  } finally {
    opening--
  }
  const streamId = newStreamId()
  streams.set(streamId, { reader, mimeType: options.mimeType })
  let closed = false
  const close = () => {
    if (closed) return
    closed = true
    streams.delete(streamId)
    reader.close()
  }
  options.signal?.addEventListener('abort', close, { once: true })
  return { src: `${STREAM_PATH}${streamId}`, size: reader.opened.size, close }
}

/** For tests: the streams this page has open. */
export function openStreamCount(): number {
  return streams.size
}
