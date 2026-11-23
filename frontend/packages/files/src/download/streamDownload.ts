// streamDownload — decrypt-and-save for downloads.
//
//   fetchDecryptedChunks(url) → the plaintext (fetchDecrypt.ts, shared with
//   the folder-as-ZIP path, ../zipDownload.ts)
//     → showSaveFilePicker WritableStream (Chrome / Edge / Brave)
//     OR Blob accumulator + <a download> (Firefox / Safari)
//
// The object is read block by block (docs/plans/drive-block-format.md §4):
// the save picker's file gets each 4 MiB block as it is verified. Without
// the picker the Blob holds the whole file, so it is refused above
// `drive.stream.blob_fallback_max_bytes` (`BlobDownloadTooLarge`).

import type { DriveObjectToOpen } from '@kutup/crypto'
import { fetchDecryptedChunks } from './fetchDecrypt'

export interface StreamDownloadOptions {
  /** Full URL — either a local file download or a verified federated
   *  Drive share content path. */
  url: string
  /** Per-file content key (unwrapped from the collection key by the
   *  caller — same flow as the existing handleDownload). */
  fileKey: Uint8Array
  /** What the object must be: the committed current content, or a version by its id. */
  context: DriveObjectToOpen
  /** Display name + MIME shown in the save picker / `<a download>`. */
  filename: string
  mimeType?: string
  /** Plaintext byte count, used only to size the Blob fallback's
   *  growing buffer. The streaming FSA path doesn't need it. */
  expectedPlainSize?: number
  /** Bearer token. Same JWT the rest of the app sends. */
  accessToken: string
  /** Headers each range request adds (a protected public link's proof). */
  headers?: Record<string, string>
  /** Without the save picker, the largest file assembled in memory (`drive.stream.blob_fallback_max_bytes`). */
  blobFallbackMaxBytes?: number | (() => Promise<number>)
  /** Plaintext bytes written + plaintext total (best-effort estimate). */
  onProgress?: (plainWritten: number, plainTotal: number) => void
  signal?: AbortSignal
}

/**
 * Detect whether the running browser supports the File System Access
 * `showSaveFilePicker` API. Treat as a side-effect-free getter so tests
 * can spy on it via `vi.spyOn(window, 'showSaveFilePicker')`.
 */
function canUseFSA(): boolean {
  return typeof window !== 'undefined' && 'showSaveFilePicker' in window
}

/**
 * streamDownload runs the full download → decrypt → save pipeline.
 * Resolves once the file is fully written (FSA path) or fully
 * accumulated and the anchor click has fired (Blob path).
 *
 * Throws on:
 *   - HTTP error (non-2xx response)
 *   - body cut off before total received (server hung up)
 *   - MAC failure mid-stream (tampered ciphertext or wrong key)
 *   - user cancelled the save picker
 *   - opts.signal aborted
 */
export async function streamDownload(opts: StreamDownloadOptions): Promise<void> {
  // Resolve the destination sink BEFORE we start reading bytes — if the
  // user cancels the save picker we want to fail fast without having
  // touched the response stream. (fetchDecryptedChunks's fetch() is lazy
  // — it fires on the first `for await` step, after this.)
  const sink = await openDownloadSink(opts)

  let plainWritten = 0
  try {
    for await (const { plain } of fetchDecryptedChunks(
      opts.url,
      opts.fileKey,
      opts.context,
      opts.accessToken,
      opts.signal,
      opts.headers,
    )) {
      await sink.write(plain)
      plainWritten += plain.length
      opts.onProgress?.(plainWritten, opts.expectedPlainSize ?? plainWritten)
    }
    await sink.finalize()
  } catch (err) {
    await sink.abort().catch(() => {})
    throw err
  }
}

// ---------------------------------------------------------------------------
// Sink abstraction — FSA WritableStream OR growing Blob fallback.
// ---------------------------------------------------------------------------

/** A download the browser can only assemble in memory, larger than the site allows for that. */
export class BlobDownloadTooLarge extends Error {
  constructor(
    readonly size: number,
    readonly maxBytes: number,
  ) {
    super(`a ${size}-byte download is larger than the ${maxBytes} bytes this browser may hold in memory`)
    this.name = 'BlobDownloadTooLarge'
  }
}

export interface DownloadSink {
  write(plain: Uint8Array): Promise<void>
  finalize(): Promise<void>
  abort(): Promise<void>
}

export async function openDownloadSink(
  opts: Pick<StreamDownloadOptions, 'filename' | 'mimeType' | 'expectedPlainSize' | 'blobFallbackMaxBytes'>,
): Promise<DownloadSink> {
  if (canUseFSA()) {
    try {
      return await openFSASink(opts)
    } catch (err) {
      // User cancelled the picker → don't fall back silently. The
      // caller probably wants to know.
      if (err instanceof DOMException && err.name === 'AbortError') {
        throw err
      }
      // Any other failure (permissions, unsupported environment that
      // still claimed support) → fall through to the Blob path so the
      // download still happens.
      console.warn('FSA sink failed, falling back to Blob:', err)
    }
  }
  // Read only here: the save picker above must not wait for it (it needs the click's activation).
  const size = opts.expectedPlainSize
  const limit = opts.blobFallbackMaxBytes
  const max = typeof limit === 'function' ? await limit() : limit
  if (size !== undefined && max !== undefined && size > max) throw new BlobDownloadTooLarge(size, max)
  return openBlobSink(opts)
}

interface FSAGlobals {
  showSaveFilePicker(opts?: {
    suggestedName?: string
    types?: { description?: string; accept: Record<string, string[]> }[]
  }): Promise<FSAFileHandle>
}
interface FSAFileHandle {
  createWritable(opts?: { keepExistingData?: boolean }): Promise<FSAWritable>
}
interface FSAWritable {
  write(data: BufferSource): Promise<void>
  close(): Promise<void>
  abort?(): Promise<void>
}

async function openFSASink(
  opts: Pick<StreamDownloadOptions, 'filename' | 'mimeType'>,
): Promise<DownloadSink> {
  const w = window as unknown as FSAGlobals
  const types = opts.mimeType
    ? [{ accept: { [opts.mimeType]: [extOf(opts.filename)] } }]
    : undefined
  const handle = await w.showSaveFilePicker({
    suggestedName: opts.filename,
    types,
  })
  const writable = await handle.createWritable()
  return {
    async write(plain) {
      // libsodium returns `Uint8Array<ArrayBufferLike>`; the FSA
      // WritableStream wants `BufferSource = ArrayBufferView<ArrayBuffer>`.
      // .slice() forces a fresh ArrayBuffer-backed view.
      await writable.write(plain.slice())
    },
    async finalize() {
      await writable.close()
    },
    async abort() {
      if (writable.abort) await writable.abort()
      else await writable.close().catch(() => {})
    },
  }
}

function openBlobSink(
  opts: Pick<StreamDownloadOptions, 'filename' | 'mimeType'>,
): DownloadSink {
  const parts: Uint8Array[] = []
  let total = 0
  return {
    async write(plain) {
      parts.push(plain)
      total += plain.length
    },
    async finalize() {
      // Same ArrayBufferLike-vs-ArrayBuffer issue as the FSA path —
      // `Blob`'s BlobPart wants ArrayBuffer-backed views.
      const blobParts: BlobPart[] = parts.map((p) => p.slice())
      const blob = new Blob(blobParts, {
        type: opts.mimeType ?? 'application/octet-stream',
      })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = opts.filename
      a.click()
      URL.revokeObjectURL(url)
      // help the GC release the per-chunk arrays sooner
      parts.length = 0
      void total
    },
    async abort() {
      parts.length = 0
    },
  }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function extOf(filename: string): string {
  const i = filename.lastIndexOf('.')
  return i >= 0 ? filename.slice(i) : ''
}
