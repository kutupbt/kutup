// streamDownload — chunked decrypt-and-save for non-federated downloads.
//
// Streaming path (RAM stays bounded ~constant regardless of file size on
// the FSA sink; the Blob fallback still buffers one full plaintext):
//
//   fetchDecryptedChunks(url) → { plain, isFinal } per 5 MB chunk
//     → showSaveFilePicker WritableStream (Chrome / Edge / Brave)
//     OR Blob accumulator + <a download> (Firefox / Safari)
//
// The fetch + re-framing + secretstream decryption all live in
// fetchDecrypt.ts, shared with the folder-as-ZIP path (../zipDownload.ts).

import { fetchDecryptedChunks } from './fetchDecrypt'
import type { FileBlobContextV1 } from '@kutup/crypto/fileBlob'

export interface StreamDownloadOptions {
  /** Full URL — either a local file download or a verified federated
   *  Drive share content path. */
  url: string
  /** Per-file content key (unwrapped from the collection key by the
   *  caller — same flow as the existing handleDownload). */
  fileKey: Uint8Array
  /** Exact authenticated Drive object binding expected in the blob header. */
  context: FileBlobContextV1
  /** Display name + MIME shown in the save picker / `<a download>`. */
  filename: string
  mimeType?: string
  /** Plaintext byte count, used only to size the Blob fallback's
   *  growing buffer. The streaming FSA path doesn't need it. */
  expectedPlainSize?: number
  /** Bearer token. Same JWT the rest of the app sends. */
  accessToken: string
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

export interface DownloadSink {
  write(plain: Uint8Array): Promise<void>
  finalize(): Promise<void>
  abort(): Promise<void>
}

export async function openDownloadSink(
  opts: Pick<StreamDownloadOptions, 'filename' | 'mimeType'>,
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
