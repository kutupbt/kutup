// streamDownload — chunked decrypt-and-save for non-federated downloads.
//
// Replaces `api.get(url, { responseType: 'arraybuffer' })` + one-shot
// `decryptStream()` which buffered the full encrypted blob AND the
// full plaintext (~3× file size in peak RAM). New path:
//
//   fetch(url) → ReadableStream<Uint8Array>
//     → re-chunk into 24-byte header + (5 MB + 17 B) ciphertext frames
//       → streamDecryptor.pull() → plaintext
//         → showSaveFilePicker WritableStream (Chrome / Edge / Brave)
//         OR Blob accumulator + <a download> (Firefox / Safari)
//
// Wire format and crypto are identical to the existing in-memory path
// — only the buffering strategy changes. RAM stays bounded at ~10 MB
// on the FSA path; the Blob fallback degrades back to the old peak
// (one full plaintext) but is still better than the 3× plaintext+
// ciphertext the previous handler held.

import { newStreamDecryptor } from '@/crypto/streamDecryptor'
import { CIPHER_CHUNK, HEADER_BYTES } from '@/crypto/streamEncryptor'

export interface StreamDownloadOptions {
  /** Full URL — already includes `/api/files/<id>/download` or the
   *  federated `/fed-proxy/.../download` path. */
  url: string
  /** Per-file content key (unwrapped from the collection key by the
   *  caller — same flow as the existing handleDownload). */
  fileKey: Uint8Array
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
  const resp = await fetch(opts.url, {
    headers: { Authorization: `Bearer ${opts.accessToken}` },
    signal: opts.signal,
  })
  if (!resp.ok) {
    throw new Error(`download HTTP ${resp.status}: ${await resp.text().catch(() => '')}`)
  }
  if (!resp.body) {
    throw new Error('download response has no body')
  }

  // Resolve the destination sink BEFORE we start reading bytes. If
  // the user cancels showSaveFilePicker we want to fail fast without
  // having consumed the response stream.
  const sink = await openSink(opts)

  const reader = resp.body.getReader()
  // `Uint8Array<ArrayBufferLike>` so we can hold both `ArrayBuffer`-
  // backed slices from libsodium AND whatever the reader yields
  // (which may be SharedArrayBuffer-backed under TS strict types).
  let buf: Uint8Array<ArrayBufferLike> = new Uint8Array(0)
  let decryptor: Awaited<ReturnType<typeof newStreamDecryptor>> | null = null
  let plainWritten = 0
  let sawFinal = false

  try {
    for (;;) {
      const { value, done } = await reader.read()
      if (value) {
        buf = appendBytes(buf, value)
      }

      // Drain as many full secretstream frames as our buffer allows.
      // Frame layout: first 24 bytes = header, then ciphertext chunks
      // of length `CIPHER_CHUNK` (last chunk may be shorter — handled
      // at EOF below).
      while (true) {
        if (!decryptor) {
          if (buf.length < HEADER_BYTES) break
          const header = buf.subarray(0, HEADER_BYTES)
          decryptor = await newStreamDecryptor(opts.fileKey, header)
          buf = buf.subarray(HEADER_BYTES)
        }
        // Only consume a full CIPHER_CHUNK while more bytes might
        // still arrive. The last chunk (which can be smaller) is
        // pulled out-of-loop once `done` is true.
        if (buf.length < CIPHER_CHUNK) break
        const chunk = buf.subarray(0, CIPHER_CHUNK)
        const { plain, isFinal } = decryptor.pull(chunk)
        await sink.write(plain)
        plainWritten += plain.length
        opts.onProgress?.(plainWritten, opts.expectedPlainSize ?? plainWritten)
        buf = buf.subarray(CIPHER_CHUNK)
        if (isFinal) {
          sawFinal = true
          break
        }
      }
      if (sawFinal) break

      if (done) {
        // Final (possibly partial) chunk lives in `buf` once the
        // server stops sending.
        if (!decryptor) {
          throw new Error('download ended before secretstream header was received')
        }
        if (buf.length > 0) {
          const { plain, isFinal } = decryptor.pull(buf)
          await sink.write(plain)
          plainWritten += plain.length
          opts.onProgress?.(plainWritten, opts.expectedPlainSize ?? plainWritten)
          buf = new Uint8Array(0)
          if (!isFinal) {
            // The encryptor tags the LAST message with TAG_FINAL. If
            // we got `done` without seeing it, the stream was cut.
            throw new Error('download ended before secretstream FINAL tag')
          }
        }
        break
      }
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

interface Sink {
  write(plain: Uint8Array): Promise<void>
  finalize(): Promise<void>
  abort(): Promise<void>
}

async function openSink(opts: StreamDownloadOptions): Promise<Sink> {
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

async function openFSASink(opts: StreamDownloadOptions): Promise<Sink> {
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

function openBlobSink(opts: StreamDownloadOptions): Sink {
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

function appendBytes(
  a: Uint8Array<ArrayBufferLike>,
  b: Uint8Array<ArrayBufferLike>,
): Uint8Array<ArrayBufferLike> {
  if (a.length === 0) return b
  const out = new Uint8Array(a.length + b.length)
  out.set(a, 0)
  out.set(b, a.length)
  return out
}

function extOf(filename: string): string {
  const i = filename.lastIndexOf('.')
  return i >= 0 ? filename.slice(i) : ''
}
