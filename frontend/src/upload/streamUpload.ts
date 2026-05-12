// streamUpload — E2EE streaming upload via the tus.io resumable
// protocol. Memory stays bounded at ~10 MB regardless of file size:
// we read 5 MB of plaintext from File.slice(), encrypt one
// secretstream chunk, and feed it into a ReadableStream that tus-js-
// client drains one PATCH at a time. The browser backs File.slice()
// with on-demand disk reads for <input>-picked files, so we never
// materialise the whole file in RAM.
//
// Replaces the existing `uploadFile` path in Drive.tsx for non-
// federated uploads. Federated uploads still go through the old
// multipart endpoint (handled at the call site) until the federated
// peer learns to speak tus too.
//
// Wire format matches `backend/handlers/tus.go` + the CLI:
//   POST  /api/uploads          — creates session, returns {fileId}
//   PATCH /api/uploads/<id>     — appends one S3 multipart part each
//   final PATCH triggers backend finaliser (Complete + INSERT files)
//
// tus-js-client owns the protocol mechanics (retry/backoff, abort,
// upload offsets); we own the cryptography and the file→stream
// adapter.

import * as tus from 'tus-js-client'
import { generateKey, encrypt, toBase64 } from '@/crypto'
import { resolveApiBase } from '@/lib/apiBase'
import {
  newStreamEncryptor,
  cipherSize,
  PLAIN_CHUNK,
  CIPHER_CHUNK,
} from '@/crypto/streamEncryptor'

export interface StreamUploadOptions {
  file: File
  collection: { id: string; collectionKey: Uint8Array }
  accessToken: string
  /** Plaintext bytes uploaded so far, plaintext total. */
  onProgress?: (plainSent: number, plainTotal: number) => void
  /** Cancel an in-flight upload. Calls tus DELETE under the hood. */
  signal?: AbortSignal
}

/**
 * streamUpload encrypts and uploads a File via the tus endpoint.
 * Resolves with the server-allocated fileId (a UUID string). Rejects
 * with the underlying error on failure; tus-js-client handles
 * transient retries internally (default 5 retries with exponential
 * backoff).
 */
export async function streamUpload(opts: StreamUploadOptions): Promise<string> {
  const fileKey = await generateKey()
  const enc = await newStreamEncryptor(fileKey)
  const cipherTotal = cipherSize(opts.file.size)

  // Encrypted metadata + wrapped file key — both committed up-front
  // via tus's Upload-Metadata header on the POST.
  const meta = {
    name: opts.file.name,
    mimeType: opts.file.type || 'application/octet-stream',
    size: opts.file.size,
  }
  const encMeta = await encrypt(
    new TextEncoder().encode(JSON.stringify(meta)),
    fileKey,
  )
  const encFileKey = await encrypt(fileKey, opts.collection.collectionKey)

  // Build the ReadableStream of encrypted bytes. Each pull():
  //   - first call:  emit the 24-byte secretstream header
  //   - subsequent:  read up to 5 MB plaintext, encrypt, emit ciphertext
  //   - empty file:  emit the header only, then close
  let pos = 0
  let headerSent = false
  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (!headerSent) {
        headerSent = true
        controller.enqueue(enc.header)
        if (opts.file.size === 0) controller.close()
        return
      }
      if (pos >= opts.file.size) {
        controller.close()
        return
      }
      const end = Math.min(pos + PLAIN_CHUNK, opts.file.size)
      const plain = new Uint8Array(await opts.file.slice(pos, end).arrayBuffer())
      const isLast = end === opts.file.size
      controller.enqueue(enc.push(plain, isLast))
      pos = end
      if (isLast) controller.close()
    },
  })

  // Resolve the tus endpoint against the API base — on the web that's
  // `/api/uploads/`; in the Tauri shell it's the user-selected backend
  // (a bare `/api/...` would resolve to `tauri://localhost/api/...`).
  const uploadsEndpoint = `${await resolveApiBase()}/uploads/`

  return new Promise<string>((resolve, reject) => {
    let resolvedFileId = ''
    let lastPlainSent = 0

    // tus-js-client wants a `Pick<ReadableStreamDefaultReader,'read'>`,
    // not the stream itself. Hand it the reader from getReader().
    const reader = stream.getReader()

    const upload = new tus.Upload(reader, {
      endpoint: uploadsEndpoint,
      uploadSize: cipherTotal,
      // chunkSize is the per-PATCH body size. We send exactly one
      // secretstream message per PATCH; CIPHER_CHUNK = 5 MiB + 17 B
      // satisfies S3's 5-MiB minimum for non-final parts. The very
      // first PATCH also carries the 24-byte header, but that's
      // still well within the upper bound the backend tolerates.
      chunkSize: CIPHER_CHUNK,
      retryDelays: [0, 1000, 3000, 5000, 10000],
      // Disable tus-js-client's cross-session resume machinery. For
      // stream inputs the default fingerprint logic is flaky and can
      // interfere with back-to-back uploads (e.g. in uploadFolder).
      // We don't support cross-reload resume on web anyway — Slice 4
      // out-of-scope.
      storeFingerprintForResuming: false,
      removeFingerprintOnSuccess: true,
      headers: {
        Authorization: `Bearer ${opts.accessToken}`,
      },
      metadata: {
        collectionId:      opts.collection.id,
        encryptedMetadata: toBase64(encMeta.ciphertext),
        metadataNonce:     toBase64(encMeta.nonce),
        encryptedFileKey:  toBase64(encFileKey.ciphertext),
        fileKeyNonce:      toBase64(encFileKey.nonce),
      },
      // The Create response (HTTP 201) returns JSON {"fileId": "..."}
      // — capture it here. We can't read the final-PATCH response
      // body via the public API; onAfterResponse on the POST is the
      // documented escape hatch.
      onAfterResponse(req, res) {
        if (req.getMethod() === 'POST' && res.getStatus() === 201) {
          try {
            const parsed = JSON.parse(res.getBody()) as { fileId?: string }
            if (parsed.fileId) resolvedFileId = parsed.fileId
          } catch {
            // Bad JSON on Create is the server's bug; surface via
            // onError when the rest of the upload eventually fails.
          }
        }
      },
      onChunkComplete(_chunkSize, bytesAccepted) {
        // Translate ciphertext-bytes to plaintext-bytes for progress.
        // Each chunk past the header is 17 B over its plaintext.
        if (bytesAccepted <= 24) {
          // Header only — no plaintext yet.
          return
        }
        const cipherAfterHeader = bytesAccepted - 24
        const chunksDone = Math.ceil(cipherAfterHeader / CIPHER_CHUNK)
        const plain = Math.min(
          opts.file.size,
          cipherAfterHeader - 17 * chunksDone,
        )
        if (plain > lastPlainSent) {
          lastPlainSent = plain
          opts.onProgress?.(plain, opts.file.size)
        }
      },
      onError(err) {
        reject(err)
      },
      onSuccess() {
        if (!resolvedFileId) {
          reject(new Error('tus upload succeeded but no fileId echoed on Create'))
          return
        }
        // Report 100 % plaintext progress one final time so UI hits
        // the end of its progress bar even when the final PATCH is
        // smaller than the per-chunk increment.
        opts.onProgress?.(opts.file.size, opts.file.size)
        resolve(resolvedFileId)
      },
    })

    if (opts.signal) {
      if (opts.signal.aborted) {
        // Abort immediately if the signal fired before start().
        void upload.abort(true).catch(() => {})
        reject(new DOMException('Upload aborted', 'AbortError'))
        return
      }
      opts.signal.addEventListener(
        'abort',
        () => {
          // shouldTerminate=true → tus DELETE on the server, freeing
          // the soft-reserved quota immediately. We also reject the
          // outer promise so the caller doesn't hang.
          void upload.abort(true).catch(() => {})
          reject(new DOMException('Upload aborted', 'AbortError'))
        },
        { once: true },
      )
    }

    upload.start()
  })
}
