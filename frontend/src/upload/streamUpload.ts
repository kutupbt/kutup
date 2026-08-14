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
import { createFileRecordV1 } from '@/crypto'
import {
  DRIVE_FILE_BLOB_CIPHER_CHUNK,
  DRIVE_FILE_BLOB_PREFIX_BYTES,
  fileBlobCipherSize,
  newFileBlobStreamEncryptorV1,
} from '@/crypto/fileBlob'
import { resolveApiBase } from '@/lib/apiBase'
import { PLAIN_CHUNK } from '@/crypto/streamEncryptor'

export interface StreamUploadOptions {
  file: File
  collection: { id: string; keyEpoch: number; collectionKey: Uint8Array }
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
  const meta = {
    name: opts.file.name,
    mimeType: opts.file.type || 'application/octet-stream',
    size: opts.file.size,
  }
  const record = await createFileRecordV1(
    opts.collection.id,
    opts.collection.keyEpoch,
    opts.collection.collectionKey,
    meta,
  )
  const blobContext = {
    fileId: record.fileId,
    collectionId: opts.collection.id,
    epoch: opts.collection.keyEpoch,
  }
  const enc = await newFileBlobStreamEncryptorV1(record.fileKey, blobContext)
  const cipherTotal = fileBlobCipherSize(opts.file.size)

  // Build the ReadableStream of encrypted bytes. Each pull():
  //   - first call:  emit the typed Drive + secretstream prefix
  //   - subsequent:  read up to 5 MB plaintext, encrypt, emit ciphertext
  //   - empty file:  emit an authenticated empty FINAL frame, then close
  let pos = 0
  let prefixSent = false
  let emptyFinalSent = false
  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (!prefixSent) {
        prefixSent = true
        controller.enqueue(enc.prefix)
        return
      }
      if (opts.file.size === 0 && !emptyFinalSent) {
        emptyFinalSent = true
        controller.enqueue(enc.push(new Uint8Array(0), true))
        controller.close()
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
      // secretstream message per PATCH; the first PATCH also carries the
      // fixed Drive-object prefix. This satisfies S3's 5-MiB minimum for
      // non-final parts; the bounded prefix overhead remains within the
      // backend and edge limits.
      chunkSize: DRIVE_FILE_BLOB_CIPHER_CHUNK,
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
        fileId:            record.fileId,
        collectionId:      opts.collection.id,
        metadataEnvelope:  record.metadataEnvelope,
        fileKeyEnvelope:   record.fileKeyEnvelope,
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
        if (bytesAccepted <= DRIVE_FILE_BLOB_PREFIX_BYTES) {
          // Typed prefix only — no plaintext yet.
          return
        }
        const cipherAfterHeader = bytesAccepted - DRIVE_FILE_BLOB_PREFIX_BYTES
        const chunksDone = Math.ceil(cipherAfterHeader / DRIVE_FILE_BLOB_CIPHER_CHUNK)
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
        if (resolvedFileId !== record.fileId) {
          reject(new Error('tus server returned a different fileId'))
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
