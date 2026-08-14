// fetchDecryptedChunks — the streaming "fetch an encrypted blob and yield
// decrypted plaintext chunks" core, shared by single-file downloads
// (streamDownload.ts) and folder-as-ZIP downloads (lib/zipDownload.ts).
//
// Persistent wire format (matches fileBlob.ts / the CLI / the backend):
//   [ 48-byte typed Drive header ][ 24-byte secretstream header ][ frames ]
// where every frame except the last is exactly CIPHER_CHUNK (5 MiB + 17 B)
// and the last frame carries TAG_FINAL. The last frame may be shorter.
//
// Memory: only the not-yet-framed tail of the response body plus one
// decrypted chunk are held at a time — peak RAM ≈ a few MB regardless of
// file size. The caller decides what to do with each plaintext chunk
// (write to a save sink, push into a ZIP entry, …).
//
// Throws on: HTTP error, missing body, the stream ending before the typed
// prefix / before the FINAL tag, context relocation, and MAC failure (wrong
// key / tampered ciphertext / reordered chunks).

import {
  DRIVE_FILE_BLOB_CIPHER_CHUNK,
  DRIVE_FILE_BLOB_PREFIX_BYTES,
  openFileBlobStreamV1,
  type FileBlobContextV1,
} from '@/crypto/fileBlob'

export interface DecryptedChunk {
  plain: Uint8Array
  /** TAG_FINAL was set on this chunk — no more chunks follow. */
  isFinal: boolean
}

export async function* fetchDecryptedChunks(
  url: string,
  fileKey: Uint8Array,
  context: FileBlobContextV1,
  accessToken: string,
  signal?: AbortSignal,
): AsyncGenerator<DecryptedChunk, void, void> {
  const resp = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
    signal,
  })
  if (!resp.ok) {
    throw new Error(
      `download HTTP ${resp.status}: ${await resp.text().catch(() => '')}`,
    )
  }
  if (!resp.body) {
    throw new Error('download response has no body')
  }

  const reader = resp.body.getReader()
  // `Uint8Array<ArrayBufferLike>` — holds both ArrayBuffer-backed slices
  // from libsodium and whatever the reader yields (possibly
  // SharedArrayBuffer-backed under TS strict types).
  let buf: Uint8Array<ArrayBufferLike> = new Uint8Array(0)
  let decryptor: Awaited<ReturnType<typeof openFileBlobStreamV1>> | null = null
  let sawFinal = false

  for (;;) {
    const { value, done } = await reader.read()
    if (sawFinal && value && value.length > 0) {
      throw new Error('Drive file blob has bytes after FINAL')
    }
    if (value) buf = appendBytes(buf, value)

    // Drain full frames while more bytes might still arrive. The header
    // comes first; then each `CIPHER_CHUNK`-sized frame. The last frame
    // (which can be shorter) is pulled out-of-loop once `done`.
    while (true) {
      if (!decryptor) {
        if (buf.length < DRIVE_FILE_BLOB_PREFIX_BYTES) break
        decryptor = await openFileBlobStreamV1(
          buf.subarray(0, DRIVE_FILE_BLOB_PREFIX_BYTES),
          fileKey,
          context,
        )
        buf = buf.subarray(DRIVE_FILE_BLOB_PREFIX_BYTES)
      }
      if (buf.length < DRIVE_FILE_BLOB_CIPHER_CHUNK) break
      const { plain, isFinal } = decryptor.pull(buf.subarray(0, DRIVE_FILE_BLOB_CIPHER_CHUNK))
      buf = buf.subarray(DRIVE_FILE_BLOB_CIPHER_CHUNK)
      yield { plain, isFinal }
      if (isFinal) {
        sawFinal = true
        if (buf.length > 0) throw new Error('Drive file blob has bytes after FINAL')
        break
      }
    }
    if (sawFinal && done) return

    if (done) {
      if (!decryptor) {
        throw new Error('download ended before Drive file-blob prefix was received')
      }
      if (buf.length > 0) {
        // The final (possibly short) frame.
        const { plain, isFinal } = decryptor.pull(buf)
        buf = new Uint8Array(0)
        yield { plain, isFinal }
        if (!isFinal) {
          throw new Error('download ended before secretstream FINAL tag')
        }
        sawFinal = true
      }
      if (!sawFinal) throw new Error('download ended before secretstream FINAL tag')
      return
    }
  }
}

export function appendBytes(
  a: Uint8Array<ArrayBufferLike>,
  b: Uint8Array<ArrayBufferLike>,
): Uint8Array<ArrayBufferLike> {
  if (a.length === 0) return b
  const out = new Uint8Array(a.length + b.length)
  out.set(a, 0)
  out.set(b, a.length)
  return out
}
