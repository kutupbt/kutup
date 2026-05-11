// streamEncryptor — stateful libsodium secretstream encryptor exposed
// chunk-by-chunk so we can feed a ReadableStream of encrypted bytes to
// tus-js-client without buffering the whole file.
//
// Wire format matches the existing one-shot encryptStream() in
// symmetric.ts and the pure-Go port in
// cmd/kutup/internal/crypto/stream.go: 24-byte secretstream header
// followed by 5 MB plaintext chunks each producing 5 MB + 17 B
// ciphertext (the 16-byte Poly1305 MAC + the 1-byte secretstream tag).
// crypto_secretstream_xchacha20poly1305 with TAG_FINAL on the last
// chunk.
//
// Why a separate module: the streaming path needs the same primitives
// as encryptStream() but exposed at the chunk granularity. Rather than
// refactor symmetric.ts and risk regressions in the one-shot callers
// (downloads-decrypt, asset uploads, etc.), we add a thin wrapper here
// and let encryptStream stay one-shot. The cost is a tiny duplicated
// per-chunk loop; the benefit is zero risk to the existing path.

import { getSodium } from './sodium'

/** 5 MB plaintext per chunk. Matches the CLI + backend. */
export const PLAIN_CHUNK = 5 * 1024 * 1024

/**
 * Bytes added per secretstream message: 1-byte tag + 16-byte Poly1305 MAC.
 * Constant; libsodium exposes it as ABYTES at runtime.
 */
export const ABYTES = 17

/**
 * Bytes of secretstream header prepended once at the start of the
 * stream. libsodium exposes it as HEADERBYTES at runtime; we hardcode
 * for use in cipherSize() before sodium is ready.
 */
export const HEADER_BYTES = 24

/**
 * One PATCH body, in bytes. tus-js-client uses this as `chunkSize`.
 * Note we send PLAIN_CHUNK + ABYTES per chunk, but the very first
 * PATCH also carries the 24-byte header so the first body is slightly
 * larger. That's fine — tus-js-client reads up to `chunkSize` and
 * sends what it has, and the backend tolerates any body ≥ S3's 5 MiB
 * minimum part size for non-final parts.
 */
export const CIPHER_CHUNK = PLAIN_CHUNK + ABYTES

/**
 * cipherSize returns the total ciphertext byte count produced by
 * encrypting `plainBytes` plaintext bytes with this wire format. Used
 * to set tus's Upload-Length up-front (the server soft-reserves quota
 * against this number).
 *
 * - Empty input: just the 24-byte header. Matches encryptStream()'s
 *   behaviour for an empty Uint8Array.
 * - Non-empty: header + plaintext + 17 bytes per chunk.
 */
export function cipherSize(plainBytes: number): number {
  if (plainBytes <= 0) return HEADER_BYTES
  const chunks = Math.ceil(plainBytes / PLAIN_CHUNK)
  return HEADER_BYTES + plainBytes + ABYTES * chunks
}

export interface StreamEncryptor {
  /** 24-byte secretstream header. Caller prepends to the wire bytes. */
  readonly header: Uint8Array
  /**
   * Encrypt one plaintext chunk. Pass isLast=true on the final chunk
   * (TAG_FINAL); the decryptor uses that tag to stop cleanly. Empty
   * isLast chunks are legal — used by the 0-byte file case.
   */
  push(plain: Uint8Array, isLast: boolean): Uint8Array
}

export async function newStreamEncryptor(key: Uint8Array): Promise<StreamEncryptor> {
  const sodium = await getSodium()
  const { state, header } =
    sodium.crypto_secretstream_xchacha20poly1305_init_push(key)
  return {
    header,
    push(plain, isLast) {
      const tag = isLast
        ? sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
        : sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
      return sodium.crypto_secretstream_xchacha20poly1305_push(
        state, plain, null, tag,
      )
    },
  }
}
