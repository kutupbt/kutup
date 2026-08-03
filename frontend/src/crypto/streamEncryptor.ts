// streamEncryptor — stateful libsodium secretstream encryptor exposed
// chunk-by-chunk so we can feed a ReadableStream of encrypted bytes to
// tus-js-client without buffering the whole file.
//
// This module is the primitive-only browser adapter used by fileBlob.ts.
// It emits a 24-byte secretstream header followed by 5 MB plaintext chunks,
// each producing 5 MB + 17 B ciphertext. fileBlob.ts owns the persistent
// Drive header, purpose key, AAD, context validation and mandatory final frame.
// crypto_secretstream_xchacha20poly1305 with TAG_FINAL on the last
// chunk.
//
// This stays separate from the Rust-owned format adapter because a browser
// upload must push bounded chunks across the JS/WASM boundary. It never owns a
// persistent header, suite choice, KDF label or validation rule.

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
 * This helper describes only the raw secretstream primitive. A persisted
 * Drive object uses fileBlobCipherSize(), which always includes a FINAL frame.
 * - Empty input: raw header only (not a valid persistent Drive object).
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

export async function newStreamEncryptor(
  key: Uint8Array,
  associatedData?: Uint8Array,
): Promise<StreamEncryptor> {
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
        state, plain, associatedData ?? null, tag,
      )
    },
  }
}
