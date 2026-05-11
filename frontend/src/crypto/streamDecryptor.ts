// streamDecryptor — stateful libsodium secretstream decryptor exposed
// chunk-by-chunk so we can pull ciphertext off a `fetch()` response
// body, decrypt it without buffering the whole file, and pipe the
// plaintext to a write sink (showSaveFilePicker WritableStream or a
// growing Blob — see upload/streamDownload.ts).
//
// Wire format matches the existing one-shot decryptStream() in
// symmetric.ts and the pure-Go port in
// cmd/kutup/internal/crypto/stream.go: 24-byte secretstream header
// followed by `5 MB + 17 B` ciphertext chunks (16-byte Poly1305 MAC
// + 1-byte secretstream tag). The final chunk carries TAG_FINAL.
//
// Symmetric to streamEncryptor.ts — kept in a separate file so the
// download side can be reasoned about independently. The one-shot
// `decryptStream()` in symmetric.ts continues to work for callers
// that already have the whole ciphertext in memory.

import { getSodium } from './sodium'
import { CIPHER_CHUNK, HEADER_BYTES } from './streamEncryptor'

export { CIPHER_CHUNK, HEADER_BYTES }

export interface StreamDecryptor {
  /**
   * Decrypt one ciphertext chunk. The chunk size must be exactly
   * `CIPHER_CHUNK` (5 MB + 17 B) for every chunk except the last —
   * libsodium's secretstream is chunk-sized at encrypt time so the
   * decrypt side has to match. The last chunk is whatever the
   * encryptor produced.
   *
   * Returns `{ plain, isFinal }`. `isFinal=true` means the secret-
   * stream TAG_FINAL was set on this chunk — caller should stop
   * pulling after that.
   *
   * Throws on MAC failure (`'Stream decryption failed'`) — meaning
   * the ciphertext was tampered with, the key is wrong, or the
   * chunks were re-ordered.
   */
  pull(cipherChunk: Uint8Array): { plain: Uint8Array; isFinal: boolean }
}

/**
 * newStreamDecryptor builds a decryptor primed with the 24-byte
 * secretstream header. The header must come from the start of the
 * encrypted blob — the caller is responsible for slicing it off the
 * wire before invoking this.
 */
export async function newStreamDecryptor(
  key: Uint8Array,
  header: Uint8Array,
): Promise<StreamDecryptor> {
  if (header.length !== HEADER_BYTES) {
    throw new Error(`stream header must be ${HEADER_BYTES} bytes, got ${header.length}`)
  }
  const sodium = await getSodium()
  const state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key)
  const TAG_FINAL = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
  return {
    pull(cipherChunk) {
      const res = sodium.crypto_secretstream_xchacha20poly1305_pull(
        state, cipherChunk, null,
      )
      if (!res) {
        throw new Error('Stream decryption failed — wrong key, tampered ciphertext, or reordered chunks')
      }
      return { plain: res.message, isFinal: res.tag === TAG_FINAL }
    },
  }
}
