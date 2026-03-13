// XChaCha20-Poly1305 symmetric encryption (192-bit nonce, random per message).
// Used for: masterKey, privateKey, collectionKey, fileKey, metadata.
// File content uses secretstream for chunked streaming.
import { getSodium } from './sodium'

export interface Encrypted {
  ciphertext: Uint8Array
  nonce: Uint8Array
}

export async function encrypt(plaintext: Uint8Array, key: Uint8Array): Promise<Encrypted> {
  const sodium = await getSodium()
  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
  const ciphertext = sodium.crypto_secretbox_easy(plaintext, nonce, key)
  return { ciphertext, nonce }
}

export async function decrypt(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
): Promise<Uint8Array> {
  const sodium = await getSodium()
  const plaintext = sodium.crypto_secretbox_open_easy(ciphertext, nonce, key)
  if (!plaintext) throw new Error('Decryption failed — wrong key or corrupted data')
  return plaintext
}

// Streaming encryption for large files (5MB chunks).
// Returns { header, encryptedChunks } — header must be prepended to the blob.
const CHUNK_SIZE = 5 * 1024 * 1024 // 5 MB

export async function encryptStream(
  data: Uint8Array,
  key: Uint8Array,
): Promise<Uint8Array> {
  const sodium = await getSodium()
  const { state, header } = sodium.crypto_secretstream_xchacha20poly1305_init_push(key)

  const chunks: Uint8Array[] = [header]
  let offset = 0

  while (offset < data.length) {
    const end = Math.min(offset + CHUNK_SIZE, data.length)
    const chunk = data.subarray(offset, end)
    const isLast = end === data.length
    const tag = isLast
      ? sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
      : sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE

    const encChunk = sodium.crypto_secretstream_xchacha20poly1305_push(
      state, chunk, null, tag,
    )
    chunks.push(encChunk)
    offset = end
  }

  // Concatenate all chunks
  const totalLen = chunks.reduce((acc, c) => acc + c.length, 0)
  const result = new Uint8Array(totalLen)
  let pos = 0
  for (const c of chunks) {
    result.set(c, pos)
    pos += c.length
  }
  return result
}

export async function decryptStream(
  encryptedData: Uint8Array,
  key: Uint8Array,
): Promise<Uint8Array> {
  const sodium = await getSodium()
  const headerLen = sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES
  const header = encryptedData.subarray(0, headerLen)
  const state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key)

  const chunkOverhead = sodium.crypto_secretstream_xchacha20poly1305_ABYTES
  const encChunkSize = CHUNK_SIZE + chunkOverhead

  const plaintextChunks: Uint8Array[] = []
  let offset = headerLen

  while (offset < encryptedData.length) {
    const end = Math.min(offset + encChunkSize, encryptedData.length)
    const encChunk = encryptedData.subarray(offset, end)
    const result = sodium.crypto_secretstream_xchacha20poly1305_pull(state, encChunk, null)
    if (!result) throw new Error('Stream decryption failed — corrupted data or wrong key')
    plaintextChunks.push(result.message)
    offset = end
  }

  const totalLen = plaintextChunks.reduce((acc, c) => acc + c.length, 0)
  const plaintext = new Uint8Array(totalLen)
  let pos = 0
  for (const c of plaintextChunks) {
    plaintext.set(c, pos)
    pos += c.length
  }
  return plaintext
}

export async function generateKey(): Promise<Uint8Array> {
  const sodium = await getSodium()
  return sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES)
}
