// Typed Drive file-blob framing. Rust owns the suite/header/KDF policy; this
// adapter feeds the resulting purpose key and canonical AAD into libsodium's
// streaming implementation so browser uploads and downloads stay bounded.

import { fromBase64, toBase64 } from './base64'
import { getCryptoWasm } from './rustWasm'
import {
  ABYTES,
  HEADER_BYTES as SECRETSTREAM_HEADER_BYTES,
  PLAIN_CHUNK,
  newStreamEncryptor,
  type StreamEncryptor,
} from './streamEncryptor'
import { newStreamDecryptor, type StreamDecryptor } from './streamDecryptor'

export const DRIVE_FILE_BLOB_HEADER_BYTES = 48
export const DRIVE_FILE_BLOB_PREFIX_BYTES =
  DRIVE_FILE_BLOB_HEADER_BYTES + SECRETSTREAM_HEADER_BYTES
export const DRIVE_FILE_BLOB_CIPHER_CHUNK = PLAIN_CHUNK + ABYTES

export interface FileBlobContextV1 {
  fileId: string
  collectionId: string
  epoch: number
}

export interface FileBlobStreamEncryptorV1 {
  /** Canonical Drive header followed by the secretstream header. */
  readonly prefix: Uint8Array
  push(plain: Uint8Array, isLast: boolean): Uint8Array
}

export function fileBlobCipherSize(plainBytes: number): number {
  const chunks = Math.max(1, Math.ceil(Math.max(0, plainBytes) / PLAIN_CHUNK))
  return DRIVE_FILE_BLOB_PREFIX_BYTES + Math.max(0, plainBytes) + ABYTES * chunks
}

async function prepare(
  fileKey: Uint8Array,
  context: FileBlobContextV1,
): Promise<{ objectHeader: Uint8Array; streamKey: Uint8Array }> {
  const module = await getCryptoWasm()
  const prepared = module.prepareDriveFileBlob(
    toBase64(fileKey),
    context.fileId,
    context.collectionId,
    context.epoch,
  )
  const objectHeader = fromBase64(prepared.objectHeader)
  const streamKey = fromBase64(prepared.streamKey)
  if (objectHeader.length !== DRIVE_FILE_BLOB_HEADER_BYTES || streamKey.length !== 32) {
    throw new Error('Rust returned malformed Drive file-blob material')
  }
  return { objectHeader, streamKey }
}

export async function newFileBlobStreamEncryptorV1(
  fileKey: Uint8Array,
  context: FileBlobContextV1,
): Promise<FileBlobStreamEncryptorV1> {
  const { objectHeader, streamKey } = await prepare(fileKey, context)
  const encryptor: StreamEncryptor = await newStreamEncryptor(streamKey, objectHeader)
  const prefix = new Uint8Array(DRIVE_FILE_BLOB_PREFIX_BYTES)
  prefix.set(objectHeader, 0)
  prefix.set(encryptor.header, DRIVE_FILE_BLOB_HEADER_BYTES)
  return { prefix, push: encryptor.push }
}

export async function openFileBlobStreamV1(
  prefix: Uint8Array,
  fileKey: Uint8Array,
  expected: FileBlobContextV1,
): Promise<StreamDecryptor> {
  if (prefix.length !== DRIVE_FILE_BLOB_PREFIX_BYTES) {
    throw new Error(`Drive file-blob prefix must be ${DRIVE_FILE_BLOB_PREFIX_BYTES} bytes`)
  }
  const objectHeader = prefix.subarray(0, DRIVE_FILE_BLOB_HEADER_BYTES)
  const streamHeader = prefix.subarray(DRIVE_FILE_BLOB_HEADER_BYTES)
  const module = await getCryptoWasm()
  const streamKey = fromBase64(module.openDriveFileBlobHeader(
    toBase64(objectHeader),
    toBase64(fileKey),
    expected.fileId,
    expected.collectionId,
    expected.epoch,
  ))
  return newStreamDecryptor(streamKey, streamHeader, objectHeader)
}

export async function encryptFileBlobV1(
  plaintext: Uint8Array,
  fileKey: Uint8Array,
  context: FileBlobContextV1,
): Promise<Uint8Array> {
  const encryptor = await newFileBlobStreamEncryptorV1(fileKey, context)
  const frames: Uint8Array[] = [encryptor.prefix]
  if (plaintext.length === 0) {
    frames.push(encryptor.push(new Uint8Array(0), true))
  } else {
    for (let offset = 0; offset < plaintext.length; offset += PLAIN_CHUNK) {
      const end = Math.min(offset + PLAIN_CHUNK, plaintext.length)
      frames.push(encryptor.push(plaintext.subarray(offset, end), end === plaintext.length))
    }
  }
  const output = new Uint8Array(frames.reduce((size, frame) => size + frame.length, 0))
  let offset = 0
  for (const frame of frames) {
    output.set(frame, offset)
    offset += frame.length
  }
  return output
}

export async function decryptFileBlobV1(
  ciphertext: Uint8Array,
  fileKey: Uint8Array,
  expected: FileBlobContextV1,
): Promise<Uint8Array> {
  if (ciphertext.length < DRIVE_FILE_BLOB_PREFIX_BYTES + ABYTES) {
    throw new Error('Drive file blob is truncated')
  }
  const decryptor = await openFileBlobStreamV1(
    ciphertext.subarray(0, DRIVE_FILE_BLOB_PREFIX_BYTES),
    fileKey,
    expected,
  )
  const plaintext: Uint8Array[] = []
  let offset = DRIVE_FILE_BLOB_PREFIX_BYTES
  let sawFinal = false
  while (offset < ciphertext.length) {
    const end = Math.min(offset + DRIVE_FILE_BLOB_CIPHER_CHUNK, ciphertext.length)
    const result = decryptor.pull(ciphertext.subarray(offset, end))
    plaintext.push(result.plain)
    offset = end
    if (result.isFinal) {
      sawFinal = true
      if (offset !== ciphertext.length) throw new Error('Drive file blob has bytes after FINAL')
    } else if (offset === ciphertext.length) {
      throw new Error('Drive file blob ended before FINAL')
    }
  }
  if (!sawFinal) throw new Error('Drive file blob has no FINAL frame')
  const output = new Uint8Array(plaintext.reduce((size, chunk) => size + chunk.length, 0))
  let plainOffset = 0
  for (const chunk of plaintext) {
    output.set(chunk, plainOffset)
    plainOffset += chunk.length
  }
  return output
}
