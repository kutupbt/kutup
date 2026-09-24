// Typed whiteboard-asset storage. Rust owns the DriveEnvelopeV1 purpose,
// binding hash, KDF, parser and AEAD; this module only moves opaque bytes.

import axios from 'axios'
import api from '@kutup/session/client'
import {
  openWhiteboardAssetV1,
  sealWhiteboardAssetV1,
  type WhiteboardAssetContextV1,
} from '@kutup/crypto/whiteboardAsset'
import { QuotaExceededError } from '@kutup/session/errors'

export { QuotaExceededError }

export type { WhiteboardAssetContextV1 } from '@kutup/crypto/whiteboardAsset'

export async function uploadAsset(
  context: WhiteboardAssetContextV1,
  plaintext: Uint8Array,
  fileKey: Uint8Array,
): Promise<void> {
  const envelope = await sealWhiteboardAssetV1(plaintext, fileKey, context)
  const fd = new FormData()
  fd.append('file', new Blob([envelope.buffer as ArrayBuffer], { type: 'application/octet-stream' }))
  try {
    await api.put(`/files/${context.fileId}/assets/${context.assetId}`, fd)
  } catch (err) {
    if (axios.isAxiosError(err) && err.response?.status === 413) {
      throw new QuotaExceededError()
    }
    throw err
  }
}

export async function fetchAsset(
  context: WhiteboardAssetContextV1,
  fileKey: Uint8Array,
  /** The file key of an older generation: an asset stored before a re-key. */
  keyAt?: (generation: number) => Promise<Uint8Array>,
): Promise<Uint8Array> {
  const res = await api.get(`/files/${context.fileId}/assets/${context.assetId}`, {
    responseType: 'arraybuffer',
  })
  // Sealed under the generation the server records for it; opening checks it.
  const stored = Number(res.headers['x-kutup-key-generation'] ?? context.generation)
  const generation = Number.isSafeInteger(stored) && stored >= 1 && stored <= context.generation
    ? stored
    : context.generation
  const key = generation === context.generation || !keyAt ? fileKey : await keyAt(generation)
  return openWhiteboardAssetV1(new Uint8Array(res.data as ArrayBuffer), key, { ...context, generation })
}
