// Typed whiteboard-asset storage. Rust owns the DriveEnvelopeV1 purpose,
// binding hash, KDF, parser and AEAD; this module only moves opaque bytes.

import axios from 'axios'
import api from './client'
import {
  openWhiteboardAssetV1,
  sealWhiteboardAssetV1,
  type WhiteboardAssetContextV1,
} from '@/crypto/whiteboardAsset'
import { QuotaExceededError } from './errors'

export { QuotaExceededError }

export type { WhiteboardAssetContextV1 } from '@/crypto/whiteboardAsset'

export async function uploadAsset(
  context: WhiteboardAssetContextV1,
  plaintext: Uint8Array,
  collectionKey: Uint8Array,
): Promise<void> {
  const envelope = await sealWhiteboardAssetV1(plaintext, collectionKey, context)
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
  collectionKey: Uint8Array,
): Promise<Uint8Array> {
  const res = await api.get(`/files/${context.fileId}/assets/${context.assetId}`, {
    responseType: 'arraybuffer',
  })
  return openWhiteboardAssetV1(
    new Uint8Array(res.data as ArrayBuffer),
    collectionKey,
    context,
  )
}
