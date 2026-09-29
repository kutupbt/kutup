// Typed per-file asset storage (whiteboard images, pictures in notes). Rust
// owns the DriveEnvelopeV1 purpose, binding hash, KDF, parser and AEAD; this
// module only moves opaque bytes. `base` is where the file's calls go: here
// (`/files/:id`) or, for a file on another server, its relay through this
// one (docs/plans/collab-federation.md).

import axios from 'axios'
import api from '@kutup/session/client'
import { localBase } from './api'
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
  base = localBase(context.fileId),
): Promise<void> {
  const envelope = await sealWhiteboardAssetV1(plaintext, fileKey, context)
  const fd = new FormData()
  fd.append('file', new Blob([envelope.buffer as ArrayBuffer], { type: 'application/octet-stream' }))
  try {
    await api.put(`${base}/assets/${context.assetId}`, fd)
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
  base = localBase(context.fileId),
): Promise<Uint8Array> {
  const res = await api.get(`${base}/assets/${context.assetId}`, {
    responseType: 'arraybuffer',
  })
  const envelope = new Uint8Array(res.data as ArrayBuffer)
  const keyFor = (generation: number) =>
    generation === context.generation || !keyAt ? Promise.resolve(fileKey) : keyAt(generation)
  // Sealed under the generation the server records for it; opening checks it.
  const header = res.headers['x-kutup-key-generation'] as string | undefined
  const stored = Number(header)
  if (header !== undefined && Number.isSafeInteger(stored) && stored >= 1 && stored <= context.generation) {
    return openWhiteboardAssetV1(envelope, await keyFor(stored), { ...context, generation: stored })
  }
  // Not said (a file on another server, through the relay): the file's keys,
  // newest first; the envelope opens under exactly one.
  let failure: unknown = null
  for (let generation = context.generation; generation >= 1 && (generation === context.generation || keyAt); generation--) {
    try {
      return await openWhiteboardAssetV1(envelope, await keyFor(generation), { ...context, generation })
    } catch (error) {
      failure = error
    }
  }
  throw failure ?? new Error('asset could not be opened')
}
