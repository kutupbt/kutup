// Encrypt + upload / fetch + decrypt of per-whiteboard binary asset blobs
// (Excalidraw embedded image binaries, today). The server stores opaque
// ciphertext at S3 path files/{kutupFileId}/assets/{assetId}; the binding
// to the parent file means asset blobs are GC'd when the .excalidraw is
// deleted (FilesHandler.Delete + Storage.DeletePrefix).
//
// At-rest format: nonce(24) || ciphertext-and-tag (XChaCha20-Poly1305-IETF).
// Key:           HKDF-SHA256(collectionMaster, salt="kutup/file-content/v1",
//                            info=kutupFileId)  — same key as the WS frames.
// AAD:           "kutup-asset/v1" || assetId   — binds the ciphertext to its
//                                                content-addressed slot, so
//                                                a server admin can't swap
//                                                blobs between assets.

import _sodium from 'libsodium-wrappers-sumo'
import api from './client'
import { deriveContentKey } from '@/collab/cryptoFrame'

interface AeadXChaCha20Poly1305Ietf {
  crypto_aead_xchacha20poly1305_ietf_encrypt(
    message: Uint8Array, additionalData: Uint8Array | null,
    secretNonce: null, publicNonce: Uint8Array, key: Uint8Array,
  ): Uint8Array
  crypto_aead_xchacha20poly1305_ietf_decrypt(
    secretNonce: null, ciphertext: Uint8Array, additionalData: Uint8Array | null,
    publicNonce: Uint8Array, key: Uint8Array,
  ): Uint8Array
}
const aead = _sodium as unknown as AeadXChaCha20Poly1305Ietf

const AAD_PREFIX = 'kutup-asset/v1'

function buildAAD(assetId: string): Uint8Array {
  return new TextEncoder().encode(AAD_PREFIX + assetId)
}

/** Encrypt a whiteboard asset (e.g. an Excalidraw image dataURL) and upload
 *  to /api/files/:fileId/assets/:assetId. Idempotent: re-uploading the same
 *  fileId+assetId is fine — assets are content-addressed by Excalidraw's
 *  SHA1 fileId so the bytes never change for a given assetId. */
export async function uploadAsset(
  kutupFileId: string,
  assetId: string,
  plaintext: Uint8Array,
  collectionMaster: Uint8Array,
): Promise<void> {
  await _sodium.ready
  const key = await deriveContentKey(collectionMaster, kutupFileId)
  const nonce = _sodium.randombytes_buf(24)
  const ct = aead.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext, buildAAD(assetId), null, nonce, key,
  )
  const blob = new Uint8Array(nonce.length + ct.length)
  blob.set(nonce, 0)
  blob.set(ct, nonce.length)

  const fd = new FormData()
  fd.append('file', new Blob([blob.buffer as ArrayBuffer], { type: 'application/octet-stream' }))
  await api.put(`/files/${kutupFileId}/assets/${assetId}`, fd)
}

/** Fetch + decrypt an asset. Returns the plaintext bytes (the dataURL
 *  string, in the whiteboard case). Throws on HTTP error or AEAD failure. */
export async function fetchAsset(
  kutupFileId: string,
  assetId: string,
  collectionMaster: Uint8Array,
): Promise<Uint8Array> {
  await _sodium.ready
  const res = await api.get(`/files/${kutupFileId}/assets/${assetId}`, { responseType: 'arraybuffer' })
  const blob = new Uint8Array(res.data as ArrayBuffer)
  if (blob.length < 24 + 16) throw new Error('asset: ciphertext too short')
  const nonce = blob.subarray(0, 24)
  const ct = blob.subarray(24)
  const key = await deriveContentKey(collectionMaster, kutupFileId)
  return aead.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, buildAAD(assetId), nonce, key)
}
