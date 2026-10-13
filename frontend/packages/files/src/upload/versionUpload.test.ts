// @vitest-environment node
import { describe, expect, it, vi } from 'vitest'
vi.mock('@kutup/crypto/rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([
    import('node:fs/promises'),
    import('../../../../wasm/crypto-wasm/kutup_crypto_wasm.js'),
  ])
  const wasm = await readFile(new URL('../../../../wasm/crypto-wasm/kutup_crypto_wasm_bg.wasm', import.meta.url))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: () => Promise.resolve(module) }
})

import { createFileRecordV1, renameFileRecordV1, type FileMetadataV1 } from '@kutup/crypto'
import type { PendingUpload } from './pendingUploads'
import {
  pendingUploadName,
  uploadIdOf,
  versionRefusalOf,
  versionUploadMetadata,
  VersionConflict,
  VersionUploading,
} from './streamUpload'

const refusal = (status: number, body: unknown) => ({
  originalResponse: { getStatus: () => status, getBody: () => (typeof body === 'string' ? body : JSON.stringify(body)) },
})

describe('a new version over tus', () => {
  it('names the file, its next metadata and, when known, the content hash and base', () => {
    const sealed = { metadataEnvelope: 'env', metadataRevision: 4 }
    expect(versionUploadMetadata({ fileId: 'f1' }, sealed, {})).toEqual({
      versionOf: 'f1',
      metadataEnvelope: 'env',
      metadataRevision: '4',
    })
    expect(versionUploadMetadata({ fileId: 'f1' }, sealed, { contentHash: 'ab'.repeat(32), basedOn: 'original' })).toEqual({
      versionOf: 'f1',
      metadataEnvelope: 'env',
      metadataRevision: '4',
      contentHash: 'ab'.repeat(32),
      basedOn: 'original',
    })
  })

  it('is remembered with the metadata revision it brings, and read back with it', async () => {
    const collectionKey = new Uint8Array(32).fill(4)
    const first: FileMetadataV1 = { name: 'report.pdf', mimeType: 'application/pdf', size: 3, sha256: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=' }
    const created = await createFileRecordV1('11111111-1111-4111-8111-111111111111', 1, collectionKey, first)
    const next: FileMetadataV1 = { ...first, size: 9, sha256: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' }
    const sealed = await renameFileRecordV1(
      { id: created.fileId, keyGeneration: 1, metadataRevision: 1 },
      created.fileKey,
      next,
    )
    const upload: PendingUpload = {
      fileId: created.fileId,
      owner: 'me',
      uploadUrl: 'https://drive.localhost/api/uploads/22222222-2222-4222-8222-222222222222',
      size: 9,
      lastModified: 1,
      collectionId: '11111111-1111-4111-8111-111111111111',
      keyEpoch: 1,
      fileKeyEnvelope: created.fileKeyEnvelope,
      metadataEnvelope: sealed.metadataEnvelope,
      prefix: '',
      startedAt: 0,
      updatedAt: 0,
      version: { keyGeneration: 1, metadataRevision: sealed.metadataRevision },
    }
    expect(sealed.metadataRevision).toBe(2)
    expect(await pendingUploadName(upload, collectionKey)).toEqual(next)
    // Read as a new file's (revision 1), it does not open.
    await expect(pendingUploadName({ ...upload, version: undefined }, collectionKey)).rejects.toThrow()
    expect(uploadIdOf(upload.uploadUrl)).toBe('22222222-2222-4222-8222-222222222222')
  })
})

describe('a refused version', () => {
  it('tells a changed file apart from another open upload', () => {
    expect(versionRefusalOf(refusal(409, { code: 'version_conflict', error: 'x' }))).toEqual(new VersionConflict('version'))
    expect((versionRefusalOf(refusal(409, { code: 'version_conflict' })) as VersionConflict).kind).toBe('version')
    expect((versionRefusalOf(refusal(409, { code: 'revision_conflict' })) as VersionConflict).kind).toBe('revision')
    expect((versionRefusalOf(refusal(409, { error: 'file key changed' })) as VersionConflict).kind).toBe('key')
    expect((versionRefusalOf(refusal(409, { error: 'file needs a re-key' })) as VersionConflict).kind).toBe('key')
    const ours = versionRefusalOf(refusal(409, { code: 'versionUploading', uploadId: 'u1', idleSeconds: 42 }))
    expect(ours).toBeInstanceOf(VersionUploading)
    expect((ours as VersionUploading).uploadId).toBe('u1')
    expect((ours as VersionUploading).idleSeconds).toBe(42)
    expect((versionRefusalOf(refusal(409, { code: 'versionUploading' })) as VersionUploading).uploadId).toBeNull()
  })

  it('is nothing for other answers', () => {
    expect(versionRefusalOf(refusal(409, { code: 'name_taken' }))).toBeNull()
    expect(versionRefusalOf(refusal(413, { code: 'version_conflict' }))).toBeNull()
    expect(versionRefusalOf(refusal(409, 'not json'))).toBeNull()
    expect(versionRefusalOf(new Error('network'))).toBeNull()
  })
})
