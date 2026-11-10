// @vitest-environment node
import { describe, expect, it, vi } from 'vitest'

vi.mock('./rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([
    import('node:fs/promises'),
    import('../../../wasm/crypto-wasm/kutup_crypto_wasm.js'),
  ])
  const wasm = await readFile(new URL('../../../wasm/crypto-wasm/kutup_crypto_wasm_bg.wasm', import.meta.url))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: async () => module }
})

import { DRIVE_BLOCK_SIZE, newDriveBlockEncryptor, newRevisionId, openDriveFile, openDriveObject, sealDriveFile } from './driveBlocks'
import { openFileMetadataDraftV1, sealFileMetadataDraftV1 } from './fileRecord'

const fileKey = new Uint8Array(32).fill(0x21)
const fileId = '11111111-1111-4111-8111-111111111111'
const signer = { masterKey: new Uint8Array(32).fill(0x09), accountId: '22222222-2222-4222-8222-222222222222' }

function bytes(length: number, seed = 1): Uint8Array {
  const out = new Uint8Array(length)
  for (let i = 0; i < length; i++) out[i] = (i * 31 + seed) & 0xff
  return out
}

describe('Drive block objects', () => {
  it('opens the current content only against its commitment and size', async () => {
    const revisionId = newRevisionId()
    const plain = bytes(1000)
    const sealed = await sealDriveFile(plain, fileKey, { fileId, revisionId, generation: 2 }, signer)
    const expected = { fileId, generation: 2 }
    expect(await openDriveFile(sealed.bytes, fileKey, expected, sealed.content, plain.length)).toEqual(plain)
    await expect(openDriveFile(sealed.bytes, fileKey, expected, sealed.content, plain.length + 1)).rejects.toThrow()
    await expect(openDriveFile(sealed.bytes, fileKey, { ...expected, generation: 1 }, sealed.content, plain.length)).rejects.toThrow()
    // Other content under the same header: its manifest is another.
    const other = await sealDriveFile(bytes(1000, 7), fileKey, { fileId, revisionId, generation: 2 }, signer)
    await expect(openDriveFile(other.bytes, fileKey, expected, sealed.content, plain.length)).rejects.toThrow()
  })

  it('opens a history version by its own revision id, and the original by its header', async () => {
    const revisionId = newRevisionId()
    for (const size of [0, 5, DRIVE_BLOCK_SIZE, DRIVE_BLOCK_SIZE + 3]) {
      const plain = bytes(size)
      const sealed = await sealDriveFile(plain, fileKey, { fileId, revisionId, generation: 1 }, signer)
      expect(await openDriveObject(sealed.bytes, fileKey, { fileId, generation: 1, revisionId })).toEqual(plain)
      expect(await openDriveObject(sealed.bytes, fileKey, { fileId, generation: 1, revisionId: null })).toEqual(plain)
    }
    const sealed = await sealDriveFile(bytes(9), fileKey, { fileId, revisionId, generation: 1 }, signer)
    await expect(openDriveObject(sealed.bytes, fileKey, { fileId, generation: 1, revisionId: newRevisionId() })).rejects.toThrow()
    const cut = sealed.bytes.slice(0, sealed.bytes.length - 1)
    await expect(openDriveObject(cut, fileKey, { fileId, generation: 1, revisionId })).rejects.toThrow()
  })

  it('gives the same bytes block by block as sealed whole', async () => {
    const revisionId = newRevisionId()
    const plain = bytes(DRIVE_BLOCK_SIZE + 10)
    const encryptor = await newDriveBlockEncryptor(fileKey, { fileId, revisionId, generation: 1 }, plain.length)
    const parts = [encryptor.header]
    for (let i = 0; i < encryptor.blockCount; i++) {
      const start = i * DRIVE_BLOCK_SIZE
      parts.push(encryptor.sealNext(plain.subarray(start, start + encryptor.plainLength(i))))
    }
    const { tail, content } = encryptor.finish(signer)
    encryptor.free()
    parts.push(tail)
    const object = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
    let at = 0
    for (const part of parts) {
      object.set(part, at)
      at += part.length
    }
    expect(object.length).toBe(encryptor.objectLength)
    expect(await openDriveFile(object, fileKey, { fileId, generation: 1 }, content, plain.length)).toEqual(plain)
  })
})

describe('upload drafts', () => {
  it('opens only for its own revision, never as the file metadata', async () => {
    const revisionId = newRevisionId()
    const draft = { name: 'a.txt', mimeType: 'text/plain', size: 3, sha256: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=' }
    const envelope = await sealFileMetadataDraftV1(fileId, 1, revisionId, fileKey, draft)
    expect(await openFileMetadataDraftV1(envelope, fileId, 1, revisionId, fileKey)).toEqual(draft)
    await expect(openFileMetadataDraftV1(envelope, fileId, 1, newRevisionId(), fileKey)).rejects.toThrow()
  })
})
