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

import { readFile } from 'node:fs/promises'
import { testRoots } from './accountRoots.testing'
import { fromBase64 } from './base64'
import {
  checkServedRecord,
  DRIVE_BLOCK_SIZE,
  newDriveBlockEncryptor,
  newRevisionId,
  openDriveFile,
  openDriveObject,
  openRevisionContent,
  resolveServed,
  sealDriveFile,
  sealRevisionContent,
} from './driveBlocks'
import { openFileMetadataDraftV1, sealFileMetadataDraftV1 } from './fileRecord'

const fileKey = new Uint8Array(32).fill(0x21)
const fileId = '11111111-1111-4111-8111-111111111111'
const signer = { identityRoot: testRoots(0x09).identityRoot, accountId: '22222222-2222-4222-8222-222222222222', incarnationId: '05'.repeat(32) }

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

  it('opens any other revision only against its sealed content record', async () => {
    const revisionId = newRevisionId()
    for (const size of [0, 5, DRIVE_BLOCK_SIZE, DRIVE_BLOCK_SIZE + 3]) {
      const plain = bytes(size)
      const sealed = await sealDriveFile(plain, fileKey, { fileId, revisionId, generation: 1 }, signer)
      const expected = { fileId, generation: 1, revisionId, revisionContentEnvelope: sealed.revisionContentEnvelope }
      expect(await openDriveObject(sealed.bytes, fileKey, expected)).toEqual(plain)
      expect(await openRevisionContent(sealed.revisionContentEnvelope, fileKey, { fileId, revisionId, generation: 1 })).toEqual({
        content: sealed.content,
        size,
      })
    }
    const sealed = await sealDriveFile(bytes(9), fileKey, { fileId, revisionId, generation: 1 }, signer)
    const expected = { fileId, generation: 1, revisionId, revisionContentEnvelope: sealed.revisionContentEnvelope }
    // No record: nothing opens (the object never vouches for itself).
    await expect(openDriveObject(sealed.bytes, fileKey, { ...expected, revisionContentEnvelope: null })).rejects.toThrow()
    // The record of another revision id, or under another generation.
    await expect(openDriveObject(sealed.bytes, fileKey, { ...expected, revisionId: newRevisionId() })).rejects.toThrow()
    await expect(openDriveObject(sealed.bytes, fileKey, { ...expected, generation: 2 })).rejects.toThrow()
    const cut = sealed.bytes.slice(0, sealed.bytes.length - 1)
    await expect(openDriveObject(cut, fileKey, expected)).rejects.toThrow()
    // A co-editor's own object under the same revision id: its manifest is
    // not the one the record commits to.
    const forged = await sealDriveFile(bytes(9, 5), fileKey, { fileId, revisionId, generation: 1 }, signer)
    await expect(openDriveObject(forged.bytes, fileKey, expected)).rejects.toThrow()
    // A record of the right revision with another size.
    const wrongSize = await sealRevisionContent(fileKey, { fileId, revisionId, generation: 1 }, sealed.content, 10)
    await expect(openDriveObject(sealed.bytes, fileKey, { ...expected, revisionContentEnvelope: wrongSize })).rejects.toThrow()
  })

  it('refuses a current content whose served record disagrees with the metadata', async () => {
    const revisionId = newRevisionId()
    const sealed = await sealDriveFile(bytes(9), fileKey, { fileId, revisionId, generation: 1 }, signer)
    const current = { fileId, generation: 1, content: sealed.content, size: 9 }
    await checkServedRecord(fileKey, current, revisionId, sealed.revisionContentEnvelope)
    await checkServedRecord(fileKey, current, null, null)
    await expect(checkServedRecord(fileKey, { ...current, size: 8 }, revisionId, sealed.revisionContentEnvelope)).rejects.toThrow()
    await expect(checkServedRecord(fileKey, current, newRevisionId(), sealed.revisionContentEnvelope)).rejects.toThrow()
  })

  it('opens a served revision only when it is the one the metadata names', async () => {
    // Two genuine revisions of the file: the server may serve either.
    const named = newRevisionId()
    const other = newRevisionId()
    const first = await sealDriveFile(bytes(9), fileKey, { fileId, revisionId: named, generation: 1 }, signer)
    const second = await sealDriveFile(bytes(9, 3), fileKey, { fileId, revisionId: other, generation: 1 }, signer)
    const asked = { fileId, generation: 1, revisionId: named, served: true as const }
    const expected = await resolveServed(fileKey, asked, { revisionId: named, revisionContentEnvelope: first.revisionContentEnvelope })
    expect(await openDriveObject(first.bytes, fileKey, expected)).toEqual(bytes(9))
    // Another genuine revision, named as itself: refused before anything opens.
    await expect(resolveServed(fileKey, asked, { revisionId: other, revisionContentEnvelope: second.revisionContentEnvelope })).rejects.toThrow()
    await expect(resolveServed(fileKey, asked, { revisionId: null, revisionContentEnvelope: first.revisionContentEnvelope })).rejects.toThrow()
    // Named as the asked one, but its record and bytes are the other's.
    const lying = await resolveServed(fileKey, asked, { revisionId: named, revisionContentEnvelope: second.revisionContentEnvelope })
    await expect(openDriveObject(second.bytes, fileKey, lying)).rejects.toThrow()
  })

  it('matches the Rust revision content vectors', async () => {
    const vectors = JSON.parse(
      await readFile(new URL('../../../../crates/kutup-crypto/tests/vectors/revision-content-v1.json', import.meta.url), 'utf8'),
    ) as {
      fileKey: string
      fileId: string
      revisionId: string
      generation: number
      content: { revisionId: string; manifestSha256: string; size: number }
      envelope: string
      negatives: { name: string; envelope: string; fileId?: string; revisionId?: string; generation?: number }[]
    }
    const key = fromBase64(vectors.fileKey)
    const at = { fileId: vectors.fileId, revisionId: vectors.revisionId, generation: vectors.generation }
    expect(await openRevisionContent(vectors.envelope, key, at)).toEqual({
      content: { revisionId: vectors.content.revisionId, manifestSha256: vectors.content.manifestSha256 },
      size: vectors.content.size,
    })
    for (const negative of vectors.negatives) {
      await expect(
        openRevisionContent(negative.envelope, key, {
          fileId: negative.fileId ?? at.fileId,
          revisionId: negative.revisionId ?? at.revisionId,
          generation: negative.generation ?? at.generation,
        }),
        negative.name,
      ).rejects.toThrow()
    }
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
    expect(await openFileMetadataDraftV1(envelope, fileId, 1, revisionId, fileKey)).toEqual({ v: 2, ...draft })
    await expect(openFileMetadataDraftV1(envelope, fileId, 1, newRevisionId(), fileKey)).rejects.toThrow()
  })
})
