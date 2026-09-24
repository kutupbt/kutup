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

import vectors from '../../../../crates/kutup-crypto/tests/vectors/crypto.json'
import { fromBase64 } from './base64'
import { fileKeyAtV1, sealPreviousFileKeyV1 } from './fileKeyring'
import { createFileRecordV1, openFileRecordV1, rekeyFileRecordV1, wrapFileKeyForV1 } from './fileRecord'

describe('file key chain', () => {
  const ring = vectors.fileKeyring
  const keys = ring.keys.map(fromBase64)

  it('reaches every older generation from the current key', async () => {
    for (let wanted = 1; wanted <= keys.length; wanted++) {
      expect(await fileKeyAtV1(keys.at(-1)!, ring.fileId, keys.length, ring.chain, wanted))
        .toEqual(keys[wanted - 1])
    }
  })

  it('opens nothing from an older key or a broken chain', async () => {
    await expect(fileKeyAtV1(keys[1], ring.fileId, keys.length, ring.chain, 1)).rejects.toThrow()
    await expect(fileKeyAtV1(keys.at(-1)!, ring.fileId, keys.length, ring.chain.slice(1), 1))
      .rejects.toThrow()
    const resealed = await sealPreviousFileKeyV1(keys[0], keys[1], ring.fileId, 2)
    expect(await fileKeyAtV1(keys.at(-1)!, ring.fileId, 3, [
      { generation: 2, previousKeyEnvelope: resealed },
      ring.chain[1],
    ], 1)).toEqual(keys[0])
  })
})

describe('file records across a re-key and a move', () => {
  const metadata = { name: 'notes.md', mimeType: 'text/markdown', size: 5 }
  const folderA = '22222222-2222-4222-8222-222222222222'
  const folderB = '44444444-4444-4444-8444-444444444444'

  it('keeps the metadata and older keys readable in the destination', async () => {
    const keyA = new Uint8Array(32).fill(0x0a)
    const keyA2 = new Uint8Array(32).fill(0x0b)
    const keyB = new Uint8Array(32).fill(0x0c)
    const created = await createFileRecordV1(folderA, 1, keyA, metadata)
    const row = {
      id: created.fileId,
      collectionId: folderA,
      metadataEnvelope: created.metadataEnvelope,
      fileKeyEnvelope: created.fileKeyEnvelope,
      keyEpoch: 1,
      keyGeneration: 1,
      metadataRevision: 1,
    }
    expect((await openFileRecordV1(row, keyA)).metadata).toEqual(metadata)

    // Folder A rotated to epoch 2: the file takes generation 2 there.
    const rekeyed = await rekeyFileRecordV1(row, created.fileKey, 2, keyA2, metadata)
    expect(rekeyed.keyGeneration).toBe(2)
    const atA = {
      ...row,
      keyEpoch: 2,
      keyGeneration: 2,
      fileKeyEnvelope: rekeyed.fileKeyEnvelope,
      metadataEnvelope: rekeyed.metadataEnvelope,
    }
    expect((await openFileRecordV1(atA, keyA2)).fileKey).toEqual(rekeyed.fileKey)

    // Moved to folder B (epoch 1): only the wrap changes.
    const envelope = await wrapFileKeyForV1(atA, rekeyed.fileKey, folderB, 1, keyB)
    const atB = { ...atA, collectionId: folderB, keyEpoch: 1, fileKeyEnvelope: envelope }
    const opened = await openFileRecordV1(atB, keyB)
    expect(opened.metadata).toEqual(metadata)
    // The upload's key is still reachable from B.
    expect(await fileKeyAtV1(opened.fileKey, atB.id, 2, [
      { generation: 2, previousKeyEnvelope: rekeyed.previousKeyEnvelope },
    ], 1)).toEqual(created.fileKey)
    // The wrap is bound to its folder.
    await expect(openFileRecordV1({ ...atB, collectionId: folderA }, keyB)).rejects.toThrow()
  })
})
