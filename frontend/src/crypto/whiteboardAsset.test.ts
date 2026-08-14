// @vitest-environment node
import { describe, expect, it, vi } from 'vitest'

vi.mock('./rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([
    import('node:fs/promises'),
    import('../../public/crypto-wasm/kutup_crypto_wasm.js'),
  ])
  const wasm = await readFile(new URL(
    '../../public/crypto-wasm/kutup_crypto_wasm_bg.wasm',
    import.meta.url,
  ))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: async () => module }
})

import { openWhiteboardAssetV1, sealWhiteboardAssetV1 } from './whiteboardAsset'

const context = {
  fileId: '11111111-1111-4111-8111-111111111111',
  collectionId: '22222222-2222-4222-8222-222222222222',
  assetId: 'asset-abc',
  epoch: 3,
}

describe('whiteboard asset envelope', () => {
  it('round-trips through the canonical Rust/WASM implementation', async () => {
    const key = new Uint8Array(32).fill(0x41)
    const plaintext = new TextEncoder().encode('data:image/png;base64,iVBORw0KGgo=')
    const envelope = await sealWhiteboardAssetV1(plaintext, key, context)
    expect(await openWhiteboardAssetV1(envelope, key, context)).toEqual(plaintext)
  })

  it('rejects key, file, collection, asset, and epoch relocation', async () => {
    const key = new Uint8Array(32).fill(0x41)
    const envelope = await sealWhiteboardAssetV1(
      new TextEncoder().encode('asset payload'),
      key,
      context,
    )
    await expect(openWhiteboardAssetV1(
      envelope,
      new Uint8Array(32).fill(0x42),
      context,
    )).rejects.toThrow()
    await expect(openWhiteboardAssetV1(envelope, key, {
      ...context,
      fileId: '33333333-3333-4333-8333-333333333333',
    })).rejects.toThrow()
    await expect(openWhiteboardAssetV1(envelope, key, {
      ...context,
      collectionId: '44444444-4444-4444-8444-444444444444',
    })).rejects.toThrow()
    await expect(openWhiteboardAssetV1(envelope, key, {
      ...context,
      assetId: 'asset-other',
    })).rejects.toThrow()
    await expect(openWhiteboardAssetV1(envelope, key, {
      ...context,
      epoch: context.epoch + 1,
    })).rejects.toThrow()
  })

  it('rejects tampering and invalid asset identifiers', async () => {
    const key = new Uint8Array(32).fill(0x41)
    const envelope = await sealWhiteboardAssetV1(
      new TextEncoder().encode('asset payload'),
      key,
      context,
    )
    const tampered = envelope.slice()
    tampered[tampered.length - 1] ^= 0x80
    await expect(openWhiteboardAssetV1(tampered, key, context)).rejects.toThrow()
    await expect(sealWhiteboardAssetV1(
      new Uint8Array([1]),
      key,
      { ...context, assetId: '../asset' },
    )).rejects.toThrow()
  })
})
