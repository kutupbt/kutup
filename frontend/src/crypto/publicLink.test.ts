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

import {
  openPublicLinkCollectionKeyV1,
  sealPublicLinkCollectionKeyV1,
} from './publicLink'

const context = {
  collectionId: '22222222-2222-4222-8222-222222222222',
  ownerUserId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  epoch: 3,
}

describe('public-link collection-key envelope', () => {
  it('round-trips through the canonical Rust/WASM implementation', async () => {
    const collectionKey = new Uint8Array(32).fill(0x41)
    const linkKey = new Uint8Array(32).fill(0x52)
    const envelope = await sealPublicLinkCollectionKeyV1(collectionKey, linkKey, context)
    expect(await openPublicLinkCollectionKeyV1(envelope, linkKey, context))
      .toEqual(collectionKey)
  })

  it('rejects a wrong fragment key', async () => {
    const envelope = await sealPublicLinkCollectionKeyV1(
      new Uint8Array(32).fill(0x41),
      new Uint8Array(32).fill(0x52),
      context,
    )
    await expect(openPublicLinkCollectionKeyV1(
      envelope,
      new Uint8Array(32).fill(0x53),
      context,
    )).rejects.toThrow()
  })

  it('rejects collection, owner, and epoch relocation', async () => {
    const collectionKey = new Uint8Array(32).fill(0x41)
    const linkKey = new Uint8Array(32).fill(0x52)
    const envelope = await sealPublicLinkCollectionKeyV1(collectionKey, linkKey, context)
    await expect(openPublicLinkCollectionKeyV1(envelope, linkKey, {
      ...context,
      collectionId: '33333333-3333-4333-8333-333333333333',
    })).rejects.toThrow()
    await expect(openPublicLinkCollectionKeyV1(envelope, linkKey, {
      ...context,
      ownerUserId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    })).rejects.toThrow()
    await expect(openPublicLinkCollectionKeyV1(envelope, linkKey, {
      ...context,
      epoch: context.epoch + 1,
    })).rejects.toThrow()
  })
})
