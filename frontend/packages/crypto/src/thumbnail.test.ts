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

import { openThumbnailV1, sealThumbnailV1, type ThumbnailImage } from './thumbnail'

const key = new Uint8Array(32).fill(0x41)
const context = { fileId: '11111111-1111-4111-8111-111111111111', epoch: 3, variant: 'sm' as const }
const picture: ThumbnailImage = {
  format: 'jpeg',
  width: 320,
  height: 180,
  image: new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3, 4]),
}

describe('thumbnail envelope', () => {
  it('round-trips through the Rust/WASM implementation, padded to a size bucket', async () => {
    const envelope = await sealThumbnailV1(picture, key, context)
    expect(envelope.length).toBeGreaterThan(4096)
    expect(await openThumbnailV1(envelope, key, context)).toEqual(picture)
  })

  it('opens only as its own file, variant, epoch and key', async () => {
    const envelope = await sealThumbnailV1(picture, key, context)
    await expect(openThumbnailV1(envelope, key, { ...context, variant: 'lg' })).rejects.toThrow()
    await expect(openThumbnailV1(envelope, key, { ...context, epoch: 4 })).rejects.toThrow()
    await expect(
      openThumbnailV1(envelope, key, { ...context, fileId: '33333333-3333-4333-8333-333333333333' }),
    ).rejects.toThrow()
    await expect(openThumbnailV1(envelope, new Uint8Array(32).fill(1), context)).rejects.toThrow()
  })

  it('refuses a picture that is not what it claims', async () => {
    const svg = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"/>')
    await expect(sealThumbnailV1({ ...picture, format: 'png', image: svg }, key, context)).rejects.toThrow()
    await expect(sealThumbnailV1({ ...picture, width: 600 }, key, context)).rejects.toThrow()
  })
})
