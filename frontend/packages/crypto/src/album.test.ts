// @vitest-environment node
import { describe, expect, it, vi } from 'vitest'

vi.mock('./rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([
    import('node:fs/promises'),
    import('../../../wasm/crypto-wasm/kutup_crypto_wasm.js'),
  ])
  const wasm = await readFile(new URL(
    '../../../wasm/crypto-wasm/kutup_crypto_wasm_bg.wasm',
    import.meta.url,
  ))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: async () => module }
})

import { openAlbumFileKeyV1, sealAlbumFileKeyV1 } from './album'

const fileKey = new Uint8Array(32).fill(0x55)
const albumKey = new Uint8Array(32).fill(0x77)
const at = { fileId: '11111111-1111-4111-8111-111111111111', albumId: '22222222-2222-4222-8222-222222222222', albumEpoch: 2, generation: 3 }

describe('a photo in an album', () => {
  it('opens only as its file, album, epoch and generation', async () => {
    const sealed = await sealAlbumFileKeyV1(fileKey, albumKey, at)
    expect(await openAlbumFileKeyV1(sealed, albumKey, at)).toEqual(fileKey)
    await expect(openAlbumFileKeyV1(sealed, albumKey, { ...at, albumEpoch: 1 })).rejects.toThrow()
    await expect(openAlbumFileKeyV1(sealed, albumKey, { ...at, generation: 4 })).rejects.toThrow()
    await expect(openAlbumFileKeyV1(sealed, albumKey, { ...at, albumId: at.fileId })).rejects.toThrow()
  })
})
