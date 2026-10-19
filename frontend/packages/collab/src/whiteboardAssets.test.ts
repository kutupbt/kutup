// @vitest-environment node
import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('@kutup/crypto/whiteboardAsset', () => ({
  // A view into a larger buffer, as WASM hands back a window on its memory.
  sealWhiteboardAssetV1: async () => {
    const memory = new Uint8Array(4096).fill(7)
    memory.set([1, 2, 3], 100)
    return memory.subarray(100, 103)
  },
  openWhiteboardAssetV1: vi.fn(),
}))

const { default: api } = await import('@kutup/session/client')
const { uploadAsset } = await import('./whiteboardAssets')

afterEach(() => vi.restoreAllMocks())

describe('uploadAsset', () => {
  it('uploads exactly the envelope bytes', async () => {
    const put = vi.spyOn(api, 'put').mockResolvedValue({ data: null } as never)
    await uploadAsset({ fileId: 'f', assetId: 'a', generation: 1 }, new Uint8Array([0]), new Uint8Array(32))
    const form = put.mock.calls[0][1] as FormData
    const file = form.get('file') as Blob
    expect(file.size).toBe(3)
    expect([...new Uint8Array(await file.arrayBuffer())]).toEqual([1, 2, 3])
  })
})
