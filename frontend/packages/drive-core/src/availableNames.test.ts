// @vitest-environment node
import { beforeEach, describe, expect, it, vi } from 'vitest'
vi.mock('@kutup/crypto/rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([
    import('node:fs/promises'),
    import('../../../wasm/crypto-wasm/kutup_crypto_wasm.js'),
  ])
  const wasm = await readFile(new URL('../../../wasm/crypto-wasm/kutup_crypto_wasm_bg.wasm', import.meta.url))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: () => Promise.resolve(module) }
})
const { post } = vi.hoisted(() => ({ post: vi.fn() }))
vi.mock('@kutup/session/client', () => ({ default: { post } }))

import type { Folder } from './model'
import { atTopLevel, findAvailableName, inFolder, nameHashIn, numberedNames, randomNameHash } from './names'

const folder = {
  id: '11111111-1111-4111-8111-111111111111',
  source: 'owned',
  key: new Uint8Array(32).fill(7),
  keyEpoch: 1,
} as Folder

/** A server where `taken` (names) are in the folder. */
async function serverWith(place: Parameters<typeof nameHashIn>[0], taken: string[]) {
  const hashes = new Set(await Promise.all(taken.map((n) => nameHashIn(place, n))))
  post.mockImplementation((_path: string, body: { hashes: string[] }) => {
    expect(body.hashes.length).toBeGreaterThan(0)
    expect(body.hashes.length).toBeLessThanOrEqual(10)
    return { data: { available: body.hashes.filter((h) => !hashes.has(h)) } }
  })
}

beforeEach(() => {
  post.mockReset()
})

describe('numbered names', () => {
  it('start at the name, number before the extension and count on', () => {
    expect(numberedNames('a.txt', 0, 3)).toEqual(['a.txt', 'a (2).txt', 'a (3).txt'])
    expect(numberedNames('a.txt', 1, 2)).toEqual(['a (2).txt', 'a (3).txt'])
    expect(numberedNames('a (5).txt', 0, 2)).toEqual(['a (5).txt', 'a (6).txt'])
    expect(numberedNames('Photos', 10, 1)).toEqual(['Photos (11)'])
  })
})

describe('an available name', () => {
  it('is asked of the server ten at a time, in the folder', async () => {
    await serverWith(inFolder(folder), ['Report.pdf', 'report (2).PDF'])
    const free = await findAvailableName(inFolder(folder), 'Report.pdf', { skipName: true })
    expect(free.name).toBe('Report (3).pdf')
    expect(free.hash).toBe(await nameHashIn(inFolder(folder), 'Report (3).pdf'))
    expect(post).toHaveBeenCalledTimes(1)
    expect(post.mock.calls[0][0]).toBe(`/collections/${folder.id}/available-hashes`)
  })

  it('goes on to the next batch when ten are taken', async () => {
    const taken = numberedNames('a.txt', 0, 12)
    await serverWith(inFolder(folder), taken)
    expect((await findAvailableName(inFolder(folder), 'a.txt')).name).toBe('a (13).txt')
    expect(post).toHaveBeenCalledTimes(2)
  })

  it('is the name itself when free, at the top level too', async () => {
    const top = atTopLevel(new Uint8Array(32).fill(3))
    await serverWith(top, [])
    expect((await findAvailableName(top, 'Projects')).name).toBe('Projects')
    expect(post.mock.calls[0][0]).toBe('/drive/top-level-available-hashes')
  })
})

describe('a random name hash', () => {
  it('looks like any other, and is never the same twice', () => {
    const a = randomNameHash()
    expect(a).toMatch(/^[0-9a-f]{64}$/)
    expect(randomNameHash()).not.toBe(a)
  })
})
