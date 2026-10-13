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

import { AxiosError, type AxiosResponse } from 'axios'
import { QueryClient } from '@tanstack/react-query'
import type { DriveIdentity } from './identity'
import { atTopLevel, nameHashIn } from './names'
import { RestoreCancelled, restoreEntry, type TrashEntry } from './trash'

const me = { userId: '33333333-3333-4333-8333-333333333333', masterKey: new Uint8Array(32).fill(9) } as DriveIdentity
const top = atTopLevel(me.masterKey)

const conflict = (data: object) =>
  new AxiosError('conflict', 'ERR_BAD_REQUEST', undefined, undefined, { status: 409, data } as AxiosResponse)

/** A folder in the trash whose parent is gone: it comes back at the top level. */
const folder: TrashEntry = {
  type: 'folder',
  id: '44444444-4444-4444-8444-444444444444',
  name: 'Projects',
  kind: 'folder',
  size: null,
  deletedAt: '2026-10-13T00:00:00Z',
  renamable: { key: new Uint8Array(32).fill(5), keyEpoch: 1, nameRevision: 1, ownerUserId: me.userId, parentCollectionId: null },
}

beforeEach(() => {
  post.mockReset()
})

describe('restoring at the top level', () => {
  it('names it there under its own name when that is free', async () => {
    post.mockResolvedValue({ data: {} })
    await restoreEntry(folder, me, new QueryClient())
    expect(post).toHaveBeenCalledTimes(1)
    expect(post.mock.calls[0]).toEqual([`/trash/${folder.id}/restore`, { nameHash: await nameHashIn(top, 'Projects') }])
  })

  it('offers the first free name when its own is taken, and renames it on the way back', async () => {
    const taken = new Set([await nameHashIn(top, 'Projects'), await nameHashIn(top, 'Projects (2)')])
    let restores = 0
    post.mockImplementation((path: string, body?: { hashes?: string[] }) => {
      if (path.endsWith('available-hashes')) return { data: { available: body!.hashes!.filter((h) => !taken.has(h)) } }
      if (restores++ === 0) throw conflict({ code: 'name_taken', holder: { kind: 'folder', id: 'x' } })
      return { data: {} }
    })
    const ask = vi.fn().mockResolvedValue(true)
    await restoreEntry(folder, me, new QueryClient(), ask)
    expect(ask).toHaveBeenCalledWith({ name: 'Projects', suggested: 'Projects (3)' })
    const last = post.mock.calls.at(-1)!
    expect(last[0]).toBe(`/trash/${folder.id}/restore`)
    expect(last[1]).toMatchObject({ nameHash: await nameHashIn(top, 'Projects (3)'), nameRevision: 2 })
    expect(typeof last[1].nameEnvelope).toBe('string')
  })

  it('leaves it in the trash when the person says so', async () => {
    post.mockImplementation((path: string, body?: { hashes?: string[] }) => {
      if (path.endsWith('available-hashes')) return { data: { available: body!.hashes } }
      throw conflict({ code: 'name_taken' })
    })
    await expect(restoreEntry(folder, me, new QueryClient(), () => Promise.resolve(false))).rejects.toBeInstanceOf(RestoreCancelled)
  })

  it('names a folder whose parent went meanwhile at the top level (nameNeeded)', async () => {
    const inside = { ...folder, renamable: { ...folder.renamable!, parentCollectionId: '55555555-5555-4555-8555-555555555555' } }
    let restores = 0
    post.mockImplementation((path: string, body?: { hashes?: string[] }) => {
      if (path.endsWith('/top-level-available-hashes')) return { data: { available: body!.hashes } }
      if (restores++ === 0) throw conflict({ code: 'nameNeeded' })
      return { data: {} }
    })
    await restoreEntry(inside, me, new QueryClient())
    expect(post.mock.calls[0]).toEqual([`/trash/${folder.id}/restore`, undefined])
    expect(post.mock.calls.at(-1)).toEqual([`/trash/${folder.id}/restore`, { nameHash: await nameHashIn(top, 'Projects') }])
  })
})
