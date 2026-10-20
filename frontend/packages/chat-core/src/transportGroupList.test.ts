import { beforeEach, describe, expect, it, vi } from 'vitest'

// The account's group list through the web head client
// (docs/plans/pairwise-groups.md §5): held to the verified index on reads,
// each entry written with the next head.

const http = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn() }))
vi.mock('@kutup/session/client', () => ({ default: { get: http.get, put: http.put } }))
vi.mock('@kutup/session/store', () => ({ getSession: () => ({ userId: 'u1', masterKey: new Uint8Array(32), envelopeBinding: 'b' }) }))

const head = vi.hoisted(() => ({ index: (_attempt: number): [string, number][] => [], covered: true, reads: 0 }))
vi.mock('@kutup/session/accountHead', async () => {
  const actual = await vi.importActual<typeof import('@kutup/session/accountHead')>('@kutup/session/accountHead')
  const index = (attempt: number) => new actual.VerifiedIndex('chatGroups', head.covered, head.index(attempt), null)
  const client = {
    verifiedIndex: () => Promise.resolve(index(++head.reads)),
    listedWrite: async <T,>(_s: string, edit: (i: InstanceType<typeof actual.VerifiedIndex>, a: number) => Promise<{ send: (h: string) => Promise<T> } | null>) => {
      for (let attempt = 1; ; attempt++) {
        const change = await edit(index(attempt), attempt)
        if (!change) return undefined
        try {
          return await change.send(`head-${attempt}`)
        } catch (error) {
          const code = (error as { response?: { data?: { code?: string } } }).response?.data?.code
          if ((code === 'head_conflict' || code === 'revision_conflict') && attempt < 5) continue
          throw error
        }
      }
    },
  }
  return { ...actual, accountHead: () => Promise.resolve(client) }
})

import { NotInVerifiedIndexError } from '@kutup/session/accountHead'
import { ApiChatTransport } from './transport'

beforeEach(() => {
  http.get.mockReset()
  http.put.mockReset()
  Object.assign(head, { index: () => [], covered: true, reads: 0 })
})

describe('the group list under the account head', () => {
  it('reads exactly the entries the head lists, at their revisions', async () => {
    head.index = () => [['a', 2], ['b', 1]]
    http.get.mockResolvedValue({ data: { entries: [{ id: 'a', revision: 2, envelope: 'A' }, { id: 'b', revision: 1, envelope: 'B' }] } })
    expect(await new ApiChatTransport().fetchGroupList()).toHaveLength(2)
    expect(http.get).toHaveBeenCalledWith('/chat/group-list')
  })

  it('refuses a dropped entry or an older revision, after reading again once', async () => {
    head.index = () => [['a', 2], ['b', 1]]
    http.get.mockResolvedValue({ data: { entries: [{ id: 'a', revision: 2, envelope: 'A' }] } })
    await expect(new ApiChatTransport().fetchGroupList()).rejects.toBeInstanceOf(NotInVerifiedIndexError)
    expect(http.get).toHaveBeenCalledTimes(2)
    http.get.mockReset()
    http.get.mockResolvedValue({ data: { entries: [{ id: 'a', revision: 1, envelope: 'A' }, { id: 'b', revision: 1, envelope: 'B' }] } })
    await expect(new ApiChatTransport().fetchGroupList()).rejects.toBeInstanceOf(NotInVerifiedIndexError)
  })

  it('writes an entry with the next head; false when another device wrote first', async () => {
    const transport = new ApiChatTransport()
    head.index = () => [['a', 2]]
    http.put.mockResolvedValue({ data: null })
    expect(await transport.storeGroupEntry({ id: 'a', baseRevision: 2, revision: 3, envelope: 'E' })).toBe(true)
    expect(http.put).toHaveBeenCalledWith('/chat/group-list/a', { baseRevision: 2, envelope: 'E', head: 'head-1' })
    // A new entry starts at base 0.
    http.put.mockClear()
    expect(await transport.storeGroupEntry({ id: 'n', baseRevision: 0, revision: 1, envelope: 'N' })).toBe(true)
    // Another device moved it on: nothing is sent.
    http.put.mockClear()
    head.index = () => [['a', 5]]
    expect(await transport.storeGroupEntry({ id: 'a', baseRevision: 2, revision: 3, envelope: 'E' })).toBe(false)
    expect(http.put).not.toHaveBeenCalled()
    // Already at that revision (ours with a lost answer, or another
    // device's): not "stored"; the engine reads again and merges.
    head.index = () => [['a', 3]]
    expect(await transport.storeGroupEntry({ id: 'a', baseRevision: 2, revision: 3, envelope: 'E' })).toBe(false)
    expect(http.put).not.toHaveBeenCalled()
  })
})
