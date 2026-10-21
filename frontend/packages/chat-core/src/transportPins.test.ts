import { beforeEach, describe, expect, it, vi } from 'vitest'

// Chat's synced identity pins through the web head client
// (docs/plans/rollback-protection.md §9): the list is held to the verified
// index on reads, and written with the next head.

const http = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn() }))
vi.mock('@kutup/session/client', () => ({ default: { get: http.get, put: http.put } }))
vi.mock('@kutup/session/store', () => ({ getSession: () => ({ userId: 'u1', masterKey: new Uint8Array(32), envelopeBinding: 'b' }) }))

const head = vi.hoisted(() => ({ index: (_attempt: number): [string, number][] => [], covered: true, reads: 0 }))
vi.mock('@kutup/session/accountHead', async () => {
  const actual = await vi.importActual<typeof import('@kutup/session/accountHead')>('@kutup/session/accountHead')
  const index = (attempt: number) => new actual.VerifiedIndex('pins', head.covered, head.index(attempt), null)
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

const conflict = (code: string) => Object.assign(new Error('409'), { isAxiosError: true, response: { status: 409, data: { code } } })

beforeEach(() => {
  http.get.mockReset()
  http.put.mockReset()
  Object.assign(head, { index: () => [], covered: true, reads: 0 })
})

describe('Chat pins under the account head', () => {
  it('reads a list at the revision the head vouches for', async () => {
    head.index = () => [['pins', 7]]
    http.get.mockResolvedValue({ data: { revision: 7, envelope: 'E' } })
    expect(await new ApiChatTransport().fetchIdentityPins()).toEqual({ revision: 7, envelope: 'E' })
  })

  it('refuses a list at another revision, after reading again once', async () => {
    head.index = () => [['pins', 7]]
    http.get.mockResolvedValue({ data: { revision: 6, envelope: 'E' } })
    await expect(new ApiChatTransport().fetchIdentityPins()).rejects.toBeInstanceOf(NotInVerifiedIndexError)
    expect(http.get).toHaveBeenCalledTimes(2)
  })

  it('refuses no list when the head lists one', async () => {
    head.index = () => [['pins', 7]]
    http.get.mockRejectedValue(Object.assign(new Error('404'), { isAxiosError: true, response: { status: 404 } }))
    await expect(new ApiChatTransport().fetchIdentityPins()).rejects.toBeInstanceOf(NotInVerifiedIndexError)
  })

  it('writes with the next head; false when another app wrote first; sent again when only the head moved', async () => {
    const transport = new ApiChatTransport()
    head.index = () => [['pins', 5]]
    http.put.mockResolvedValue({ data: null })
    expect(await transport.storeIdentityPins({ baseRevision: 5, envelope: 'E', revision: 6 })).toBe(true)
    expect(http.put).toHaveBeenCalledWith('/user/identity-pins', { baseRevision: 5, envelope: 'E', head: 'head-1' })

    // Another app stored a list first: the engine reads it again.
    head.index = () => [['pins', 9]]
    http.put.mockClear()
    expect(await transport.storeIdentityPins({ baseRevision: 5, envelope: 'E', revision: 6 })).toBe(false)
    expect(http.put).not.toHaveBeenCalled()

    // Only another value moved: sent again on the new head.
    head.index = () => [['pins', 5]]
    http.put.mockReset()
    http.put.mockRejectedValueOnce(conflict('head_conflict')).mockResolvedValue({ data: null })
    expect(await transport.storeIdentityPins({ baseRevision: 5, envelope: 'E', revision: 6 })).toBe(true)
    expect(http.put).toHaveBeenCalledTimes(2)

    // Already at that revision (an earlier try whose answer was lost, or
    // another app's list at the same number): not "stored"; the engine reads
    // the list again, and finds its own if it was.
    head.index = () => [['pins', 6]]
    http.put.mockClear()
    expect(await transport.storeIdentityPins({ baseRevision: 5, envelope: 'E', revision: 6 })).toBe(false)
    expect(http.put).not.toHaveBeenCalled()
  })
})
