import { beforeEach, describe, expect, it, vi } from 'vitest'

// Chat's synced identity pins through the web head client: the one record
// of the account-records scope `pins` (docs/plans/account-records.md), read
// as the head vouches for it and written with the next head. The head's own
// checks are tested in @kutup/session/accountHead.test.ts.

vi.mock('@kutup/session/client', () => ({ default: { get: vi.fn(), put: vi.fn() } }))
vi.mock('@kutup/session/store', () => ({ getSession: () => ({ accountId: 'u1', masterKey: new Uint8Array(32), roots: { identityGeneration: 1, identityRoot: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', driveGeneration: 1, driveRoot: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', pseudonymGeneration: 1, pseudonymRoot: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', callLinkGeneration: 1, callLinkRoot: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', objectIdGeneration: 1, objectIdKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' }, envelopeBinding: 'b' }) }))

const head = vi.hoisted(() => ({
  /** The `pins` record the verified copy holds, per attempt (null: none). */
  record: (_attempt: number): { revision: number; envelope: string } | null => null,
  mismatch: false,
  send: vi.fn<(batch: unknown) => Promise<void>>(),
}))
vi.mock('@kutup/session/accountHead', async () => {
  const actual = await vi.importActual<typeof import('@kutup/session/accountHead')>('@kutup/session/accountHead')
  const { ScopeRecords } = await vi.importActual<typeof import('@kutup/session/accountRecords')>('@kutup/session/accountRecords')
  const copyAt = (attempt: number) => {
    const copy = new ScopeRecords('pins')
    const record = head.record(attempt)
    if (record) copy.records.set('pins', record)
    return copy
  }
  const client = {
    records: () => (head.mismatch ? Promise.reject(new actual.IndexMismatchError('pins')) : Promise.resolve(copyAt(1))),
    recordsWrite: async <T,>(_s: string, edit: (copy: InstanceType<typeof ScopeRecords>, attempt: number) => Promise<{ puts: { id: string; revision: number; envelope: string }[]; deletes: string[]; done: T } | null>) => {
      for (let attempt = 1; ; attempt++) {
        const copy = copyAt(attempt)
        const change = await edit(copy, attempt)
        if (!change) return undefined
        try {
          await head.send(copy.plan(change))
          return change.done
        } catch (error) {
          const code = (error as { response?: { data?: { code?: string } } }).response?.data?.code
          if ((code === 'headConflict' || code === 'revisionConflict') && attempt < 5) continue
          throw error
        }
      }
    },
  }
  return { ...actual, accountHead: () => Promise.resolve(client) }
})

import { IndexMismatchError } from '@kutup/session/accountHead'
import { ApiChatTransport } from './transport'

const conflict = (code: string) => Object.assign(new Error('409'), { isAxiosError: true, response: { status: 409, data: { code } } })

beforeEach(() => {
  head.send.mockReset()
  head.send.mockResolvedValue()
  head.record = () => null
  head.mismatch = false
})

describe('Chat pins under the account head', () => {
  it('reads the list the head vouches for, or none', async () => {
    head.record = () => ({ revision: 7, envelope: 'E' })
    expect(await new ApiChatTransport().fetchIdentityPins()).toEqual({ revision: 7, envelope: 'E' })
    head.record = () => null
    expect(await new ApiChatTransport().fetchIdentityPins()).toBeNull()
  })

  it('refuses a list the head does not vouch for', async () => {
    head.mismatch = true
    await expect(new ApiChatTransport().fetchIdentityPins()).rejects.toBeInstanceOf(IndexMismatchError)
  })

  it('writes with the next head; false when another app wrote first; sent again when only the head moved', async () => {
    const transport = new ApiChatTransport()
    head.record = () => ({ revision: 5, envelope: 'D' })
    expect(await transport.storeIdentityPins({ baseRevision: 5, envelope: 'E', revision: 6 })).toBe(true)
    expect(head.send).toHaveBeenCalledWith({ scope: 'pins', puts: [{ id: 'pins', baseRevision: 5, revision: 6, envelope: 'E' }], deletes: [] })

    // Another app stored a list first: the engine reads it again.
    head.record = () => ({ revision: 9, envelope: 'F' })
    head.send.mockClear()
    expect(await transport.storeIdentityPins({ baseRevision: 5, envelope: 'E', revision: 6 })).toBe(false)
    expect(head.send).not.toHaveBeenCalled()

    // Only another value moved: sent again on the new head.
    head.record = () => ({ revision: 5, envelope: 'D' })
    head.send.mockReset()
    head.send.mockRejectedValueOnce(conflict('headConflict')).mockResolvedValue()
    expect(await transport.storeIdentityPins({ baseRevision: 5, envelope: 'E', revision: 6 })).toBe(true)
    expect(head.send).toHaveBeenCalledTimes(2)

    // Already at that revision (an earlier try whose answer was lost, or
    // another app's list at the same number): not "stored"; the engine reads
    // the list again, and finds its own if it was.
    head.record = () => ({ revision: 6, envelope: 'E' })
    head.send.mockClear()
    expect(await transport.storeIdentityPins({ baseRevision: 5, envelope: 'E', revision: 6 })).toBe(false)
    expect(head.send).not.toHaveBeenCalled()
  })
})
