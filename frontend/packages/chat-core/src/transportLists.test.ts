import { AxiosError, AxiosHeaders } from 'axios'
import { beforeEach, describe, expect, it, vi } from 'vitest'

// Chat's group list and contact list through the web head client: the
// account-records scopes `chatGroups` and `chatContacts`
// (docs/plans/account-records.md), read as the head vouches for them and
// written with the next head. The head's own checks are tested in
// @kutup/session/accountHead.test.ts.

vi.mock('@kutup/session/client', () => ({ default: { get: vi.fn(), put: vi.fn() } }))
vi.mock('@kutup/session/store', () => ({ getSession: () => ({ accountId: 'u1', masterKey: new Uint8Array(32), roots: { identityGeneration: 1, identityRoot: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', driveGeneration: 1, driveRoot: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', pseudonymGeneration: 1, pseudonymRoot: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', callLinkGeneration: 1, callLinkRoot: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', objectIdGeneration: 1, objectIdKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' }, envelopeBinding: 'b' }) }))

const head = vi.hoisted(() => ({
  /** Each scope's records in the verified copy: `[id, revision, envelope]`. */
  records: {} as Record<string, [string, number, string][]>,
  mismatch: false,
  send: vi.fn<(batch: unknown) => Promise<void>>(),
}))
vi.mock('@kutup/session/accountHead', async () => {
  const actual = await vi.importActual<typeof import('@kutup/session/accountHead')>('@kutup/session/accountHead')
  const { ScopeRecords } = await vi.importActual<typeof import('@kutup/session/accountRecords')>('@kutup/session/accountRecords')
  type Scope = ConstructorParameters<typeof ScopeRecords>[0]
  const copyOf = (scope: Scope) => {
    const copy = new ScopeRecords(scope)
    for (const [id, revision, envelope] of head.records[scope] ?? []) copy.records.set(id, { revision, envelope })
    return copy
  }
  const client = {
    records: (scope: Scope) => (head.mismatch ? Promise.reject(new actual.IndexMismatchError(scope)) : Promise.resolve(copyOf(scope))),
    recordsWrite: async <T,>(scope: Scope, edit: (copy: InstanceType<typeof ScopeRecords>, attempt: number) => Promise<{ puts: { id: string; revision: number; envelope: string }[]; deletes: string[]; done: T } | null>) => {
      const copy = copyOf(scope)
      const change = await edit(copy, 1)
      if (!change) return undefined
      const batch = copy.plan(change)
      if (batch.puts.length === 0 && batch.deletes.length === 0) return change.done
      await head.send(batch)
      return change.done
    },
  }
  return { ...actual, accountHead: () => Promise.resolve(client) }
})

import { IndexMismatchError } from '@kutup/session/accountHead'
import { ApiChatTransport } from './transport'

beforeEach(() => {
  head.send.mockReset()
  head.send.mockResolvedValue()
  head.records = {}
  head.mismatch = false
})

describe('the group list under the account head', () => {
  it('reads the entries the head vouches for, at their revisions', async () => {
    head.records = { chatGroups: [['a', 2, 'A'], ['b', 1, 'B']] }
    expect(await new ApiChatTransport().fetchGroupList()).toEqual([
      { id: 'a', revision: 2, envelope: 'A' },
      { id: 'b', revision: 1, envelope: 'B' },
    ])
  })

  it('refuses a list the head does not vouch for', async () => {
    head.mismatch = true
    await expect(new ApiChatTransport().fetchGroupList()).rejects.toBeInstanceOf(IndexMismatchError)
  })

  it('writes an entry with the next head; false when another device wrote first', async () => {
    const transport = new ApiChatTransport()
    head.records = { chatGroups: [['a', 2, 'A']] }
    expect(await transport.storeGroupEntry({ id: 'a', baseRevision: 2, revision: 3, envelope: 'E' })).toBe(true)
    expect(head.send).toHaveBeenCalledWith({ scope: 'chatGroups', puts: [{ id: 'a', baseRevision: 2, revision: 3, envelope: 'E' }], deletes: [] })
    head.send.mockClear()
    head.records = { chatGroups: [['a', 5, 'A']] }
    expect(await transport.storeGroupEntry({ id: 'a', baseRevision: 2, revision: 3, envelope: 'E' })).toBe(false)
    // Already at that revision: not "stored", so the engine reads and merges.
    head.records = { chatGroups: [['a', 3, 'A']] }
    expect(await transport.storeGroupEntry({ id: 'a', baseRevision: 2, revision: 3, envelope: 'E' })).toBe(false)
    expect(head.send).not.toHaveBeenCalled()
  })
})

describe('the contact list under the account head', () => {
  it('reads the entries the head vouches for, at their revisions', async () => {
    head.records = { chatContacts: [['a', 2, 'A'], ['b', 1, 'B']] }
    expect(await new ApiChatTransport().fetchContactList()).toHaveLength(2)
    head.mismatch = true
    await expect(new ApiChatTransport().fetchContactList()).rejects.toBeInstanceOf(IndexMismatchError)
  })

  it('writes an entry with the next head; a conflict when another device wrote first', async () => {
    const transport = new ApiChatTransport()
    head.records = { chatContacts: [['a', 2, 'A']] }
    expect(await transport.storeContactEntry({ id: 'a', baseRevision: 2, revision: 3, envelope: 'E' })).toBe('stored')
    expect(head.send).toHaveBeenCalledWith({ scope: 'chatContacts', puts: [{ id: 'a', baseRevision: 2, revision: 3, envelope: 'E' }], deletes: [] })
    head.send.mockClear()
    head.records = { chatContacts: [['a', 5, 'A']] }
    expect(await transport.storeContactEntry({ id: 'a', baseRevision: 2, revision: 3, envelope: 'E' })).toBe('conflict')
    // Already at that revision: a conflict, so the engine reads and merges.
    head.records = { chatContacts: [['a', 3, 'A']] }
    expect(await transport.storeContactEntry({ id: 'a', baseRevision: 2, revision: 3, envelope: 'E' })).toBe('conflict')
    expect(head.send).not.toHaveBeenCalled()
  })

  it('says a full list is full, and nothing else', async () => {
    const transport = new ApiChatTransport()
    const refused = (code: string) =>
      new AxiosError('refused', '400', undefined, undefined, {
        status: 400,
        statusText: 'Bad Request',
        headers: {},
        config: { headers: new AxiosHeaders() },
        data: { error: 'refused', code },
      })
    head.send.mockRejectedValueOnce(refused('scopeFull'))
    expect(await transport.storeContactEntry({ id: 'n', baseRevision: 0, revision: 1, envelope: 'N' })).toBe('full')
    head.send.mockRejectedValueOnce(refused('badRequest'))
    await expect(transport.storeContactEntry({ id: 'n', baseRevision: 0, revision: 1, envelope: 'N' })).rejects.toBeInstanceOf(AxiosError)
  })

  it('evicts an entry at its listed revision with the next head', async () => {
    const transport = new ApiChatTransport()
    head.records = { chatContacts: [['old', 4, 'O']] }
    expect(await transport.deleteContactEntry({ id: 'old', baseRevision: 4 })).toBe(true)
    expect(head.send).toHaveBeenCalledWith({ scope: 'chatContacts', puts: [], deletes: [{ id: 'old', baseRevision: 4 }] })
    head.send.mockClear()
    // Another device changed it meanwhile: not removed.
    head.records = { chatContacts: [['old', 5, 'O']] }
    expect(await transport.deleteContactEntry({ id: 'old', baseRevision: 4 })).toBe(false)
    // Already gone: done.
    head.records = {}
    expect(await transport.deleteContactEntry({ id: 'old', baseRevision: 4 })).toBe(true)
    expect(head.send).not.toHaveBeenCalled()
  })
})
