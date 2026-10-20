import { beforeEach, describe, expect, it, vi } from 'vitest'

// The account's Chat contact list through the web head client
// (docs/plans/chat-contacts-sync.md): held to the verified index on reads,
// each entry written (or evicted) with the next head; a full list says so.

const http = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn(), delete: vi.fn() }))
vi.mock('@kutup/session/client', () => ({ default: { get: http.get, put: http.put, delete: http.delete } }))
vi.mock('@kutup/session/store', () => ({ getSession: () => ({ userId: 'u1', masterKey: new Uint8Array(32), envelopeBinding: 'b' }) }))

const head = vi.hoisted(() => ({ index: (_attempt: number): [string, number][] => [], covered: true, reads: 0 }))
vi.mock('@kutup/session/accountHead', async () => {
  const actual = await vi.importActual<typeof import('@kutup/session/accountHead')>('@kutup/session/accountHead')
  const index = (attempt: number) => new actual.VerifiedIndex('chatContacts', head.covered, head.index(attempt), null)
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
import { AxiosError, AxiosHeaders } from 'axios'
import { ApiChatTransport } from './transport'

beforeEach(() => {
  http.get.mockReset()
  http.put.mockReset()
  http.delete.mockReset()
  Object.assign(head, { index: () => [], covered: true, reads: 0 })
})

describe('the contact list under the account head', () => {
  it('reads exactly the entries the head lists, at their revisions', async () => {
    head.index = () => [['a', 2], ['b', 1]]
    http.get.mockResolvedValue({ data: { entries: [{ id: 'a', revision: 2, envelope: 'A' }, { id: 'b', revision: 1, envelope: 'B' }] } })
    expect(await new ApiChatTransport().fetchContactList()).toHaveLength(2)
    expect(http.get).toHaveBeenCalledWith('/chat/contact-list')
  })

  it('refuses a dropped entry, after reading again once', async () => {
    head.index = () => [['a', 2], ['b', 1]]
    http.get.mockResolvedValue({ data: { entries: [{ id: 'a', revision: 2, envelope: 'A' }] } })
    await expect(new ApiChatTransport().fetchContactList()).rejects.toBeInstanceOf(NotInVerifiedIndexError)
    expect(http.get).toHaveBeenCalledTimes(2)
  })

  it('writes an entry with the next head; a conflict when another device wrote first', async () => {
    const transport = new ApiChatTransport()
    head.index = () => [['a', 2]]
    http.put.mockResolvedValue({ data: null })
    expect(await transport.storeContactEntry({ id: 'a', baseRevision: 2, revision: 3, envelope: 'E' })).toBe('stored')
    expect(http.put).toHaveBeenCalledWith('/chat/contact-list/a', { baseRevision: 2, envelope: 'E', head: 'head-1' })
    http.put.mockClear()
    head.index = () => [['a', 5]]
    expect(await transport.storeContactEntry({ id: 'a', baseRevision: 2, revision: 3, envelope: 'E' })).toBe('conflict')
    expect(http.put).not.toHaveBeenCalled()
    head.index = () => [['a', 3]]
    expect(await transport.storeContactEntry({ id: 'a', baseRevision: 2, revision: 3, envelope: 'E' })).toBe('stored')
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
    http.put.mockRejectedValueOnce(refused('contactListFull'))
    expect(await transport.storeContactEntry({ id: 'n', baseRevision: 0, revision: 1, envelope: 'N' })).toBe('full')
    http.put.mockRejectedValueOnce(refused('badRequest'))
    await expect(transport.storeContactEntry({ id: 'n', baseRevision: 0, revision: 1, envelope: 'N' })).rejects.toBeInstanceOf(AxiosError)
  })

  it('evicts an entry at its listed revision with the next head', async () => {
    const transport = new ApiChatTransport()
    head.index = () => [['old', 4]]
    http.delete.mockResolvedValue({ data: null })
    expect(await transport.deleteContactEntry({ id: 'old', baseRevision: 4 })).toBe(true)
    expect(http.delete).toHaveBeenCalledWith('/chat/contact-list/old', { data: { baseRevision: 4, head: 'head-1' } })
    http.delete.mockClear()
    // Another device changed it meanwhile: not removed.
    head.index = () => [['old', 5]]
    expect(await transport.deleteContactEntry({ id: 'old', baseRevision: 4 })).toBe(false)
    expect(http.delete).not.toHaveBeenCalled()
    // Already gone: done.
    head.index = () => []
    expect(await transport.deleteContactEntry({ id: 'old', baseRevision: 4 })).toBe(true)
  })
})
