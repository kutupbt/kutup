import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Session } from '@kutup/session/store'

// The address book under the account head (docs/plans/rollback-protection.md).
// The crypto is Rust's (vectors there); here a summary is its JSON, signed by
// nothing, and a card is JSON naming its UID and revision.

vi.mock('@kutup/crypto', async () => {
  const guard = await vi.importActual<typeof import('@kutup/crypto/revisionGuard')>('@kutup/crypto/revisionGuard')
  const base64 = await vi.importActual<typeof import('@kutup/crypto/base64')>('@kutup/crypto/base64')
  return {
    ...base64,
    revisionGuard: guard.revisionGuard,
    deriveAccountIdentityKeys: () => Promise.resolve({ authorityPublicKey: 'A' }),
    describeExternalMailKey: () => Promise.reject(new Error('no keys here')),
    signContactSummary: (_m: string, _b: string, revision: number, summary: unknown) =>
      Promise.resolve({ summary: JSON.stringify({ ...(summary as object), revision }), signature: 'sig' }),
    verifyContactSummary: (summary: string) => Promise.resolve(JSON.parse(summary) as unknown),
    sealContactCard: (_m: string, _b: string, uid: string, revision: number, vcard: string) => Promise.resolve(JSON.stringify({ uid, revision, vcard })),
    openContactCard: (_m: string, _b: string, uid: string, card: string) => {
      const parsed = JSON.parse(card) as { uid: string; revision: number; vcard: string }
      return parsed.uid === uid ? Promise.resolve({ value: parsed.vcard, revision: parsed.revision }) : Promise.reject(new Error('another contact'))
    },
  }
})

const http = vi.hoisted(() => ({
  rows: [] as { id: string; summary: string; signature: string; card: string; revision: number; updatedAt: string }[],
  get: vi.fn(),
  post: vi.fn(),
  put: vi.fn(),
}))
vi.mock('@kutup/session/client', () => ({
  default: {
    get: (url: string) => {
      http.get(url)
      return Promise.resolve({ data: { contacts: http.rows, total: http.rows.length } })
    },
    post: (url: string, body: unknown) => http.post(url, body) as Promise<unknown>,
    put: (url: string, body: unknown) => http.put(url, body) as Promise<unknown>,
  },
}))

// The head, its rules kept small (its own tests: @kutup/session).
const head = vi.hoisted(() => ({ index: (_attempt: number): [string, number][] => [], covered: false, blocked: false }))
vi.mock('@kutup/session/accountHead', async () => {
  const actual = await vi.importActual<typeof import('@kutup/session/accountHead')>('@kutup/session/accountHead')
  let reads = 0
  const index = (attempt: number) => new actual.VerifiedIndex('contacts', head.covered, head.index(attempt), null)
  const client = {
    verifiedIndex: () => (head.blocked ? Promise.reject(new actual.HeadBlockedError('fork')) : Promise.resolve(index(++reads))),
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
  return { ...actual, accountHead: () => Promise.resolve(client), resetReads: () => (reads = 0) }
})

import { resetRevisionGuardsForTesting } from '@kutup/crypto/revisionGuard'
import { NotInVerifiedIndexError } from '@kutup/session/accountHead'
import { ContactChangedError, createContact, deleteContacts, loadContacts, putContact } from './api'
import { emptyDraft } from './model'

const session = { userId: 'u1', masterKey: new Uint8Array(32), envelopeBinding: 'b' } as unknown as Session
const draft = (name: string) => ({ ...emptyDraft(), name })
const conflict = (code: string) => Object.assign(new Error('409'), { isAxiosError: true, response: { status: 409, data: { code } } })

/** A stored row, as the server lists it. */
function row(id: string, uid: string, revision: number) {
  return {
    id,
    summary: JSON.stringify({ uid, name: id, emails: [], groups: [], pinnedKeys: [], revision }),
    signature: 'sig',
    card: JSON.stringify({ uid, revision, vcard: `BEGIN:VCARD\r\nVERSION:4.0\r\nUID:${uid}\r\nFN:${id}\r\nEND:VCARD\r\n` }),
    revision,
    updatedAt: '',
  }
}

beforeEach(() => {
  resetRevisionGuardsForTesting()
  http.rows = []
  for (const fn of [http.get, http.post, http.put]) fn.mockReset()
  Object.assign(head, { index: () => [], covered: false, blocked: false })
})

describe('reading the address book', () => {
  it('shows contacts the head vouches for', async () => {
    http.rows = [row('r1', 'u-1', 5), row('r2', 'u-2', 7)]
    head.covered = true
    head.index = () => [['u-1', 5], ['u-2', 7]]
    expect((await loadContacts(session)).contacts.map((c) => c.uid).sort()).toEqual(['u-1', 'u-2'])
  })

  it('refuses a book with a contact dropped or brought back, after reading again once', async () => {
    http.rows = [row('r1', 'u-1', 5)]
    head.covered = true
    head.index = () => [['u-1', 5], ['u-2', 7]]
    await expect(loadContacts(session)).rejects.toBeInstanceOf(NotInVerifiedIndexError)
    expect(http.get).toHaveBeenCalledTimes(2)
  })

  it('refuses a contact rolled back to another revision', async () => {
    http.rows = [row('r1', 'u-1', 4)]
    head.covered = true
    head.index = () => [['u-1', 5]]
    await expect(loadContacts(session)).rejects.toBeInstanceOf(NotInVerifiedIndexError)
  })

  it('reads on, held to the guard only, while the app is blocked', async () => {
    http.rows = [row('r1', 'u-1', 4)]
    head.blocked = true
    expect((await loadContacts(session)).contacts).toHaveLength(1)
  })
})

describe('writing contacts', () => {
  it('creates a contact named by its UID in the head', async () => {
    http.post.mockResolvedValue({ data: { id: 'r9' } })
    expect(await createContact(session, 'u-9', draft('Ada'))).toBe('r9')
    expect(http.post).toHaveBeenCalledWith('/contacts', expect.objectContaining({ head: 'head-1' }))
  })

  it('saves an edit with the next head; sends it again when only another value moved', async () => {
    http.put.mockRejectedValueOnce(conflict('head_conflict')).mockResolvedValue({ data: {} })
    head.index = () => [['u-1', 5]]
    await putContact(session, { id: 'r1', uid: 'u-1', revision: 5 }, draft('Ada'))
    expect(http.put).toHaveBeenCalledTimes(2)
    expect(http.put.mock.calls[1]).toEqual(['/contacts/r1', expect.objectContaining({ baseRevision: 5, head: 'head-2' })])
  })

  it('does not lay a form over a contact another device changed', async () => {
    http.put.mockRejectedValueOnce(conflict('revision_conflict'))
    head.index = (attempt) => [['u-1', attempt > 1 ? 6 : 5]]
    await expect(putContact(session, { id: 'r1', uid: 'u-1', revision: 5 }, draft('Ada'))).rejects.toBeInstanceOf(ContactChangedError)
    expect(http.put).toHaveBeenCalledTimes(1)
  })

  it('deletes with the next head, skipping contacts already gone', async () => {
    http.post.mockResolvedValue({ data: null })
    head.index = () => [['u-1', 5]]
    await deleteContacts(session, [
      { id: 'r1', uid: 'u-1' },
      { id: 'r2', uid: 'u-2' },
    ])
    expect(http.post).toHaveBeenCalledWith('/contacts/delete', { ids: ['r1'], head: 'head-1' })
    head.index = () => []
    http.post.mockClear()
    await deleteContacts(session, [{ id: 'r1', uid: 'u-1' }])
    expect(http.post).not.toHaveBeenCalled()
  })
})
