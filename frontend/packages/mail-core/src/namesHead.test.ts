import { beforeEach, describe, expect, it, vi } from 'vitest'

// Folder, label and filter names under the account head
// (docs/plans/rollback-protection.md). The crypto is Rust's (vectors there);
// here a sealed name is JSON naming its kind, id and revision.

vi.mock('@kutup/crypto', async () => {
  const guard = await vi.importActual<typeof import('@kutup/crypto/revisionGuard')>('@kutup/crypto/revisionGuard')
  const base64 = await vi.importActual<typeof import('@kutup/crypto/base64')>('@kutup/crypto/base64')
  return {
    ...base64,
    revisionGuard: guard.revisionGuard,
    sealMailName: (_m: string, _b: string, kind: string, id: string, revision: number, value: string) => Promise.resolve(JSON.stringify({ kind, id, revision, value })),
    openMailName: (_m: string, _b: string, kind: string, id: string, sealed: string) => {
      const parsed = JSON.parse(sealed) as { kind: string; id: string; revision: number; value: string }
      return parsed.kind === kind && parsed.id === id ? Promise.resolve({ value: parsed.value, revision: parsed.revision }) : Promise.reject(new Error('moved'))
    },
  }
})
vi.mock('react-i18next', () => ({ getI18n: () => ({ t: (key: string) => (key === 'mailPlaces.unnamedFolder' ? 'Unnamed folder' : key) }) }))

const http = vi.hoisted(() => ({
  places: { folders: [] as unknown[], labels: [] as unknown[] },
  filters: [] as unknown[],
  get: vi.fn(),
  patch: vi.fn(),
  post: vi.fn(),
  del: vi.fn(),
}))
vi.mock('@kutup/session/client', () => ({
  default: {
    get: (url: string) => {
      http.get(url)
      return Promise.resolve({ data: url === '/mail/places' ? http.places : http.filters })
    },
    patch: (url: string, body: unknown) => http.patch(url, body) as Promise<unknown>,
    post: (url: string, body: unknown) => http.post(url, body) as Promise<unknown>,
    delete: (url: string, config: unknown) => http.del(url, config) as Promise<unknown>,
  },
}))

// The head, its rules kept small (its own tests: @kutup/session).
const head = vi.hoisted(() => ({ index: (_attempt: number): [string, number][] => [], covered: false }))
vi.mock('@kutup/session/accountHead', async () => {
  const actual = await vi.importActual<typeof import('@kutup/session/accountHead')>('@kutup/session/accountHead')
  const index = (attempt: number) => new actual.VerifiedIndex('mailNames', head.covered, head.index(attempt), null)
  const client = {
    verifiedIndex: () => Promise.resolve(index(1)),
    listedWrite: async <T,>(_s: string, edit: (i: InstanceType<typeof actual.VerifiedIndex>, a: number) => Promise<{ changes: unknown; send: (h: string) => Promise<T> } | null>) => {
      for (let attempt = 1; ; attempt++) {
        const change = await edit(index(attempt), attempt)
        if (!change) return undefined
        sentChanges.push(change.changes)
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
const sentChanges: unknown[] = []

import { resetRevisionGuardsForTesting } from '@kutup/crypto/revisionGuard'
import { NotInVerifiedIndexError } from '@kutup/session/accountHead'
import { loadFilters } from './filters'
import { createName, folderAndInside, loadPlaces, renameName } from './places'

const session = { userId: 'u1', masterKey: new Uint8Array(32), envelopeBinding: 'b' }
const sealed = (kind: string, id: string, revision: number, value: string) => JSON.stringify({ kind, id, revision, value })
const folderRow = (id: string, name: string | null, parentId: string | null = null) => ({ id, parentId, name, color: '#8080ff', position: 0, expanded: true, notify: true })

beforeEach(() => {
  resetRevisionGuardsForTesting()
  http.places = { folders: [], labels: [] }
  http.filters = []
  for (const fn of [http.get, http.patch, http.post, http.del]) fn.mockReset()
  Object.assign(head, { index: () => [], covered: false })
  sentChanges.length = 0
})

describe('reading names', () => {
  it('shows a folder kept through a reset as unnamed, neither unreadable nor a value the head lists', async () => {
    http.places = { folders: [folderRow('f1', sealed('folder', 'f1', 3, 'İş')), folderRow('f2', null)], labels: [] }
    head.covered = true
    head.index = () => [['folder:f1', 3]]
    const places = await loadPlaces(session)
    expect(places.folders.get('f2')).toMatchObject({ name: 'Unnamed folder', unnamed: true, nameRevision: 0 })
    expect(places.folders.get('f1')?.name).toBe('İş')
    expect(places.unreadable).toBe(0)
  })

  it('refuses names the head does not vouch for, after reading again once', async () => {
    http.places = { folders: [folderRow('f1', sealed('folder', 'f1', 3, 'İş'))], labels: [] }
    head.covered = true
    // A label the head lists is missing, and the folder is at another revision.
    head.index = () => [['folder:f1', 3], ['label:l1', 2]]
    await expect(loadPlaces(session)).rejects.toBeInstanceOf(NotInVerifiedIndexError)
    expect(http.get).toHaveBeenCalledTimes(2)
    head.index = () => [['folder:f1', 4]]
    await expect(loadPlaces(session)).rejects.toBeInstanceOf(NotInVerifiedIndexError)
  })

  it('holds filters to their own kind of the index', async () => {
    http.filters = [{ id: 'x', name: sealed('filter', 'x', 2, 'Faturalar') }]
    head.covered = true
    head.index = () => [['folder:f1', 3], ['filter:x', 2]]
    expect((await loadFilters(session)).map((f) => f.name)).toEqual(['Faturalar'])
    head.index = () => [['filter:x', 2], ['filter:y', 1]]
    await expect(loadFilters(session)).rejects.toBeInstanceOf(NotInVerifiedIndexError)
  })
})

describe('writing names', () => {
  it('creates a name with the next head, once', async () => {
    const post = vi.fn(() => Promise.resolve())
    await createName(session, 'label', 'l1', 'Önemli', post)
    expect(post).toHaveBeenCalledWith(expect.stringContaining('"value":"Önemli"'), 'head-1')
  })

  it('renames on top of the revision the head lists, from 0 for an unnamed folder', async () => {
    const patch = vi.fn((_body: { baseNameRevision: number; head: string }) => Promise.resolve())
    head.index = () => [['folder:f1', 7]]
    await renameName(session, 'folder', 'f1', 'Arşiv', patch)
    expect(patch.mock.calls[0]?.[0]).toMatchObject({ baseNameRevision: 7, head: 'head-1' })
    await renameName(session, 'folder', 'f2', 'Adlı', patch)
    expect(patch.mock.calls[1]?.[0]).toMatchObject({ baseNameRevision: 0 })
  })

  it('a folder delete names it and every folder inside it', () => {
    const inner = { id: 'c', children: [] }
    const middle = { id: 'b', children: [inner] }
    const places = { folders: new Map([['a', { id: 'a', children: [middle] }], ['b', middle], ['c', inner]]) } as never
    expect(folderAndInside(places, 'a')).toEqual(['a', 'b', 'c'])
  })
})
