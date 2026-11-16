import { beforeEach, describe, expect, it, vi } from 'vitest'

// The library record as this browser reads it: the account-records scope as
// the verified account head vouches for it (`AccountHead.records` checks the
// index), each record opened as exactly the revision listed; a second record
// a race made is merged in, and the next write deletes it.

interface Stored { revision: number; envelope: string }
const scope = { records: new Map<string, Stored>() }
const writes: unknown[] = []
const head = {
  records: vi.fn(() => Promise.resolve(scope)),
  recordsWrite: vi.fn(async (_name: string, edit: (copy: typeof scope, attempt: number) => Promise<{ puts: unknown[]; deletes: string[]; done: unknown } | null>) => {
    const change = await edit(scope, 1)
    if (!change) return undefined
    writes.push({ puts: change.puts, deletes: change.deletes })
    return change.done
  }),
}
vi.mock('@kutup/session/accountHead', () => ({ accountHead: vi.fn(() => Promise.resolve(head)) }))
vi.mock('@kutup/session/accountRecords', () => ({ randomRecordId: () => 'NEW' }))

const opened = new Map<string, { marks: { favourites: string[]; archived: string[]; hidden: string[] }; revision: number }>()
const crypto = {
  openPhotosLibrary: vi.fn((envelope: string) => Promise.resolve(opened.get(envelope)!)),
  sealPhotosLibrary: vi.fn((_marks: unknown, _me: unknown, id: string, revision: number) => Promise.resolve(`sealed:${id}:${revision}`)),
}
vi.mock('@kutup/crypto/photosLibrary', () => crypto)
vi.mock('@kutup/drive-core/identity', () => ({ useDriveIdentity: vi.fn() }))

const { changeMarks, loadMarks, withMark } = await import('./marks')

const me = { userId: 'u', binding: 'b', masterKeys: 'keys', roots: {} } as never

describe('the Photos library record, as read', () => {
  beforeEach(() => {
    scope.records.clear()
    opened.clear()
    writes.length = 0
  })

  it('starts empty when the scope holds no record', async () => {
    expect(await loadMarks(me)).toEqual({
      id: null,
      revision: 0,
      marks: { favourites: [], archived: [], hidden: [] },
      others: [],
    })
  })

  it('opens the record at the revision the verified index lists', async () => {
    scope.records.set('A', { revision: 2, envelope: 'a2' })
    opened.set('a2', { marks: { favourites: ['f'], archived: [], hidden: [] }, revision: 2 })
    expect(await loadMarks(me)).toMatchObject({ id: 'A', revision: 2, marks: { favourites: ['f'] } })
    expect(crypto.openPhotosLibrary).toHaveBeenCalledWith('a2', me, 'A')
  })

  it('refuses a record sealed at another revision than the one listed', async () => {
    scope.records.set('A', { revision: 3, envelope: 'a2' })
    opened.set('a2', { marks: { favourites: [], archived: [], hidden: [] }, revision: 2 })
    await expect(loadMarks(me)).rejects.toThrow(/differs/)
  })

  it('merges a second record a race made into the first', async () => {
    scope.records.set('B', { revision: 1, envelope: 'b1' })
    scope.records.set('A', { revision: 4, envelope: 'a4' })
    opened.set('a4', { marks: { favourites: ['1'], archived: [], hidden: [] }, revision: 4 })
    opened.set('b1', { marks: { favourites: ['2'], archived: [], hidden: ['3'] }, revision: 1 })
    expect(await loadMarks(me)).toMatchObject({
      id: 'A',
      revision: 4,
      marks: { favourites: ['1', '2'], hidden: ['3'] },
      others: ['B'],
    })
  })

  it('writes the first record under a new random id, then the next revision of it', async () => {
    const cache = { setQueryData: vi.fn() }
    await changeMarks(cache as never, me, (marks) => withMark(marks, 'hidden', ['h'], true))
    expect(writes).toEqual([{ puts: [{ id: 'NEW', revision: 1, envelope: 'sealed:NEW:1' }], deletes: [] }])
    expect(cache.setQueryData).toHaveBeenCalledWith(['photos-marks', 'u'], {
      id: 'NEW',
      revision: 1,
      marks: { favourites: [], archived: [], hidden: ['h'] },
      others: [],
    })
  })

  it('folds a raced second record into the first and deletes it', async () => {
    scope.records.set('A', { revision: 4, envelope: 'a4' })
    scope.records.set('B', { revision: 1, envelope: 'b1' })
    opened.set('a4', { marks: { favourites: ['1'], archived: [], hidden: [] }, revision: 4 })
    opened.set('b1', { marks: { favourites: ['2'], archived: [], hidden: [] }, revision: 1 })
    await changeMarks({ setQueryData: vi.fn() } as never, me, (marks) => withMark(marks, 'favourites', ['1'], false))
    expect(writes).toEqual([{ puts: [{ id: 'A', revision: 5, envelope: 'sealed:A:5' }], deletes: ['B'] }])
    expect(crypto.sealPhotosLibrary).toHaveBeenLastCalledWith(
      { favourites: ['2'], archived: [], hidden: [] }, me, 'A', 5,
    )
  })
})
