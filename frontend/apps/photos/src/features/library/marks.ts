import { useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query'
import { useCallback, useMemo } from 'react'
import {
  openPhotosLibrary,
  sealPhotosLibrary,
  type PhotosLibraryMarks,
} from '@kutup/crypto/photosLibrary'
import { useDriveIdentity, type DriveIdentity } from '@kutup/drive-core/identity'
import { accountHead } from '@kutup/session/accountHead'
import { randomRecordId, type ScopeRecords } from '@kutup/session/accountRecords'

// Your own marks on photos (docs/plans/photos.md): favourites, archived and
// hidden, in one account-private record, the account-records store's
// `photosLibrary` scope (docs/plans/account-records.md). The account head
// covers it: every read is checked against the verified head, so a server
// can't bring back marks that were taken off (a photo hidden again shown),
// and a write another device made first is read again and the change
// applied on top of it.

export type MarkKind = 'favourites' | 'archived' | 'hidden'

interface MarksState {
  /** The record's id; null before the first. */
  id: string | null
  /** 0 before the first record. */
  revision: number
  marks: PhotosLibraryMarks
  /**
   * Any other record: the library is one, but two devices' first writes
   * could each have made one. Their marks are merged in, and the next write
   * deletes them.
   */
  others: string[]
}

const EMPTY: PhotosLibraryMarks = { favourites: [], archived: [], hidden: [] }
export const marksKey = ['photos-marks'] as const

const KINDS: readonly MarkKind[] = ['favourites', 'archived', 'hidden']

function headOf(me: DriveIdentity) {
  return accountHead({ accountId: me.accountId, masterKeys: me.masterKeys, roots: me.roots, envelopeBinding: me.binding })
}

/** The marks in a verified copy of the scope, each record opened as the revision listed. */
async function marksOf(copy: ScopeRecords, me: DriveIdentity): Promise<MarksState> {
  const ids = [...copy.records.keys()].sort()
  if (ids.length === 0) return { id: null, revision: 0, marks: EMPTY, others: [] }
  const opened: { id: string; revision: number; marks: PhotosLibraryMarks }[] = []
  for (const id of ids) {
    const stored = copy.records.get(id)!
    const { marks, revision } = await openPhotosLibrary(stored.envelope, me, id)
    // The revision the verified index lists must be the record's own.
    if (revision !== stored.revision) {
      throw new Error('the Photos library record differs from what the server says of it')
    }
    opened.push({ id, revision, marks })
  }
  const [first, ...rest] = opened
  let marks = first.marks
  for (const other of rest) {
    for (const kind of KINDS) marks = withMark(marks, kind, other.marks[kind], true)
  }
  return { id: first.id, revision: first.revision, marks, others: rest.map((r) => r.id) }
}

/** The account's marks as the server keeps them, checked against the verified account head. */
export async function loadMarks(me: DriveIdentity): Promise<MarksState> {
  const head = await headOf(me)
  return marksOf(await head.records('photosLibrary'), me)
}

/** Changes the marks and stores them with the next account head; the cache holds the result. */
export async function changeMarks(
  queryClient: QueryClient,
  me: DriveIdentity,
  change: (marks: PhotosLibraryMarks) => PhotosLibraryMarks,
): Promise<void> {
  const cacheKey = [...marksKey, me.accountId]
  const head = await headOf(me)
  // Redone on the newest copy when another device wrote first.
  const state = await head.recordsWrite('photosLibrary', async (copy) => {
    const current = await marksOf(copy, me)
    const marks = change(current.marks)
    const id = current.id ?? randomRecordId()
    const revision = current.revision + 1
    const envelope = await sealPhotosLibrary(marks, me, id, revision)
    const done: MarksState = { id, revision, marks, others: [] }
    return { puts: [{ id, revision, envelope }], deletes: current.others, done }
  })
  // The record's canonical order comes back when it is next read; the sets are what matter.
  if (state) queryClient.setQueryData<MarksState>(cacheKey, state)
}

/** Add or remove photos from one of the marks. */
export function withMark(marks: PhotosLibraryMarks, kind: MarkKind, ids: readonly string[], on: boolean): PhotosLibraryMarks {
  const set = new Set(marks[kind])
  for (const id of ids) {
    if (on) set.add(id)
    else set.delete(id)
  }
  return { ...marks, [kind]: [...set] }
}

export interface Marks {
  favourites: ReadonlySet<string>
  archived: ReadonlySet<string>
  hidden: ReadonlySet<string>
  loading: boolean
  error: boolean
  /** Mark or unmark photos; resolves once stored. */
  set: (kind: MarkKind, ids: readonly string[], on: boolean) => Promise<void>
}

export function useMarks(): Marks {
  const queryClient = useQueryClient()
  const identity = useDriveIdentity()
  const me = identity.data
  const query = useQuery({
    queryKey: [...marksKey, me?.accountId],
    enabled: Boolean(me),
    queryFn: () => loadMarks(me!),
  })
  const data = query.data
  const sets = useMemo(
    () => ({
      favourites: new Set(data?.marks.favourites ?? []),
      archived: new Set(data?.marks.archived ?? []),
      hidden: new Set(data?.marks.hidden ?? []),
    }),
    [data],
  )
  const set = useCallback(
    (kind: MarkKind, ids: readonly string[], on: boolean) => {
      if (!me) return Promise.reject(new Error('the library is not ready'))
      // Queued with the account's other records writes, one at a time.
      return changeMarks(queryClient, me, (marks) => withMark(marks, kind, ids, on))
    },
    [me, queryClient],
  )
  const loading = query.isPending
  const error = query.isError
  return useMemo(() => ({ ...sets, loading, error, set }), [sets, loading, error, set])
}
