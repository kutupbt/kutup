import { useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { useCallback, useMemo } from 'react'
import {
  openPhotosLibrary,
  photosLibraryKey,
  sealPhotosLibrary,
  type PhotosLibraryMarks,
} from '@kutup/crypto/photosLibrary'
import { useDriveIdentity, type DriveIdentity } from '@kutup/drive-core/identity'
import api from '@kutup/session/client'

// Your own marks on photos (docs/plans/photos.md): favourites, archived and
// hidden, in one account-private record. The server keeps the latest and
// accepts only its successor; a change another device made first comes back
// as 409 with the newer record, and the change is applied again on top of it.

export type MarkKind = keyof PhotosLibraryMarks

interface StoredRecord {
  envelope: string
  revision: number
  envelopeDigest: string
}

interface MarksState {
  /** 0 before the first record. */
  revision: number
  digest: string | undefined
  marks: PhotosLibraryMarks
}

const EMPTY: PhotosLibraryMarks = { favourites: [], archived: [], hidden: [] }
export const marksKey = ['photos-marks'] as const

async function openRecord(record: StoredRecord, key: string, me: DriveIdentity): Promise<MarksState> {
  const { marks } = await openPhotosLibrary(record.envelope, key, me.incarnationId)
  return { revision: record.revision, digest: record.envelopeDigest, marks }
}

async function loadMarks(me: DriveIdentity): Promise<MarksState> {
  const key = await photosLibraryKey(me.masterKey)
  try {
    const { data } = await api.get<StoredRecord>('/photos/library')
    return await openRecord(data, key, me)
  } catch (error) {
    if (isAxiosError(error) && error.response?.status === 404) return { revision: 0, digest: undefined, marks: EMPTY }
    throw error
  }
}

// One write at a time per tab, so this tab never races itself.
let writing: Promise<unknown> = Promise.resolve()

async function write(
  queryClient: QueryClient,
  me: DriveIdentity,
  change: (marks: PhotosLibraryMarks) => PhotosLibraryMarks,
): Promise<void> {
  const key = await photosLibraryKey(me.masterKey)
  const cacheKey = [...marksKey, me.userId]
  let state = queryClient.getQueryData<MarksState>(cacheKey) ?? (await loadMarks(me))
  for (let attempt = 0; attempt < 5; attempt++) {
    const next = change(state.marks)
    const sealed = await sealPhotosLibrary(next, key, me.incarnationId, state.revision + 1, state.digest)
    try {
      await api.put('/photos/library', { envelope: sealed.envelope })
      // The record's canonical order comes back when it is next read; the sets are what matter.
      queryClient.setQueryData<MarksState>(cacheKey, { revision: state.revision + 1, digest: sealed.digest, marks: next })
      return
    } catch (error) {
      if (!(isAxiosError(error) && error.response?.status === 409)) throw error
      const newer = error.response.data as Partial<StoredRecord> | undefined
      state = newer?.envelope && newer.revision && newer.envelopeDigest
        ? await openRecord(newer as StoredRecord, key, me)
        : await loadMarks(me)
      queryClient.setQueryData<MarksState>(cacheKey, state)
    }
  }
  throw new Error('the library kept changing; try again')
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
    queryKey: [...marksKey, me?.userId],
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
      const run = writing.then(() => write(queryClient, me, (marks) => withMark(marks, kind, ids, on)))
      writing = run.catch(() => {})
      return run
    },
    [me, queryClient],
  )
  const loading = query.isPending
  const error = query.isError
  return useMemo(() => ({ ...sets, loading, error, set }), [sets, loading, error, set])
}
