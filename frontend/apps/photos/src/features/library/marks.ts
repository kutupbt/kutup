import { useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { useCallback, useMemo } from 'react'
import {
  openPhotosLibrary,
  photosLibraryDigest,
  sealPhotosLibrary,
  type PhotosLibraryMarks,
} from '@kutup/crypto/photosLibrary'
import { localChainPins } from '@kutup/crypto/localChainPins'
import { useDriveIdentity, type DriveIdentity } from '@kutup/drive-core/identity'
import api from '@kutup/session/client'

// Your own marks on photos (docs/plans/photos.md): favourites, archived and
// hidden, in one account-private record. The server keeps the latest and
// accepts only its successor; a change another device made first comes back
// as 409 with the newer record, and the change is applied again on top of it.
// This browser keeps the newest record it has seen (its revision and digest,
// a local chain pin) and refuses an older one, or another at the same
// revision: a server can't bring back marks that were taken off (a photo
// hidden again shown).

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

// The pin is a sealed, account-bound record in this browser's IndexedDB
// (`@kutup/crypto/localChainPins`, purpose `LocalChainPin`), named by a keyed
// hash of the incarnation; a missing pin, or one that does not open, is
// unseen (the record read is trusted and pinned, as on a new browser).
const PIN_SCOPE = 'photos-library'
/** Where pins were kept before they were sealed: removed on the first pin stored. */
const OLD_PIN_PREFIX = 'kutup.photos.library.pin.v1.'

function pinsOf(me: DriveIdentity) {
  return localChainPins({ masterKey: me.masterKey, roots: me.roots, envelopeBinding: me.binding })
}

async function loadPin(me: DriveIdentity): Promise<{ revision: number; digest: string } | null> {
  const pin = await pinsOf(me).loadPin(PIN_SCOPE, me.incarnationId)
  return pin && { revision: Number(pin.revision), digest: pin.digest }
}

let oldPinsRemoved = false

/** Remember `revision` as the newest record seen, never moving back. */
async function storePin(me: DriveIdentity, revision: number, digest: string): Promise<void> {
  try {
    await pinsOf(me).storePin(PIN_SCOPE, me.incarnationId, revision, digest)
  } catch {
    // Storage may be off: the chain is still checked, only not across restarts.
    return
  }
  if (!oldPinsRemoved) {
    oldPinsRemoved = true
    removeOldPins()
  }
}

function removeOldPins(): void {
  try {
    const storage = globalThis.localStorage
    if (!storage) return
    const old: string[] = []
    for (let i = 0; i < storage.length; i++) {
      const key = storage.key(i)
      if (key?.startsWith(OLD_PIN_PREFIX)) old.push(key)
    }
    for (const key of old) storage.removeItem(key)
  } catch {
    // Storage may be off: nothing to remove then.
  }
}

/** A record the server shows, against the newest this browser has seen. */
async function checkPin(me: DriveIdentity, revision: number, digest: string): Promise<void> {
  const pin = await loadPin(me)
  if (!pin) return
  if (revision < pin.revision || (revision === pin.revision && digest !== pin.digest)) {
    throw new Error('the server showed an older Photos library than this browser has seen')
  }
}

async function openRecord(record: StoredRecord, me: DriveIdentity): Promise<MarksState> {
  const { marks, header } = await openPhotosLibrary(record.envelope, me, me.incarnationId)
  // What the server says of the record must be what the record says.
  const digest = await photosLibraryDigest(record.envelope)
  if (header.revision !== record.revision || digest !== record.envelopeDigest) {
    throw new Error('the Photos library record differs from what the server says of it')
  }
  await checkPin(me, header.revision, digest)
  await storePin(me, header.revision, digest)
  return { revision: header.revision, digest, marks }
}

/** The account's marks as the server keeps them, checked against this browser's pin. */
export async function loadMarks(me: DriveIdentity): Promise<MarksState> {
  try {
    const { data } = await api.get<StoredRecord>('/photos/library')
    return await openRecord(data, me)
  } catch (error) {
    if (isAxiosError(error) && error.response?.status === 404) {
      // No record, though this browser saw one: dropped by the server.
      if (await loadPin(me)) throw new Error('the server no longer shows the Photos library this browser has seen')
      return { revision: 0, digest: undefined, marks: EMPTY }
    }
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
  const cacheKey = [...marksKey, me.userId]
  let state = queryClient.getQueryData<MarksState>(cacheKey) ?? (await loadMarks(me))
  for (let attempt = 0; attempt < 5; attempt++) {
    const next = change(state.marks)
    const sealed = await sealPhotosLibrary(next, me, me.incarnationId, state.revision + 1, state.digest)
    try {
      await api.put('/photos/library', { envelope: sealed.envelope })
      await storePin(me, state.revision + 1, sealed.digest)
      // The record's canonical order comes back when it is next read; the sets are what matter.
      queryClient.setQueryData<MarksState>(cacheKey, { revision: state.revision + 1, digest: sealed.digest, marks: next })
      return
    } catch (error) {
      if (!(isAxiosError(error) && error.response?.status === 409)) throw error
      const newer = error.response.data as Partial<StoredRecord> | undefined
      state = newer?.envelope && newer.revision && newer.envelopeDigest
        ? await openRecord(newer as StoredRecord, me)
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
