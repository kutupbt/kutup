import { useMutation, useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { getI18n } from 'react-i18next'
import { openMailName, revisionGuard, sealMailName, toBase64, type MailNameKind } from '@kutup/crypto'
import {
  accountHead,
  HeadBlockedError,
  NotInVerifiedIndexError,
  type ListedEdit,
  type VerifiedIndex,
} from '@kutup/session/accountHead'
import api from '@kutup/session/client'
import { useRequiredSession } from '@kutup/session/store'
import { mailKey, useMailAccount } from './api'

// The account's own folders and labels (docs/plans/mail-filters.md, F1), as
// Proton's: folders nest three deep and hold mail in one place, labels are
// tags. Names are sealed here, bound to the account's key binding and an id
// chosen here, so the server keeps only ids, colours, order and the tree.
// Each name carries its revision: a name older than this browser has seen is
// refused (`RevisionGuard`), and a rename is stored only on top of the name
// it started from (`baseNameRevision`).

/** What the guard calls a sealed name. */
export const MAIL_NAME_SCOPE = 'mail-name'

/**
 * Folder, label and filter names are the account head's `mailNames` scope
 * (docs/plans/rollback-protection.md), each named `kind:id`.
 */
const HEAD_SCOPE = 'mailNames'

type HeadSession = { masterKey: Uint8Array; envelopeBinding: string; userId: string }

/**
 * The head's index of the mail names, or null when it cannot vouch (this
 * app is blocked on another history: reads go on, held to this browser's own
 * guard, and the banner says why).
 */
export async function mailNamesIndex(session: HeadSession): Promise<VerifiedIndex | null> {
  try {
    return await (await accountHead(session)).verifiedIndex(HEAD_SCOPE)
  } catch (error) {
    if (error instanceof HeadBlockedError) return null
    throw error
  }
}

/** A listed write of mail names, with the next account head. */
export async function listedNames<T>(session: HeadSession, edit: (index: VerifiedIndex, attempt: number) => Promise<ListedEdit<T> | null>): Promise<T | undefined> {
  return (await accountHead(session)).listedWrite(HEAD_SCOPE, edit)
}

/**
 * Reads names with the head's index: names that are not the ones it vouches
 * for (rolled back, dropped, brought back) are read again once, then refused
 * (the list does not show at all rather than show what the server chose).
 */
export async function readGuarded<T>(session: HeadSession, read: (index: VerifiedIndex | null) => Promise<T>): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    const index = await mailNamesIndex(session)
    try {
      return await read(index)
    } catch (error) {
      if (!(error instanceof NotInVerifiedIndexError) || attempt > 0) throw error
    }
  }
}

/** "Unnamed folder", in the person's language: a folder kept through an account reset, its name gone with the old keys. */
function unnamedFolder(): string {
  return getI18n()?.t('mailPlaces.unnamedFolder') ?? 'Unnamed folder'
}

/** Opens a sealed name and checks it is not older than one seen; `null` when it does not open. */
export async function openGuardedName(
  session: { masterKey: Uint8Array; envelopeBinding: string; userId: string },
  kind: MailNameKind,
  id: string,
  sealed: string,
): Promise<{ name: string; revision: number } | null> {
  try {
    const opened = await openMailName(toBase64(session.masterKey), session.envelopeBinding, kind, id, sealed)
    await revisionGuard(session).accept(MAIL_NAME_SCOPE, `${kind}:${id}`, opened.revision)
    return { name: opened.value, revision: opened.revision }
  } catch {
    return null
  }
}

/** Seals `name` for `kind`/`id` above every revision seen and above `base` (the name a rename started from). */
export async function sealGuardedName(
  session: { masterKey: Uint8Array; envelopeBinding: string; userId: string },
  kind: MailNameKind,
  id: string,
  name: string,
  base = 0,
): Promise<{ sealed: string; revision: number }> {
  const revision = await revisionGuard(session).next(MAIL_NAME_SCOPE, `${kind}:${id}`, base)
  return { sealed: await sealMailName(toBase64(session.masterKey), session.envelopeBinding, kind, id, revision, name), revision }
}

/** Another device renamed it first (the server's `revision_conflict`). */
export function isRevisionConflict(error: unknown): boolean {
  return isAxiosError(error) && error.response?.status === 409 && (error.response.data as { code?: string } | undefined)?.code === 'revision_conflict'
}

/** Folders nest at most this deep (the server enforces it too). */
export const MAX_FOLDER_DEPTH = 3

/** Colours to choose from, as Proton offers a palette (`ACCENT_COLORS`). */
export const PLACE_COLORS = [
  '#8080ff', '#db60d6', '#ec3e7c', '#f78400', '#efc500', '#54b77b',
  '#3cbb3a', '#00b2a3', '#1da4d4', '#4d85e0', '#7c5cff', '#7e7e7e',
] as const

export interface MailFolder {
  id: string
  parentId: string | null
  name: string
  color: string
  position: number
  expanded: boolean
  notify: boolean
  /** The revision of the sealed name (0 when it did not open). */
  nameRevision: number
  /** Kept through an account reset without its name ("Unnamed folder" until named again). */
  unnamed?: boolean
  /** 1 for a top folder. */
  depth: number
  children: MailFolder[]
}

export interface MailLabel {
  id: string
  name: string
  color: string
  position: number
  /** The revision of the sealed name (0 when it did not open). */
  nameRevision: number
}

export interface MailPlaces {
  /** Top folders, each with its children, in order. */
  tree: MailFolder[]
  /** Every folder, by id. */
  folders: Map<string, MailFolder>
  labels: MailLabel[]
  labelsById: Map<string, MailLabel>
  /** Names that did not open (counted, shown as such). */
  unreadable: number
}

interface PlacesRow {
  /** `name` is null for a folder kept through an account reset (its name went with the old keys). */
  folders: { id: string; parentId: string | null; name: string | null; color: string; position: number; expanded: boolean; notify: boolean }[]
  labels: { id: string; name: string; color: string; position: number }[]
}

export const placesKey = ['mail', 'places'] as const

function byPosition<T extends { position: number; name: string }>(a: T, b: T) {
  return a.position - b.position || a.name.localeCompare(b.name)
}

/** The account's folders and labels, with their names opened. */
export function usePlaces() {
  const session = useRequiredSession()
  const account = useMailAccount()
  const address = account.data?.address
  return useQuery({
    queryKey: [...placesKey, address],
    enabled: !!address,
    staleTime: 60_000,
    queryFn: () => loadPlaces(session),
  })
}

type NameSession = { masterKey: Uint8Array; envelopeBinding: string; userId: string }

/** The account's folders and labels, read now, with their names opened and held to the account head. */
async function loadPlaces(session: NameSession): Promise<MailPlaces> {
  return readGuarded(session, (index) => openPlaces(session, index))
}

async function openPlaces(session: NameSession, index: VerifiedIndex | null): Promise<MailPlaces> {
  const { data } = await api.get<PlacesRow>('/mail/places')
  index?.expectListing(
    data.folders.filter((row) => row.name !== null).map((row) => `folder:${row.id}`),
    'folder:',
  )
  index?.expectListing(
    data.labels.map((row) => `label:${row.id}`),
    'label:',
  )
  let unreadable = 0
  const open = async (kind: 'folder' | 'label', id: string, sealed: string) => {
    const opened = await openGuardedName(session, kind, id, sealed)
    if (!opened) unreadable += 1
    else index?.expect(`${kind}:${id}`, opened.revision)
    return { name: opened?.name ?? '…', nameRevision: opened?.revision ?? 0 }
  }
  const folders = new Map<string, MailFolder>()
  await Promise.all(
    data.folders.map(async (row) => {
      // Kept through an account reset without its name: not a value the
      // head lists, nor an unreadable one.
      const named = row.name === null ? { name: unnamedFolder(), nameRevision: 0, unnamed: true } : await open('folder', row.id, row.name)
      folders.set(row.id, { ...row, ...named, depth: 1, children: [] })
    }),
  )
  const tree: MailFolder[] = []
  for (const folder of folders.values()) {
    const parent = folder.parentId ? folders.get(folder.parentId) : undefined
    if (parent) parent.children.push(folder)
    else tree.push(folder)
  }
  const place = (list: MailFolder[], depth: number) => {
    list.sort(byPosition)
    for (const folder of list) {
      folder.depth = depth
      place(folder.children, depth + 1)
    }
  }
  place(tree, 1)
  const labels = (await Promise.all(data.labels.map(async (row) => ({ ...row, ...(await open('label', row.id, row.name)) })))).sort(byPosition)
  return { tree, folders, labels, labelsById: new Map(labels.map((l) => [l.id, l])), unreadable }
}

/** Every folder in tree order, for pickers: each with its depth. */
export function flattenFolders(tree: MailFolder[]): MailFolder[] {
  return tree.flatMap((folder) => [folder, ...flattenFolders(folder.children)])
}

/** The folder's path ("Work / Clients / Acme"). */
export function folderPath(places: MailPlaces, id: string): string {
  const names: string[] = []
  for (let folder = places.folders.get(id); folder; folder = folder.parentId ? places.folders.get(folder.parentId) : undefined) {
    names.unshift(folder.name)
  }
  return names.join(' / ')
}

/** How deep the deepest folder under `folder` goes, counted from it (1 when it has none). */
export function heightOf(folder: MailFolder): number {
  return 1 + Math.max(0, ...folder.children.map(heightOf))
}

/** Whether `name` is free among `siblings` (the server cannot check sealed names). */
export function nameIsFree(name: string, siblings: { id: string; name: string }[], except?: string): boolean {
  const wanted = foldName(name)
  return !siblings.some((s) => s.id !== except && foldName(s.name) === wanted)
}

/**
 * A name as compared for uniqueness: trimmed, case folded with Turkish İ, I,
 * ı and i taken as one letter (a plain `toLowerCase` turns İ into "i̇").
 */
export function foldName(name: string): string {
  return name.trim().normalize('NFC').replace(/[İIı]/g, 'i').toLowerCase().normalize('NFC')
}

/**
 * Creates a sealed name (folder, label or filter) with the next account head:
 * `post` gets the sealed name and the head. Stored already (a retry after a
 * lost answer) counts as stored.
 */
export async function createName(
  session: HeadSession,
  kind: MailNameKind,
  id: string,
  name: string,
  post: (sealed: string, head: string) => Promise<unknown>,
): Promise<void> {
  const { sealed, revision } = await sealGuardedName(session, kind, id, name)
  const key = `${kind}:${id}`
  await listedNames(session, (index) =>
    Promise.resolve(index.revision(key) === revision ? null : { changes: [[key, revision]] as const, send: (head: string) => post(sealed, head) }),
  )
  await revisionGuard(session)
    .accept(MAIL_NAME_SCOPE, key, revision)
    .catch(() => undefined)
}

/**
 * Renames on top of the name the account head lists now (0 for a folder
 * kept through a reset without its name), with the next head; when another
 * device renamed first, once more on top of that name.
 */
export async function renameName(
  session: HeadSession,
  kind: MailNameKind,
  id: string,
  name: string,
  patch: (body: { name: string; baseNameRevision: number; head: string }) => Promise<unknown>,
): Promise<void> {
  const key = `${kind}:${id}`
  let stored = 0
  await listedNames(session, async (index) => {
    const base = index.revision(key) ?? 0
    const { sealed, revision } = await sealGuardedName(session, kind, id, name, base)
    return {
      changes: [[key, revision]] as const,
      send: async (head: string) => {
        await patch({ name: sealed, baseNameRevision: base, head })
        stored = revision
      },
    }
  })
  if (stored) await revisionGuard(session).accept(MAIL_NAME_SCOPE, key, stored)
}

interface PlaceTools {
  /** Creates a folder or label: `post` gets its sealed name and the head. */
  create: (kind: 'folder' | 'label', id: string, name: string, post: (sealed: string, head: string) => Promise<unknown>) => Promise<void>
  /** Renames with `patch` (the sealed name, the revision it starts from, the head). */
  rename: (kind: 'folder' | 'label', id: string, name: string, patch: (body: { name: string; baseNameRevision: number; head: string }) => Promise<unknown>) => Promise<void>
  /** The places as cached for the first try, then as the server has them now. */
  places: (attempt: number) => Promise<MailPlaces>
  session: HeadSession
}

/** The places as the server has them now (also when no page shows them). */
function freshPlaces(queryClient: QueryClient, address: string, session: NameSession): Promise<MailPlaces> {
  return queryClient.fetchQuery({ queryKey: [...placesKey, address], queryFn: () => loadPlaces(session), staleTime: 0 })
}

function usePlaceMutation<T, R>(fn: (input: T, tools: PlaceTools) => Promise<R>) {
  const session = useRequiredSession()
  const account = useMailAccount()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (input: T) => {
      const address = account.data?.address
      if (!address) throw new Error('mail is not ready')
      const tools: PlaceTools = {
        create: (kind, id, name, post) => createName(session, kind, id, name, post),
        rename: (kind, id, name, patch) => renameName(session, kind, id, name, patch),
        places: async (attempt) =>
          (attempt <= 1 ? queryClient.getQueryData<MailPlaces>([...placesKey, address]) : undefined) ?? freshPlaces(queryClient, address, session),
        session,
      }
      return fn(input, tools)
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: mailKey }),
  })
}

export function useCreateFolder() {
  return usePlaceMutation(async (input: { name: string; color: string; parentId: string | null }, { create }) => {
    const id = crypto.randomUUID()
    await create('folder', id, input.name, (name, head) => api.post('/mail/folders', { id, parentId: input.parentId, name, color: input.color, head }))
    return id
  })
}

export function useUpdateFolder() {
  return usePlaceMutation(
    async (
      input: { id: string; name?: string; color?: string; parentId?: string | null; position?: number; expanded?: boolean; notify?: boolean },
      { rename },
    ) => {
      const { id, name, ...rest } = input
      // Colour, place, order and folding are not sealed: no head.
      if (name === undefined) await api.patch(`/mail/folders/${id}`, rest)
      else await rename('folder', id, name, (body) => api.patch(`/mail/folders/${id}`, { ...rest, ...body }))
    },
  )
}

/** A folder and every folder inside it, as the server removes them together. */
export function folderAndInside(places: MailPlaces, id: string): string[] {
  const folder = places.folders.get(id)
  return folder ? [id, ...folder.children.flatMap((child) => folderAndInside(places, child.id))] : [id]
}

/**
 * Deletes a folder and the folders inside it, naming them all with the next
 * head (one made inside meanwhile: the server refuses, and it is read again).
 */
export function useDeleteFolder() {
  return usePlaceMutation(async (id: string, { places, session }) => {
    let moved: { folders: number; moved: number } | undefined
    await listedNames(session, async (index, attempt) => {
      const removes = folderAndInside(await places(attempt), id)
      return {
        // Folders without a name (kept through a reset) are not in the head.
        changes: removes.filter((folder) => index.revision(`folder:${folder}`) !== undefined).map((folder) => [`folder:${folder}`, null] as const),
        send: async (head: string) => {
          moved = (await api.delete<{ folders: number; moved: number }>(`/mail/folders/${id}`, { data: { removes, head } })).data
        },
      }
    })
    return moved
  })
}

export function useCreateLabel() {
  return usePlaceMutation(async (input: { name: string; color: string }, { create }) => {
    const id = crypto.randomUUID()
    await create('label', id, input.name, (name, head) => api.post('/mail/labels', { id, name, color: input.color, head }))
    return id
  })
}

export function useUpdateLabel() {
  return usePlaceMutation(async (input: { id: string; name?: string; color?: string; position?: number }, { rename }) => {
    const { id, name, ...rest } = input
    if (name === undefined) await api.patch(`/mail/labels/${id}`, rest)
    else await rename('label', id, name, (body) => api.patch(`/mail/labels/${id}`, { ...rest, ...body }))
  })
}

export function useDeleteLabel() {
  return usePlaceMutation(async (id: string, { session }) => {
    await listedNames(session, (index) =>
      Promise.resolve(
        // Gone already: nothing to do.
        index.revision(`label:${id}`) === undefined
          ? null
          : {
              changes: [[`label:${id}`, null]] as const,
              send: async (head: string) => {
                await api.delete(`/mail/labels/${id}`, { data: { head } })
              },
            },
      ),
    )
  })
}

/**
 * Puts `id` at `index` among `siblings` (already in order) and saves the
 * positions that changed, for drag-to-reorder in Settings.
 */
export function reorder<T extends { id: string; position: number }>(siblings: T[], id: string, index: number): { id: string; position: number }[] {
  const rest = siblings.filter((s) => s.id !== id)
  const moved = siblings.find((s) => s.id === id)
  if (!moved) return []
  rest.splice(Math.max(0, Math.min(index, rest.length)), 0, moved)
  return rest.flatMap((s, position) => (s.position === position ? [] : [{ id: s.id, position }]))
}
