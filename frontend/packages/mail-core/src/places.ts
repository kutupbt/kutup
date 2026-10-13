import { useMutation, useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { openMailName, revisionGuard, sealMailName, toBase64, type MailNameKind } from '@kutup/crypto'
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
  folders: { id: string; parentId: string | null; name: string; color: string; position: number; expanded: boolean; notify: boolean }[]
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

/** The account's folders and labels, read now, with their names opened. */
async function loadPlaces(session: NameSession): Promise<MailPlaces> {
  const { data } = await api.get<PlacesRow>('/mail/places')
  let unreadable = 0
  const open = async (kind: 'folder' | 'label', id: string, sealed: string) => {
    const opened = await openGuardedName(session, kind, id, sealed)
    if (!opened) unreadable += 1
    return { name: opened?.name ?? '…', nameRevision: opened?.revision ?? 0 }
  }
  const folders = new Map<string, MailFolder>()
  await Promise.all(
    data.folders.map(async (row) => {
      folders.set(row.id, { ...row, ...(await open('folder', row.id, row.name)), depth: 1, children: [] })
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

interface PlaceTools {
  /** A sealed name for a new folder or label. */
  seal: (kind: 'folder' | 'label', id: string, name: string) => Promise<string>
  /**
   * Renames with `patch` (given the sealed name and the revision it started
   * from); when another device renamed it first, reads the places again and
   * renames once more on top of that name.
   */
  rename: (kind: 'folder' | 'label', id: string, name: string, patch: (body: { name: string; baseNameRevision: number }) => Promise<unknown>) => Promise<void>
}

/** The places as the server has them now (also when no page shows them). */
function freshPlaces(queryClient: QueryClient, address: string, session: NameSession): Promise<MailPlaces> {
  return queryClient.fetchQuery({ queryKey: [...placesKey, address], queryFn: () => loadPlaces(session), staleTime: 0 })
}

function nameRevisionIn(places: MailPlaces | undefined, kind: 'folder' | 'label', id: string): number {
  if (!places) return 0
  return (kind === 'folder' ? places.folders.get(id)?.nameRevision : places.labelsById.get(id)?.nameRevision) ?? 0
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
        seal: async (kind, id, name) => (await sealGuardedName(session, kind, id, name)).sealed,
        rename: async (kind, id, name, patch) => {
          let places = queryClient.getQueryData<MailPlaces>([...placesKey, address])
          for (let attempt = 0; ; attempt++) {
            const base = nameRevisionIn(places, kind, id)
            const { sealed, revision } = await sealGuardedName(session, kind, id, name, base)
            try {
              await patch({ name: sealed, baseNameRevision: base })
              await revisionGuard(session).accept(MAIL_NAME_SCOPE, `${kind}:${id}`, revision)
              return
            } catch (error) {
              if (attempt > 0 || !isRevisionConflict(error)) throw error
              places = await freshPlaces(queryClient, address, session)
            }
          }
        },
      }
      return fn(input, tools)
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: mailKey }),
  })
}

export function useCreateFolder() {
  return usePlaceMutation(async (input: { name: string; color: string; parentId: string | null }, { seal }) => {
    const id = crypto.randomUUID()
    await api.post('/mail/folders', { id, parentId: input.parentId, name: await seal('folder', id, input.name), color: input.color })
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
      if (name === undefined) await api.patch(`/mail/folders/${id}`, rest)
      else await rename('folder', id, name, (body) => api.patch(`/mail/folders/${id}`, { ...rest, ...body }))
    },
  )
}

export function useDeleteFolder() {
  return usePlaceMutation(async (id: string) => (await api.delete<{ folders: number; moved: number }>(`/mail/folders/${id}`)).data)
}

export function useCreateLabel() {
  return usePlaceMutation(async (input: { name: string; color: string }, { seal }) => {
    const id = crypto.randomUUID()
    await api.post('/mail/labels', { id, name: await seal('label', id, input.name), color: input.color })
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
  return usePlaceMutation(async (id: string) => {
    await api.delete(`/mail/labels/${id}`)
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
