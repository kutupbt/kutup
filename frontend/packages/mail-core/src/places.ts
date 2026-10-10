import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { openMailName, sealMailName, toBase64 } from '@kutup/crypto'
import api from '@kutup/session/client'
import { useRequiredSession } from '@kutup/session/store'
import { mailKey, useMailAccount } from './api'

// The account's own folders and labels (docs/plans/mail-filters.md, F1), as
// Proton's: folders nest three deep and hold mail in one place, labels are
// tags. Names are sealed here, bound to the account and an id chosen here,
// so the server keeps only ids, colours, order and the tree.

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
  /** 1 for a top folder. */
  depth: number
  children: MailFolder[]
}

export interface MailLabel {
  id: string
  name: string
  color: string
  position: number
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
    queryFn: async (): Promise<MailPlaces> => {
      const { data } = await api.get<PlacesRow>('/mail/places')
      const masterKey = toBase64(session.masterKey)
      let unreadable = 0
      const open = (kind: 'folder' | 'label', id: string, sealed: string) =>
        openMailName(masterKey, address!, kind, id, sealed).catch(() => {
          unreadable += 1
          return '…'
        })
      const folders = new Map<string, MailFolder>()
      await Promise.all(
        data.folders.map(async (row) => {
          folders.set(row.id, { ...row, name: await open('folder', row.id, row.name), depth: 1, children: [] })
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
      const labels = (await Promise.all(data.labels.map(async (row) => ({ ...row, name: await open('label', row.id, row.name) })))).sort(byPosition)
      return { tree, folders, labels, labelsById: new Map(labels.map((l) => [l.id, l])), unreadable }
    },
  })
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

function usePlaceMutation<T, R>(fn: (input: T, seal: (kind: 'folder' | 'label', id: string, name: string) => Promise<string>) => Promise<R>) {
  const session = useRequiredSession()
  const account = useMailAccount()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (input: T) => {
      const address = account.data?.address
      if (!address) throw new Error('mail is not ready')
      const masterKey = toBase64(session.masterKey)
      return fn(input, (kind, id, name) => sealMailName(masterKey, address, kind, id, name))
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: mailKey }),
  })
}

export function useCreateFolder() {
  return usePlaceMutation(async (input: { name: string; color: string; parentId: string | null }, seal) => {
    const id = crypto.randomUUID()
    await api.post('/mail/folders', { id, parentId: input.parentId, name: await seal('folder', id, input.name), color: input.color })
    return id
  })
}

export function useUpdateFolder() {
  return usePlaceMutation(
    async (
      input: { id: string; name?: string; color?: string; parentId?: string | null; position?: number; expanded?: boolean; notify?: boolean },
      seal,
    ) => {
      const { id, name, ...rest } = input
      await api.patch(`/mail/folders/${id}`, { ...rest, ...(name !== undefined ? { name: await seal('folder', id, name) } : {}) })
    },
  )
}

export function useDeleteFolder() {
  return usePlaceMutation(async (id: string) => (await api.delete<{ folders: number; moved: number }>(`/mail/folders/${id}`)).data)
}

export function useCreateLabel() {
  return usePlaceMutation(async (input: { name: string; color: string }, seal) => {
    const id = crypto.randomUUID()
    await api.post('/mail/labels', { id, name: await seal('label', id, input.name), color: input.color })
    return id
  })
}

export function useUpdateLabel() {
  return usePlaceMutation(async (input: { id: string; name?: string; color?: string; position?: number }, seal) => {
    const { id, name, ...rest } = input
    await api.patch(`/mail/labels/${id}`, { ...rest, ...(name !== undefined ? { name: await seal('label', id, name) } : {}) })
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
