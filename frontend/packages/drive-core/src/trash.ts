import { useMutation, useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import {
  openFileRecordV1,
  openOwnedCollectionKeyV1,
  openOwnedCollectionV1,
  renameFileRecordV1,
  renameOwnedCollectionV1,
} from '@kutup/crypto'
import api from '@kutup/session/client'
import { updateSession } from '@kutup/session/store'
import { toDriveFile } from './files'
import { cachedFolderIndex, foldersKey, openRow, type CollectionRowWithTimes } from './folders'
import { useDriveIdentity, type DriveIdentity } from './identity'
import { fileKind, type ItemKind } from './kinds'
import { folderKeyAt, type KeyringFolder } from './keyring'
import { fileMetadataOf, type DriveFile } from './model'
import { asNameTaken, atTopLevel, availableHashes, findAvailableName, inFolder, nameHashIn, type NamePlace } from './names'

interface TrashFolderRow {
  id: string
  ownerUserId: string
  nameEnvelope: string
  ownerKeyEnvelope: string
  keyEpoch: number
  nameRevision: number
  epochStatement: string
  epochStatementHash: string
  color: string | null
  /** Where it comes back: this folder while it is live; null: the top level. */
  parentCollectionId: string | null
  items: number
  deletedAt: string
}

interface TrashFileRow {
  id: string
  collectionId: string
  metadataEnvelope: string
  fileKeyEnvelope: string
  keyEpoch: number
  keyGeneration: number
  metadataRevision: number
  collectionOwnerUserId: string
  collectionOwnerKeyEnvelope: string
  collectionKeyEpoch: number
  collectionEpochStatement: string
  collectionEpochStatementHash: string
  deletedAt: string
  thumbnails: { sm?: string; lg?: string; smKeyGeneration?: number; lgKeyGeneration?: number }
}

export interface TrashEntry {
  type: 'folder' | 'file'
  id: string
  name: string | null
  kind: ItemKind
  size: number | null
  deletedAt: string
  /** Folders: how many files went to trash with it. */
  files?: number
  /** Files: the file as opened (its key and thumbnails), for pictures of it. */
  file?: DriveFile
  /** Files: the folder it comes back to, as far as naming it there needs. */
  folder?: KeyringFolder
  /** Folders: what renaming it on the way back needs. */
  renamable?: { key: Uint8Array; keyEpoch: number; nameRevision: number; ownerUserId: string; parentCollectionId: string | null }
}

export const trashKey = ['trash'] as const

/** Your trash: folders (with everything inside) and files, decrypted. */
export function useTrash() {
  const identity = useDriveIdentity()
  return useQuery({
    queryKey: trashKey,
    enabled: identity.isSuccess,
    queryFn: async (): Promise<TrashEntry[]> => {
      const me = identity.data!
      const masterKey = me.masterKey
      const { data } = await api.get<{ folders: TrashFolderRow[]; files: TrashFileRow[] }>('/trash')
      const folders = await Promise.all(
        data.folders.map(async (row): Promise<TrashEntry> => {
          const opened = await openOwnedCollectionV1(row, masterKey).catch(() => null)
          return {
            type: 'folder',
            id: row.id,
            name: opened?.name ?? null,
            kind: 'folder',
            size: null,
            deletedAt: row.deletedAt,
            files: row.items,
            renamable: opened
              ? {
                  key: opened.collectionKey,
                  keyEpoch: row.keyEpoch,
                  nameRevision: row.nameRevision,
                  ownerUserId: row.ownerUserId,
                  parentCollectionId: row.parentCollectionId ?? null,
                }
              : undefined,
          }
        }),
      )
      const files = await Promise.all(
        data.files.map(async (row): Promise<TrashEntry> => {
          let folder: KeyringFolder | undefined
          const opened = await openOwnedCollectionKeyV1(
            {
              id: row.collectionId,
              ownerUserId: row.collectionOwnerUserId,
              ownerKeyEnvelope: row.collectionOwnerKeyEnvelope,
              keyEpoch: row.collectionKeyEpoch,
              epochStatement: row.collectionEpochStatement,
              epochStatementHash: row.collectionEpochStatementHash,
            },
            masterKey,
          )
            // A file not re-keyed since its folder rotated is wrapped under an older key.
            .then((key) => {
              folder = {
                id: row.collectionId,
                source: 'owned',
                key,
                keyEpoch: row.collectionKeyEpoch,
                ownerUserId: row.collectionOwnerUserId,
                ownerAuthorityPublicKey: me.authorityPublicKey,
                epochStatementHash: row.collectionEpochStatementHash,
              }
              return row.keyEpoch === row.collectionKeyEpoch
                ? key
                : folderKeyAt(
                    {
                      id: row.collectionId,
                      source: 'owned',
                      key,
                      keyEpoch: row.collectionKeyEpoch,
                      ownerUserId: row.collectionOwnerUserId,
                      ownerAuthorityPublicKey: me.authorityPublicKey,
                      epochStatementHash: row.collectionEpochStatementHash,
                    },
                    row.keyEpoch,
                  )
            })
            .then((key) => openFileRecordV1(row, key))
            .catch(() => null)
          const metadata = opened?.metadata ?? null
          return {
            type: 'file',
            id: row.id,
            name: metadata?.name ?? null,
            kind: metadata ? fileKind(metadata.name, metadata.mimeType) : 'other',
            size: metadata?.size ?? null,
            deletedAt: row.deletedAt,
            folder,
            file: toDriveFile(
              {
                ...row,
                // What a listing would say of it: its content as sealed now.
                originalKeyGeneration: row.keyGeneration,
                contentKeyGeneration: row.keyGeneration,
                keyHistory: [],
                createdAt: row.deletedAt,
                encryptedSizeBytes: 0,
              },
              opened,
            ),
          }
        }),
      )
      return [...folders, ...files]
    },
  })
}

function useTrashMutation<T>(fn: (input: T) => Promise<void>) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: fn,
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: trashKey }),
        queryClient.invalidateQueries({ queryKey: foldersKey }),
        queryClient.invalidateQueries({ queryKey: ['files'] }),
        // What fills the pool (storage.storageKey).
        queryClient.invalidateQueries({ queryKey: ['storage'] }),
      ])
      // Purging frees quota.
      const { data } = await api.get<{ storageUsedBytes: number }>('/user/me')
      updateSession({ storageUsedBytes: data.storageUsedBytes })
    },
  })
}

/** Restoring needs a name: what is asked, and the name offered. */
export interface RestoreNameQuestion {
  name: string
  /** The first free `name (n)` where it comes back. */
  suggested: string
}

/** Asks the person whether to restore under the offered name; false: leave it in the trash. */
export type AskRestoreName = (question: RestoreNameQuestion) => Promise<boolean>

/** A restore the person called off (its name is taken where it comes back). */
export class RestoreCancelled extends Error {
  constructor() {
    super('restore cancelled')
  }
}

/** A restore refused because the item needs a name where it comes back. */
function refusedName(error: unknown): 'taken' | 'needed' | null {
  if (asNameTaken(error)) return 'taken'
  if (isAxiosError(error) && error.response?.status === 409) {
    const code = (error.response.data as { code?: unknown } | undefined)?.code
    if (code === 'nameNeeded') return 'needed'
  }
  return null
}

/** Where `entry` comes back, to name it there; null when this device cannot tell. */
async function placeOf(entry: TrashEntry, me: DriveIdentity, queryClient: QueryClient, top: boolean): Promise<NamePlace | null> {
  if (entry.type === 'file') return entry.folder ? inFolder(entry.folder) : null
  const parentId = top ? null : (entry.renamable?.parentCollectionId ?? null)
  if (!parentId) return atTopLevel(me.masterKey)
  const known = cachedFolderIndex(queryClient)?.byId.get(parentId)
  if (known?.key) return inFolder(known)
  const { data } = await api.get<CollectionRowWithTimes>(`/collections/${parentId}`)
  const parent = await openRow(data, me)
  return parent.key ? inFolder(parent) : null
}

/** The rename a restore carries: the new name sealed at the next revision, with its hash. */
async function renameBody(entry: TrashEntry, name: string, hash: string): Promise<Record<string, unknown>> {
  if (entry.type === 'file') {
    const file = entry.file
    if (!file?.fileKey || !file.name) throw new Error('file is not open')
    const next = await renameFileRecordV1(
      { id: file.id, keyGeneration: file.keyGeneration, metadataRevision: file.metadataRevision },
      file.fileKey,
      fileMetadataOf(file, { name }),
    )
    return { nameHash: hash, ...next }
  }
  const folder = entry.renamable
  if (!folder) throw new Error('folder is not open')
  const next = await renameOwnedCollectionV1(
    { id: entry.id, ownerUserId: folder.ownerUserId, keyEpoch: folder.keyEpoch, nameRevision: folder.nameRevision },
    folder.key,
    name,
  )
  return { nameHash: hash, ...next }
}

/**
 * Put `entry` back where it was (docs/plans/drive-unique-names.md). A
 * folder coming back at the top level is named there (its hash belonged to
 * the folder it left). When its name is taken there, the person is offered
 * the first free `name (n)` (`ask`), and it comes back renamed — in the
 * same request, so it is never in the folder under a clashing name. An id
 * alone (an undo) is restored as it was.
 */
export async function restoreEntry(
  entry: TrashEntry | string,
  me: DriveIdentity,
  queryClient: QueryClient,
  ask?: AskRestoreName,
): Promise<void> {
  if (typeof entry === 'string') {
    await api.post(`/trash/${entry}/restore`)
    return
  }
  const name = entry.name
  let top = entry.type === 'folder' && entry.renamable !== undefined && entry.renamable.parentCollectionId === null
  let body: Record<string, unknown> | undefined =
    top && name ? { nameHash: await nameHashIn(atTopLevel(me.masterKey), name) } : undefined
  for (let attempt = 0; ; attempt++) {
    try {
      await api.post(`/trash/${entry.id}/restore`, body)
      return
    } catch (error) {
      const refused = refusedName(error)
      if (!refused || !name || attempt > 2) throw error
      // Its parent went meanwhile: it comes back at the top level.
      if (refused === 'needed') top = true
      const place = await placeOf(entry, me, queryClient, top)
      if (!place) throw error
      if (refused === 'needed') {
        const hash = await nameHashIn(place, name)
        if ((await availableHashes(place, [hash])).has(hash)) {
          body = { nameHash: hash }
          continue
        }
      }
      const free = await findAvailableName(place, name, { skipName: true })
      if (!ask || !(await ask({ name, suggested: free.name }))) throw new RestoreCancelled()
      body = await renameBody(entry, free.name, free.hash)
    }
  }
}

/** Restore one trash entry (or an id, for an undo); `ask` offers a free name when its own is taken. */
export function useRestore(ask?: AskRestoreName) {
  const identity = useDriveIdentity()
  const queryClient = useQueryClient()
  return useTrashMutation(async (entry: TrashEntry | string) => {
    if (!identity.data) throw new Error('drive identity is not ready')
    await restoreEntry(entry, identity.data, queryClient, ask)
  })
}

export function usePurge() {
  return useTrashMutation(async (id: string) => {
    await api.delete(`/trash/${id}`)
  })
}

export function useEmptyTrash() {
  return useTrashMutation(async (_: void) => {
    await api.delete('/trash')
  })
}
