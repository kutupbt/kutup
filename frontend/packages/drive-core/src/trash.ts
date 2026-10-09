import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { openFileRecordV1, openOwnedCollectionKeyV1, openOwnedCollectionV1 } from '@kutup/crypto'
import api from '@kutup/session/client'
import { updateSession } from '@kutup/session/store'
import { toDriveFile } from './files'
import { foldersKey } from './folders'
import { useDriveIdentity } from './identity'
import { fileKind, type ItemKind } from './kinds'
import { folderKeyAt } from './keyring'
import type { DriveFile } from './model'

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
          const name = await openOwnedCollectionV1(row, masterKey).then((r) => r.name, () => null)
          return { type: 'folder', id: row.id, name, kind: 'folder', size: null, deletedAt: row.deletedAt, files: row.items }
        }),
      )
      const files = await Promise.all(
        data.files.map(async (row): Promise<TrashEntry> => {
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
            .then((key) =>
              row.keyEpoch === row.collectionKeyEpoch
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
                  ),
            )
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

export function useRestore() {
  return useTrashMutation(async (id: string) => {
    await api.post(`/trash/${id}/restore`)
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
