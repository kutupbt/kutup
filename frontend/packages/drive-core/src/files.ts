import { useQuery, useQueryClient } from '@tanstack/react-query'
import { openFileRecordV1, type FileMetadataV1 } from '@kutup/crypto'
import api from '@kutup/session/client'
import type { FileRow } from '@kutup/session/api-types'
import { fileKind } from './kinds'
import { foldersKey } from './folders'
import { folderKeyAt } from './keyring'
import { folderLocation, type DriveFile, type Folder } from './model'

export const filesKey = (folderId: string) => ['files', folderId] as const

/**
 * One folder's file list query. Keyed by the folder's epoch too: after a
 * rotation the files open with the new key.
 */
export const folderFilesKey = (folder: Pick<Folder, 'id' | 'remoteShareId' | 'keyEpoch'>) =>
  [...filesKey(folder.remoteShareId ?? folder.id), folder.keyEpoch] as const

export type FileRowLike = Omit<FileRow, 'uploaderUserId' | 'updatedAt'> & {
  uploaderUserId?: string
  updatedAt?: string
}

const opened = new Map<string, Promise<Awaited<ReturnType<typeof openFileRecordV1>> | null>>()

async function openRow(row: FileRowLike, folder: Folder): Promise<DriveFile> {
  const cacheKey = `${row.id}:${row.fileKeyEnvelope}:${row.metadataEnvelope}`
  let pending = opened.get(cacheKey)
  if (!pending) {
    // A file not re-keyed since the folder rotated is wrapped under an older key.
    pending = folderKeyAt(folder, row.keyEpoch)
      .then((collectionKey) => openFileRecordV1(row, collectionKey))
      .catch(() => null)
    opened.set(cacheKey, pending)
  }
  return toDriveFile(row, await pending)
}

/** A listed file, from its row and what opening it gave (null: it did not open). */
export function toDriveFile(
  row: FileRowLike,
  result: { fileKey: Uint8Array; metadata: FileMetadataV1 } | null,
): DriveFile {
  const name = result?.metadata.name ?? null
  return {
    id: row.id,
    collectionId: row.collectionId,
    uploaderUserId: row.uploaderUserId ?? null,
    keyEpoch: row.keyEpoch,
    keyGeneration: row.keyGeneration,
    metadataRevision: row.metadataRevision,
    name,
    mimeType: result?.metadata.mimeType ?? 'application/octet-stream',
    size: result?.metadata.size ?? 0,
    media: result?.metadata.media ?? null,
    fileKey: result?.fileKey ?? null,
    originalKeyGeneration: row.originalKeyGeneration,
    contentKeyGeneration: row.contentKeyGeneration,
    keyHistory: row.keyHistory ?? [],
    kind: name ? fileKind(name, result?.metadata.mimeType) : 'other',
    createdAt: row.createdAt,
    // Federated listings carry no updatedAt; creation is the best they know.
    updatedAt: row.updatedAt ?? row.createdAt,
    thumbnails: row.thumbnails ?? {},
    thumbnailStale: row.thumbnailStale ?? false,
    shared: row.shared ?? false,
  }
}

export async function loadFolderFiles(folder: Folder): Promise<DriveFile[]> {
  if (!folder.key) return []
  const location = folderLocation(folder)
  const { data } = await api.get<FileRowLike[]>(
    location.kind === 'local'
      ? `/collections/${location.collectionId}/files`
      : `/drive/federation/shares/${location.shareId}/files`,
  )
  return Promise.all(data.map((row) => openRow(row, folder)))
}

/** The files directly in a folder, decrypted. */
export function useFolderFiles(folder: Folder | undefined) {
  const queryClient = useQueryClient()
  return useQuery({
    queryKey: folder ? folderFilesKey(folder) : filesKey(''),
    enabled: Boolean(folder?.key),
    queryFn: async () => {
      const files = await loadFolderFiles(folder!)
      // A folder on another server whose owner moved it to a new key: bring
      // the stored share up to date (docs/plans/drive-share-revocation.md).
      if (folder!.remoteShareId && files.some((f) => f.keyEpoch > folder!.keyEpoch)) {
        await api
          .post(`/drive/federation/shares/${folder!.remoteShareId}/refresh`)
          .then(() => queryClient.invalidateQueries({ queryKey: foldersKey }))
          .catch(() => {})
      }
      return files
    },
  })
}
