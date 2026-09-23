import { useQuery } from '@tanstack/react-query'
import { openFileRecordV1 } from '@kutup/crypto'
import api from '@kutup/session/client'
import type { FileRow } from '@kutup/session/api-types'
import { fileKind } from '../explorer/kinds'
import { folderLocation, type DriveFile, type Folder } from './model'

export const filesKey = (folderId: string) => ['files', folderId] as const

type FileRowLike = Omit<FileRow, 'uploaderUserId' | 'updatedAt'> & {
  uploaderUserId?: string
  updatedAt?: string
}

const opened = new Map<string, Promise<Awaited<ReturnType<typeof openFileRecordV1>> | null>>()

async function openRow(row: FileRowLike, collectionKey: Uint8Array): Promise<DriveFile> {
  const cacheKey = `${row.id}:${row.fileKeyEnvelope}:${row.metadataEnvelope}`
  let pending = opened.get(cacheKey)
  if (!pending) {
    pending = openFileRecordV1(row, collectionKey).catch(() => null)
    opened.set(cacheKey, pending)
  }
  const result = await pending
  const name = result?.metadata.name ?? null
  return {
    id: row.id,
    collectionId: row.collectionId,
    uploaderUserId: row.uploaderUserId ?? null,
    keyEpoch: row.keyEpoch,
    metadataRevision: row.metadataRevision,
    name,
    mimeType: result?.metadata.mimeType ?? 'application/octet-stream',
    size: result?.metadata.size ?? 0,
    fileKey: result?.fileKey ?? null,
    kind: name ? fileKind(name, result?.metadata.mimeType) : 'other',
    createdAt: row.createdAt,
    // Federated listings carry no updatedAt; creation is the best they know.
    updatedAt: row.updatedAt ?? row.createdAt,
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
  const key = folder.key
  return Promise.all(data.map((row) => openRow(row, key)))
}

/** The files directly in a folder, decrypted. */
export function useFolderFiles(folder: Folder | undefined) {
  return useQuery({
    queryKey: filesKey(folder?.remoteShareId ?? folder?.id ?? ''),
    enabled: Boolean(folder?.key),
    queryFn: () => loadFolderFiles(folder!),
  })
}
