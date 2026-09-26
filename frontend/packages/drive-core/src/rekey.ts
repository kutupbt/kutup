import { isAxiosError } from 'axios'
import { rekeyFileRecordV1 } from '@kutup/crypto/fileRecord'
import api from '@kutup/session/client'
import { loadFolderFiles } from './files'
import type { DriveFile, Folder } from './model'

/**
 * Before anything new is written to a file the folder has rotated past — or
 * before it moves — the file takes a new key wrapped at the folder's current
 * epoch, so nobody removed from the folder can read what comes next
 * (docs/plans/drive-share-revocation.md). The key it leaves is sealed under
 * the new one, so everything already stored stays readable wherever the file
 * goes (docs/plans/drive-move.md). Returns the file as it is now; unchanged
 * when it is already current. If another editor re-keyed it first, theirs is
 * used.
 */
export async function rekeyFile(folder: Folder, file: DriveFile): Promise<DriveFile> {
  if (file.keyEpoch >= folder.keyEpoch) return file
  if (!folder.key || !file.fileKey || !file.name) throw new Error('file is not open')
  const next = await rekeyFileRecordV1(
    {
      id: file.id,
      collectionId: file.collectionId,
      keyGeneration: file.keyGeneration,
      metadataRevision: file.metadataRevision,
    },
    file.fileKey,
    folder.keyEpoch,
    folder.key,
    { name: file.name, mimeType: file.mimeType, size: file.size },
  )
  try {
    await api.post(`/files/${file.id}/rekey`, {
      fromGeneration: file.keyGeneration,
      fileKeyEnvelope: next.fileKeyEnvelope,
      metadataEnvelope: next.metadataEnvelope,
      previousKeyEnvelope: next.previousKeyEnvelope,
    })
  } catch (error) {
    if (!(isAxiosError(error) && error.response?.status === 409)) throw error
  }
  const fresh = (await loadFolderFiles(folder)).find((f) => f.id === file.id)
  if (!fresh || fresh.keyEpoch !== folder.keyEpoch || !fresh.fileKey) {
    throw new Error('the file could not be moved to the folder key')
  }
  return fresh
}
