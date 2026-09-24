import { isAxiosError } from 'axios'
import { rekeyFileRecordV1 } from '@kutup/crypto/fileRecord'
import api from '@kutup/session/client'
import { loadFolderFiles } from './files'
import type { DriveFile, Folder } from './model'

/**
 * Before anything new is written to a file the folder has rotated past, the
 * file moves to the folder's current key, so nobody removed from the folder
 * can read what is written next (docs/plans/drive-share-revocation.md).
 * Returns the file as it is now; unchanged when it is already current. If
 * another editor re-keyed it first, theirs is used.
 */
export async function rekeyFile(folder: Folder, file: DriveFile): Promise<DriveFile> {
  if (file.keyEpoch >= folder.keyEpoch) return file
  if (!folder.key || !file.fileKey || !file.name) throw new Error('file is not open')
  const next = await rekeyFileRecordV1(
    { id: file.id, collectionId: file.collectionId, metadataRevision: file.metadataRevision },
    folder.keyEpoch,
    folder.key,
    { name: file.name, mimeType: file.mimeType, size: file.size },
  )
  try {
    await api.post(`/files/${file.id}/rekey`, {
      fromEpoch: file.keyEpoch,
      fileKeyEnvelope: next.fileKeyEnvelope,
      metadataEnvelope: next.metadataEnvelope,
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
