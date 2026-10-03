import { fetchDecryptedChunks } from '@kutup/files/download/fetchDecrypt'
import { resolveApiBase } from '@kutup/session/apiBase'
import { freshAccessToken } from '@kutup/session/client'
import { sealedAt } from './keyring'
import { contentPath, fileLocation, type DriveFile, type Folder } from './model'

/**
 * A file's content as uploaded, decrypted as it streams, as a Blob (which the
 * browser may keep on disk). For files no editor saves versions of, such as
 * photos and videos, this is the file; `onProgress` gets plaintext bytes read.
 */
export async function readOriginal(
  folder: Pick<Folder, 'id' | 'source' | 'remoteShareId' | 'remoteFileShareId'>,
  file: DriveFile,
  signal?: AbortSignal,
  onProgress?: (read: number, total: number) => void,
): Promise<Blob> {
  if (!file.fileKey) throw new Error('file is not open')
  const url = `${await resolveApiBase()}${contentPath(fileLocation(folder), file.id)}`
  const sealed = await sealedAt(file, file.contentKeyGeneration)
  const parts: BlobPart[] = []
  let read = 0
  for await (const { plain } of fetchDecryptedChunks(url, sealed.fileKey, sealed.context, await freshAccessToken(), signal)) {
    parts.push(new Blob([plain as BlobPart]))
    read += plain.byteLength
    onProgress?.(read, file.size)
  }
  return new Blob(parts, { type: file.mimeType })
}
