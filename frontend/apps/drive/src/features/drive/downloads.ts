import { streamDownload } from '@kutup/files/download/streamDownload'
import { downloadAsZip, FsaRequiredError, type ZipFile } from '@kutup/files/zipDownload'
import { resolveApiBase } from '@kutup/session/apiBase'
import { freshAccessToken } from '@kutup/session/client'
import { loadFolderFiles } from './files'
import { folderLocation, type DriveFile, type Folder } from './model'

/**
 * Save one file: decrypted as it streams, straight to disk where the browser
 * allows (Chromium's save picker), otherwise assembled in memory. Cancelling
 * the save picker rejects with an AbortError the caller ignores.
 */
export async function downloadFile(folder: Folder, file: DriveFile): Promise<void> {
  if (!file.fileKey || !file.name) throw new Error('file is not open')
  const base = await resolveApiBase()
  const location = folderLocation(folder)
  await streamDownload({
    url:
      location.kind === 'local'
        ? `${base}/files/${file.id}/download`
        : `${base}/drive/federation/shares/${location.shareId}/files/${file.id}/content`,
    fileKey: file.fileKey,
    // The epoch the blob was sealed with is the file row's own.
    context: { fileId: file.id, collectionId: file.collectionId, epoch: file.keyEpoch },
    filename: file.name,
    mimeType: file.mimeType,
    expectedPlainSize: file.size,
    accessToken: await freshAccessToken(),
  })
}

export { FsaRequiredError }

/** A folder's files (not its subfolders) as one ZIP, split at 2 GiB. */
export async function downloadFolderZip(folder: Folder, onProgress: (done: number, total: number) => void): Promise<'empty' | 'done'> {
  const files = (await loadFolderFiles(folder)).filter((f) => f.fileKey && f.name)
  if (files.length === 0) return 'empty'
  const location = folderLocation(folder)
  const zipFiles: ZipFile[] = files.map((f) => ({
    id: f.id,
    collectionId: f.collectionId,
    keyEpoch: f.keyEpoch,
    name: f.name!,
    size: f.size,
    fileKey: f.fileKey!,
    ...(location.kind === 'remote' ? { isRemote: true, remoteShareId: location.shareId } : {}),
  }))
  await downloadAsZip(zipFiles, folder.name ?? 'folder', await freshAccessToken(), (done, total) => onProgress(done, total))
  return 'done'
}
