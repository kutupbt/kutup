import { fetchDecryptedChunks } from '@kutup/files/download/fetchDecrypt'
import { openDownloadSink } from '@kutup/files/download/streamDownload'
import { downloadAsZip, FsaRequiredError, type ZipFile } from '@kutup/files/zipDownload'
import { resolveApiBase } from '@kutup/session/apiBase'
import { freshAccessToken } from '@kutup/session/client'
import { currentContent } from '../editor/content'
import { loadFolderFiles } from './files'
import { folderLocation, type DriveFile, type Folder } from './model'

/**
 * Save one file: decrypted as it streams, straight to disk where the browser
 * allows (Chromium's save picker), otherwise assembled in memory. Cancelling
 * the save picker rejects with an AbortError the caller ignores.
 *
 * A file an editor has saved is downloaded as its latest version, not as
 * the original upload (see currentContent).
 */
export async function downloadFile(folder: Folder, file: DriveFile): Promise<void> {
  if (!file.fileKey || !file.name) throw new Error('file is not open')
  // The save picker needs the click's user activation: ask for it first.
  const sink = await openDownloadSink({ filename: file.name, mimeType: file.mimeType })
  try {
    const base = await resolveApiBase()
    const location = folderLocation(folder)
    const content = location.kind === 'local' ? await currentContent(file) : { kind: 'original' as const }
    if (content.kind === 'plain') {
      await sink.write(content.bytes)
    } else {
      const url =
        content.kind === 'version'
          ? `${base}${content.path}`
          : location.kind === 'local'
            ? `${base}/files/${file.id}/download`
            : `${base}/drive/federation/shares/${location.shareId}/files/${file.id}/content`
      // The epoch the blob was sealed with is the file row's own.
      const context = { fileId: file.id, collectionId: file.collectionId, epoch: file.keyEpoch }
      for await (const { plain } of fetchDecryptedChunks(url, file.fileKey, context, await freshAccessToken())) {
        await sink.write(plain)
      }
    }
    await sink.finalize()
  } catch (err) {
    await sink.abort().catch(() => {})
    throw err
  }
}

export { FsaRequiredError }

/** A folder's files (not its subfolders) as one ZIP, split at 2 GiB. */
export async function downloadFolderZip(folder: Folder, onProgress: (done: number, total: number) => void): Promise<'empty' | 'done'> {
  const files = (await loadFolderFiles(folder)).filter((f) => f.fileKey && f.name)
  if (files.length === 0) return 'empty'
  const location = folderLocation(folder)
  const zipFiles: ZipFile[] = await Promise.all(
    files.map(async (f) => {
      const entry: ZipFile = {
        id: f.id,
        collectionId: f.collectionId,
        keyEpoch: f.keyEpoch,
        name: f.name!,
        size: f.size,
        fileKey: f.fileKey!,
      }
      if (location.kind === 'remote') return { ...entry, isRemote: true, remoteShareId: location.shareId }
      const content = await currentContent(f)
      if (content.kind === 'version') return { ...entry, contentPath: content.path }
      if (content.kind === 'plain') return { ...entry, plain: content.bytes, size: content.bytes.length }
      return entry
    }),
  )
  await downloadAsZip(zipFiles, folder.name ?? 'folder', await freshAccessToken(), (done, total) => onProgress(done, total))
  return 'done'
}
