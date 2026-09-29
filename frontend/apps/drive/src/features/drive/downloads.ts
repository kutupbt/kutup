import { fetchDecryptedChunks } from '@kutup/files/download/fetchDecrypt'
import { openDownloadSink } from '@kutup/files/download/streamDownload'
import { downloadAsZip, FsaRequiredError, type ZipFile } from '@kutup/files/zipDownload'
import { resolveApiBase } from '@kutup/session/apiBase'
import { freshAccessToken } from '@kutup/session/client'
import { currentContent } from '../editor/content'
import { readFile } from './copy'
import { embeddingKind, exportEmbedded, type ExportedFile } from './embedded'
import { loadFolderFiles } from '@kutup/drive-core/files'
import { sealedAt } from '@kutup/drive-core/keyring'
import { contentPath, fileLocation, folderLocation, type DriveFile, type Folder } from '@kutup/drive-core/model'

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
  // A note or whiteboard with pictures of its own leaves with them.
  if (embeddingKind(file.name)) {
    const exported = await exportEmbedded(folder, file, await (await readFile(folder, file)).text())
    if (exported) return saveExported(file, exported)
  }
  // The save picker needs the click's user activation: ask for it first.
  const sink = await openDownloadSink({ filename: file.name, mimeType: file.mimeType })
  try {
    const base = await resolveApiBase()
    const content = await currentContent(folder, file)
    if (content.kind === 'plain') {
      await sink.write(content.bytes)
    } else {
      const url = content.kind === 'version' ? `${base}${content.path}` : `${base}${contentPath(fileLocation(folder), file.id)}`
      // Sealed under the key generation of the content served (a file
      // re-keyed since keeps older content under its older key).
      const sealed = await sealedAt(file, content.kind === 'version' ? content.keyGeneration : file.contentKeyGeneration)
      for await (const { plain } of fetchDecryptedChunks(url, sealed.fileKey, sealed.context, await freshAccessToken())) {
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

/**
 * A file with its pictures: one file (a whiteboard, pictures inline) is
 * saved as itself; a note and its pictures as a ZIP named after the note.
 */
async function saveExported(file: DriveFile, exported: ExportedFile[]): Promise<void> {
  if (exported.length === 1) {
    const only = exported[0]
    const sink = await openDownloadSink({ filename: file.name ?? only.path, mimeType: file.mimeType })
    try {
      await sink.write(only.bytes)
      await sink.finalize()
    } catch (err) {
      await sink.abort().catch(() => {})
      throw err
    }
    return
  }
  const archive = (file.name ?? 'note').replace(/\.[^.]+$/, '')
  await downloadAsZip(
    exported.map((e, i) => ({ id: `${file.id}-${i}`, keyGeneration: 1, name: e.path, size: e.bytes.length, fileKey: new Uint8Array(32), plain: e.bytes })),
    archive,
    await freshAccessToken(),
    () => {},
  )
}

/**
 * A file's ZIP entries at `path`: its content, and for a note or whiteboard
 * with pictures, the pictures too (beside it, as a single download has them).
 */
async function zipEntries(folder: Folder, file: DriveFile, path: string): Promise<ZipFile[]> {
  if (embeddingKind(file.name)) {
    const exported = await exportEmbedded(folder, file, await (await readFile(folder, file)).text())
    if (exported) {
      const dir = path.includes('/') ? path.slice(0, path.lastIndexOf('/') + 1) : ''
      return exported.map((e, i) => ({
        id: `${file.id}-${i}`,
        keyGeneration: 1,
        name: i === 0 ? path : dir + e.path,
        size: e.bytes.length,
        fileKey: new Uint8Array(32),
        plain: e.bytes,
      }))
    }
  }
  return [await zipEntry(folder, file, path)]
}

/** One ZIP entry: the file's current content (latest edit), at `path` inside the archive. */
async function zipEntry(folder: Folder, file: DriveFile, path: string): Promise<ZipFile> {
  const location = folderLocation(folder)
  const content = await currentContent(folder, file)
  const sealed = await sealedAt(file, content.kind === 'version' ? content.keyGeneration : file.contentKeyGeneration)
  const entry: ZipFile = {
    id: file.id,
    keyGeneration: sealed.context.generation,
    name: path,
    size: file.size,
    fileKey: sealed.fileKey,
  }
  if (content.kind === 'plain') return { ...entry, plain: content.bytes, size: content.bytes.length }
  if (location.kind === 'remote') return { ...entry, isRemote: true, remoteShareId: location.shareId }
  if (content.kind === 'version') return { ...entry, contentPath: content.path }
  return entry
}

/** A folder's files (not its subfolders) as one ZIP, split at 2 GiB. */
export async function downloadFolderZip(folder: Folder, onProgress: (done: number, total: number) => void): Promise<'empty' | 'done'> {
  const files = (await loadFolderFiles(folder)).filter((f) => f.fileKey && f.name)
  if (files.length === 0) return 'empty'
  const zipFiles = (await Promise.all(files.map((f) => zipEntries(folder, f, f.name!)))).flat()
  await downloadAsZip(zipFiles, folder.name ?? 'folder', await freshAccessToken(), (done, total) => onProgress(done, total))
  return 'done'
}

/**
 * Several selected items as one ZIP named `archive`: files at the top, each
 * selected folder's files under the folder's name (its own files, not its
 * subfolders — the same depth a single folder's ZIP has).
 */
export async function downloadSelectionZip(
  items: ({ folder: Folder; file?: undefined } | { folder: Folder; file: DriveFile })[],
  archive: string,
  onProgress: (done: number, total: number) => void,
): Promise<'empty' | 'done'> {
  const entries: ZipFile[] = []
  const used = new Set<string>()
  const unique = (path: string) => {
    let candidate = path
    for (let n = 1; used.has(candidate.toLocaleLowerCase()); n++) {
      // The number goes before an extension in the last path segment.
      const dot = path.lastIndexOf('.')
      candidate = dot > path.lastIndexOf('/') + 1 ? `${path.slice(0, dot)} (${n})${path.slice(dot)}` : `${path} (${n})`
    }
    used.add(candidate.toLocaleLowerCase())
    return candidate
  }
  for (const item of items) {
    if (item.file) {
      if (item.file.fileKey && item.file.name) entries.push(...(await zipEntries(item.folder, item.file, unique(item.file.name))))
      continue
    }
    if (!item.folder.key) continue
    const dir = unique(item.folder.name ?? 'folder')
    for (const f of await loadFolderFiles(item.folder)) {
      if (f.fileKey && f.name) entries.push(...(await zipEntries(item.folder, f, `${dir}/${f.name}`)))
    }
  }
  if (entries.length === 0) return 'empty'
  await downloadAsZip(entries, archive, await freshAccessToken(), (done, total) => onProgress(done, total))
  return 'done'
}
