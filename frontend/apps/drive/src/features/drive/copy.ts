import { createOwnedCollectionV1 } from '@kutup/crypto'
import { fetchDecryptedChunks } from '@kutup/files/download/fetchDecrypt'
import { resolveApiBase } from '@kutup/session/apiBase'
import api from '@kutup/session/client'
import { freshAccessToken } from '@kutup/session/client'
import { currentContent } from '../editor/content'
import { uploadCreating } from '../uploads/useUploadActions'
import { copyEmbedded, embeddingKind } from './embedded'
import { sealedAt } from '@kutup/drive-core/keyring'
import { loadFolderFiles } from '@kutup/drive-core/files'
import type { FolderIndex } from '@kutup/drive-core/folders'
import type { DriveIdentity } from '@kutup/drive-core/identity'
import { contentPath, fileLocation, type DriveFile, type Folder } from '@kutup/drive-core/model'

// Copying, end to end encrypted: the server never holds a readable file, so
// a copy is the browser reading the file (decrypting as it streams) and
// uploading it again, sealed under a new key for the destination. It costs
// what a re-upload costs; version history stays with the original.

/**
 * `name`, or the first free `name (1)`, `name (2)`… — the number goes before
 * the extension (`report (1).pdf`). Case-insensitive, like the server.
 */
export function copyName(name: string, taken: Iterable<string>): string {
  const names = new Set([...taken].map((n) => n.toLocaleLowerCase()))
  if (!names.has(name.toLocaleLowerCase())) return name
  const dot = name.lastIndexOf('.')
  const [base, ext] = dot > 0 ? [name.slice(0, dot), name.slice(dot)] : [name, '']
  for (let n = 1; ; n++) {
    const candidate = `${base} (${n})${ext}`
    if (!names.has(candidate.toLocaleLowerCase())) return candidate
  }
}

/** Whether `candidate` is `folder` or somewhere inside it (a folder cannot be copied into itself). */
export function isWithin(index: FolderIndex, candidate: Folder, folder: Folder): boolean {
  let at: Folder | undefined = candidate
  while (at) {
    if (at.id === folder.id && at.source === folder.source) return true
    at = at.parentId ? index.byId.get(at.parentId) : undefined
  }
  return false
}

/** The file's current plaintext (its latest edit, for documents), as a Blob. */
export async function readFile(folder: Folder, file: DriveFile, signal?: AbortSignal): Promise<Blob> {
  if (!file.fileKey) throw new Error('file is not open')
  const content = await currentContent(folder, file)
  if (content.kind === 'plain') return new Blob([content.bytes as BlobPart], { type: file.mimeType })
  const base = await resolveApiBase()
  const url = content.kind === 'version' ? `${base}${content.path}` : `${base}${contentPath(fileLocation(folder), file.id)}`
  const parts: BlobPart[] = []
  const sealed = await sealedAt(file, content.kind === 'version' ? content.keyGeneration : file.contentKeyGeneration)
  for await (const { plain } of fetchDecryptedChunks(url, sealed.fileKey, sealed.context, await freshAccessToken(), signal)) {
    // Blobs, not one growing buffer: the browser may keep large ones on disk.
    parts.push(new Blob([plain as BlobPart]))
  }
  return new Blob(parts, { type: file.mimeType })
}

/** Names already used directly in `dest` (its files and subfolders). */
export async function namesIn(index: FolderIndex, dest: Folder): Promise<string[]> {
  const files = await loadFolderFiles(dest)
  return [
    ...files.flatMap((f) => (f.name ? [f.name] : [])),
    ...index.childrenOf(dest.id).flatMap((f) => (f.name ? [f.name] : [])),
  ]
}

export async function copyFile(
  source: { folder: Folder; file: DriveFile },
  dest: Folder,
  name: string,
  signal: AbortSignal,
  progress: (sent: number, total: number) => void,
): Promise<void> {
  const blob = await readFile(source.folder, source.file, signal)
  const created = await uploadCreating(dest, new File([blob], name, { type: source.file.mimeType }), signal, progress, source.file.media ?? undefined)
  // A note's or whiteboard's pictures are its own: sealed anew for the copy.
  if (embeddingKind(source.file.name)) {
    signal.throwIfAborted()
    await copyEmbedded(source, await blob.text(), dest, created)
  }
}

/** Files (not folders) under `folder`, all levels — for progress totals. */
export async function countFiles(index: FolderIndex, folder: Folder): Promise<number> {
  const own = (await loadFolderFiles(folder)).filter((f) => f.fileKey && f.name).length
  const nested = await Promise.all(index.childrenOf(folder.id).map((c) => countFiles(index, c)))
  return own + nested.reduce((a, b) => a + b, 0)
}

/**
 * Copy `source` and everything in it as a new folder `name` under `destParent`
 * (which must be a folder the account owns). Files that cannot be decrypted
 * are skipped, as they would be by a download.
 */
export async function copyFolder(
  me: DriveIdentity,
  index: FolderIndex,
  source: Folder,
  destParent: Folder,
  name: string,
  signal: AbortSignal,
  onFileDone: () => void,
): Promise<void> {
  signal.throwIfAborted()
  const created = await createOwnedCollectionV1(me.masterKey, me.userId, name, destParent.id)
  await api.post('/collections', created.payload)
  const copy: Folder = {
    ...destParent,
    source: 'owned',
    remoteShareId: undefined,
    id: created.payload.id,
    parentId: destParent.id,
    name,
    key: created.collectionKey,
    keyEpoch: 1,
    ownerUserId: me.userId,
    ownerAuthorityPublicKey: me.authorityPublicKey,
    epochStatementHash: created.epochStatementHash,
    nameRevision: 1,
    color: null,
    ownerAccount: null,
    canUpload: true,
    canDelete: true,
    canManage: true,
    isRoot: false,
  }
  const files = (await loadFolderFiles(source)).filter((f) => f.fileKey && f.name)
  const taken: string[] = []
  for (const file of files) {
    signal.throwIfAborted()
    const fileName = copyName(file.name!, taken)
    taken.push(fileName)
    await copyFile({ folder: source, file }, copy, fileName, signal, () => {})
    onFileDone()
  }
  for (const child of index.childrenOf(source.id)) {
    if (!child.key) continue
    const childName = copyName(child.name ?? 'folder', taken)
    taken.push(childName)
    await copyFolder(me, index, child, copy, childName, signal, onFileDone)
  }
}
