import { createFileRecordV1, renameFileRecordV1, type FileMetadataV1, type MediaMetadataV1 } from '@kutup/crypto'
import { hashBlob } from '@kutup/crypto/contentHash'
import { readMedia } from '@kutup/files/media'
import { newFileBlobStreamEncryptorV1, type FileBlobContextV1 } from '@kutup/crypto/fileBlob'
import { PLAIN_CHUNK } from '@kutup/crypto/streamEncryptor'
import { streamUpload, type UploadedFile } from '@kutup/files/upload/streamUpload'
import api, { freshAccessToken } from '@kutup/session/client'
import { getSession } from '@kutup/session/store'
import { loadFolderFiles } from '@kutup/drive-core/files'
import { opensInOffice } from '@kutup/drive-core/editorKind'
import { fileMetadataOf, folderLocation, type DriveFile, type Folder } from '@kutup/drive-core/model'
import {
  asNameTaken,
  findAvailableName,
  freeName,
  inFolder,
  nameHashIn,
  namesIn,
  planUpload,
  recordContentHash,
  type FolderListing,
} from '@kutup/drive-core/names'
import { rekeyFile } from '@kutup/drive-core/rekey'
import type { ConflictPolicy } from '@kutup/drive-ui/nameConflicts'
import type { UploadOutcome } from '@kutup/drive-ui/uploadStore'
import { thumbnailAfterUpload } from '../thumbnails/schedule'
import type { CreatedFile } from '@kutup/editors/files/embedded'

/**
 * A file into a federated folder: the other server takes one multipart body,
 * which our server spools to disk and streams on. It is encrypted a chunk at
 * a time into a Blob (which the browser may keep on disk), never whole in
 * memory.
 */
async function uploadRemote(
  folder: Folder,
  shareId: string,
  file: File,
  media: MediaMetadataV1 | undefined,
  signal: AbortSignal,
  progress: (s: number, t: number) => void,
  nameHash: string,
  sha256?: string,
): Promise<CreatedFile> {
  if (!folder.key) throw new Error('folder is not open')
  const metadata: FileMetadataV1 = {
    name: file.name,
    mimeType: file.type || 'application/octet-stream',
    size: file.size,
    sha256: sha256 ?? (await hashBlob(file, signal)),
  }
  if (media) metadata.media = media
  const record = await createFileRecordV1(folder.id, folder.keyEpoch, folder.key, metadata)
  const sealed = await sealToBlob(file, { fileId: record.fileId, generation: record.keyGeneration }, record.fileKey, signal)
  const form = new FormData()
  form.append('fileId', record.fileId)
  form.append('metadataEnvelope', record.metadataEnvelope)
  form.append('fileKeyEnvelope', record.fileKeyEnvelope)
  form.append('nameHash', nameHash)
  form.append('file', sealed, 'encrypted')
  await api.post(`/drive/federation/shares/${shareId}/files`, form, {
    signal,
    onUploadProgress: (e) => progress(Math.round((e.progress ?? 0) * file.size), file.size),
  })
  return { fileId: record.fileId, fileKey: record.fileKey, keyGeneration: record.keyGeneration }
}

/**
 * `file` sealed as Drive stores a file's content, a chunk at a time into a
 * Blob (which the browser may keep on disk), never whole in memory.
 */
async function sealToBlob(file: File, context: FileBlobContextV1, fileKey: Uint8Array, signal?: AbortSignal): Promise<Blob> {
  const enc = await newFileBlobStreamEncryptorV1(fileKey, context)
  const parts: BlobPart[] = [enc.prefix as BlobPart]
  if (file.size === 0) parts.push(enc.push(new Uint8Array(0), true) as BlobPart)
  for (let pos = 0; pos < file.size; ) {
    if (signal?.aborted) throw new DOMException('Upload cancelled', 'AbortError')
    const end = Math.min(pos + PLAIN_CHUNK, file.size)
    const plain = new Uint8Array(await file.slice(pos, end).arrayBuffer())
    parts.push(enc.push(plain, end === file.size) as BlobPart)
    pos = end
  }
  return new Blob(parts, { type: 'application/octet-stream' })
}

/**
 * Put a file into `folder`, returning what was made (null for a folder on
 * another server, whose files this server does not hold). A photo's or
 * video's details are read first and sealed with its name
 * (docs/plans/photos.md); `media` gives them instead (a copy keeps the
 * original's). Its thumbnail is queued from the plaintext still in hand.
 *
 * Its name's hash goes with it (`nameHash` when the caller worked it out,
 * as "Keep both" does), so the server keeps the name unique, and its
 * content hash is recorded once it is stored
 * (docs/plans/drive-unique-names.md). `sha256`: the content's, when it was
 * read already. A taken name rejects with the server's `name_taken`
 * (`asNameTaken`).
 */
export async function uploadOne(
  folder: Folder,
  file: File,
  signal?: AbortSignal,
  progress?: (s: number, t: number) => void,
  media?: MediaMetadataV1 | null,
  waiting?: (waiting: boolean) => void,
  known: { nameHash?: string; sha256?: string } = {},
): Promise<UploadedFile | null> {
  if (!folder.key) throw new Error('folder is not open')
  const details = media === undefined ? await readMedia(file, signal) : (media ?? undefined)
  const nameHash = known.nameHash ?? (await nameHashIn(inFolder(folder), file.name))
  const location = folderLocation(folder)
  if (location.kind === 'remote') {
    await uploadRemote(
      folder,
      location.shareId,
      file,
      details,
      signal ?? new AbortController().signal,
      progress ?? (() => {}),
      nameHash,
      known.sha256,
    )
    return null
  }
  const owner = getSession()?.userId
  const uploaded = await streamUpload({
    file,
    collection: { id: folder.id, keyEpoch: folder.keyEpoch, collectionKey: folder.key },
    accessToken: freshAccessToken,
    onProgress: progress,
    onWaiting: waiting,
    signal,
    media: details,
    // A reload or a crash leaves it to go on with (the upload panel).
    resumable: owner ? { owner } : undefined,
    nameHash,
    sha256: known.sha256,
  })
  await recordContentHash(folder, uploaded.fileId, uploaded.contentSha256)
  thumbnailAfterUpload(uploaded, file)
  return uploaded
}

/** The same bytes under another name (read from disk as the original is). */
function renamed(file: File, name: string): File {
  return new File([file], name, { type: file.type, lastModified: file.lastModified })
}

/**
 * The most a Replace sends: the new content goes up as a version of the
 * file there, in one request the server caps at 2 GiB sealed. Larger files
 * are kept both or skipped (resumable versions: docs/roadmap.md).
 */
export const REPLACE_LIMIT_BYTES = 2 * 1024 ** 3 - 64 * 1024 ** 2

/** Whether `holder` can be replaced by `file`'s content here. */
export function canReplace(folder: Folder, holder: DriveFile, file: File): boolean {
  return (
    folder.canUpload &&
    folderLocation(folder).kind === 'local' &&
    holder.fileKey !== null &&
    holder.name !== null &&
    // What opens in Office keeps its own history (a collaboration log, a
    // note's state): new content comes in through its editor.
    !opensInOffice(holder.name) &&
    file.size <= REPLACE_LIMIT_BYTES
  )
}

/**
 * Replace (Proton's "Replace"): `file`'s content becomes the newest
 * version of `listed`, which keeps its id, name, sharing and history. Its
 * metadata takes the new size, SHA-256 and photo details, and the folder's
 * content hash is recorded for the new content.
 */
async function replaceContent(
  folder: Folder,
  listed: DriveFile,
  file: File,
  signal: AbortSignal,
  progress?: (s: number, t: number) => void,
  sha256?: string,
): Promise<void> {
  // New content is never sealed under a key the folder has left.
  const holder = await rekeyFile(folder, listed)
  if (!holder.fileKey) throw new Error('file is not open')
  const digest = sha256 ?? (await hashBlob(file, signal))
  const media = await readMedia(file, signal)
  const sealed = await sealToBlob(file, { fileId: holder.id, generation: holder.keyGeneration }, holder.fileKey, signal)
  const form = new FormData()
  form.append('kind', 'file')
  form.append('seqAtSnapshot', '0')
  form.append('docKeyId', '1')
  form.append('keepForever', 'false')
  form.append('file', sealed, 'version')
  await api.post(`/files/${holder.id}/versions`, form, {
    signal,
    onUploadProgress: (e) => progress?.(Math.round((e.progress ?? 0) * file.size), file.size),
  })
  // The name stays as it is: no nameHash.
  const next = await renameFileRecordV1(
    { id: holder.id, keyGeneration: holder.keyGeneration, metadataRevision: holder.metadataRevision },
    holder.fileKey,
    fileMetadataOf(holder, { size: file.size, mimeType: file.type || holder.mimeType, sha256: digest, media }),
  )
  await api.put(`/files/${holder.id}`, next)
  await recordContentHash(folder, holder.id, digest)
}

/** A folder's listing, read once for a batch and again when the server says it changed. */
export class BatchListing {
  private current: Promise<FolderListing> | null = null

  constructor(
    private readonly folder: Folder,
    private readonly subfolders: () => Folder[],
  ) {}

  get(): Promise<FolderListing> {
    if (!this.current) {
      const folder = this.folder
      this.current = loadFolderFiles(folder).then((files) => ({ files, subfolders: this.subfolders() }))
      this.current.catch(() => (this.current = null))
    }
    return this.current
  }

  /** Read it anew next time (something was added since). */
  stale(): void {
    this.current = null
  }
}

export interface PlaceFileOptions {
  folder: Folder
  file: File
  folderName: string
  listing: BatchListing
  policy: ConflictPolicy
  signal: AbortSignal
  progress?: (s: number, t: number) => void
  waiting?: (waiting: boolean) => void
}

/**
 * One file into a folder whose names are unique
 * (docs/plans/drive-unique-names.md): a free name is uploaded; the same
 * file already there under its name is skipped; another item holding the
 * name has the person choose — Replace (this content as the newest version
 * of the file there), Keep both (this one under the first free
 * `name (n)`, as the server says) or Skip. A name taken meanwhile is looked
 * at again once.
 */
export async function placeFile(opts: PlaceFileOptions): Promise<UploadOutcome> {
  const { folder, file } = opts
  for (let attempt = 0; ; attempt++) {
    const listing = await opts.listing.get()
    const plan = await planUpload(folder, file, listing, opts.signal)
    if (plan.kind === 'same') return { skipped: 'here' }
    let upload = file
    let nameHash: string | undefined
    const sha256 = plan.kind === 'taken' ? plan.sha256 : undefined
    if (plan.kind === 'taken') {
      // The next free name, asked of the server (it knows names this
      // listing may not); a folder on another server is asked of its listing.
      const kept =
        folderLocation(folder).kind === 'local'
          ? await findAvailableName(inFolder(folder), file.name, { skipName: true })
          : { name: freeName(file.name, namesIn(listing.files, listing.subfolders)), hash: undefined }
      const replaceable = plan.holder.kind === 'file' && canReplace(folder, plan.holder.file, file)
      const choice = await opts.policy.choose(
        {
          name: file.name,
          folderName: opts.folderName,
          holder: plan.holder.kind,
          keptAs: kept.name,
          canReplace: replaceable,
          replaceTooLarge: plan.holder.kind === 'file' && file.size > REPLACE_LIMIT_BYTES,
        },
        opts.signal,
      )
      if (choice === 'skip') return { skipped: 'chosen' }
      if (choice === 'replace' && plan.holder.kind === 'file' && replaceable) {
        await replaceContent(folder, plan.holder.file, file, opts.signal, opts.progress, sha256)
        opts.listing.stale()
        return
      }
      upload = renamed(file, kept.name)
      nameHash = kept.hash
    }
    try {
      await uploadOne(folder, upload, opts.signal, opts.progress, undefined, opts.waiting, { nameHash, sha256 })
      opts.listing.stale()
      return
    } catch (error) {
      if (!asNameTaken(error) || attempt > 0) throw error
      // Someone took the name meanwhile: look at the folder again.
      opts.listing.stale()
    }
  }
}

/**
 * As `uploadOne`, for a copy: the new file's id and key wherever it went
 * (here, or a folder on another server), so what belongs to it (its
 * pictures) can be sealed for it too.
 */
export async function uploadCreating(
  folder: Folder,
  file: File,
  signal: AbortSignal,
  progress: (s: number, t: number) => void,
  media: MediaMetadataV1 | undefined,
): Promise<CreatedFile> {
  if (!folder.key) throw new Error('folder is not open')
  const location = folderLocation(folder)
  if (location.kind === 'remote') {
    return uploadRemote(folder, location.shareId, file, media, signal, progress, await nameHashIn(inFolder(folder), file.name))
  }
  const uploaded = await uploadOne(folder, file, signal, progress, media)
  if (!uploaded) throw new Error('upload made no file')
  return uploaded
}
