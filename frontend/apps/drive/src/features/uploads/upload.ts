import { createFileRecordV1, type FileMetadataV1, type MediaMetadataV1 } from '@kutup/crypto'
import { readMedia } from '@kutup/files/media'
import { newFileBlobStreamEncryptorV1 } from '@kutup/crypto/fileBlob'
import { PLAIN_CHUNK } from '@kutup/crypto/streamEncryptor'
import { streamUpload, type UploadedFile } from '@kutup/files/upload/streamUpload'
import api, { freshAccessToken } from '@kutup/session/client'
import { getSession } from '@kutup/session/store'
import { loadFolderFiles } from '@kutup/drive-core/files'
import { folderLocation, type DriveFile, type Folder } from '@kutup/drive-core/model'
import {
  asNameTaken,
  freeName,
  inFolder,
  nameHashIn,
  namesIn,
  planUpload,
  recordContentHash,
  type FolderListing,
} from '@kutup/drive-core/names'
import type { ConflictPolicy } from '@kutup/drive-ui/nameConflicts'
import type { UploadOutcome } from '@kutup/drive-ui/uploadStore'
import { thumbnailAfterUpload } from '../thumbnails/schedule'
import type { CreatedFile } from '../drive/embedded'

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
  nameHash: string | null,
): Promise<CreatedFile> {
  if (!folder.key) throw new Error('folder is not open')
  const metadata: FileMetadataV1 = { name: file.name, mimeType: file.type || 'application/octet-stream', size: file.size }
  if (media) metadata.media = media
  const record = await createFileRecordV1(folder.id, folder.keyEpoch, folder.key, metadata)
  const enc = await newFileBlobStreamEncryptorV1(record.fileKey, {
    fileId: record.fileId,
    generation: record.keyGeneration,
  })
  const parts: BlobPart[] = [enc.prefix as BlobPart]
  if (file.size === 0) parts.push(enc.push(new Uint8Array(0), true) as BlobPart)
  for (let pos = 0; pos < file.size; ) {
    if (signal.aborted) throw new DOMException('Upload cancelled', 'AbortError')
    const end = Math.min(pos + PLAIN_CHUNK, file.size)
    const plain = new Uint8Array(await file.slice(pos, end).arrayBuffer())
    parts.push(enc.push(plain, end === file.size) as BlobPart)
    pos = end
  }
  const form = new FormData()
  form.append('fileId', record.fileId)
  form.append('metadataEnvelope', record.metadataEnvelope)
  form.append('fileKeyEnvelope', record.fileKeyEnvelope)
  if (nameHash) form.append('nameHash', nameHash)
  form.append('file', new Blob(parts, { type: 'application/octet-stream' }), 'encrypted')
  await api.post(`/drive/federation/shares/${shareId}/files`, form, {
    signal,
    onUploadProgress: (e) => progress(Math.round((e.progress ?? 0) * file.size), file.size),
  })
  return { fileId: record.fileId, fileKey: record.fileKey, keyGeneration: record.keyGeneration }
}

/**
 * Put a file into `folder`, returning what was made (null for a folder on
 * another server, whose files this server does not hold). A photo's or
 * video's details are read first and sealed with its name
 * (docs/plans/photos.md); `media` gives them instead (a copy keeps the
 * original's). Its thumbnail is queued from the plaintext still in hand.
 *
 * Its name's hash goes with it, so the server keeps the name unique, and
 * its content hash is recorded once it is stored
 * (docs/plans/drive-unique-names.md); `withoutNameHash` sends none (a file
 * replacing another takes the name after it). A taken name rejects with
 * the server's `name_taken` (`asNameTaken`).
 */
export async function uploadOne(
  folder: Folder,
  file: File,
  signal?: AbortSignal,
  progress?: (s: number, t: number) => void,
  media?: MediaMetadataV1 | null,
  waiting?: (waiting: boolean) => void,
  withoutNameHash = false,
): Promise<UploadedFile | null> {
  if (!folder.key) throw new Error('folder is not open')
  const details = media === undefined ? await readMedia(file, signal) : (media ?? undefined)
  const nameHash = withoutNameHash ? null : await nameHashIn(inFolder(folder), file.name)
  const location = folderLocation(folder)
  if (location.kind === 'remote') {
    await uploadRemote(folder, location.shareId, file, details, signal ?? new AbortController().signal, progress ?? (() => {}), nameHash)
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
    nameHash: nameHash ?? undefined,
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
 * The file `old` gives way to `uploaded`, which was sent without a name
 * hash: `old` goes to the trash (restorable), then the new file takes the
 * name. Stopped in between (a closed tab), both stay, and the owner's next
 * visit names the newer one `name (2)` — nothing is lost.
 */
async function finishReplace(folder: Folder, old: DriveFile, uploaded: UploadedFile, name: string): Promise<void> {
  await api.delete(`/files/${old.id}`)
  await api.post(`/collections/${folder.id}/name-hashes`, {
    files: [{ id: uploaded.fileId, nameHash: await nameHashIn(inFolder(folder), name) }],
  })
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
 * name has the person choose — Replace (that file to the trash), Keep both
 * (this one as `name (2)`) or Skip. A name taken meanwhile is looked at
 * again once.
 */
export async function placeFile(opts: PlaceFileOptions): Promise<UploadOutcome> {
  const { folder, file } = opts
  for (let attempt = 0; ; attempt++) {
    const listing = await opts.listing.get()
    const plan = await planUpload(folder, file, listing, opts.signal)
    if (plan.kind === 'same') return { skipped: 'here' }
    let upload = file
    let replaces: DriveFile | null = null
    if (plan.kind === 'taken') {
      const keptAs = freeName(file.name, namesIn(listing.files, listing.subfolders))
      const choice = await opts.policy.choose(
        {
          name: file.name,
          folderName: opts.folderName,
          holder: plan.holder.kind,
          keptAs,
          // Replacing moves the file there to the trash; files on other
          // servers are not named afterwards here, so they are kept.
          canReplace: plan.holder.kind === 'file' && folder.canDelete && folderLocation(folder).kind === 'local',
        },
        opts.signal,
      )
      if (choice === 'skip') return { skipped: 'chosen' }
      if (choice === 'keepBoth') upload = renamed(file, keptAs)
      else if (plan.holder.kind === 'file') replaces = plan.holder.file
    }
    try {
      const uploaded = await uploadOne(folder, upload, opts.signal, opts.progress, undefined, opts.waiting, replaces !== null)
      opts.listing.stale()
      if (replaces && uploaded) await finishReplace(folder, replaces, uploaded, upload.name)
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
