import { hashBlob } from '@kutup/crypto/contentHash'
import { opensInOffice } from '@kutup/drive-core/editorKind'
import { fileMetadataOf, folderLocation, type DriveFile, type Folder } from '@kutup/drive-core/model'
import { contentHashIn } from '@kutup/drive-core/names'
import { rekeyFile } from '@kutup/drive-core/rekey'
import type { ReplaceProblem } from '@kutup/drive-ui/nameConflicts'
import { readMedia } from '@kutup/files/media'
import { pendingUploads } from '@kutup/files/upload/pendingUploads'
import {
  FolderKeyChanged,
  NotTheSameFile,
  resumeUpload,
  streamVersionUpload,
  UploadNoLongerOnServer,
  uploadIdOf,
  VersionConflict,
  VersionUploading,
  type UploadedFile,
} from '@kutup/files/upload/streamUpload'
import api, { freshAccessToken } from '@kutup/session/client'
import { getSession } from '@kutup/session/store'

/** Whether `holder` can be replaced by new content here. */
export function canReplace(folder: Folder, holder: DriveFile): boolean {
  return (
    folder.canUpload &&
    folderLocation(folder).kind === 'local' &&
    holder.fileKey !== null &&
    holder.name !== null &&
    // What opens in Office keeps its own history (a collaboration log, a
    // note's state): new content comes in through its editor.
    !opensInOffice(holder.name)
  )
}

export interface ReplaceOptions {
  signal: AbortSignal
  progress?: (s: number, t: number) => void
  waiting?: (waiting: boolean) => void
  /** The new content's SHA-256, when it was read already. */
  sha256?: string
}

/** What a Replace came to: done, or why it could not go ahead (the person chooses then). */
export type ReplaceOutcome = { done: UploadedFile } | { problem: ReplaceProblem; uploadId?: string }

/**
 * How long this account's own open replacement must have gone without a
 * part before it is taken for one a crash left behind and may be cancelled
 * to start again. Not minutes: a large file on a slow connection can sit
 * well over two minutes between parts, and cancelling it would throw away
 * a replacement still running on another device or tab.
 */
export const ABANDONED_VERSION_UPLOAD_SECONDS = 3600

/** Whether a refused resume should fall back to asking (anything else is a real failure). */
function cannotResume(error: unknown): boolean {
  return error instanceof NotTheSameFile || error instanceof FolderKeyChanged || error instanceof UploadNoLongerOnServer
}

/**
 * Replace (Proton's "Replace", a new revision): `file`'s content becomes
 * the newest version of `listed`, which keeps its id, name, sharing and
 * history. It goes up over tus like a new file — resumable after a reload,
 * at any size — and its next metadata (new size, SHA-256, photo details)
 * and the folder's content hash land with it (docs/api.md, "POST
 * /api/uploads with versionOf"). A file changed meanwhile, or another open
 * replacement of it, is not retried: the caller asks the person. This
 * account's own open replacement of the same local file is gone on with;
 * one idle for an hour is offered to cancel; anything else is running
 * right now (maybe on another device) and is never cancelled.
 */
export async function replaceContent(folder: Folder, listed: DriveFile, file: File, opts: ReplaceOptions): Promise<ReplaceOutcome> {
  if (!folder.key) throw new Error('folder is not open')
  // New content is never sealed under a key the folder has left.
  const holder = await rekeyFile(folder, listed)
  if (!holder.fileKey || !holder.name) throw new Error('file is not open')
  const sha256 = opts.sha256 ?? (await hashBlob(file, opts.signal))
  const media = await readMedia(file, opts.signal)
  const owner = getSession()?.userId
  try {
    const done = await streamVersionUpload({
      file,
      target: {
        fileId: holder.id,
        collectionId: folder.id,
        keyEpoch: holder.keyEpoch,
        fileKeyEnvelope: holder.fileKeyEnvelope,
        fileKey: holder.fileKey,
        keyGeneration: holder.keyGeneration,
        metadataRevision: holder.metadataRevision,
      },
      metadata: fileMetadataOf(holder, { size: file.size, mimeType: file.type || holder.mimeType, sha256, media }),
      contentHash: await contentHashIn(folder, sha256),
      accessToken: freshAccessToken,
      onProgress: opts.progress,
      onWaiting: opts.waiting,
      signal: opts.signal,
      resumable: owner ? { owner } : undefined,
    })
    return { done }
  } catch (error) {
    if (error instanceof VersionConflict) return { problem: 'changed' }
    if (!(error instanceof VersionUploading)) throw error
    if (!error.uploadId) return { problem: 'othersUpload' }
    const uploadId = error.uploadId
    // Ours: gone on with when this browser remembers it for this same file.
    const mine = owner
      ? (await pendingUploads.list(owner)).find(
          (p) => p.fileId === holder.id && p.version && uploadIdOf(p.uploadUrl) === uploadId,
        )
      : undefined
    if (mine) {
      try {
        const done = await resumeUpload({
          upload: mine,
          file,
          collection: { id: folder.id, keyEpoch: folder.keyEpoch, collectionKey: folder.key },
          accessToken: freshAccessToken,
          onProgress: opts.progress,
          onWaiting: opts.waiting,
          signal: opts.signal,
        })
        return { done }
      } catch (resumeError) {
        if (resumeError instanceof VersionConflict) return { problem: 'changed' }
        if (!cannotResume(resumeError)) throw resumeError
      }
    }
    const abandoned = (error.idleSeconds ?? 0) >= ABANDONED_VERSION_UPLOAD_SECONDS
    return abandoned ? { problem: 'ownUpload', uploadId } : { problem: 'othersUpload' }
  }
}

/** Cancel this account's open upload `uploadId` of a new version of `fileId` (tus DELETE). */
export async function cancelVersionUpload(fileId: string, uploadId: string): Promise<void> {
  await api.delete(`/uploads/${encodeURIComponent(uploadId)}`, { headers: { 'Tus-Resumable': '1.0.0' } }).catch((error: unknown) => {
    // One the server already let go is fine.
    if ((error as { response?: { status?: number } }).response?.status !== 404) throw error
  })
  const owner = getSession()?.userId
  const remembered = owner ? (await pendingUploads.list(owner)).find((p) => p.fileId === fileId && uploadIdOf(p.uploadUrl) === uploadId) : undefined
  if (remembered) await pendingUploads.remove(fileId)
}
